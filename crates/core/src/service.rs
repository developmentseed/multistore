//! S3-compatible service implementing the [`s3s::S3`] trait.
//!
//! [`MultistoreService`] maps S3 API operations to `object_store` calls,
//! providing a complete S3 protocol implementation that works across all
//! backends (S3, Azure, GCS) and all runtimes (native, WASM).
//!
//! ## Architecture
//!
//! ```text
//! S3 request → s3s protocol dispatch → MultistoreService (S3 trait)
//!   → bucket registry lookup + authorization
//!   → object_store call
//!   → s3s response
//! ```
//!
//! The service owns:
//! - A [`BucketRegistry`] for bucket lookup and authorization
//! - A [`CredentialRegistry`] for credential verification (via [`MultistoreAuth`])
//! - A [`StoreFactory`] for creating object stores per request
//! - A [`DashMap`] for tracking in-progress multipart uploads

use std::borrow::Cow;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use dashmap::DashMap;
use futures::{Stream, TryStreamExt};
use object_store::list::PaginatedListStore;
use object_store::multipart::{MultipartStore, PartId};
use object_store::path::Path;
use object_store::{GetOptions, ObjectStore, ObjectStoreExt, PutPayload};
use s3s::auth::SecretKey;
use s3s::dto::{self, StreamingBlob, Timestamp};
use s3s::s3_error;
use s3s::stream::{ByteStream, RemainingLength};
use s3s::{S3Request, S3Response, S3Result};

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Wrapper that adds `Sync` to a `Send`-only stream via `Mutex`.
///
/// `object_store`'s `GetResult::into_stream()` returns `BoxStream` which is
/// `Send` but not `Sync`. s3s's `StreamingBlob` requires `Send + Sync`.
/// Since streams are only ever polled from a single task, wrapping in a
/// `Mutex` is safe and has negligible overhead.
struct SyncStream<S> {
    inner: Mutex<S>,
    remaining_bytes: usize,
}

impl<S> SyncStream<S> {
    fn new(stream: S, remaining_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(stream),
            remaining_bytes,
        }
    }
}

impl<S, E> Stream for SyncStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    type Item = Result<Bytes, StdError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut guard = self.inner.lock().unwrap();
        Pin::new(&mut *guard)
            .poll_next(cx)
            .map(|opt| opt.map(|r| r.map_err(|e| Box::new(e) as StdError)))
    }
}

impl<S, E> ByteStream for SyncStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    fn remaining_length(&self) -> RemainingLength {
        RemainingLength::new_exact(self.remaining_bytes)
    }
}

// SAFETY: The inner stream is Send and the Mutex provides synchronization.
// Streams are only polled from a single task, so this is safe.
unsafe impl<S: Send> Sync for SyncStream<S> {}

use crate::api::list::build_list_prefix;
use crate::api::list_rewrite::ListRewrite;
use crate::error::ProxyError;
use crate::registry::{BucketRegistry, CredentialRegistry, ResolvedBucket};
use crate::types::{BucketConfig, ResolvedIdentity, S3Operation};

/// Factory trait for creating object stores from bucket configuration.
///
/// Each runtime provides its own implementation (e.g. injecting custom HTTP
/// connectors for WASM). The factory creates stores per-request since bucket
/// configs may differ.
pub trait StoreFactory: Send + Sync + 'static {
    /// Create an [`ObjectStore`] for GET/HEAD/PUT/DELETE operations.
    fn create_store(&self, config: &BucketConfig) -> Result<Arc<dyn ObjectStore>, ProxyError>;

    /// Create a [`PaginatedListStore`] for LIST operations.
    fn create_paginated_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, ProxyError>;

    /// Create a [`MultipartStore`] for multipart upload operations.
    fn create_multipart_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Arc<dyn MultipartStore>, ProxyError>;
}

/// State for an in-progress multipart upload.
struct UploadState {
    config: BucketConfig,
    path: Path,
    parts: Vec<Option<PartId>>,
}

/// S3 service implementation backed by object_store.
///
/// Implements [`s3s::S3`] by mapping each S3 operation to the appropriate
/// object_store call, with bucket registry lookup and authorization in between.
pub struct MultistoreService<R, F> {
    bucket_registry: R,
    store_factory: F,
    uploads: DashMap<String, UploadState>,
}

impl<R, F> MultistoreService<R, F>
where
    R: BucketRegistry,
    F: StoreFactory,
{
    /// Create a new service with the given registries and store factory.
    pub fn new(bucket_registry: R, store_factory: F) -> Self {
        Self {
            bucket_registry,
            store_factory,
            uploads: DashMap::new(),
        }
    }

    /// Resolve a bucket and authorize the operation.
    async fn resolve_bucket(
        &self,
        bucket: &str,
        identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> S3Result<ResolvedBucket> {
        self.bucket_registry
            .get_bucket(bucket, identity, operation)
            .await
            .map_err(proxy_error_to_s3)
    }

    /// Extract the identity from the s3s request credentials.
    fn identity_from_credentials(
        &self,
        credentials: &Option<s3s::auth::Credentials>,
    ) -> ResolvedIdentity {
        match credentials {
            Some(creds) => {
                // s3s verified the signature; we treat authenticated requests
                // as long-lived credentials for authorization purposes.
                // The actual StoredCredential is not needed here since
                // authorization is done via the bucket registry.
                ResolvedIdentity::LongLived {
                    credential: crate::types::StoredCredential {
                        access_key_id: creds.access_key.clone(),
                        secret_access_key: String::new(), // not needed for authz
                        principal_name: creds.access_key.clone(),
                        allowed_scopes: vec![], // authorization is done via bucket registry
                        created_at: chrono::Utc::now(),
                        expires_at: None,
                        enabled: true,
                    },
                }
            }
            None => ResolvedIdentity::Anonymous,
        }
    }

    /// Build an object_store Path from a bucket config and S3 key.
    fn build_path(config: &BucketConfig, key: &str) -> Path {
        match &config.backend_prefix {
            Some(prefix) => {
                let p = prefix.trim_end_matches('/');
                if p.is_empty() {
                    Path::from(key)
                } else {
                    Path::from(format!("{}/{}", p, key))
                }
            }
            None => Path::from(key),
        }
    }
}

#[async_trait::async_trait]
impl<R, F> s3s::S3 for MultistoreService<R, F>
where
    R: BucketRegistry,
    F: StoreFactory,
{
    async fn get_object(
        &self,
        req: S3Request<dto::GetObjectInput>,
    ) -> S3Result<S3Response<dto::GetObjectOutput>> {
        let identity = self.identity_from_credentials(&req.credentials);
        let bucket = &req.input.bucket;
        let key = &req.input.key;
        let operation = S3Operation::GetObject {
            bucket: bucket.clone(),
            key: key.clone(),
        };

        let resolved = self.resolve_bucket(bucket, &identity, &operation).await?;
        let store = self
            .store_factory
            .create_store(&resolved.config)
            .map_err(proxy_error_to_s3)?;
        let path = Self::build_path(&resolved.config, key);

        let opts = GetOptions {
            if_match: req.input.if_match.as_ref().map(etag_condition_to_string),
            if_none_match: req
                .input
                .if_none_match
                .as_ref()
                .map(etag_condition_to_string),
            range: parse_range(&req.input.range),
            head: false,
            ..Default::default()
        };

        let result = store
            .get_opts(&path, opts)
            .await
            .map_err(object_store_error_to_s3)?;

        let meta = &result.meta;
        let content_length = (result.range.end - result.range.start) as i64;
        let e_tag = meta.e_tag.as_ref().map(|e| dto::ETag::Strong(e.clone()));
        let last_modified = Some(Timestamp::from(std::time::SystemTime::from(
            meta.last_modified,
        )));

        // Wrap the object_store stream with SyncStream to satisfy StreamingBlob's
        // Send + Sync requirement. The stream is Send but not Sync; the Mutex
        // wrapper adds Sync with negligible overhead since polling is sequential.
        let stream = result.into_stream();
        let sync_stream = SyncStream::new(stream, content_length as usize);
        let body = StreamingBlob::new(sync_stream);

        Ok(S3Response::new(dto::GetObjectOutput {
            body: Some(body),
            content_length: Some(content_length),
            e_tag,
            last_modified,
            ..Default::default()
        }))
    }

    async fn head_object(
        &self,
        req: S3Request<dto::HeadObjectInput>,
    ) -> S3Result<S3Response<dto::HeadObjectOutput>> {
        let identity = self.identity_from_credentials(&req.credentials);
        let bucket = &req.input.bucket;
        let key = &req.input.key;
        let operation = S3Operation::HeadObject {
            bucket: bucket.clone(),
            key: key.clone(),
        };

        let resolved = self.resolve_bucket(bucket, &identity, &operation).await?;
        let store = self
            .store_factory
            .create_store(&resolved.config)
            .map_err(proxy_error_to_s3)?;
        let path = Self::build_path(&resolved.config, key);

        let opts = GetOptions {
            if_match: req.input.if_match.as_ref().map(etag_condition_to_string),
            if_none_match: req
                .input
                .if_none_match
                .as_ref()
                .map(etag_condition_to_string),
            head: true,
            ..Default::default()
        };

        let result = store
            .get_opts(&path, opts)
            .await
            .map_err(object_store_error_to_s3)?;

        let meta = &result.meta;

        Ok(S3Response::new(dto::HeadObjectOutput {
            content_length: Some(meta.size as i64),
            e_tag: meta.e_tag.as_ref().map(|e| dto::ETag::Strong(e.clone())),
            last_modified: Some(Timestamp::from(std::time::SystemTime::from(
                meta.last_modified,
            ))),
            ..Default::default()
        }))
    }

    async fn put_object(
        &self,
        req: S3Request<dto::PutObjectInput>,
    ) -> S3Result<S3Response<dto::PutObjectOutput>> {
        let identity = self.identity_from_credentials(&req.credentials);
        let bucket = &req.input.bucket;
        let key = &req.input.key;
        let operation = S3Operation::PutObject {
            bucket: bucket.clone(),
            key: key.clone(),
        };

        let resolved = self.resolve_bucket(bucket, &identity, &operation).await?;
        let store = self
            .store_factory
            .create_store(&resolved.config)
            .map_err(proxy_error_to_s3)?;
        let path = Self::build_path(&resolved.config, key);

        // Materialize the body into bytes for PutPayload.
        // object_store's PutPayload doesn't support streaming directly.
        let payload = match req.input.body {
            Some(blob) => {
                let data: Bytes = blob
                    .try_collect::<Vec<_>>()
                    .await
                    .map_err(|e| s3_error!(InternalError, "failed to read body: {e}"))?
                    .into_iter()
                    .fold(bytes::BytesMut::new(), |mut acc, chunk| {
                        acc.extend_from_slice(&chunk);
                        acc
                    })
                    .freeze();
                PutPayload::from_bytes(data)
            }
            None => PutPayload::default(),
        };

        let result = store
            .put(&path, payload)
            .await
            .map_err(object_store_error_to_s3)?;

        Ok(S3Response::new(dto::PutObjectOutput {
            e_tag: result
                .e_tag
                .as_ref()
                .map(|e: &String| dto::ETag::Strong(e.clone())),
            ..Default::default()
        }))
    }

    async fn delete_object(
        &self,
        req: S3Request<dto::DeleteObjectInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectOutput>> {
        let identity = self.identity_from_credentials(&req.credentials);
        let bucket = &req.input.bucket;
        let key = &req.input.key;
        let operation = S3Operation::DeleteObject {
            bucket: bucket.clone(),
            key: key.clone(),
        };

        let resolved = self.resolve_bucket(bucket, &identity, &operation).await?;
        let store = self
            .store_factory
            .create_store(&resolved.config)
            .map_err(proxy_error_to_s3)?;
        let path = Self::build_path(&resolved.config, key);

        store
            .delete(&path)
            .await
            .map_err(object_store_error_to_s3)?;

        Ok(S3Response::new(dto::DeleteObjectOutput::default()))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<dto::ListObjectsV2Input>,
    ) -> S3Result<S3Response<dto::ListObjectsV2Output>> {
        let identity = self.identity_from_credentials(&req.credentials);
        let bucket = &req.input.bucket;
        let operation = S3Operation::ListBucket {
            bucket: bucket.clone(),
            raw_query: None,
        };

        let resolved = self.resolve_bucket(bucket, &identity, &operation).await?;
        let store = self
            .store_factory
            .create_paginated_store(&resolved.config)
            .map_err(proxy_error_to_s3)?;

        let client_prefix = req.input.prefix.as_deref().unwrap_or("");
        let delimiter = req.input.delimiter.as_deref().unwrap_or("/").to_string();
        let max_keys = req.input.max_keys.unwrap_or(1000).min(1000) as usize;

        let full_prefix = build_list_prefix(&resolved.config, client_prefix);

        let offset = req
            .input
            .start_after
            .as_ref()
            .map(|sa| build_list_prefix(&resolved.config, sa));

        let prefix = if full_prefix.is_empty() {
            None
        } else {
            Some(full_prefix.as_str())
        };

        let opts = object_store::list::PaginatedListOptions {
            offset,
            delimiter: Some(Cow::Owned(delimiter.clone())),
            max_keys: Some(max_keys),
            page_token: req.input.continuation_token.clone(),
            ..Default::default()
        };

        let paginated = store
            .list_paginated(prefix, opts)
            .await
            .map_err(object_store_error_to_s3)?;

        // Compute strip prefix for backend_prefix removal
        let backend_prefix = resolved
            .config
            .backend_prefix
            .as_deref()
            .unwrap_or("")
            .trim_end_matches('/');
        let strip_prefix = if backend_prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", backend_prefix)
        };
        let list_rewrite = resolved.list_rewrite.as_ref();

        let contents: Vec<dto::Object> = paginated
            .result
            .objects
            .iter()
            .map(|obj| {
                let raw_key = obj.location.to_string();
                let key = rewrite_key(&raw_key, &strip_prefix, list_rewrite);
                dto::Object {
                    key: Some(key),
                    size: Some(obj.size as i64),
                    last_modified: Some(Timestamp::from(std::time::SystemTime::from(
                        obj.last_modified,
                    ))),
                    e_tag: obj.e_tag.as_ref().map(|e| dto::ETag::Strong(e.clone())),
                    ..Default::default()
                }
            })
            .collect();

        let common_prefixes: Vec<dto::CommonPrefix> = paginated
            .result
            .common_prefixes
            .iter()
            .map(|p| {
                let raw_prefix = format!("{}/", p);
                let prefix = rewrite_key(&raw_prefix, &strip_prefix, list_rewrite);
                dto::CommonPrefix {
                    prefix: Some(prefix),
                }
            })
            .collect();

        let key_count = (contents.len() + common_prefixes.len()) as i32;

        Ok(S3Response::new(dto::ListObjectsV2Output {
            name: Some(bucket.clone()),
            prefix: Some(client_prefix.to_string()),
            delimiter: Some(delimiter),
            max_keys: Some(max_keys as i32),
            key_count: Some(key_count),
            is_truncated: Some(paginated.page_token.is_some()),
            next_continuation_token: paginated.page_token,
            continuation_token: req.input.continuation_token,
            start_after: req.input.start_after,
            contents: if contents.is_empty() {
                None
            } else {
                Some(contents)
            },
            common_prefixes: if common_prefixes.is_empty() {
                None
            } else {
                Some(common_prefixes)
            },
            ..Default::default()
        }))
    }

    async fn list_buckets(
        &self,
        req: S3Request<dto::ListBucketsInput>,
    ) -> S3Result<S3Response<dto::ListBucketsOutput>> {
        let identity = self.identity_from_credentials(&req.credentials);

        let buckets = self
            .bucket_registry
            .list_buckets(&identity)
            .await
            .map_err(proxy_error_to_s3)?;

        let s3_buckets: Vec<dto::Bucket> = buckets
            .into_iter()
            .map(|b| dto::Bucket {
                name: Some(b.name),
                // BucketEntry.creation_date is pre-formatted as ISO 8601 string
                creation_date: chrono::DateTime::parse_from_rfc3339(&b.creation_date)
                    .ok()
                    .map(|d| Timestamp::from(std::time::SystemTime::from(d))),
                ..Default::default()
            })
            .collect();

        let o = self.bucket_registry.bucket_owner();
        let owner = Some(dto::Owner {
            display_name: Some(o.display_name.clone()),
            id: Some(o.id.clone()),
        });

        Ok(S3Response::new(dto::ListBucketsOutput {
            buckets: if s3_buckets.is_empty() {
                None
            } else {
                Some(s3_buckets)
            },
            owner,
            ..Default::default()
        }))
    }

    // -- Multipart operations --

    async fn create_multipart_upload(
        &self,
        req: S3Request<dto::CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::CreateMultipartUploadOutput>> {
        let identity = self.identity_from_credentials(&req.credentials);
        let bucket = &req.input.bucket;
        let key = &req.input.key;
        let operation = S3Operation::CreateMultipartUpload {
            bucket: bucket.clone(),
            key: key.clone(),
        };

        let resolved = self.resolve_bucket(bucket, &identity, &operation).await?;
        let store = self
            .store_factory
            .create_multipart_store(&resolved.config)
            .map_err(proxy_error_to_s3)?;
        let path = Self::build_path(&resolved.config, key);

        let upload_id = store
            .create_multipart(&path)
            .await
            .map_err(object_store_error_to_s3)?;

        self.uploads.insert(
            upload_id.clone(),
            UploadState {
                config: resolved.config.clone(),
                path,
                parts: Vec::new(),
            },
        );

        Ok(S3Response::new(dto::CreateMultipartUploadOutput {
            bucket: Some(bucket.clone()),
            key: Some(key.clone()),
            upload_id: Some(upload_id),
            ..Default::default()
        }))
    }

    async fn upload_part(
        &self,
        req: S3Request<dto::UploadPartInput>,
    ) -> S3Result<S3Response<dto::UploadPartOutput>> {
        let upload_id = &req.input.upload_id;
        let part_number = req.input.part_number;

        let state = self
            .uploads
            .get(upload_id)
            .ok_or_else(|| s3_error!(NoSuchUpload, "upload not found: {upload_id}"))?;

        let store = self
            .store_factory
            .create_multipart_store(&state.config)
            .map_err(proxy_error_to_s3)?;

        // Materialize the body
        let payload = match req.input.body {
            Some(blob) => {
                let data: Bytes = blob
                    .try_collect::<Vec<_>>()
                    .await
                    .map_err(|e| s3_error!(InternalError, "failed to read part body: {e}"))?
                    .into_iter()
                    .fold(bytes::BytesMut::new(), |mut acc, chunk| {
                        acc.extend_from_slice(&chunk);
                        acc
                    })
                    .freeze();
                PutPayload::from_bytes(data)
            }
            None => PutPayload::default(),
        };

        let part_idx = (part_number - 1) as usize; // S3 parts are 1-indexed
        let part_id = store
            .put_part(&state.path, upload_id, part_idx, payload)
            .await
            .map_err(object_store_error_to_s3)?;

        // Release the read lock before acquiring write lock
        drop(state);

        // Store the part ID for later completion
        let mut state = self
            .uploads
            .get_mut(upload_id)
            .ok_or_else(|| s3_error!(NoSuchUpload, "upload not found: {upload_id}"))?;

        // Ensure the parts vec is large enough
        if state.parts.len() <= part_idx {
            state.parts.resize(part_idx + 1, None);
        }
        state.parts[part_idx] = Some(part_id.clone());

        Ok(S3Response::new(dto::UploadPartOutput {
            e_tag: Some(dto::ETag::Strong(part_id.content_id)),
            ..Default::default()
        }))
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<dto::CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::CompleteMultipartUploadOutput>> {
        let upload_id = &req.input.upload_id;
        let bucket = &req.input.bucket;
        let key = &req.input.key;

        let (_, state) = self
            .uploads
            .remove(upload_id)
            .ok_or_else(|| s3_error!(NoSuchUpload, "upload not found: {upload_id}"))?;

        let store = self
            .store_factory
            .create_multipart_store(&state.config)
            .map_err(proxy_error_to_s3)?;

        // Collect ordered parts
        let parts: Vec<PartId> = state
            .parts
            .into_iter()
            .enumerate()
            .map(|(i, p)| p.ok_or_else(|| s3_error!(InvalidPart, "missing part {}", i + 1)))
            .collect::<S3Result<Vec<_>>>()?;

        let result = store
            .complete_multipart(&state.path, upload_id, parts)
            .await
            .map_err(object_store_error_to_s3)?;

        Ok(S3Response::new(dto::CompleteMultipartUploadOutput {
            bucket: Some(bucket.clone()),
            key: Some(key.clone()),
            e_tag: result.e_tag.as_ref().map(|e| dto::ETag::Strong(e.clone())),
            ..Default::default()
        }))
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<dto::AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<dto::AbortMultipartUploadOutput>> {
        let upload_id = &req.input.upload_id;

        let (_, state) = self
            .uploads
            .remove(upload_id)
            .ok_or_else(|| s3_error!(NoSuchUpload, "upload not found: {upload_id}"))?;

        let store = self
            .store_factory
            .create_multipart_store(&state.config)
            .map_err(proxy_error_to_s3)?;

        store
            .abort_multipart(&state.path, upload_id)
            .await
            .map_err(object_store_error_to_s3)?;

        Ok(S3Response::new(dto::AbortMultipartUploadOutput::default()))
    }
}

// -- Auth --

/// s3s auth implementation that delegates to a [`CredentialRegistry`].
pub struct MultistoreAuth<C> {
    credential_registry: C,
}

impl<C> MultistoreAuth<C> {
    pub fn new(credential_registry: C) -> Self {
        Self {
            credential_registry,
        }
    }
}

#[async_trait::async_trait]
impl<C: CredentialRegistry> s3s::auth::S3Auth for MultistoreAuth<C> {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        match self
            .credential_registry
            .get_credential(access_key)
            .await
            .map_err(proxy_error_to_s3)?
        {
            Some(cred) if cred.enabled => Ok(SecretKey::from(cred.secret_access_key)),
            Some(_) => Err(s3_error!(InvalidAccessKeyId, "credential disabled")),
            None => Err(s3_error!(InvalidAccessKeyId)),
        }
    }
}

// -- Helpers --

/// Convert a [`ProxyError`] to an [`s3s::S3Error`].
fn proxy_error_to_s3(e: ProxyError) -> s3s::S3Error {
    use s3s::S3ErrorCode;
    match e {
        ProxyError::BucketNotFound(msg) => s3_error!(NoSuchBucket, "{msg}"),
        ProxyError::NoSuchKey(msg) => s3_error!(NoSuchKey, "{msg}"),
        ProxyError::AccessDenied | ProxyError::MissingAuth => s3_error!(AccessDenied),
        ProxyError::SignatureDoesNotMatch => s3_error!(SignatureDoesNotMatch),
        ProxyError::InvalidRequest(msg) => s3_error!(InvalidRequest, "{msg}"),
        ProxyError::ExpiredCredentials => s3_error!(ExpiredToken),
        ProxyError::InvalidOidcToken(msg) => {
            S3Error::with_message(S3ErrorCode::Custom("InvalidIdentityToken".into()), msg)
        }
        ProxyError::RoleNotFound(_) => s3_error!(AccessDenied),
        ProxyError::PreconditionFailed => s3_error!(PreconditionFailed),
        ProxyError::NotModified => {
            let mut err = S3Error::new(s3s::S3ErrorCode::Custom("NotModified".into()));
            err.set_status_code(http::StatusCode::NOT_MODIFIED);
            err
        }
        ProxyError::BackendError(msg) => s3_error!(InternalError, "backend error: {msg}"),
        ProxyError::ConfigError(msg) => s3_error!(InternalError, "config error: {msg}"),
        ProxyError::Internal(msg) => s3_error!(InternalError, "{msg}"),
    }
}

use s3s::S3Error;

/// Convert an [`object_store::Error`] to an [`s3s::S3Error`].
fn object_store_error_to_s3(e: object_store::Error) -> S3Error {
    match e {
        object_store::Error::NotFound { path, .. } => s3_error!(NoSuchKey, "{path}"),
        object_store::Error::Precondition { .. } => s3_error!(PreconditionFailed),
        object_store::Error::NotModified { .. } => {
            let mut err = S3Error::new(s3s::S3ErrorCode::Custom("NotModified".into()));
            err.set_status_code(http::StatusCode::NOT_MODIFIED);
            err
        }
        other => s3_error!(InternalError, "backend error: {other}"),
    }
}

/// Convert an [`ETagCondition`] to a string for object_store's `GetOptions`.
fn etag_condition_to_string(cond: &dto::ETagCondition) -> String {
    match cond {
        dto::ETagCondition::ETag(etag) => etag.value().to_string(),
        dto::ETagCondition::Any => "*".to_string(),
    }
}

/// Convert an s3s Range to an object_store GetRange.
fn parse_range(range: &Option<dto::Range>) -> Option<object_store::GetRange> {
    let range = range.as_ref()?;
    match *range {
        dto::Range::Int {
            first,
            last: Some(last),
        } => Some(object_store::GetRange::Bounded(first..last + 1)),
        dto::Range::Int { first, last: None } => Some(object_store::GetRange::Offset(first)),
        dto::Range::Suffix { length } => Some(object_store::GetRange::Suffix(length)),
    }
}

/// Apply strip/add prefix rewriting to a key or prefix value.
fn rewrite_key(raw: &str, strip_prefix: &str, list_rewrite: Option<&ListRewrite>) -> String {
    let key = if !strip_prefix.is_empty() {
        raw.strip_prefix(strip_prefix).unwrap_or(raw)
    } else {
        raw
    };

    if let Some(rewrite) = list_rewrite {
        let key = if !rewrite.strip_prefix.is_empty() {
            key.strip_prefix(rewrite.strip_prefix.as_str())
                .unwrap_or(key)
        } else {
            key
        };

        if !rewrite.add_prefix.is_empty() {
            return if key.is_empty() || key.starts_with('/') {
                format!("{}{}", rewrite.add_prefix, key)
            } else {
                format!("{}/{}", rewrite.add_prefix, key)
            };
        }

        return key.to_string();
    }

    key.to_string()
}
