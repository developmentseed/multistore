//! Shared types used across the proxy.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Owner identity for S3 ListBuckets responses.
#[derive(Debug, Clone, Serialize)]
pub struct BucketOwner {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

/// Configuration for a virtual bucket exposed by the proxy.
#[derive(Clone, Serialize, Deserialize)]
pub struct BucketConfig {
    /// The virtual bucket name exposed to clients.
    pub name: String,

    /// Provider type: "s3", "az", "gcs", etc.
    pub backend_type: String,

    /// Optional prefix to prepend to all keys when forwarding.
    pub backend_prefix: Option<String>,

    /// Whether this bucket allows anonymous (unsigned) access.
    pub anonymous_access: bool,

    /// IAM role ARNs that are allowed to access this bucket.
    /// Empty means only anonymous access (if enabled) or long-lived credentials.
    #[serde(default)]
    pub allowed_roles: Vec<String>,

    /// Provider-specific config passed to the object_store builder.
    /// Keys are the short aliases accepted by each provider's ConfigKey::from_str().
    /// S3: "endpoint", "bucket_name", "region", "access_key_id", "secret_access_key", "skip_signature"
    /// Azure: "account_name", "container_name", "access_key", "skip_signature"
    /// GCS: "bucket_name", "service_account_key", "skip_signature"
    #[serde(default)]
    pub backend_options: HashMap<String, String>,
}

/// Keys in `backend_options` that hold secret values.
const REDACTED_OPTION_KEYS: &[&str] = &[
    "secret_access_key",
    "access_key",
    "service_account_key",
    "token",
];

impl fmt::Debug for BucketConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_opts: HashMap<&str, &str> = self
            .backend_options
            .iter()
            .map(|(k, v)| {
                let val = if REDACTED_OPTION_KEYS.contains(&k.as_str()) {
                    "[REDACTED]"
                } else {
                    v.as_str()
                };
                (k.as_str(), val)
            })
            .collect();

        f.debug_struct("BucketConfig")
            .field("name", &self.name)
            .field("backend_type", &self.backend_type)
            .field("backend_prefix", &self.backend_prefix)
            .field("anonymous_access", &self.anonymous_access)
            .field("allowed_roles", &self.allowed_roles)
            .field("backend_options", &redacted_opts)
            .finish()
    }
}

/// Known backend provider types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// Amazon S3 or S3-compatible storage.
    S3,
    /// Azure Blob Storage.
    Azure,
    /// Google Cloud Storage.
    Gcs,
}

impl BucketConfig {
    /// Parse the `backend_type` string into a known [`BackendType`].
    pub fn parsed_backend_type(&self) -> Option<BackendType> {
        match self.backend_type.as_str() {
            "s3" => Some(BackendType::S3),
            "az" | "azure" => Some(BackendType::Azure),
            "gcs" | "gs" => Some(BackendType::Gcs),
            _ => None,
        }
    }

    /// Whether this is an S3 backend. Operations that go through raw signed
    /// HTTP rather than presigned URLs — multipart uploads and batch delete —
    /// are gated on this.
    pub fn is_s3_backend(&self) -> bool {
        matches!(self.parsed_backend_type(), Some(BackendType::S3))
    }

    /// Look up a value in `backend_options`.
    pub fn option(&self, key: &str) -> Option<&str> {
        self.backend_options.get(key).map(|s| s.as_str())
    }
}

/// Configuration for an IAM role that can be assumed via STS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// The role identifier (used as the RoleArn in AssumeRoleWithWebIdentity).
    pub role_id: String,

    /// Human-readable name.
    pub name: String,

    /// OIDC provider URLs trusted by this role (e.g., "https://token.actions.githubusercontent.com").
    #[serde(default)]
    pub trusted_oidc_issuers: Vec<String>,

    /// Audience claim values accepted for this role. A token is accepted if its
    /// `aud` claim matches any entry; empty (or absent/null) means no audience
    /// restriction. Accepts a single string or a list, and the legacy
    /// `required_audience` key, for backward compatibility — set one key or the
    /// other, not both (specifying both is a config error).
    #[serde(
        default,
        alias = "required_audience",
        deserialize_with = "deserialize_audiences"
    )]
    pub required_audiences: Vec<String>,

    /// Conditions on the subject claim (glob patterns).
    /// e.g., "repo:myorg/myrepo:ref:refs/heads/main"
    #[serde(default)]
    pub subject_conditions: Vec<String>,

    /// Buckets and prefixes this role can access.
    #[serde(default)]
    pub allowed_scopes: Vec<AccessScope>,

    /// Maximum session duration in seconds.
    pub max_session_duration_secs: u64,
}

/// Deserialize a role's accepted audiences from either a single string or a
/// list, so legacy `required_audience: "x"` configs keep working alongside
/// `required_audiences: ["x", "y"]`.
fn deserialize_audiences<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    // `Option` so an explicit `null` (e.g. legacy `required_audience: null`)
    // maps to "unrestricted", matching the old `Option<String>` behavior
    // instead of failing to parse.
    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => vec![],
        Some(OneOrMany::One(s)) => vec![s],
        Some(OneOrMany::Many(v)) => v,
    })
}

/// Defines what a credential is allowed to access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessScope {
    /// The virtual bucket name this scope grants access to.
    pub bucket: String,
    /// Allowed key prefixes. Empty means full bucket access.
    pub prefixes: Vec<String>,
    /// The set of S3 actions permitted under this scope.
    pub actions: Vec<Action>,
}

/// S3 actions that can be authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    GetObject,
    HeadObject,
    PutObject,
    ListBucket,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    DeleteObject,
}

/// A long-lived access credential stored in the config backend.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// The access key ID used in SigV4 authentication.
    pub access_key_id: String,
    /// The secret key used for HMAC signing.
    pub secret_access_key: String,
    /// Human-readable identity of the credential owner.
    pub principal_name: String,
    /// The buckets and actions this credential is authorized for.
    pub allowed_scopes: Vec<AccessScope>,
    /// When this credential was created.
    pub created_at: DateTime<Utc>,
    /// Optional expiration time; `None` means the credential does not expire.
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this credential is active and can be used for authentication.
    pub enabled: bool,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("principal_name", &self.principal_name)
            .field("allowed_scopes", &self.allowed_scopes)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Temporary credentials minted by the STS API.
#[derive(Clone, Serialize, Deserialize)]
pub struct TemporaryCredentials {
    /// The temporary access key ID.
    pub access_key_id: String,
    /// The temporary secret key for HMAC signing.
    pub secret_access_key: String,
    /// The session token that must accompany requests using these credentials.
    pub session_token: String,
    /// When these temporary credentials expire.
    pub expiration: DateTime<Utc>,
    /// The buckets and actions these credentials are authorized for.
    pub allowed_scopes: Vec<AccessScope>,
    /// The IAM role that was assumed to produce these credentials.
    pub assumed_role_id: String,
    /// The identity (e.g. OIDC subject) that assumed the role.
    pub source_identity: String,
}

impl fmt::Debug for TemporaryCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemporaryCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .field("allowed_scopes", &self.allowed_scopes)
            .field("assumed_role_id", &self.assumed_role_id)
            .field("source_identity", &self.source_identity)
            .finish()
    }
}

/// Short-lived credentials obtained by federating the proxy's OIDC identity
/// into a backend cloud's STS (e.g. AWS `AssumeRoleWithWebIdentity`), used to
/// sign requests to the *backend* object store.
///
/// Distinct from [`TemporaryCredentials`], which the proxy's own STS mints for
/// *callers*: those carry the proxy's authorization model (`allowed_scopes`,
/// `assumed_role_id`, `source_identity`), whereas these carry only what an
/// object-store client needs to sign, plus the expiry so the caller can cache
/// and refresh them.
#[derive(Clone)]
pub struct BackendCredentials {
    /// Temporary access key id (AWS `ASIA…`).
    pub access_key_id: String,
    /// Temporary secret access key.
    pub secret_access_key: String,
    /// Session token that must accompany requests using these credentials.
    pub session_token: String,
    /// When these credentials expire.
    pub expiration: DateTime<Utc>,
}

impl BackendCredentials {
    /// Inject these credentials into a [`BucketConfig`] so the multistore
    /// backend signs requests with them instead of going anonymous.
    ///
    /// Sets the canonical S3 option keys (`access_key_id`, `secret_access_key`,
    /// and `token` — the alias object_store maps to the session token and that
    /// `BucketConfig`'s `Debug` redacts) and clears `skip_signature` so the
    /// backend signs.
    ///
    /// This governs only *outbound* (backend) signing. It deliberately leaves
    /// [`BucketConfig::anonymous_access`] untouched: that flag controls
    /// *inbound* authorization (whether proxy callers may read the bucket
    /// unauthenticated), which is orthogonal — a bucket can be public to
    /// anonymous callers yet served from a private backend the proxy signs into.
    pub fn apply_to(&self, config: &mut BucketConfig) {
        let opts = &mut config.backend_options;
        opts.insert("access_key_id".to_string(), self.access_key_id.clone());
        opts.insert(
            "secret_access_key".to_string(),
            self.secret_access_key.clone(),
        );
        opts.insert("token".to_string(), self.session_token.clone());
        opts.remove("skip_signature");
    }
}

impl fmt::Debug for BackendCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// The authenticated identity after credential verification.
///
/// This is the output of the authentication pipeline. It contains only
/// the information downstream consumers need — not the raw credentials
/// used during signature verification.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    pub principal_name: String,
    pub allowed_scopes: Vec<AccessScope>,
}

/// Represents the resolved identity after authentication.
#[derive(Debug, Clone)]
pub enum ResolvedIdentity {
    Anonymous,
    Authenticated(AuthenticatedIdentity),
}

/// The parsed S3 operation extracted from an incoming request.
#[derive(Debug, Clone)]
pub enum S3Operation {
    GetObject {
        bucket: String,
        key: String,
    },
    HeadObject {
        bucket: String,
        key: String,
    },
    PutObject {
        bucket: String,
        key: String,
    },
    CreateMultipartUpload {
        bucket: String,
        key: String,
    },
    UploadPart {
        bucket: String,
        key: String,
        upload_id: String,
        part_number: u32,
    },
    CompleteMultipartUpload {
        bucket: String,
        key: String,
        upload_id: String,
    },
    AbortMultipartUpload {
        bucket: String,
        key: String,
        upload_id: String,
    },
    DeleteObject {
        bucket: String,
        key: String,
    },
    /// Server-side copy (`PUT /{bucket}/{key}` carrying `x-amz-copy-source`).
    ///
    /// Carries both the destination (`bucket`/`key`) and the parsed source
    /// (`src_bucket`/`src_key`/`src_version`). Unlike every other operation,
    /// a copy touches two virtual buckets: the destination is authorized as a
    /// write via [`action`](S3Operation::action) on the main pipeline, and the
    /// source is authorized as a read separately when the copy is dispatched.
    CopyObject {
        /// Destination virtual bucket.
        bucket: String,
        /// Destination key.
        key: String,
        /// Source virtual bucket, from `x-amz-copy-source`.
        src_bucket: String,
        /// Source key (percent-decoded, client-visible), from `x-amz-copy-source`.
        src_key: String,
        /// Optional source `versionId` from `x-amz-copy-source`.
        src_version: Option<String>,
    },
    /// Batch delete (`POST /{bucket}?delete`). The keys to delete live in the
    /// request body, so this operation carries only the bucket — the body is
    /// parsed and each key authorized individually once it arrives.
    DeleteObjects {
        bucket: String,
    },
    ListBucket {
        bucket: String,
        /// Raw query string from the incoming request, forwarded to the backend.
        /// The proxy may modify `prefix` (prepend backend_prefix) and inject
        /// defaults for `max-keys` and `list-type`.
        raw_query: Option<String>,
    },
    /// List all virtual buckets exposed by the proxy.
    ListBuckets,
}

impl S3Operation {
    /// The HTTP method implied by this operation.
    pub fn method(&self) -> http::Method {
        match self {
            S3Operation::GetObject { .. }
            | S3Operation::ListBucket { .. }
            | S3Operation::ListBuckets => http::Method::GET,
            S3Operation::HeadObject { .. } => http::Method::HEAD,
            S3Operation::PutObject { .. }
            | S3Operation::UploadPart { .. }
            | S3Operation::CopyObject { .. } => http::Method::PUT,
            S3Operation::DeleteObject { .. } | S3Operation::AbortMultipartUpload { .. } => {
                http::Method::DELETE
            }
            S3Operation::CreateMultipartUpload { .. }
            | S3Operation::CompleteMultipartUpload { .. }
            | S3Operation::DeleteObjects { .. } => http::Method::POST,
        }
    }

    /// The authorization action for this operation.
    pub fn action(&self) -> Action {
        match self {
            S3Operation::GetObject { .. } => Action::GetObject,
            S3Operation::HeadObject { .. } => Action::HeadObject,
            // A copy's destination is a write; the source read is authorized
            // separately at dispatch (see `execute_copy`).
            S3Operation::PutObject { .. } | S3Operation::CopyObject { .. } => Action::PutObject,
            S3Operation::ListBucket { .. } => Action::ListBucket,
            S3Operation::CreateMultipartUpload { .. } => Action::CreateMultipartUpload,
            S3Operation::UploadPart { .. } => Action::UploadPart,
            S3Operation::CompleteMultipartUpload { .. } => Action::CompleteMultipartUpload,
            S3Operation::AbortMultipartUpload { .. } => Action::AbortMultipartUpload,
            S3Operation::DeleteObject { .. } => Action::DeleteObject,
            // Batch delete authorizes as DeleteObject; each key in the body is
            // checked individually against the caller's scopes.
            S3Operation::DeleteObjects { .. } => Action::DeleteObject,
            S3Operation::ListBuckets => Action::ListBucket,
        }
    }

    /// The bucket name, if any.
    pub fn bucket(&self) -> Option<&str> {
        match self {
            S3Operation::GetObject { bucket, .. }
            | S3Operation::HeadObject { bucket, .. }
            | S3Operation::PutObject { bucket, .. }
            | S3Operation::ListBucket { bucket, .. }
            | S3Operation::CreateMultipartUpload { bucket, .. }
            | S3Operation::UploadPart { bucket, .. }
            | S3Operation::CompleteMultipartUpload { bucket, .. }
            | S3Operation::AbortMultipartUpload { bucket, .. }
            | S3Operation::DeleteObject { bucket, .. }
            | S3Operation::CopyObject { bucket, .. }
            | S3Operation::DeleteObjects { bucket } => Some(bucket),
            S3Operation::ListBuckets => None,
        }
    }

    /// The object key, if any. Returns empty string for non-object operations.
    pub fn key(&self) -> &str {
        match self {
            S3Operation::GetObject { key, .. }
            | S3Operation::HeadObject { key, .. }
            | S3Operation::PutObject { key, .. }
            | S3Operation::CreateMultipartUpload { key, .. }
            | S3Operation::UploadPart { key, .. }
            | S3Operation::CompleteMultipartUpload { key, .. }
            | S3Operation::AbortMultipartUpload { key, .. }
            | S3Operation::CopyObject { key, .. }
            | S3Operation::DeleteObject { key, .. } => key,
            S3Operation::ListBucket { .. }
            | S3Operation::ListBuckets
            | S3Operation::DeleteObjects { .. } => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action() {
        let op = S3Operation::GetObject {
            bucket: "b".into(),
            key: "k".into(),
        };
        assert_eq!(op.action(), Action::GetObject);

        let op = S3Operation::PutObject {
            bucket: "b".into(),
            key: "k".into(),
        };
        assert_eq!(op.action(), Action::PutObject);

        let op = S3Operation::ListBucket {
            bucket: "b".into(),
            raw_query: None,
        };
        assert_eq!(op.action(), Action::ListBucket);

        assert_eq!(S3Operation::ListBuckets.action(), Action::ListBucket);

        let op = S3Operation::DeleteObject {
            bucket: "b".into(),
            key: "k".into(),
        };
        assert_eq!(op.action(), Action::DeleteObject);
    }

    #[test]
    fn test_bucket() {
        let op = S3Operation::GetObject {
            bucket: "my-bucket".into(),
            key: "k".into(),
        };
        assert_eq!(op.bucket(), Some("my-bucket"));

        assert_eq!(S3Operation::ListBuckets.bucket(), None);
    }

    #[test]
    fn test_key() {
        let op = S3Operation::GetObject {
            bucket: "b".into(),
            key: "my/key.txt".into(),
        };
        assert_eq!(op.key(), "my/key.txt");

        let op = S3Operation::ListBucket {
            bucket: "b".into(),
            raw_query: Some("prefix=foo/".into()),
        };
        assert_eq!(op.key(), "");

        assert_eq!(S3Operation::ListBuckets.key(), "");
    }

    fn anon_s3_bucket() -> BucketConfig {
        use std::collections::HashMap;
        let mut backend_options = HashMap::new();
        backend_options.insert("bucket_name".to_string(), "my-bucket".to_string());
        backend_options.insert("region".to_string(), "us-west-2".to_string());
        backend_options.insert("skip_signature".to_string(), "true".to_string());
        BucketConfig {
            name: "acct:product".to_string(),
            backend_type: "s3".to_string(),
            backend_prefix: None,
            anonymous_access: true,
            allowed_roles: vec![],
            backend_options,
        }
    }

    #[test]
    fn backend_credentials_apply_to_signs_the_bucket() {
        use chrono::{TimeZone, Utc};
        let creds = BackendCredentials {
            access_key_id: "ASIA123".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: "session".to_string(),
            expiration: Utc.with_ymd_and_hms(2026, 6, 3, 4, 13, 40).unwrap(),
        };

        let mut config = anon_s3_bucket();
        creds.apply_to(&mut config);

        assert_eq!(config.option("access_key_id"), Some("ASIA123"));
        assert_eq!(config.option("secret_access_key"), Some("secret"));
        // `token` is the alias object_store maps to the session token and that
        // multistore redacts in `BucketConfig`'s Debug impl.
        assert_eq!(config.option("token"), Some("session"));
        // Unsigned access must be turned off so the backend signs.
        assert_eq!(config.option("skip_signature"), None);
        // `apply_to` governs only outbound signing; inbound `anonymous_access`
        // is left as-is (the test bucket was public to anonymous callers).
        assert!(config.anonymous_access);
        // Untouched options remain.
        assert_eq!(config.option("bucket_name"), Some("my-bucket"));
    }

    #[test]
    fn backend_credentials_bucket_debug_redacts_applied_secrets() {
        use chrono::{TimeZone, Utc};
        let creds = BackendCredentials {
            access_key_id: "ASIA123".to_string(),
            secret_access_key: "super-secret".to_string(),
            session_token: "super-session".to_string(),
            expiration: Utc.with_ymd_and_hms(2026, 6, 3, 4, 13, 40).unwrap(),
        };
        let mut config = anon_s3_bucket();
        creds.apply_to(&mut config);

        let dbg = format!("{config:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(!dbg.contains("super-session"));
    }

    /// Parse a `RoleConfig` from JSON with the given audience field snippet
    /// (e.g. `,"required_audiences":["x"]`), so the deserialization edge cases
    /// for the audience config can be exercised directly.
    fn parse_role(audience_field: &str) -> Result<RoleConfig, serde_json::Error> {
        serde_json::from_str(&format!(
            r#"{{"role_id":"r","name":"R","max_session_duration_secs":3600{audience_field}}}"#
        ))
    }

    #[test]
    fn audiences_accepts_legacy_single_string() {
        let r = parse_role(r#","required_audience":"x""#).unwrap();
        assert_eq!(r.required_audiences, vec!["x".to_string()]);
    }

    #[test]
    fn audiences_accepts_single_string_and_list() {
        assert_eq!(
            parse_role(r#","required_audiences":"x""#)
                .unwrap()
                .required_audiences,
            vec!["x".to_string()]
        );
        assert_eq!(
            parse_role(r#","required_audiences":["x","y"]"#)
                .unwrap()
                .required_audiences,
            vec!["x".to_string(), "y".to_string()]
        );
    }

    #[test]
    fn audiences_absent_or_null_is_unrestricted() {
        // Absent, or an explicit null on either key, means "no restriction" —
        // matching the old `Option<String>` behavior rather than erroring.
        assert!(parse_role("").unwrap().required_audiences.is_empty());
        assert!(parse_role(r#","required_audiences":null"#)
            .unwrap()
            .required_audiences
            .is_empty());
        assert!(parse_role(r#","required_audience":null"#)
            .unwrap()
            .required_audiences
            .is_empty());
    }

    #[test]
    fn audiences_both_keys_is_an_error() {
        // Setting both the legacy and new keys fails loudly rather than
        // silently picking one, so a leftover key during migration is caught.
        assert!(parse_role(r#","required_audience":"x","required_audiences":["y"]"#).is_err());
    }
}
