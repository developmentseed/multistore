# Supported Operations

## S3 Operations

| Operation | HTTP Method | Dispatch | Description |
|-----------|------------|----------|-------------|
| GetObject | `GET /{bucket}/{key}` | Forward | Download a file |
| HeadObject | `HEAD /{bucket}/{key}` | Forward | Get file metadata |
| PutObject | `PUT /{bucket}/{key}` | Forward | Upload a file |
| DeleteObject | `DELETE /{bucket}/{key}` | Forward | Delete a file |
| DeleteObjects | `POST /{bucket}?delete` | NeedsBody | Batch-delete up to 1000 keys (`aws s3 rm --recursive`, `delete_objects`) |
| ListBucket | `GET /{bucket}` | Response | List objects in a bucket (ListObjectsV1 and V2) |
| ListBuckets | `GET /` | Response | List all virtual buckets |
| CreateMultipartUpload | `POST /{bucket}/{key}?uploads` | NeedsBody | Initiate a multipart upload |
| UploadPart | `PUT /{bucket}/{key}?partNumber=N&uploadId=ID` | NeedsBody | Upload a part |
| CompleteMultipartUpload | `POST /{bucket}/{key}?uploadId=ID` | NeedsBody | Complete a multipart upload |
| AbortMultipartUpload | `DELETE /{bucket}/{key}?uploadId=ID` | NeedsBody | Abort a multipart upload |

### Dispatch Types

- **Forward** — A presigned URL is generated and returned to the runtime, which executes it with its native HTTP client. Bodies stream directly between client and backend without buffering.
- **Response** — The handler builds a complete response (XML for LIST, error responses) and returns it. No presigned URL involved.
- **NeedsBody** — The runtime collects the request body, then the handler signs and sends the request via raw HTTP (`backend.send_raw()`). Used by multipart and batch delete.

### Batch delete authorization

`DeleteObjects` carries its keys in the request body, so authorization happens in two stages: the bucket-level check confirms the caller may delete *something* in the bucket, then **each key in the body is authorized individually** against the caller's allowed prefixes. Keys the caller is not permitted to delete are returned as per-key `AccessDenied` entries in the `DeleteResult` (S3's partial-result semantics) and are never forwarded to the backend; authorized keys are deleted regardless. Anonymous callers cannot batch-delete.

### Writes and request headers

`PutObject` forwards the request body plus standard HTTP entity headers (`Content-Type`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Cache-Control`, `Expires`, `Content-MD5`) to a presigned URL. `x-amz-*` headers (user metadata `x-amz-meta-*`, storage class, tagging, ACLs, SSE, and checksum headers such as `x-amz-checksum-*`) are **not** forwarded: S3 rejects unsigned `x-amz-*` headers on presigned requests, and the proxy presigns over `host` only. Supporting those headers requires a header-signing forward path — see the design note in `.plans/`.

## STS Operations

Handled by an STS closure (registered on the `Router` via `StsRouterExt`).

| Operation | HTTP Method | Description |
|-----------|------------|-------------|
| AssumeRoleWithWebIdentity | `POST /?Action=AssumeRoleWithWebIdentity&...` | Exchange OIDC JWT for temporary credentials |

## OIDC Discovery Endpoints

Handled by OIDC discovery closures (registered on the `Router` via `OidcRouterExt`). Served when `OIDC_PROVIDER_KEY` and `OIDC_PROVIDER_ISSUER` are configured.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OpenID Connect discovery document |
| `/.well-known/jwks.json` | GET | JSON Web Key Set (proxy's RSA public key) |

## Limitations

> [!WARNING]
> - **Multipart and batch delete are S3 only** — Both use raw HTTP with `S3RequestSigner` and are gated to `backend_type = "s3"`. Non-S3 backends should use single PUT/DELETE requests.
> - **DeleteObject does not return confirmation** — The proxy forwards the DELETE and returns the backend's response status.
> - **Server-side copy is not supported** — A `PUT` carrying `x-amz-copy-source` (CopyObject / UploadPartCopy) is rejected with `501 NotImplemented` rather than silently overwriting the destination.
> - **`x-amz-*` write headers are dropped** — Object metadata, storage class, tagging, ACLs, SSE, and checksum headers on writes are not forwarded (see "Writes and request headers" above).
> - **Versioned/MFA delete is not handled** — A `?versionId=` on a delete is ignored; the current object version is deleted.

### Upload size on the Cloudflare Workers runtime

The Workers runtime is bounded by Cloudflare's [request-body size limit](https://developers.cloudflare.com/workers/platform/limits/#request-and-response-limits) — 100 MB on Free/Pro, 200 MB on Business, 500 MB (default) on Enterprise. This is a **hard platform limit enforced at Cloudflare's edge**: a request body larger than the plan limit is rejected with `413` before the proxy can act on it, and the proxy cannot raise it.

Consequences and guidance:

- **A single `PutObject` cannot exceed the plan body limit.** Upload larger objects as a **multipart upload**: each `UploadPart` is a separate request, so only the *part* size must stay under the limit. With S3's 10,000-part maximum, 100 MB parts allow objects up to ~1 TB even on Free/Pro.
- **Configure clients to chunk below the limit.** e.g. boto3 `TransferConfig(multipart_threshold=…, multipart_chunksize=…)` with a chunk size under the plan limit; aws-cli's `s3.multipart_chunksize`.
- Until [streaming `UploadPart`](https://github.com/developmentseed/multistore/issues/89) lands, parts on Workers are additionally capped by the 128 MB worker memory limit (parts are buffered in WASM). Keep `multipart_chunksize` comfortably below 100 MB.
- The native server and Lambda runtimes have their own, generally higher, limits — this constraint is specific to Workers.

**Surfacing a clean error.** Configure the gateway with [`with_max_request_body_size`](https://docs.rs/multistore/latest/multistore/proxy/struct.ProxyGateway.html) so a `PutObject`/`UploadPart` whose `Content-Length` exceeds the limit is rejected up front with S3's `EntityTooLarge` (HTTP 400) — an actionable error instead of Cloudflare's opaque `413`. The Workers example reads this from the `MAX_UPLOAD_BYTES` environment variable; set it to your plan's request-body limit (e.g. `104857600` for 100 MB). The check requires a declared `Content-Length`; unknown-length streaming requests fall through to the platform limit.
