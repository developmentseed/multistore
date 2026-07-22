# Supported Operations

## S3 Operations

| Operation | HTTP Method | Dispatch | Description |
|-----------|------------|----------|-------------|
| GetObject | `GET /{bucket}/{key}` | Forward | Download a file |
| HeadObject | `HEAD /{bucket}/{key}` | Forward | Get file metadata |
| PutObject | `PUT /{bucket}/{key}` | Forward | Upload a file |
| CopyObject | `PUT /{bucket}/{key}` + `x-amz-copy-source` | Response | Server-side copy within one backing store |
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

### Server-side copy

`CopyObject` is a `PUT /{bucket}/{key}` carrying an `x-amz-copy-source: /{src-bucket}/{src-key}[?versionId=…]` header. The proxy resolves and authorizes **both** ends — the source as a read (`GetObject`) and the destination as a write (`PutObject`) — then delegates the copy to the backend: a signed `PUT` to the destination key carries `x-amz-copy-source` rewritten into the source's backend bucket/key space. The backend's `CopyObjectResult` XML (and any error, including S3's "error embedded in a `200 OK`" case) is passed straight through. Copy-relevant client headers are forwarded and signed: `x-amz-metadata-directive`, `x-amz-tagging-directive`, `x-amz-tagging`, `x-amz-acl`, `x-amz-storage-class`, `x-amz-website-redirect-location`, `x-amz-meta-*`, `x-amz-server-side-encryption*`, and the `x-amz-copy-source-if-*` preconditions.

**Same-store only.** A native S3 copy needs one endpoint that can read the source and write the destination, so source and destination must resolve to the same S3 backend — same endpoint, region, and credentials (the backend bucket names may differ, so cross-bucket copies within one account work). A cross-store copy, or a copy from a backend without a `bucket_name`, is rejected with `501 NotImplemented`. `UploadPartCopy` (a copy-source `PUT` with `uploadId`/`partNumber`) is likewise not supported.

### Writes and request headers

`PutObject` forwards the request body plus standard HTTP entity headers (`Content-Type`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Cache-Control`, `Expires`, `Content-MD5`) and the conditional-write preconditions (`If-Match`, `If-None-Match`) to a presigned URL. S3 applies all of these even though they are not part of the (host-only) presigned signature. `x-amz-*` headers (user metadata `x-amz-meta-*`, storage class, tagging, ACLs, SSE, checksum headers such as `x-amz-checksum-*`, and the `x-amz-copy-source-if-*` copy preconditions) are **not** forwarded: S3 rejects unsigned `x-amz-*` headers on presigned requests, and the proxy presigns over `host` only. Supporting those headers requires a header-signing forward path — see the design note in `.plans/`.

**Conditional writes.** `If-Match` / `If-None-Match` are enforced by the backend: a write with a stale or wrong ETag fails with **412 Precondition Failed** (and `If-None-Match: *` fails when the object already exists) instead of silently clobbering. This is the compare-and-swap that native Zarr/Icechunk writers rely on to protect refs from concurrent commits, and it holds across every write path that produces an object:

- **`PutObject`, presigned path** — plain bodies; preconditions forwarded unsigned (S3 applies them anyway).
- **`PutObject`, `aws-chunked` streaming path** — what AWS SDKs and the CLI use by default; preconditions forwarded *and* signed via the header-signing re-sign.
- **`CompleteMultipartUpload`** — the request that materializes a multipart object; preconditions forwarded (and signed, like all headers on the raw multipart path), so large multipart writes get the same guarantee.

Either way the backend's 412 passes through unchanged.

## STS Operations

Handled by an STS closure (registered on the `Router` via `StsRouterExt`).

| Operation | HTTP Method | Description |
|-----------|------------|-------------|
| AssumeRoleWithWebIdentity | `POST /?Action=AssumeRoleWithWebIdentity&...` (params in the query string or a form-encoded body, as AWS SDKs send them) | Exchange OIDC JWT for temporary credentials |

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
> - **Server-side copy is same-store only** — `CopyObject` works when source and destination resolve to the same S3 backend (see "Server-side copy" above). A cross-store copy, or `UploadPartCopy`, is rejected with `501 NotImplemented`.
> - **`x-amz-*` write headers are dropped** — Object metadata, storage class, tagging, ACLs, SSE, and checksum headers on writes are not forwarded (see "Writes and request headers" above).
> - **Versioned/MFA delete is not handled** — A `?versionId=` on a delete is ignored; the current object version is deleted.
> - **Degenerate object keys are rejected** — Keys containing empty, `.`, or `..` path segments (including leading/trailing slashes, e.g. `dir/` folder markers), or ASCII control characters, return `400 InvalidRequest` on every keyed operation. Real S3 accepts such keys; the proxy is deliberately stricter because they cannot be addressed consistently across its presigned and raw-signed backend paths. Batch-delete body keys are exempt, as the remediation route for legacy keys already stored under such names.
> - **Keys are otherwise byte-faithful** — All other keys (including `*`, `%`, `~`, `#`, unicode) are stored on the backend exactly as sent. Objects written through versions **before 0.6.4** via single presigned PUT with characters in object_store's rewrite set (`*`, `%`, `~`, `#`, `?`, `[`, `]`, ...) were silently stored under percent-encoded names (`a*.bin` as `a%2A.bin`); they remain addressable only by that literal mangled name and need a one-time rename to recover their logical keys.

### Upload size on the Cloudflare Workers runtime

The Workers runtime is bounded by Cloudflare's [request-body size limit](https://developers.cloudflare.com/workers/platform/limits/#request-and-response-limits) — 100 MB on Free/Pro, 200 MB on Business, 500 MB (default) on Enterprise. This is a **hard platform limit enforced at Cloudflare's edge**: a request body larger than the plan limit is rejected with `413` before the proxy can act on it, and the proxy cannot raise it.

Consequences and guidance:

- **A single `PutObject` cannot exceed the plan body limit.** Upload larger objects as a **multipart upload**: each `UploadPart` is a separate request, so only the *part* size must stay under the limit. With S3's 10,000-part maximum, 100 MB parts allow objects up to ~1 TB even on Free/Pro.
- **Configure clients to chunk below the limit.** e.g. boto3 `TransferConfig(multipart_threshold=…, multipart_chunksize=…)` with a chunk size under the plan limit; aws-cli's `s3.multipart_chunksize`.
- Until [streaming `UploadPart`](https://github.com/developmentseed/multistore/issues/89) lands, parts on Workers are additionally capped by the 128 MB worker memory limit (parts are buffered in WASM). Keep `multipart_chunksize` comfortably below 100 MB.
- The native server and Lambda runtimes have their own, generally higher, limits — this constraint is specific to Workers.

**Surfacing a clean error.** Configure the gateway with [`with_max_request_body_size`](https://docs.rs/multistore/latest/multistore/proxy/struct.ProxyGateway.html) so a body-bearing write (`PutObject`, `UploadPart`, or `DeleteObjects`) whose `Content-Length` exceeds the limit is rejected up front with S3's `EntityTooLarge` (HTTP 400) — an actionable error instead of Cloudflare's opaque `413`. The Workers example reads this from the `MAX_UPLOAD_BYTES` environment variable; set it to your plan's request-body limit (e.g. `104857600` for 100 MB). The check requires a declared `Content-Length`; unknown-length streaming requests fall through to the platform limit.
