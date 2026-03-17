# CORS

Per-bucket CORS (Cross-Origin Resource Sharing) configuration controls which browser origins can access your buckets. CORS is configured as an optional field on each bucket.

## How It Works

The CORS middleware sits **before** authentication in the middleware chain. This means:

- **Preflight requests** (`OPTIONS`) are handled without requiring credentials, which is how browsers expect CORS to work.
- **Normal requests** pass through the full middleware chain (auth, bucket resolution, dispatch), and CORS headers are stamped on the response.
- **No `Origin` header** -- the request passes through without CORS processing.

If a bucket has no `cors` configuration, no CORS headers are emitted for requests to that bucket.

## Configuration

Add a `cors` section to any bucket definition:

```toml
[[buckets]]
name = "public-data"
backend_type = "s3"
anonymous_access = true

[buckets.backend_options]
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket_name = "my-public-assets"
region = "us-east-1"

[buckets.cors]
allowed_origins = ["https://app.example.com"]
allowed_methods = ["GET", "HEAD"]
allowed_headers = ["range", "if-none-match"]
expose_headers = ["etag", "content-length"]
max_age_seconds = 7200
allow_credentials = false
```

## Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_origins` | string[] | (required) | Origins allowed to make cross-origin requests. Use `"*"` for any origin. |
| `allowed_methods` | string[] | `["GET", "HEAD"]` | HTTP methods allowed in cross-origin requests. |
| `allowed_headers` | string[] | `[]` | Request headers allowed in cross-origin requests. If empty, the middleware mirrors the `Access-Control-Request-Headers` value from preflight requests. |
| `expose_headers` | string[] | `[]` | Response headers exposed to the browser via `Access-Control-Expose-Headers`. |
| `max_age_seconds` | integer | `3600` | How long (in seconds) the browser may cache preflight results. |
| `allow_credentials` | bool | `false` | Whether the response may be shared when the request's credentials mode is `include`. When `true`, the `Access-Control-Allow-Origin` header echoes the specific origin instead of `*`. |

## Examples

### Wildcard origin (public bucket)

Allow any origin to read from a public data bucket:

```toml
[buckets.cors]
allowed_origins = ["*"]
```

### Specific origin

Restrict access to a single web application:

```toml
[buckets.cors]
allowed_origins = ["https://app.example.com"]
allowed_methods = ["GET", "HEAD", "PUT"]
allowed_headers = ["content-type", "content-length", "x-amz-content-sha256"]
expose_headers = ["etag"]
```

### With credentials

Allow credentialed requests from a specific origin. Note that `allowed_origins` must list specific origins (not `"*"`) when `allow_credentials` is `true`:

```toml
[buckets.cors]
allowed_origins = ["https://dashboard.example.com"]
allowed_methods = ["GET", "HEAD"]
allow_credentials = true
```

### Multiple origins

```toml
[buckets.cors]
allowed_origins = ["https://app.example.com", "https://staging.example.com"]
allowed_methods = ["GET", "HEAD"]
```
