# Caching

Multistore mints and fetches several kinds of short-lived data on the hot path — backend credentials, signing keys, config lookups. Re-doing that work on every request would add latency and hammer upstream services (STS, identity providers, config stores). This page covers what is cached, the credential cache, and — most importantly — how caching behaves differently on each runtime, with best practices for deploying it safely on Cloudflare Workers.

## What gets cached

| Cache | Crate | What it holds | Layer |
|-------|-------|---------------|-------|
| Credential cache | `multistore-oidc-provider` | Short-lived backend/cloud credentials, keyed by credential identity | Outbound auth |
| JWKS cache | `multistore-sts` | Identity providers' public verification keys | Inbound auth |
| Config provider cache | example code (`CachedProvider`) | Bucket/role/credential config lookups | Configuration |

These are independent layers — they protect different upstreams. This page focuses on the **credential cache**, since it is the most performance-sensitive and the most subtle to deploy correctly across runtimes. See [Caching Providers](/configuration/providers/cached) for config-lookup caching and [Backend Auth](/auth/backend-auth) for where credentials come from.

## The credential cache

[`multistore-oidc-provider`](/auth/backend-auth#oidc-backend-auth) caches the cloud credentials it exchanges for in an in-memory `CredentialCache` (its `cache` module), keyed by the backend's credential identity (e.g. the IAM role ARN). It is an internal detail of the provider — callers get its benefit transparently through `OidcCredentialProvider::get_credentials`.

On a miss the cache runs a caller-supplied `fetch` closure (the JWT mint + STS exchange) and stores the result:

```rust
let creds = cache
    .get_or_fetch(role_arn, || async { mint_via_sts().await })
    .await?;
```

It gives you three behaviours:

- **Serve-while-fresh** — a cached value is returned directly while it is comfortably valid.
- **Proactive refresh** — once a value is within its *refresh lead* (60s) of expiry, the next access re-mints it, so a credential is never handed out about to expire mid-request.
- **Non-blocking single-flight renewal** — while one caller is renewing a key, concurrent callers keep receiving the cached credential, which has not expired. One mint runs, and **no caller ever waits on another**.

The entry is keyed by the credential's full identity — the backend scope (e.g. the role ARN) *and* the subject the assertion is minted for. Those are not interchangeable: an AWS role's trust policy conditions on the assertion's `sub`, so a subject the policy would reject must never be served a credential minted for one it accepts.

> [!IMPORTANT]
> A **cold** key — absent or already expired — is deliberately *not* single-flighted: concurrent callers each mint. There is nothing valid to serve them, so collapsing the burst would mean making them wait, which is [not an option on Workers](#why-the-cache-never-blocks). The duplication is bounded (one burst per process start, or per isolate cold start) while the recurring event — renewal — is collapsed.

### Why the cache never blocks

The cache holds a plain `std::sync::Mutex` for map reads and writes and never holds it across an `.await`. That is a correctness requirement, not a style preference.

On Cloudflare Workers, a request parked on an in-memory waker has no pending I/O of its own. The runtime detects that "all the code associated with the request has executed and no events are left in the event loop" and **cancels the request** — surfacing as `The Workers runtime canceled this request because it detected that your Worker's code had hung and would never generate a response` — rather than waiting for whoever holds the lock. Sharing the in-flight future instead of the lock does not help either: that trips `Cannot perform I/O on behalf of a different request`.

An earlier revision of this cache took a per-key `futures::lock::Mutex` on both the hit *and* miss paths. On Workers a single isolate renewing one key therefore killed every concurrent request touching that key — including requests whose credentials were already cached, since the fast path took the same lock. Serving stale-but-valid credentials is what removes the need for the lock: latecomers never need the claimant's result, so there is nothing to wait for.

Native runtimes benefit from the same design — a renewal no longer stalls every concurrent caller for the duration of an STS round-trip.

Because the cache calls *your* fetch closure on a miss, you can layer additional cache tiers (e.g. the Cloudflare Cache API) *inside* the closure without the cache ever depending on a runtime — see [Layering an external tier](#layering-an-external-tier).

## Runtime caveats

A credential cache is only as useful as the lifetime of the thing holding it. The same `CredentialCache` behaves very differently depending on the runtime and on where you construct it.

> [!IMPORTANT]
> An in-memory cache only helps across requests if it lives in **persistent scope** (constructed once and reused), not rebuilt inside the per-request handler. If the provider holding the cache is created fresh on every request, every request starts with an empty cache and the cache does nothing.

| Tier | Scope | Survives | Use for |
|------|-------|----------|---------|
| In-memory (`CredentialCache`) | Per-process (native) / **per-isolate** (Workers) | While the process/isolate is warm | The default; non-blocking renewal single-flight + proactive refresh |
| Cloudflare Cache API | **Per-colo** (data center) | Isolate cold starts within a colo | Sharing mints across isolates in one location |
| Workers KV | Global, eventually consistent | Everything (≈seconds to propagate) | Cross-colo sharing of short-lived creds |
| Durable Objects | Global, single owner per key | Everything | True cross-isolate single-flight |

### Native (server) runtime

The server runtime is a long-lived multi-threaded process. Construct the provider (and thus its `CredentialCache`) **once at startup** and share it across requests. The in-memory cache is then global to the process: one mint per credential lifetime, and renewals collapse to a single mint without stalling concurrent requests. This is the simple, fully-effective case.

### Cloudflare Workers runtime

Workers run in V8 **isolates**, not per-request containers. Global/module-scope state persists across requests handled by the same warm isolate — but:

- The cache is **per-isolate**, and Cloudflare runs many isolates across many colos. With _N_ live isolates you get up to _N_ independent mints per credential lifetime, not one.
- Isolates cold-start empty and are evicted under memory pressure or idle.
- Renewal single-flight only collapses concurrency *within* one isolate.

Even so, this is a large win: a warm isolate serving thousands of requests for the same bucket reuses one credential instead of minting per request. To get *any* cross-request benefit, hoist the provider into module scope (e.g. a `OnceCell`) rather than rebuilding it inside the `fetch` handler.

For sharing beyond a single isolate, layer an external tier.

## Layering an external tier

The Cloudflare Cache API is **colo-local**: shared across all isolates in one data center and surviving isolate cold-starts there. It is the cheapest way to stop every fresh isolate in a busy colo from re-minting. Because `get_or_fetch` calls your closure on a miss, the external tier lives *inside* the closure — keeping the cache itself free of any runtime dependency:

```text
request
  └─ L1: in-memory CredentialCache  (per-isolate, non-blocking renewal, proactive refresh)
       └─ on miss, the fetch closure does:
            L2: Cache API            (colo-local, shared across isolates in the colo)
                 └─ on miss, origin:  STS / token exchange (mint)
                      └─ write back to L2
```

This same shape works with Workers KV (global) as an L3, or Durable Objects when you need *global* single-flight (one DO instance per key serialises the mint across all isolates).

### Best practices for an external credential cache

> [!WARNING]
> An external cache value is a usable credential at rest. Treat it as a secret.

- **Use a synthetic, non-routable cache key.** Namespace it under a host you control (e.g. `https://creds.internal/v1/<hash>`) so a client can never `fetch` credentials straight out of the cache.
- **Encrypt the stored value.** The proxy already holds a signing key; encrypting at rest means a leaked cache entry is not directly usable.
- **Keep TTLs short** and aligned with the credential lifetime — these are already short-lived credentials; do not extend their reach.
- **Align the external TTL with the in-memory refresh lead.** Set the external entry's `max-age` to `remaining_lifetime − refresh_lead`. Otherwise the in-memory layer enters its refresh window, reads a still-present-but-stale value from the external tier, and re-reads forever without ever minting fresh.
- **Write back without blocking the response** (e.g. `ctx.waitUntil(...)` on Workers) so populating the cache never adds latency.
- **Don't rely on presence.** External caches evict early; always re-check the embedded expiry rather than trusting that a hit is fresh.

## See also

- [Multi-Runtime Design](/architecture/multi-runtime) — why the cache is runtime-agnostic
- [Backend Auth](/auth/backend-auth) — what the credential cache stores and where it's minted
- [Cloudflare Workers Deployment](/deployment/cloudflare-workers) — deploying the Workers runtime
- [Caching Providers](/configuration/providers/cached) — caching config/credential *lookups* (a separate layer)
