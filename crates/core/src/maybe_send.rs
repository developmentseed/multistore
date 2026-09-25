//! Conditional `Send`/`Sync` bounds for traits whose wasm implementations
//! use `!Send` types (JS interop via `Rc<RefCell<...>>`, `JsValue`, etc.).
//!
//! On native targets, `MaybeSend` resolves to `Send` and `MaybeSync` to
//! `Sync`. On `wasm32` targets, both are no-ops.
//!
//! Used by traits whose implementations may hold `!Send` types on WASM:
//! [`ProxyBackend`](crate::backend::ProxyBackend),
//! [`Middleware`](crate::middleware::Middleware),
//! [`RouteHandler`](crate::route_handler::RouteHandler),
//! [`BucketRegistry`](crate::registry::BucketRegistry),
//! [`CredentialRegistry`](crate::registry::CredentialRegistry), and the
//! `oidc-provider` crate's [`HttpExchange`] / [`CredentialExchange`] traits.

// --- Native targets: MaybeSend = Send, MaybeSync = Sync ---

/// `Send` on native targets, no bound on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

/// `Sync` on native targets, no bound on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync> MaybeSync for T {}

// --- WASM targets: MaybeSend and MaybeSync are no-ops ---

/// `Send` on native targets, no bound on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// `Sync` on native targets, no bound on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSync for T {}
