//! Authentication and authorization.
//!
//! - [`sigv4`] — SigV4 request parsing and signature verification
//! - [`identity`] — identity resolution (mapping access key → principal)
//! - [`authorize`](self::authorize::authorize) — authorization (scope checking)

mod authorize;
pub mod identity;
pub mod sigv4;

pub use authorize::authorize;
pub use identity::resolve_identity;
pub use sigv4::{parse_sigv4_auth, verify_sigv4_signature, SigV4Auth};

#[cfg(test)]
mod tests;
