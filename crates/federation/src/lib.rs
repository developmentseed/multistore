//! Outbound credential federation for the multistore S3 proxy gateway.
//!
//! Multistore already federates *inbound* identity — callers exchange an OIDC
//! token for proxy credentials via [`multistore-sts`], and the proxy can act as
//! an OIDC provider via [`multistore-oidc-provider`]. This crate is the
//! symmetric *outbound* half: letting the proxy present its own identity to a
//! **backend cloud** and assume a role there, so it can serve data from a
//! private bucket the operator doesn't hold long-lived keys for.
//!
//! The flow, per backend, at bucket-resolution time:
//!
//! 1. Mint a short-lived OIDC assertion with the proxy's signing key
//!    (`multistore-oidc-provider`), scoped via its `aud`/`sub` claims.
//! 2. Exchange it at the backend cloud's STS — for AWS, [`aws`]'s
//!    `AssumeRoleWithWebIdentity` — for temporary [`FederatedCredentials`].
//! 3. [`FederatedCredentials::apply_to`] those onto the [`BucketConfig`] so the
//!    multistore backend signs requests with them instead of going anonymous.
//!
//! No long-lived backend secret is stored anywhere: the bucket config only
//! needs a role ARN, and the assumed credentials are short-lived and refreshed
//! before expiry. Trust and blast radius are governed by the backend role's
//! trust and permission policies, which the bucket owner controls.
//!
//! This crate is **runtime-agnostic** — it builds requests and parses
//! responses but does not perform HTTP, leaving transport to the caller (the
//! same split multistore uses elsewhere for native vs. Cloudflare Workers).
//!
//! [`multistore-sts`]: https://docs.rs/multistore-sts
//! [`multistore-oidc-provider`]: https://docs.rs/multistore-oidc-provider
//! [`BucketConfig`]: multistore::types::BucketConfig

pub mod aws;
mod credentials;
mod error;

pub use credentials::FederatedCredentials;
pub use error::FederationError;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use multistore::types::BucketConfig;
    use std::collections::HashMap;

    fn anon_s3_bucket() -> BucketConfig {
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
    fn apply_to_signs_the_bucket() {
        let creds = FederatedCredentials {
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
        // Anonymous/unsigned access must be turned off so the backend signs.
        assert_eq!(config.option("skip_signature"), None);
        assert!(!config.anonymous_access);
        // Untouched options remain.
        assert_eq!(config.option("bucket_name"), Some("my-bucket"));
    }

    #[test]
    fn bucket_debug_redacts_applied_secrets() {
        let creds = FederatedCredentials {
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
}
