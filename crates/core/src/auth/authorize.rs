//! Authorization — checking if an identity can perform an operation.

use crate::error::ProxyError;
use crate::types::{Action, ResolvedIdentity, S3Operation};

/// Check if a key falls under an authorized prefix.
///
/// If the prefix already ends with `/`, a plain `starts_with` is sufficient.
/// Otherwise we require that the key either equals the prefix exactly or
/// that the character immediately after the prefix is `/`. This prevents
/// a prefix like `data` from matching `data-private/secret.txt`.
fn key_matches_prefix(key: &str, prefix: &str) -> bool {
    if prefix.ends_with('/') || prefix.is_empty() {
        return key.starts_with(prefix);
    }
    // Prefix does not end with '/' — require an exact match or a '/' boundary
    key == prefix || key.starts_with(&format!("{}/", prefix))
}

/// Check if a resolved identity is authorized to perform an operation.
pub fn authorize(
    identity: &ResolvedIdentity,
    operation: &S3Operation,
    bucket_config: &crate::types::BucketConfig,
) -> Result<(), ProxyError> {
    // Anonymous access check
    if matches!(identity, ResolvedIdentity::Anonymous) {
        if bucket_config.anonymous_access {
            // Anonymous users can only read
            let action = operation.action();
            if matches!(
                action,
                Action::GetObject | Action::HeadObject | Action::ListBucket
            ) {
                return Ok(());
            }
        }
        return Err(ProxyError::AccessDenied);
    }

    let scopes = match identity {
        ResolvedIdentity::Anonymous => unreachable!(),
        ResolvedIdentity::Authenticated(id) => &id.allowed_scopes,
    };

    let action = operation.action();
    let bucket = operation.bucket().unwrap_or_default().to_string();
    let key = match operation {
        S3Operation::ListBucket { raw_query, .. } => {
            // Extract prefix from raw query for authorization checks
            raw_query
                .as_deref()
                .and_then(|q| {
                    url::form_urlencoded::parse(q.as_bytes())
                        .find(|(k, _)| k == "prefix")
                        .map(|(_, v)| v.to_string())
                })
                .unwrap_or_default()
        }
        _ => operation.key().to_string(),
    };

    // Batch delete carries no key here — the keys live in the request body. This
    // is only a coarse check that *some* scope grants DeleteObject on the bucket;
    // each key is authorized individually (against its prefix) once the body is
    // parsed. See [`key_authorized`].
    let ignore_prefix = matches!(operation, S3Operation::DeleteObjects { .. });

    // Check if any scope grants access
    let authorized = scopes.iter().any(|scope| {
        if scope.bucket != bucket {
            return false;
        }
        if !scope.actions.contains(&action) {
            return false;
        }
        // Check prefix restrictions
        if ignore_prefix || scope.prefixes.is_empty() {
            return true; // Full bucket access (or deferred per-key check)
        }
        scope
            .prefixes
            .iter()
            .any(|prefix| key_matches_prefix(&key, prefix))
    });

    if authorized {
        Ok(())
    } else {
        tracing::warn!(
            action = ?action,
            bucket = %bucket,
            key = %key,
            scopes = ?scopes,
            "authorization denied — no scope grants access"
        );
        Err(ProxyError::AccessDenied)
    }
}

/// Check whether `identity` may perform `action` on a single `key` in `bucket`.
///
/// Used for per-key authorization of batch operations such as
/// [`DeleteObjects`](crate::types::S3Operation::DeleteObjects), where the coarse
/// [`authorize`] check only verified that *some* scope grants the action on the
/// bucket. Anonymous identities are never authorized here — this is only used
/// for write actions, which anonymous callers can never perform.
pub fn key_authorized(
    identity: &ResolvedIdentity,
    bucket: &str,
    action: Action,
    key: &str,
) -> bool {
    let scopes = match identity {
        ResolvedIdentity::Anonymous => return false,
        ResolvedIdentity::Authenticated(id) => &id.allowed_scopes,
    };
    scopes.iter().any(|scope| {
        scope.bucket == bucket
            && scope.actions.contains(&action)
            && (scope.prefixes.is_empty()
                || scope.prefixes.iter().any(|p| key_matches_prefix(key, p)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_with_slash_matches_children() {
        assert!(key_matches_prefix("data/file.txt", "data/"));
        assert!(key_matches_prefix("data/sub/file.txt", "data/"));
    }

    #[test]
    fn prefix_without_slash_enforces_boundary() {
        assert!(key_matches_prefix("data/file.txt", "data"));
        assert!(key_matches_prefix("data", "data"));
        assert!(!key_matches_prefix("data-private/secret.txt", "data"));
        assert!(!key_matches_prefix("database/dump.sql", "data"));
    }

    #[test]
    fn empty_prefix_matches_everything() {
        assert!(key_matches_prefix("anything/at/all.txt", ""));
        assert!(key_matches_prefix("", ""));
    }

    #[test]
    fn prefix_no_match() {
        assert!(!key_matches_prefix("other/file.txt", "data/"));
        assert!(!key_matches_prefix("other/file.txt", "data"));
    }

    use crate::types::{AccessScope, AuthenticatedIdentity, BucketConfig};

    fn identity_with(scope: AccessScope) -> ResolvedIdentity {
        ResolvedIdentity::Authenticated(AuthenticatedIdentity {
            principal_name: "tester".into(),
            allowed_scopes: vec![scope],
        })
    }

    fn bucket(name: &str, anonymous: bool) -> BucketConfig {
        BucketConfig {
            name: name.into(),
            backend_type: "s3".into(),
            backend_prefix: None,
            anonymous_access: anonymous,
            allowed_roles: vec![],
            backend_options: Default::default(),
        }
    }

    #[test]
    fn key_authorized_enforces_prefix_per_key() {
        let id = identity_with(AccessScope {
            bucket: "b".into(),
            prefixes: vec!["data/".into()],
            actions: vec![Action::DeleteObject],
        });
        assert!(key_authorized(&id, "b", Action::DeleteObject, "data/x.txt"));
        assert!(!key_authorized(
            &id,
            "b",
            Action::DeleteObject,
            "other/x.txt"
        ));
        // Wrong bucket / wrong action are denied.
        assert!(!key_authorized(
            &id,
            "other",
            Action::DeleteObject,
            "data/x.txt"
        ));
        assert!(!key_authorized(&id, "b", Action::PutObject, "data/x.txt"));
    }

    #[test]
    fn key_authorized_denies_anonymous() {
        assert!(!key_authorized(
            &ResolvedIdentity::Anonymous,
            "b",
            Action::DeleteObject,
            "anything"
        ));
    }

    #[test]
    fn delete_objects_coarse_authz_ignores_prefix() {
        // A prefix-scoped caller passes the coarse batch-delete check even though
        // the operation carries no key; per-key enforcement happens later.
        let id = identity_with(AccessScope {
            bucket: "b".into(),
            prefixes: vec!["data/".into()],
            actions: vec![Action::DeleteObject],
        });
        let op = S3Operation::DeleteObjects { bucket: "b".into() };
        assert!(authorize(&id, &op, &bucket("b", false)).is_ok());
    }

    #[test]
    fn delete_objects_denied_without_delete_action() {
        let id = identity_with(AccessScope {
            bucket: "b".into(),
            prefixes: vec![],
            actions: vec![Action::GetObject],
        });
        let op = S3Operation::DeleteObjects { bucket: "b".into() };
        assert!(authorize(&id, &op, &bucket("b", false)).is_err());
    }

    #[test]
    fn delete_objects_denied_for_anonymous() {
        let op = S3Operation::DeleteObjects { bucket: "b".into() };
        // Even on an anonymous-readable bucket, batch delete is a write.
        assert!(authorize(&ResolvedIdentity::Anonymous, &op, &bucket("b", true)).is_err());
    }
}
