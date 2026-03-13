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

    // Check if any scope grants access
    let authorized = scopes.iter().any(|scope| {
        if scope.bucket != bucket {
            return false;
        }
        if !scope.actions.contains(&action) {
            return false;
        }
        // Check prefix restrictions
        if scope.prefixes.is_empty() {
            return true; // Full bucket access
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
}
