//! STS credential minting.

use chrono::{Duration, Utc};
use multistore::error::ProxyError;
use multistore::types::{AccessScope, RoleConfig, TemporaryCredentials};
use rand::RngCore;

/// Resolve `{claim_name}` template variables in access scopes against JWT claims.
///
/// Each `{name}` in `bucket` or `prefixes` is replaced with the corresponding
/// string claim value. A claim that is missing or not a string is an error:
/// an empty prefix matches every key in the bucket, so a template that cannot
/// be resolved must not mint anything.
fn resolve_scopes(
    scopes: &[AccessScope],
    claims: &serde_json::Value,
) -> Result<Vec<AccessScope>, ProxyError> {
    scopes
        .iter()
        .map(|scope| {
            Ok(AccessScope {
                bucket: resolve_template(&scope.bucket, claims)?,
                prefixes: scope
                    .prefixes
                    .iter()
                    .map(|p| resolve_template(p, claims))
                    .collect::<Result<_, _>>()?,
                actions: scope.actions.clone(),
            })
        })
        .collect()
}

/// Replace all `{key}` placeholders in `template` with values from `claims`.
fn resolve_template(template: &str, claims: &serde_json::Value) -> Result<String, ProxyError> {
    let mut result = template.to_string();
    while let Some(start) = result.find('{') {
        let Some(end) = result[start..].find('}') else {
            break;
        };
        let end = start + end;
        let key = &result[start + 1..end];
        let value = claims.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
            ProxyError::InvalidOidcToken(format!(
                "token has no string claim '{}', which an access scope requires",
                key
            ))
        })?;
        result = format!("{}{}{}", &result[..start], value, &result[end + 1..]);
    }
    Ok(result)
}

/// Mint a new set of temporary credentials for an assumed role.
///
/// Template variables (`{claim_name}`) in `role.allowed_scopes` are resolved
/// against the provided JWT `claims` before being stored in the credentials;
/// a claim the template needs but the token lacks is an error, not an empty
/// scope.
pub fn mint_temporary_credentials(
    role: &RoleConfig,
    source_identity: &str,
    duration_seconds: u64,
    key_prefix: &str,
    claims: &serde_json::Value,
) -> Result<TemporaryCredentials, ProxyError> {
    let allowed_scopes = resolve_scopes(&role.allowed_scopes, claims)?;
    let access_key_id = format!("{}{}", key_prefix, generate_random_id(16));
    let secret_access_key = generate_random_id(40);
    let session_token = generate_session_token();

    let expiration = Utc::now() + Duration::seconds(duration_seconds as i64);

    Ok(TemporaryCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
        allowed_scopes,
        assumed_role_id: role.role_id.clone(),
        source_identity: source_identity.to_string(),
    })
}

fn generate_random_id(len: usize) -> String {
    use base64::Engine;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    // Take only alphanumeric chars to match AWS key format
    encoded
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(len)
        .collect()
}

fn generate_session_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use multistore::types::Action;
    use serde_json::json;

    fn scope(bucket: &str, prefixes: &[&str], actions: &[Action]) -> AccessScope {
        AccessScope {
            bucket: bucket.to_string(),
            prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
            actions: actions.to_vec(),
        }
    }

    #[test]
    fn resolve_template_in_bucket() {
        let scopes = vec![scope("{sub}", &[], &[Action::GetObject])];
        let claims = json!({"sub": "alice"});
        let resolved = resolve_scopes(&scopes, &claims).unwrap();
        assert_eq!(resolved[0].bucket, "alice");
    }

    #[test]
    fn resolve_template_in_prefix() {
        let scopes = vec![scope("my-bucket", &["data/{sub}/"], &[Action::GetObject])];
        let claims = json!({"sub": "alice"});
        let resolved = resolve_scopes(&scopes, &claims).unwrap();
        assert_eq!(resolved[0].prefixes[0], "data/alice/");
    }

    #[test]
    fn resolve_multiple_claims() {
        let scopes = vec![scope("{org}", &["{sub}/"], &[Action::GetObject])];
        let claims = json!({"sub": "alice", "org": "acme"});
        let resolved = resolve_scopes(&scopes, &claims).unwrap();
        assert_eq!(resolved[0].bucket, "acme");
        assert_eq!(resolved[0].prefixes[0], "alice/");
    }

    #[test]
    fn no_templates_unchanged() {
        let scopes = vec![scope("static-bucket", &["prefix/"], &[Action::GetObject])];
        let claims = json!({"sub": "alice"});
        let resolved = resolve_scopes(&scopes, &claims).unwrap();
        assert_eq!(resolved[0].bucket, "static-bucket");
        assert_eq!(resolved[0].prefixes[0], "prefix/");
    }

    #[test]
    fn missing_claim_is_an_error_not_an_empty_scope() {
        // An empty prefix matches every key, so a claim the template needs
        // but the token lacks must refuse to mint rather than widen.
        let scopes = vec![scope("bucket", &["{org}/"], &[Action::GetObject])];
        let claims = json!({"sub": "alice", "org": 7});
        let err = resolve_scopes(&scopes, &claims).unwrap_err().to_string();
        assert!(err.contains("no string claim 'org'"), "{}", err);
        assert!(resolve_scopes(&scopes, &json!({"sub": "alice"})).is_err());
    }
}
