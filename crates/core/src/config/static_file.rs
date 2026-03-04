//! Static file-based configuration provider.
//!
//! Loads configuration from a TOML or JSON file at startup.
//! Suitable for simple deployments or development.

use crate::config::ConfigProvider;
use crate::error::ProxyError;
use crate::s3::response::BucketOwner;
use crate::types::{BucketConfig, RoleConfig, StoredCredential};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

/// Full configuration file structure.
#[derive(Debug, Clone, Deserialize)]
pub struct StaticConfig {
    /// Owner ID returned in ListBuckets responses.
    pub owner_id: Option<String>,
    /// Owner display name returned in ListBuckets responses.
    pub owner_display_name: Option<String>,
    #[serde(default)]
    pub buckets: Vec<BucketConfig>,
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    #[serde(default)]
    pub credentials: Vec<StoredCredential>,
}

impl StaticConfig {
    /// Validate the configuration, collecting all errors into a single message.
    ///
    /// Checks for:
    /// - Empty bucket names, role_ids, or credential access_key_ids
    /// - Duplicate bucket names, role_ids, or access_key_ids
    /// - Roles with empty `trusted_oidc_issuers` (would never accept a token)
    /// - `allowed_roles` referencing unknown role_ids (warning only, roles may come from a separate STS config)
    pub fn validate(&self) -> Result<(), ProxyError> {
        let mut errors = Vec::new();

        // Check buckets
        let mut bucket_names = HashSet::new();
        for (i, bucket) in self.buckets.iter().enumerate() {
            if bucket.name.is_empty() {
                errors.push(format!("bucket[{}] has an empty name", i));
            } else if !bucket_names.insert(&bucket.name) {
                errors.push(format!("duplicate bucket name: {:?}", bucket.name));
            }
        }

        // Check roles
        let mut role_ids = HashSet::new();
        for (i, role) in self.roles.iter().enumerate() {
            if role.role_id.is_empty() {
                errors.push(format!("role[{}] has an empty role_id", i));
            } else if !role_ids.insert(&role.role_id) {
                errors.push(format!("duplicate role_id: {:?}", role.role_id));
            }
            if role.trusted_oidc_issuers.is_empty() {
                errors.push(format!(
                    "role {:?} has no trusted_oidc_issuers (will never accept a token)",
                    role.role_id
                ));
            }
        }

        // Check credentials
        let mut access_key_ids = HashSet::new();
        for (i, cred) in self.credentials.iter().enumerate() {
            if cred.access_key_id.is_empty() {
                errors.push(format!("credential[{}] has an empty access_key_id", i));
            } else if !access_key_ids.insert(&cred.access_key_id) {
                errors.push(format!(
                    "duplicate credential access_key_id: {:?}",
                    cred.access_key_id
                ));
            }
        }

        // Warn about allowed_roles referencing unknown role_ids
        for bucket in &self.buckets {
            for role_ref in &bucket.allowed_roles {
                if !role_ids.contains(role_ref) {
                    tracing::warn!(
                        bucket = %bucket.name,
                        role = %role_ref,
                        "allowed_roles references unknown role_id (may be defined in a separate STS config)"
                    );
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ProxyError::ConfigError(errors.join("; ")))
        }
    }
}

/// Configuration provider backed by a static TOML/JSON file.
///
/// # Example
///
/// ```rust,ignore
/// let provider = StaticProvider::from_toml(r#"
///     [[buckets]]
///     name = "public-data"
///     backend_type = "s3"
///     anonymous_access = true
///     allowed_roles = []
///
///     [buckets.backend_options]
///     endpoint = "https://s3.amazonaws.com"
///     bucket_name = "my-real-bucket"
///     region = "us-east-1"
///     access_key_id = "AKIA..."
///     secret_access_key = "..."
/// "#)?;
/// ```
#[derive(Clone, Debug)]
pub struct StaticProvider {
    inner: Arc<StaticProviderInner>,
}

#[derive(Debug)]
struct StaticProviderInner {
    config: StaticConfig,
}

impl StaticProvider {
    /// Parse a TOML string into a provider.
    pub fn from_toml(toml_str: &str) -> Result<Self, ProxyError> {
        let config: StaticConfig =
            toml::from_str(toml_str).map_err(|e| ProxyError::ConfigError(e.to_string()))?;
        Self::from_config(config)
    }

    /// Parse a JSON string into a provider.
    pub fn from_json(json_str: &str) -> Result<Self, ProxyError> {
        let config: StaticConfig =
            serde_json::from_str(json_str).map_err(|e| ProxyError::ConfigError(e.to_string()))?;
        Self::from_config(config)
    }

    /// Read and parse a TOML file.
    pub fn from_file(path: &str) -> Result<Self, ProxyError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ProxyError::ConfigError(e.to_string()))?;
        if path.ends_with(".json") {
            Self::from_json(&content)
        } else {
            Self::from_toml(&content)
        }
    }

    pub fn from_config(config: StaticConfig) -> Result<Self, ProxyError> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(StaticProviderInner { config }),
        })
    }
}

impl ConfigProvider for StaticProvider {
    fn bucket_owner(&self) -> BucketOwner {
        let default_owner = super::DEFAULT_BUCKET_OWNER;
        BucketOwner {
            id: self
                .inner
                .config
                .owner_id
                .clone()
                .unwrap_or_else(|| default_owner.to_string()),
            display_name: self
                .inner
                .config
                .owner_display_name
                .clone()
                .unwrap_or_else(|| default_owner.to_string()),
        }
    }

    async fn list_buckets(&self) -> Result<Vec<BucketConfig>, ProxyError> {
        Ok(self.inner.config.buckets.clone())
    }

    async fn get_bucket(&self, name: &str) -> Result<Option<BucketConfig>, ProxyError> {
        Ok(self
            .inner
            .config
            .buckets
            .iter()
            .find(|b| b.name == name)
            .cloned())
    }

    async fn get_role(&self, role_id: &str) -> Result<Option<RoleConfig>, ProxyError> {
        Ok(self
            .inner
            .config
            .roles
            .iter()
            .find(|r| r.role_id == role_id)
            .cloned())
    }

    async fn get_credential(
        &self,
        access_key_id: &str,
    ) -> Result<Option<StoredCredential>, ProxyError> {
        Ok(self
            .inner
            .config
            .credentials
            .iter()
            .find(|c| c.access_key_id == access_key_id)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> StaticConfig {
        StaticConfig {
            owner_id: None,
            owner_display_name: None,
            buckets: vec![BucketConfig {
                name: "my-bucket".into(),
                backend_type: "s3".into(),
                backend_prefix: None,
                anonymous_access: true,
                allowed_roles: vec![],
                backend_options: Default::default(),
            }],
            roles: vec![RoleConfig {
                role_id: "my-role".into(),
                name: "My Role".into(),
                trusted_oidc_issuers: vec!["https://issuer.example.com".into()],
                required_audience: None,
                subject_conditions: vec![],
                allowed_scopes: vec![],
                max_session_duration_secs: 3600,
            }],
            credentials: vec![StoredCredential {
                access_key_id: "AKID1".into(),
                secret_access_key: "secret".into(),
                principal_name: "user".into(),
                allowed_scopes: vec![],
                created_at: chrono::Utc::now(),
                expires_at: None,
                enabled: true,
            }],
        }
    }

    #[test]
    fn test_valid_config_passes_validation() {
        valid_config().validate().unwrap();
    }

    #[test]
    fn test_empty_config_passes_validation() {
        let config = StaticConfig {
            owner_id: None,
            owner_display_name: None,
            buckets: vec![],
            roles: vec![],
            credentials: vec![],
        };
        config.validate().unwrap();
    }

    #[test]
    fn test_empty_bucket_name() {
        let mut config = valid_config();
        config.buckets[0].name = "".into();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("bucket[0] has an empty name"), "{}", err);
    }

    #[test]
    fn test_duplicate_bucket_names() {
        let mut config = valid_config();
        config.buckets.push(config.buckets[0].clone());
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate bucket name"), "{}", err);
    }

    #[test]
    fn test_empty_role_id() {
        let mut config = valid_config();
        config.roles[0].role_id = "".into();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("role[0] has an empty role_id"), "{}", err);
    }

    #[test]
    fn test_duplicate_role_ids() {
        let mut config = valid_config();
        config.roles.push(config.roles[0].clone());
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate role_id"), "{}", err);
    }

    #[test]
    fn test_empty_trusted_oidc_issuers() {
        let mut config = valid_config();
        config.roles[0].trusted_oidc_issuers.clear();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("no trusted_oidc_issuers"), "{}", err);
    }

    #[test]
    fn test_empty_access_key_id() {
        let mut config = valid_config();
        config.credentials[0].access_key_id = "".into();
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("credential[0] has an empty access_key_id"),
            "{}",
            err
        );
    }

    #[test]
    fn test_duplicate_access_key_ids() {
        let mut config = valid_config();
        config.credentials.push(config.credentials[0].clone());
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("duplicate credential access_key_id"),
            "{}",
            err
        );
    }

    #[test]
    fn test_multiple_errors_collected() {
        let mut config = valid_config();
        config.buckets[0].name = "".into();
        config.roles[0].role_id = "".into();
        config.credentials[0].access_key_id = "".into();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("bucket[0] has an empty name"), "{}", err);
        assert!(err.contains("role[0] has an empty role_id"), "{}", err);
        assert!(
            err.contains("credential[0] has an empty access_key_id"),
            "{}",
            err
        );
    }

    #[test]
    fn test_from_config_runs_validation() {
        let mut config = valid_config();
        config.buckets[0].name = "".into();
        assert!(StaticProvider::from_config(config).is_err());
    }

    #[test]
    fn test_from_toml_runs_validation() {
        let toml = r#"
            [[roles]]
            role_id = "bad-role"
            name = "Bad"
            max_session_duration_secs = 3600
        "#;
        let err = StaticProvider::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("no trusted_oidc_issuers"), "{}", err);
    }

    #[test]
    fn test_from_json_runs_validation() {
        let json = r#"{"roles": [{"role_id": "bad-role", "name": "Bad", "max_session_duration_secs": 3600}]}"#;
        let err = StaticProvider::from_json(json).unwrap_err().to_string();
        assert!(err.contains("no trusted_oidc_issuers"), "{}", err);
    }
}
