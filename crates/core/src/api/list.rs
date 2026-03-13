//! LIST-specific helpers.

use crate::types::BucketConfig;

/// Build the full backend prefix by prepending `backend_prefix` (if set).
pub(crate) fn build_list_prefix(config: &BucketConfig, client_prefix: &str) -> String {
    match &config.backend_prefix {
        Some(prefix) => {
            let bp = prefix.trim_end_matches('/');
            if bp.is_empty() {
                client_prefix.to_string()
            } else {
                let mut full_prefix = String::with_capacity(bp.len() + 1 + client_prefix.len());
                full_prefix.push_str(bp);
                full_prefix.push('/');
                full_prefix.push_str(client_prefix);
                full_prefix
            }
        }
        None => client_prefix.to_string(),
    }
}
