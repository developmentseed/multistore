//! Server backend using the default object_store connector.

use multistore::backend::create_builder;
use multistore::error::ProxyError;
use multistore::service::StoreFactory;
use multistore::types::BucketConfig;
use object_store::list::PaginatedListStore;
use object_store::multipart::MultipartStore;
use object_store::ObjectStore;
use std::sync::Arc;

/// Backend for the Tokio/Hyper server runtime.
///
/// Uses the default object_store HTTP connector for all operations.
#[derive(Clone)]
pub struct ServerBackend {
    _client: reqwest::Client,
}

impl ServerBackend {
    pub fn new() -> Self {
        Self {
            _client: reqwest::Client::builder()
                .pool_max_idle_per_host(20)
                .build()
                .expect("failed to build reqwest client"),
        }
    }
}

impl Default for ServerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreFactory for ServerBackend {
    fn create_store(&self, config: &BucketConfig) -> Result<Arc<dyn ObjectStore>, ProxyError> {
        create_builder(config)?.build_object_store()
    }

    fn create_paginated_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
        create_builder(config)?.build()
    }

    fn create_multipart_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Arc<dyn MultipartStore>, ProxyError> {
        create_builder(config)?.build_multipart_store()
    }
}
