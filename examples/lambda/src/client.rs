//! Lambda backend using the default object_store connector.

use multistore::backend::create_builder;
use multistore::error::ProxyError;
use multistore::service::StoreFactory;
use multistore::types::BucketConfig;
use object_store::list::PaginatedListStore;
use object_store::multipart::MultipartStore;
use object_store::ObjectStore;
use std::sync::Arc;

/// Backend for the Lambda runtime.
///
/// Uses the default object_store HTTP connector for all operations.
#[derive(Clone)]
pub struct LambdaBackend;

impl LambdaBackend {
    pub fn new() -> Self {
        Self
    }
}

impl StoreFactory for LambdaBackend {
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
