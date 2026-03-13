//! Backend client for the Cloudflare Workers runtime.
//!
//! `WorkerBackend` implements `StoreFactory` using the Fetch API via `FetchConnector`.

use crate::fetch_connector::FetchConnector;
use multistore::backend::{create_builder, StoreBuilder};
use multistore::error::ProxyError;
use multistore::service::StoreFactory;
use multistore::types::BucketConfig;
use object_store::list::PaginatedListStore;
use object_store::multipart::MultipartStore;
use object_store::ObjectStore;
use std::sync::Arc;

/// Backend for the Cloudflare Workers runtime.
///
/// Uses `FetchConnector` for `object_store` HTTP requests.
#[derive(Clone)]
pub struct WorkerBackend;

impl StoreFactory for WorkerBackend {
    fn create_store(&self, config: &BucketConfig) -> Result<Arc<dyn ObjectStore>, ProxyError> {
        let builder = match create_builder(config)? {
            StoreBuilder::S3(s) => StoreBuilder::S3(s.with_http_connector(FetchConnector)),
        };
        builder.build_object_store()
    }

    fn create_paginated_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
        let builder = match create_builder(config)? {
            StoreBuilder::S3(s) => StoreBuilder::S3(s.with_http_connector(FetchConnector)),
        };
        builder.build()
    }

    fn create_multipart_store(
        &self,
        config: &BucketConfig,
    ) -> Result<Arc<dyn MultipartStore>, ProxyError> {
        let builder = match create_builder(config)? {
            StoreBuilder::S3(s) => StoreBuilder::S3(s.with_http_connector(FetchConnector)),
        };
        builder.build_multipart_store()
    }
}
