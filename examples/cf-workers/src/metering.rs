//! Bandwidth metering backed by Durable Objects.
//!
//! Implements [`QuotaChecker`] and [`UsageRecorder`] by delegating to a
//! [`BandwidthMeter`](super::BandwidthMeter) Durable Object. Each DO instance
//! tracks bandwidth for one (bucket, identity) pair using a sliding window.

use std::collections::HashMap;
use std::net::IpAddr;

use multistore::types::ResolvedIdentity;
use multistore_metering::{QuotaChecker, QuotaExceeded, UsageEvent, UsageRecorder};

/// Per-bucket bandwidth quota configuration.
#[derive(Clone, serde::Deserialize)]
pub struct BucketQuota {
    /// Maximum bytes within the window. `None` means unlimited.
    pub limit_bytes: Option<u64>,
    /// Sliding window in seconds.
    pub window_secs: u64,
}

/// Bandwidth quota checker and usage recorder backed by Durable Objects.
///
/// Builds a DO key from `{bucket}:{identity_part}` and forwards check/record
/// calls to the [`BandwidthMeter`](super::BandwidthMeter) DO. Buckets without
/// a configured quota are treated as unlimited.
pub struct DoBandwidthMeter {
    namespace: worker::ObjectNamespace,
    quotas: HashMap<String, BucketQuota>,
}

// SAFETY: Workers runtime is single-threaded.
unsafe impl Send for DoBandwidthMeter {}
unsafe impl Sync for DoBandwidthMeter {}

impl DoBandwidthMeter {
    /// Create a new bandwidth meter.
    ///
    /// - `namespace`: the Durable Object namespace binding for `BandwidthMeter`
    /// - `quotas`: per-bucket quota configuration (buckets not present are unlimited)
    pub fn new(namespace: worker::ObjectNamespace, quotas: HashMap<String, BucketQuota>) -> Self {
        Self { namespace, quotas }
    }

    /// Build the DO key for a given bucket and identity.
    fn do_key(bucket: &str, identity: &ResolvedIdentity, source_ip: Option<IpAddr>) -> String {
        let identity_part = match identity {
            ResolvedIdentity::Anonymous => {
                let ip = source_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("anon:{ip}")
            }
            ResolvedIdentity::Authenticated(id) => {
                format!("auth:{}", id.principal_name)
            }
        };
        format!("{bucket}:{identity_part}")
    }
}

impl QuotaChecker for DoBandwidthMeter {
    async fn check_quota<'a>(
        &'a self,
        identity: &'a ResolvedIdentity,
        _operation: &'a multistore::types::S3Operation,
        bucket: Option<&'a str>,
        estimated_bytes: u64,
        source_ip: Option<IpAddr>,
    ) -> Result<(), QuotaExceeded> {
        // No bucket means a bucket-less operation (e.g. ListBuckets) — no bandwidth quota.
        let bucket = match bucket {
            Some(b) => b,
            None => return Ok(()),
        };

        // No quota configured for this bucket — unlimited.
        let quota = match self.quotas.get(bucket) {
            Some(q) => q,
            None => return Ok(()),
        };

        // Explicitly unlimited.
        let limit = match quota.limit_bytes {
            Some(l) => l,
            None => return Ok(()),
        };

        let key = Self::do_key(bucket, identity, source_ip);
        let url = format!(
            "https://do/check?bytes={}&limit={}&window={}",
            estimated_bytes, limit, quota.window_secs,
        );

        let result: Result<worker::Response, worker::Error> = async {
            let id = self.namespace.id_from_name(&key)?;
            let stub = id.get_stub()?;
            let req = worker::Request::new(&url, worker::Method::Get)?;
            stub.fetch_with_request(req).await
        }
        .await;

        match result {
            Ok(resp) if resp.status_code() == 429 => Err(QuotaExceeded {
                message: format!("Bandwidth quota exceeded for bucket '{bucket}'"),
            }),
            Ok(_) => Ok(()),
            Err(e) => {
                // Fail open: don't block legitimate traffic on DO errors.
                tracing::error!(bucket, key, error = %e, "bandwidth check failed, allowing request");
                Ok(())
            }
        }
    }
}

impl UsageRecorder for DoBandwidthMeter {
    async fn record_operation<'a>(&'a self, event: UsageEvent<'a>) {
        // No bucket or zero bytes — nothing to record.
        let bucket = match event.bucket {
            Some(b) => b,
            None => return,
        };
        if event.bytes_transferred == 0 {
            return;
        }

        // No quota configured for this bucket — no need to track.
        let quota = match self.quotas.get(bucket) {
            Some(q) => q,
            None => return,
        };

        let identity = match event.identity {
            Some(id) => id,
            None => return,
        };

        let key = Self::do_key(bucket, identity, event.source_ip);
        let url = format!(
            "https://do/record?bytes={}&window={}",
            event.bytes_transferred, quota.window_secs,
        );

        let result: Result<worker::Response, worker::Error> = async {
            let id = self.namespace.id_from_name(&key)?;
            let stub = id.get_stub()?;
            let req = worker::Request::new(&url, worker::Method::Post)?;
            stub.fetch_with_request(req).await
        }
        .await;

        if let Err(e) = result {
            tracing::error!(bucket, key, error = %e, "bandwidth record failed");
        }
    }
}
