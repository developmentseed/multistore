//! Cross-path key-encoding contract.
//!
//! The proxy builds backend request paths in three places: object_store
//! presigned URLs (authenticated CRUD), `UnsignedUrlSigner` (anonymous
//! CRUD), and `build_backend_url` (raw-signed multipart and batch delete).
//! A backend percent-decodes each wire path to decide which object a
//! request addresses, so every builder must emit a path that decodes to
//! the same logical key — and the builders must agree byte-for-byte, or
//! the same logical key addresses different backend objects depending on
//! upload size, client payload mode, or bucket auth (see #105, #108).
//!
//! If an object_store upgrade changes its path encoding, these tests are
//! the loud alarm.

use std::collections::HashMap;
use std::time::Duration;

use multistore::backend::multipart::build_backend_url;
use multistore::backend::url_signer::build_signer;
use multistore::types::{BucketConfig, S3Operation};
use object_store::path::Path;
use percent_encoding::percent_decode_str;

/// Corpus of logical keys: the plain case, every character class the url
/// crate leaves literal in paths, and the characters object_store's
/// `Path::from` used to rewrite.
const KEYS: &[&str] = &[
    "plain/file.bin",
    "by_country/country_iso=ETH/ETH.pmtiles",
    "spaces in/every segment.txt",
    "specials !('):@+,;$&.bin",
    "unicode/café/naïve.txt",
    "report*.pdf",
    "100%.txt",
    "tilde~hash#pipe|.bin",
    "brackets[1]{2}.bin",
    "literal-%3D-triplet.txt",
];

fn bucket_config(with_creds: bool) -> BucketConfig {
    let mut backend_options: HashMap<String, String> = HashMap::new();
    backend_options.insert(
        "endpoint".into(),
        "https://s3.us-east-1.amazonaws.com".into(),
    );
    backend_options.insert("bucket_name".into(), "backend-bucket".into());
    backend_options.insert("region".into(), "us-east-1".into());
    if with_creds {
        backend_options.insert("access_key_id".into(), "AKIAIOSFODNN7EXAMPLE".into());
        backend_options.insert(
            "secret_access_key".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        );
    }
    BucketConfig {
        name: "test".into(),
        backend_type: "s3".into(),
        backend_prefix: None,
        anonymous_access: !with_creds,
        allowed_roles: vec![],
        backend_options,
    }
}

/// Wire path emitted by the presigned CRUD builder (object_store signer
/// for authenticated buckets, `UnsignedUrlSigner` for anonymous ones).
/// `Path::parse` mirrors `build_object_path`.
fn presigned_path(config: &BucketConfig, key: &str) -> String {
    let signer = build_signer(config).unwrap();
    let path = Path::parse(key).unwrap();
    let url = futures::executor::block_on(signer.signed_url(
        http::Method::GET,
        &path,
        Duration::from_secs(60),
    ))
    .unwrap();
    url.path().to_string()
}

/// Wire path emitted by the raw-signed builder (multipart, batch delete).
fn raw_signed_path(config: &BucketConfig, key: &str) -> String {
    let op = S3Operation::CreateMultipartUpload {
        bucket: "test".into(),
        key: key.into(),
    };
    let url = build_backend_url(config, &op).unwrap();
    url::Url::parse(&url).unwrap().path().to_string()
}

/// The two SigV4 builders (authenticated presign, raw-signed) and the
/// anonymous builder must produce byte-identical wire paths for the same
/// logical key.
#[test]
fn all_builders_agree_byte_for_byte() {
    let authed = bucket_config(true);
    let anon = bucket_config(false);
    for key in KEYS {
        let presigned = presigned_path(&authed, key);
        let raw = raw_signed_path(&authed, key);
        let unsigned = presigned_path(&anon, key);
        assert_eq!(presigned, raw, "presigned vs raw-signed for key {key:?}");
        assert_eq!(
            presigned, unsigned,
            "presigned vs anonymous for key {key:?}"
        );
    }
}

/// Every wire path must percent-decode back to exactly the logical key —
/// that decode is what the backend uses to pick the object. One builder
/// suffices: `all_builders_agree_byte_for_byte` pins the others to it.
#[test]
fn wire_paths_decode_to_the_logical_key() {
    let config = bucket_config(true);
    for key in KEYS {
        let path = presigned_path(&config, key);
        let decoded = percent_decode_str(&path).decode_utf8().unwrap();
        assert_eq!(decoded, format!("/backend-bucket/{key}"), "key {key:?}");
    }
}
