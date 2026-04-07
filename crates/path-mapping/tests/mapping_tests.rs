use multistore_path_mapping::PathMapping;

fn default_mapping() -> PathMapping {
    PathMapping {
        bucket_segments: 2,
        bucket_separator: "--".to_string(),
        display_bucket_segments: 1,
    }
}

// ── parse ───────────────────────────────────────────────────────────

#[test]
fn two_segment_mapping() {
    let mapping = default_mapping();
    let result = mapping.parse("/account/product/file.parquet").unwrap();

    assert_eq!(result.bucket, "account--product");
    assert_eq!(result.key, Some("file.parquet".to_string()));
    assert_eq!(result.display_bucket, "account");
    assert_eq!(result.key_prefix, "product/");
    assert_eq!(result.segments, vec!["account", "product"]);
}

#[test]
fn single_segment_not_enough() {
    let mapping = default_mapping();
    let result = mapping.parse("/account");

    assert!(result.is_none());
}

#[test]
fn nested_key() {
    let mapping = default_mapping();
    let result = mapping
        .parse("/account/product/dir/subdir/file.parquet")
        .unwrap();

    assert_eq!(result.bucket, "account--product");
    assert_eq!(result.key, Some("dir/subdir/file.parquet".to_string()));
    assert_eq!(result.display_bucket, "account");
    assert_eq!(result.key_prefix, "product/");
}

#[test]
fn just_bucket_segments_no_key() {
    let mapping = default_mapping();
    let result = mapping.parse("/account/product").unwrap();

    assert_eq!(result.bucket, "account--product");
    assert_eq!(result.key, None);
    assert_eq!(result.display_bucket, "account");
    assert_eq!(result.key_prefix, "product/");
}

#[test]
fn parse_bucket_name() {
    let mapping = default_mapping();
    let result = mapping.parse_bucket_name("account--product").unwrap();

    assert_eq!(result.bucket, "account--product");
    assert_eq!(result.key, None);
    assert_eq!(result.display_bucket, "account");
    assert_eq!(result.key_prefix, "product/");
    assert_eq!(result.segments, vec!["account", "product"]);
}

#[test]
fn empty_root_path() {
    let mapping = default_mapping();

    assert!(mapping.parse("/").is_none());
    assert!(mapping.parse("").is_none());
}

#[test]
fn custom_separator() {
    let mapping = PathMapping {
        bucket_segments: 2,
        bucket_separator: "-".to_string(),
        display_bucket_segments: 1,
    };

    let result = mapping.parse("/org/repo/data.csv").unwrap();

    assert_eq!(result.bucket, "org-repo");
    assert_eq!(result.key, Some("data.csv".to_string()));
    assert_eq!(result.display_bucket, "org");
    assert_eq!(result.key_prefix, "repo/");
}

#[test]
fn parse_bucket_name_wrong_segment_count() {
    let mapping = default_mapping();

    // Too few segments
    assert!(mapping.parse_bucket_name("account").is_none());
    // Too many segments
    assert!(mapping.parse_bucket_name("a--b--c").is_none());
}

#[test]
fn trailing_slash_on_bucket_segments() {
    let mapping = default_mapping();
    let result = mapping.parse("/account/product/").unwrap();

    // Trailing slash means key portion is empty, so key should be None
    assert_eq!(result.bucket, "account--product");
    assert_eq!(result.key, None);
}

// ── rewrite_request ─────────────────────────────────────────────────

#[test]
fn rewrite_multi_segment_path() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/account/product/file.parquet", None);
    assert_eq!(result.path, "/account--product/file.parquet");
    assert_eq!(result.query, None);
    assert_eq!(result.signing_path, "/account/product/file.parquet");
    assert_eq!(result.signing_query, None);
}

#[test]
fn rewrite_multi_segment_nested_key() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/account/product/dir/sub/file.parquet", None);
    assert_eq!(result.path, "/account--product/dir/sub/file.parquet");
    assert_eq!(result.query, None);
    assert_eq!(result.signing_path, "/account/product/dir/sub/file.parquet");
    assert_eq!(result.signing_query, None);
}

#[test]
fn rewrite_bucket_only_no_key() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/account/product", Some("list-type=2"));
    assert_eq!(result.path, "/account--product");
    assert_eq!(result.query, Some("list-type=2".to_string()));
    assert_eq!(result.signing_path, "/account/product");
    assert_eq!(result.signing_query, Some("list-type=2".to_string()));
}

#[test]
fn rewrite_prefix_routed_list() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/account", Some("list-type=2&prefix=product/"));
    assert_eq!(result.path, "/account--product");
    assert_eq!(result.query, Some("list-type=2&prefix=".to_string()));
    assert_eq!(result.signing_path, "/account");
    assert_eq!(
        result.signing_query,
        Some("list-type=2&prefix=product/".to_string())
    );
}

#[test]
fn rewrite_prefix_routed_list_with_subdir() {
    let mapping = default_mapping();
    let result =
        mapping.rewrite_request("/account", Some("list-type=2&prefix=product/subdir/"));
    assert_eq!(result.path, "/account--product");
    assert_eq!(result.query, Some("list-type=2&prefix=subdir/".to_string()));
    assert_eq!(result.signing_path, "/account");
    assert_eq!(
        result.signing_query,
        Some("list-type=2&prefix=product/subdir/".to_string())
    );
}

#[test]
fn rewrite_url_encoded_prefix() {
    let mapping = default_mapping();
    let result =
        mapping.rewrite_request("/account", Some("list-type=2&prefix=my%20product/subdir/"));
    assert_eq!(result.path, "/account--my product");
    assert_eq!(result.query, Some("list-type=2&prefix=subdir/".to_string()));
    assert_eq!(result.signing_path, "/account");
    assert_eq!(
        result.signing_query,
        Some("list-type=2&prefix=my%20product/subdir/".to_string())
    );
}

#[test]
fn rewrite_single_segment_no_list_passes_through() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/account", None);
    assert_eq!(result.path, "/account");
    assert_eq!(result.query, None);
    assert_eq!(result.signing_path, "/account");
    assert_eq!(result.signing_query, None);
}

#[test]
fn rewrite_single_segment_list_no_prefix_passes_through() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/account", Some("list-type=2"));
    assert_eq!(result.path, "/account");
    assert_eq!(result.query, Some("list-type=2".to_string()));
    assert_eq!(result.signing_path, "/account");
    assert_eq!(result.signing_query, Some("list-type=2".to_string()));
}

#[test]
fn rewrite_root_passes_through() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/", None);
    assert_eq!(result.path, "/");
    assert_eq!(result.query, None);
}

#[test]
fn rewrite_empty_passes_through() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("", None);
    assert_eq!(result.path, "");
    assert_eq!(result.query, None);
}

#[test]
fn rewrite_trailing_slash_passes_through() {
    let mapping = default_mapping();
    let result = mapping.rewrite_request("/account/", Some("list-type=2"));
    assert_eq!(result.path, "/account/");
    assert_eq!(result.query, Some("list-type=2".to_string()));
}
