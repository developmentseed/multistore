"""Smoke tests for the multistore preview deployment.

Requires environment variables:
  DEPLOY_URL: The deployed preview worker URL
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: GitHub Actions OIDC bearer token (automatic)
  ACTIONS_ID_TOKEN_REQUEST_URL: GitHub Actions OIDC endpoint (automatic)
"""

import os
import uuid
import xml.etree.ElementTree as ET
from io import BytesIO

import boto3
import pytest
import requests
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

DEPLOY_URL = os.environ.get("DEPLOY_URL", "http://localhost:8787")

# S3 requires every multipart part except the last to be at least 5 MiB.
MIB = 1024 * 1024

# A writable bucket on a *real* AWS-S3 backend, addressable by the smoke
# identity. The integration suite already covers multipart against MinIO, but
# MinIO does not enforce S3's flexible-checksum validation — the exact gap that
# let the dropped-`x-amz-checksum-*` bug through — so this regression must run
# against real S3. The preview's other buckets are read-only (`skip_signature`)
# mirrors, so this is opt-in: set SMOKE_WRITE_BUCKET to the writable bucket's
# virtual name (see `smoke-writable` in examples/cf-workers/wrangler.deploy.toml).
WRITE_BUCKET = os.environ.get("SMOKE_WRITE_BUCKET")

requires_write_bucket = pytest.mark.skipif(
    not WRITE_BUCKET,
    reason="SMOKE_WRITE_BUCKET not set (no writable real-S3 bucket configured)",
)


def assume_role(role_arn: str, oidc_token: str) -> dict:
    """Assume a role via the STS proxy and return parsed credentials."""
    resp = requests.get(
        f"{DEPLOY_URL}/.sts",
        params={
            "Action": "AssumeRoleWithWebIdentity",
            "RoleArn": role_arn,
            "WebIdentityToken": oidc_token,
        },
    )
    resp.raise_for_status()

    root = ET.fromstring(resp.text)
    # Handle XML namespaces - find Credentials element regardless of namespace
    creds_el = root.find(".//{*}Credentials")
    assert creds_el is not None, f"No Credentials element in response:\n{resp.text}"

    def text(tag: str) -> str:
        el = creds_el.find(f"{{*}}{tag}")
        assert el is not None and el.text, f"Missing {tag} in credentials"
        return el.text

    return {
        "AccessKeyId": text("AccessKeyId"),
        "SecretAccessKey": text("SecretAccessKey"),
        "SessionToken": text("SessionToken"),
    }


def s3_client(creds: dict):
    """Create an S3 client using the given credentials against the preview endpoint."""
    return boto3.client(
        "s3",
        endpoint_url=DEPLOY_URL,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )


requires_oidc = pytest.mark.skipif(
    not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    reason="ACTIONS_ID_TOKEN_REQUEST_TOKEN not set",
)


@pytest.fixture(scope="module")
def oidc_token() -> str:
    """Fetch a GitHub Actions OIDC token."""
    token = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    resp = requests.get(
        f"{url}&audience=sts.amazonaws.com",
        headers={"Authorization": f"bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()["value"]


@pytest.fixture(scope="module")
def actions_credentials(oidc_token):
    """Credentials from assuming the github-actions role."""
    return assume_role("github-actions", oidc_token)


@pytest.fixture(scope="module")
def no_access_credentials(oidc_token):
    """Credentials from assuming the github-actions-no-access role."""
    return assume_role("github-actions-no-access", oidc_token)


@requires_oidc
class TestAssumeRole:
    def test_assume_role_returns_credentials(self, actions_credentials):
        assert actions_credentials["AccessKeyId"]
        assert actions_credentials["SecretAccessKey"]
        assert actions_credentials["SessionToken"]

    def test_assume_no_access_role_returns_credentials(self, no_access_credentials):
        assert no_access_credentials["AccessKeyId"]
        assert no_access_credentials["SecretAccessKey"]
        assert no_access_credentials["SessionToken"]


@requires_oidc
class TestS3Access:
    def test_list_bucket_with_access(self, actions_credentials):
        client = s3_client(actions_credentials)
        resp = client.list_objects_v2(Bucket="cholmes", MaxKeys=5)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_list_bucket_denied_without_access(self, no_access_credentials):
        client = s3_client(no_access_credentials)
        with pytest.raises(ClientError) as exc_info:
            client.list_objects_v2(Bucket="cholmes", MaxKeys=5)
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


class TestStaticCredentials:
    """Verify access using static credentials from the proxy config.

    The demo-user credentials have allowed_scopes granting read access to the
    cholmes bucket. Unauthenticated requests and bad credentials must be denied.
    """

    @staticmethod
    def _client(access_key: str = "AKPROXY00000EXAMPLE", secret_key: str = "EXAMPLE000000000000"):
        return boto3.client(
            "s3",
            endpoint_url=DEPLOY_URL,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",
            config=Config(s3={"addressing_style": "path"}),
        )

    def test_list_bucket_with_valid_credentials(self):
        client = self._client()
        resp = client.list_objects_v2(Bucket="cholmes", MaxKeys=5)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_get_object_with_valid_credentials(self):
        client = self._client()
        resp = client.head_object(Bucket="cholmes", Key="overture/catalog.json")
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_anonymous_access_denied_for_private_bucket(self):
        resp = requests.get(f"{DEPLOY_URL}/cholmes/", params={"list-type": "2", "max-keys": "1"})
        assert resp.status_code == 403

    def test_bad_access_key_denied(self):
        client = self._client(access_key="AKBADKEY0000000000", secret_key="BADSECRET00000000000")
        with pytest.raises(ClientError) as exc_info:
            client.list_objects_v2(Bucket="cholmes", MaxKeys=5)
        assert exc_info.value.response["Error"]["Code"] in ("AccessDenied", "InvalidAccessKeyId")

    def test_wrong_secret_key_denied(self):
        client = self._client(access_key="AKPROXY00000EXAMPLE", secret_key="WRONGSECRET00000000")
        with pytest.raises(ClientError) as exc_info:
            client.list_objects_v2(Bucket="cholmes", MaxKeys=5)
        assert exc_info.value.response["Error"]["Code"] in ("AccessDenied", "SignatureDoesNotMatch")


# Public bucket + key used for range request tests.
RANGE_TEST_PATH = "/harvard-lil/gov-data/README.md"


class TestRangeRequests:
    """Verify range request headers on GET and HEAD responses."""

    def test_get_range_returns_206(self):
        resp = requests.get(
            f"{DEPLOY_URL}{RANGE_TEST_PATH}",
            headers={"Range": "bytes=0-10"},
        )
        assert resp.status_code == 206
        assert resp.headers.get("content-range") is not None
        assert resp.headers["content-range"].startswith("bytes 0-10/")
        assert resp.headers["content-length"] == "11"
        assert resp.headers.get("accept-ranges") == "bytes"

    def test_head_includes_accept_ranges(self):
        resp = requests.head(f"{DEPLOY_URL}{RANGE_TEST_PATH}")
        assert resp.status_code == 200
        assert resp.headers.get("accept-ranges") == "bytes"
        assert int(resp.headers["content-length"]) > 0

    def test_head_range_returns_206(self):
        resp = requests.head(
            f"{DEPLOY_URL}{RANGE_TEST_PATH}",
            headers={"Range": "bytes=0-10"},
        )
        assert resp.status_code == 206
        assert resp.headers.get("content-range") is not None
        assert resp.headers["content-range"].startswith("bytes 0-10/")
        assert resp.headers["content-length"] == "11"

    def test_get_without_range_returns_200(self):
        resp = requests.head(f"{DEPLOY_URL}{RANGE_TEST_PATH}")
        assert resp.status_code == 200
        assert "content-range" not in resp.headers

    def test_range_after_full_get_still_returns_206(self):
        """Regression test for CF subrequest caching breaking Range requests.

        CF's edge cache can store a full-body 200 from a non-Range GET and
        then serve it for subsequent Range requests instead of forwarding
        the Range header to the origin. This simulates what `aws s3 cp` does:
        HEAD → full-size GET (or cached) → concurrent Range GETs.
        """
        url = f"{DEPLOY_URL}{RANGE_TEST_PATH}"

        # Prime the cache with a full GET (no Range).
        full = requests.get(url)
        assert full.status_code == 200
        total_size = int(full.headers["content-length"])

        # Now issue Range requests — these must return 206, not a cached 200.
        chunk = min(1024, total_size - 1)
        for start in [0, chunk]:
            end = min(start + chunk - 1, total_size - 1)
            resp = requests.get(url, headers={"Range": f"bytes={start}-{end}"})
            assert resp.status_code == 206, (
                f"Range bytes={start}-{end} returned {resp.status_code} "
                f"(content-length: {resp.headers.get('content-length')}, "
                f"content-range: {resp.headers.get('content-range')}). "
                f"CF may be serving a cached full-body response."
            )
            assert resp.headers.get("content-range") is not None


@requires_oidc
@requires_write_bucket
class TestMultipartUpload:
    """Multipart upload against a real S3 backend.

    Regression guard for the dropped flexible-checksum headers bug: modern AWS
    CLI/SDK enable CRC32 integrity checksums by default, so a multipart upload
    sends a per-part checksum on each UploadPart and echoes them on
    CompleteMultipartUpload. If the proxy drops the `x-amz-checksum-*` headers,
    the upload is initialized with no checksum context while the parts carry
    checksums, and S3 rejects completion with `InvalidPart`. Checksums are
    forced on here (`ChecksumAlgorithm=CRC32`) so the path is exercised
    regardless of the client's botocore default.

    This is what `aws s3 cp` of a large file does and what originally surfaced
    the bug; MinIO (the integration backend) does not reproduce it.
    """

    def test_multipart_roundtrip_with_checksums(self, actions_credentials):
        client = s3_client(actions_credentials)
        key = f"smoke-multipart-{uuid.uuid4()}.bin"
        # 6 MiB → two parts (5 MiB + 1 MiB) at a 5 MiB chunk size.
        body = bytes(i % 251 for i in range(6 * MIB))
        config = TransferConfig(
            multipart_threshold=5 * MIB,
            multipart_chunksize=5 * MIB,
            max_concurrency=1,
            use_threads=False,
        )
        try:
            client.upload_fileobj(
                BytesIO(body),
                WRITE_BUCKET,
                key,
                Config=config,
                ExtraArgs={"ChecksumAlgorithm": "CRC32"},
            )
            resp = client.get_object(Bucket=WRITE_BUCKET, Key=key)
            assert resp["Body"].read() == body
        finally:
            client.delete_object(Bucket=WRITE_BUCKET, Key=key)
