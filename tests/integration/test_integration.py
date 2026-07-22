"""Integration tests for multistore proxy against a local MinIO backend.

Requires CF Workers (wrangler dev) running with wrangler.integration.toml
and MinIO on localhost:9000 seeded with test data.

Environment variables:
  PROXY_URL: Proxy server URL (default: http://localhost:8787)
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: GitHub Actions OIDC bearer token (automatic in CI)
  ACTIONS_ID_TOKEN_REQUEST_URL: GitHub Actions OIDC endpoint (automatic in CI)
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

# S3 requires every multipart part except the last to be at least 5 MiB.
MIB = 1024 * 1024

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:8787")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def assume_role(role_arn: str, oidc_token: str) -> dict:
    """Assume a role via the STS proxy and return parsed credentials."""
    resp = requests.get(
        f"{PROXY_URL}/.sts",
        params={
            "Action": "AssumeRoleWithWebIdentity",
            "RoleArn": role_arn,
            "WebIdentityToken": oidc_token,
        },
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
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
    """Create an S3 client using the given credentials against the proxy."""
    return boto3.client(
        "s3",
        endpoint_url=PROXY_URL,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )


def static_client(
    access_key: str = "AKTEST000000000001",
    secret_key: str = "testSecretKey00000000000000000001",
):
    """Create an S3 client using static credentials."""
    return boto3.client(
        "s3",
        endpoint_url=PROXY_URL,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}),
    )


requires_oidc = pytest.mark.skipif(
    not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    reason="ACTIONS_ID_TOKEN_REQUEST_TOKEN not set (not running in GitHub Actions)",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Static credential writes
# ---------------------------------------------------------------------------

class TestStaticCredentialWrites:
    """Verify write operations using static credentials."""

    def test_put_then_get_roundtrip(self):
        client = static_client()
        key = f"test-{uuid.uuid4()}.txt"
        body = b"integration test payload"

        client.put_object(Bucket="private-uploads", Key=key, Body=body)
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == body

        # Cleanup
        client.delete_object(Bucket="private-uploads", Key=key)

    def test_put_larger_body_single_request(self):
        """A non-trivial single PUT (streamed, not buffered) round-trips intact."""
        client = static_client()
        key = f"test-large-{uuid.uuid4()}.bin"
        # 2 MiB: well above the trivial happy-path size, still a single PUT
        # (put_object never switches to multipart).
        body = bytes((i % 251 for i in range(2 * MIB)))

        client.put_object(Bucket="private-uploads", Key=key, Body=body)
        resp = client.get_object(Bucket="private-uploads", Key=key)
        data = resp["Body"].read()
        assert len(data) == len(body)
        assert data == body

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_put_preserves_content_headers(self):
        """Standard entity headers set on PUT survive the round-trip.

        Exercises the widened PUT forward allowlist (Content-Type was always
        forwarded; Content-Disposition / Cache-Control are new). Note:
        `x-amz-meta-*` user metadata is intentionally NOT forwarded (it requires
        the deferred header-signing path), so it is not asserted.
        """
        client = static_client()
        key = f"test-headers-{uuid.uuid4()}.txt"
        client.put_object(
            Bucket="private-uploads",
            Key=key,
            Body=b"payload with content metadata",
            ContentType="application/json",
            ContentDisposition='attachment; filename="report.json"',
            CacheControl="max-age=3600",
        )
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["ContentType"] == "application/json"
        assert resp["ContentDisposition"] == 'attachment; filename="report.json"'
        assert resp["CacheControl"] == "max-age=3600"

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_list_after_write(self):
        client = static_client()
        key = f"test-list-{uuid.uuid4()}.txt"

        client.put_object(Bucket="private-uploads", Key=key, Body=b"list me")
        resp = client.list_objects_v2(Bucket="private-uploads", Prefix=key)
        keys = [obj["Key"] for obj in resp.get("Contents", [])]
        assert key in keys

        # Cleanup
        client.delete_object(Bucket="private-uploads", Key=key)

    def test_delete_object(self):
        client = static_client()
        key = f"test-delete-{uuid.uuid4()}.txt"

        client.put_object(Bucket="private-uploads", Key=key, Body=b"delete me")
        client.delete_object(Bucket="private-uploads", Key=key)

        with pytest.raises(ClientError) as exc_info:
            client.get_object(Bucket="private-uploads", Key=key)
        assert exc_info.value.response["Error"]["Code"] in ("NoSuchKey", "404")

    def test_head_object(self):
        client = static_client()
        key = f"test-head-{uuid.uuid4()}.txt"
        body = b"head check"

        client.put_object(Bucket="private-uploads", Key=key, Body=body)
        resp = client.head_object(Bucket="private-uploads", Key=key)
        assert resp["ContentLength"] == len(body)

        # Cleanup
        client.delete_object(Bucket="private-uploads", Key=key)

    def test_batch_delete(self):
        client = static_client()
        keys = [f"test-batch-{uuid.uuid4()}.txt" for _ in range(3)]
        for key in keys:
            client.put_object(Bucket="private-uploads", Key=key, Body=b"batch")

        resp = client.delete_objects(
            Bucket="private-uploads",
            Delete={"Objects": [{"Key": k} for k in keys]},
        )
        deleted = {d["Key"] for d in resp.get("Deleted", [])}
        assert deleted == set(keys), resp
        assert not resp.get("Errors"), resp

        # All keys are gone.
        for key in keys:
            with pytest.raises(ClientError) as exc_info:
                client.get_object(Bucket="private-uploads", Key=key)
            assert exc_info.value.response["Error"]["Code"] in ("NoSuchKey", "404")

    def test_oversized_put_rejected_entity_too_large(self):
        """A PUT exceeding MAX_UPLOAD_BYTES (10 MiB in the test config) is
        rejected with EntityTooLarge rather than forwarded to the backend."""
        client = static_client()
        key = f"test-toolarge-{uuid.uuid4()}.bin"
        body = b"z" * (12 * MIB)  # over the 10 MiB limit
        with pytest.raises(ClientError) as exc_info:
            client.put_object(Bucket="private-uploads", Key=key, Body=body)
        err = exc_info.value.response["Error"]
        assert err["Code"] == "EntityTooLarge", err
        assert exc_info.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    def test_batch_delete_partial_authorization(self):
        """Per-key authz: a batch delete with one in-scope and one out-of-scope
        key deletes the allowed one, reports the other as AccessDenied, and does
        NOT delete the out-of-scope key."""
        full = static_client()  # full access to private-uploads
        restricted = static_client(  # scoped to the "allowed/" prefix only
            access_key="AKTEST000000000002",
            secret_key="testSecretKey00000000000000000002",
        )
        suffix = uuid.uuid4()
        allowed_key = f"allowed/{suffix}.txt"
        denied_key = f"denied/{suffix}.txt"
        full.put_object(Bucket="private-uploads", Key=allowed_key, Body=b"a")
        full.put_object(Bucket="private-uploads", Key=denied_key, Body=b"b")

        resp = restricted.delete_objects(
            Bucket="private-uploads",
            Delete={"Objects": [{"Key": allowed_key}, {"Key": denied_key}]},
        )
        deleted = {d["Key"] for d in resp.get("Deleted", [])}
        errors = {e["Key"]: e["Code"] for e in resp.get("Errors", [])}
        assert deleted == {allowed_key}, resp
        assert errors == {denied_key: "AccessDenied"}, resp

        # Security property: the out-of-scope key must still exist; the in-scope
        # key must be gone.
        full.head_object(Bucket="private-uploads", Key=denied_key)  # raises if deleted
        with pytest.raises(ClientError) as exc:
            full.head_object(Bucket="private-uploads", Key=allowed_key)
        assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404

        full.delete_object(Bucket="private-uploads", Key=denied_key)  # cleanup

    def test_copy_object_same_bucket(self):
        """Server-side copy (x-amz-copy-source) within one bucket succeeds and
        the destination has the source's content."""
        client = static_client()
        src = f"copy-src-{uuid.uuid4()}.txt"
        dst = f"copy-dst-{uuid.uuid4()}.txt"
        client.put_object(Bucket="private-uploads", Key=src, Body=b"source-bytes")
        resp = client.copy_object(
            Bucket="private-uploads",
            Key=dst,
            CopySource={"Bucket": "private-uploads", "Key": src},
        )
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert resp["CopyObjectResult"]["ETag"]
        # The destination now exists with the copied bytes.
        got = client.get_object(Bucket="private-uploads", Key=dst)
        assert got["Body"].read() == b"source-bytes"

        client.delete_object(Bucket="private-uploads", Key=src)  # cleanup
        client.delete_object(Bucket="private-uploads", Key=dst)

    def test_copy_object_cross_bucket_same_store(self):
        """A copy across two virtual buckets that resolve to the same backing
        store (same endpoint/credentials) is a native same-store copy and
        succeeds — the backend bucket names differing does not matter."""
        client = static_client()
        src = f"copy-src-{uuid.uuid4()}.txt"
        dst = f"copy-dst-{uuid.uuid4()}.txt"
        client.put_object(Bucket="public-data", Key=src, Body=b"cross-bucket")
        resp = client.copy_object(
            Bucket="private-uploads",
            Key=dst,
            CopySource={"Bucket": "public-data", "Key": src},
        )
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        got = client.get_object(Bucket="private-uploads", Key=dst)
        assert got["Body"].read() == b"cross-bucket"

        client.delete_object(Bucket="public-data", Key=src)  # cleanup
        client.delete_object(Bucket="private-uploads", Key=dst)


# ---------------------------------------------------------------------------
# Conditional writes
# ---------------------------------------------------------------------------

class TestConditionalWrites:
    """Conditional-write preconditions (`If-Match` / `If-None-Match`) on PutObject.

    boto3's `put_object` streams the body as `aws-chunked`, so these exercise
    the header-signed streaming forward path (the one AWS SDKs actually use)
    end-to-end against MinIO, which enforces the precondition and returns 412.
    This is the compare-and-swap native Zarr/Icechunk writers rely on to keep
    concurrent commits from clobbering each other.
    """

    def test_if_none_match_star_blocks_overwrite(self):
        """`If-None-Match: *` must fail with 412 when the object already exists,
        and must NOT clobber the existing content (create-if-absent CAS)."""
        client = static_client()
        key = f"cond-inm-{uuid.uuid4()}.txt"
        client.put_object(Bucket="private-uploads", Key=key, Body=b"original")

        with pytest.raises(ClientError) as exc_info:
            client.put_object(
                Bucket="private-uploads",
                Key=key,
                Body=b"should-not-land",
                IfNoneMatch="*",
            )
        assert exc_info.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
        assert exc_info.value.response["Error"]["Code"] == "PreconditionFailed"

        # The precondition failure must have left the original object intact.
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == b"original"

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_if_none_match_star_allows_create(self):
        """`If-None-Match: *` must succeed when the object does not yet exist."""
        client = static_client()
        key = f"cond-inm-new-{uuid.uuid4()}.txt"
        client.put_object(
            Bucket="private-uploads",
            Key=key,
            Body=b"fresh",
            IfNoneMatch="*",
        )
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == b"fresh"

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_if_match_wrong_etag_rejected(self):
        """A PUT with a wrong `If-Match` must fail with 412 and not overwrite."""
        client = static_client()
        key = f"cond-ifm-{uuid.uuid4()}.txt"
        client.put_object(Bucket="private-uploads", Key=key, Body=b"original")

        with pytest.raises(ClientError) as exc_info:
            client.put_object(
                Bucket="private-uploads",
                Key=key,
                Body=b"should-not-land",
                IfMatch='"0000000000000000deadbeef00000000"',
            )
        assert exc_info.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
        assert exc_info.value.response["Error"]["Code"] == "PreconditionFailed"

        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == b"original"

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_if_match_correct_etag_succeeds(self):
        """A PUT whose `If-Match` equals the current ETag must succeed and
        replace the object (the successful side of the compare-and-swap)."""
        client = static_client()
        key = f"cond-ifm-ok-{uuid.uuid4()}.txt"
        put = client.put_object(Bucket="private-uploads", Key=key, Body=b"v1")
        etag = put["ETag"]

        client.put_object(
            Bucket="private-uploads",
            Key=key,
            Body=b"v2",
            IfMatch=etag,
        )
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == b"v2"

        client.delete_object(Bucket="private-uploads", Key=key)

    def _complete_multipart(self, client, key: str, body: bytes, **complete_kwargs):
        """Drive a low-level multipart upload, passing extra kwargs (e.g.
        IfMatch/IfNoneMatch) to CompleteMultipartUpload.

        If the completion fails (e.g. a 412 precondition), the MPU is left open
        by the backend — abort it before propagating so repeated CI runs don't
        accumulate stray incomplete uploads in the test bucket.
        """
        create = client.create_multipart_upload(Bucket="private-uploads", Key=key)
        upload_id = create["UploadId"]
        parts = []
        # 5 MiB + remainder → at least two parts (S3 requires >=5 MiB per
        # non-final part), forcing a real multipart completion.
        chunks = [body[: 5 * MIB], body[5 * MIB :]]
        for num, chunk in enumerate(chunks, start=1):
            up = client.upload_part(
                Bucket="private-uploads",
                Key=key,
                PartNumber=num,
                UploadId=upload_id,
                Body=chunk,
            )
            parts.append({"PartNumber": num, "ETag": up["ETag"]})
        try:
            return client.complete_multipart_upload(
                Bucket="private-uploads",
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
                **complete_kwargs,
            )
        except ClientError:
            client.abort_multipart_upload(
                Bucket="private-uploads", Key=key, UploadId=upload_id
            )
            raise

    def test_multipart_complete_if_none_match_star_blocks_overwrite(self):
        """`If-None-Match: *` on CompleteMultipartUpload must fail with 412 when
        the object exists — a large multipart write gets the same CAS guarantee
        as a single-shot PutObject."""
        client = static_client()
        key = f"cond-mpu-inm-{uuid.uuid4()}.bin"
        body = b"m" * (6 * MIB)
        self._complete_multipart(client, key, body)  # object now exists

        with pytest.raises(ClientError) as exc_info:
            self._complete_multipart(client, key, body, IfNoneMatch="*")
        assert exc_info.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
        assert exc_info.value.response["Error"]["Code"] == "PreconditionFailed"

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_multipart_complete_if_match_wrong_etag_rejected(self):
        """A wrong `If-Match` on CompleteMultipartUpload must fail with 412."""
        client = static_client()
        key = f"cond-mpu-ifm-{uuid.uuid4()}.bin"
        body = b"m" * (6 * MIB)
        self._complete_multipart(client, key, body)  # object now exists

        with pytest.raises(ClientError) as exc_info:
            self._complete_multipart(
                client,
                key,
                body,
                IfMatch='"0000000000000000deadbeef00000000"',
            )
        assert exc_info.value.response["ResponseMetadata"]["HTTPStatusCode"] == 412
        assert exc_info.value.response["Error"]["Code"] == "PreconditionFailed"

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_upload_part_tolerates_leaked_precondition(self):
        """`UploadPart` shares its `aws-chunked` forward list with the conditional
        PutObject path. `If-Match`/`If-None-Match` don't apply to a part, and
        boto3 can't even set them there, so the shared list is only safe if a
        (hand-injected) precondition rides through the proxy's sign-and-forward
        without breaking the upload — the backend ignores it.

        Inject a *signed* `If-Match` on every UploadPart and assert the multipart
        upload still completes intact. Locks in the shared-list assumption at the
        proxy level (a regression here would surface as a signature/4xx failure).
        """
        client = static_client()
        key = f"cond-part-leak-{uuid.uuid4()}.bin"

        def inject_if_match(request, **kwargs):
            # before-sign → the header is part of the client's SigV4 signature,
            # mirroring a client that genuinely (if pointlessly) sent it.
            request.headers["If-Match"] = '"0000000000000000deadbeef00000000"'

        client.meta.events.register("before-sign.s3.UploadPart", inject_if_match)

        # 6 MiB → two parts, forcing a real multipart upload.
        self._complete_multipart(client, key, b"p" * (6 * MIB))
        assert (
            client.head_object(Bucket="private-uploads", Key=key)["ContentLength"]
            == 6 * MIB
        )

        client.delete_object(Bucket="private-uploads", Key=key)


# ---------------------------------------------------------------------------
# Multipart uploads
# ---------------------------------------------------------------------------

class TestMultipartUploads:
    """Exercise the full multipart upload path (Create/UploadPart/Complete/Abort)."""

    def test_multipart_roundtrip_high_level(self):
        """boto3's transfer manager: forces Create + 2x UploadPart + Complete."""
        client = static_client()
        key = f"test-multipart-{uuid.uuid4()}.bin"
        # 6 MiB → two parts (5 MiB + 1 MiB) at a 5 MiB chunk size.
        body = b"multipart-payload-block!" * (6 * MIB // 24 + 1)
        body = body[: 6 * MIB]
        config = TransferConfig(
            multipart_threshold=5 * MIB,
            multipart_chunksize=5 * MIB,
            max_concurrency=1,
            use_threads=False,
        )

        client.upload_fileobj(BytesIO(body), "private-uploads", key, Config=config)
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == body

        client.delete_object(Bucket="private-uploads", Key=key)

    @pytest.mark.parametrize(
        "key_stem",
        [
            # Hive-style partition path — data.source.coop#180.
            "by_country/country_iso=ETH/ETH",
            # The other chars the url crate leaves literal in paths but AWS
            # strict-encodes when reconstructing the canonical URI. The
            # object_store PathPart INVALID set (`*`, `%`, `~`, `#`, ...) is
            # covered by the cross-path contract test
            # (crates/core/tests/key_encoding_contract.rs) and by
            # TestByteFaithfulKeys.
            "specials !('):@+,;$&/part=2",
        ],
    )
    def test_multipart_special_char_key_roundtrip(self, key_stem):
        """Multipart to a key with chars outside the RFC 3986 unreserved set.

        The raw-signed backend URL must percent-encode these or the backend
        (AWS/MinIO) re-encodes them server-side and rejects the signature with
        SignatureDoesNotMatch at CreateMultipartUpload.
        """
        client = static_client()
        key = f"{key_stem}-{uuid.uuid4()}.bin"
        body = b"special-key-payload!" * (6 * MIB // 20 + 1)
        body = body[: 6 * MIB]  # 6 MiB → two parts, forces multipart
        config = TransferConfig(
            multipart_threshold=5 * MIB,
            multipart_chunksize=5 * MIB,
            max_concurrency=1,
            use_threads=False,
        )

        client.upload_fileobj(BytesIO(body), "private-uploads", key, Config=config)
        # Reading back through the presigned GET path proves both paths agree
        # on what the key is.
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == body

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_multipart_low_level_explicit(self):
        """Drive Create/UploadPart/Complete directly and verify the round-trip."""
        client = static_client()
        key = f"test-mpu-explicit-{uuid.uuid4()}.bin"
        part1 = b"A" * (5 * MIB)
        part2 = b"B" * (2 * MIB)

        create = client.create_multipart_upload(Bucket="private-uploads", Key=key)
        upload_id = create["UploadId"]
        assert upload_id

        parts = []
        for num, chunk in enumerate([part1, part2], start=1):
            up = client.upload_part(
                Bucket="private-uploads",
                Key=key,
                PartNumber=num,
                UploadId=upload_id,
                Body=chunk,
            )
            parts.append({"PartNumber": num, "ETag": up["ETag"]})

        client.complete_multipart_upload(
            Bucket="private-uploads",
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == part1 + part2

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_multipart_abort(self):
        """AbortMultipartUpload tears down an in-progress upload."""
        client = static_client()
        key = f"test-mpu-abort-{uuid.uuid4()}.bin"

        create = client.create_multipart_upload(Bucket="private-uploads", Key=key)
        upload_id = create["UploadId"]

        client.upload_part(
            Bucket="private-uploads",
            Key=key,
            PartNumber=1,
            UploadId=upload_id,
            Body=b"C" * (5 * MIB),
        )
        client.abort_multipart_upload(
            Bucket="private-uploads", Key=key, UploadId=upload_id
        )

        # Completing an aborted upload must fail.
        with pytest.raises(ClientError):
            client.complete_multipart_upload(
                Bucket="private-uploads",
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": "x"}]},
            )


# ---------------------------------------------------------------------------
# Byte-faithful keys
# ---------------------------------------------------------------------------

class TestByteFaithfulKeys:
    """Keys with chars object_store's `Path::from` rewrites (`*`, `%`, `~`, ...)
    must round-trip byte-faithfully through every path: the backend object
    carries the exact requested key, and the presigned CRUD path and the
    raw-signed multipart path agree on what that key is.
    """

    @staticmethod
    def _backend_client():
        """Direct MinIO client, bypassing the proxy, to inspect stored keys."""
        return boto3.client(
            "s3",
            endpoint_url="http://localhost:9000",
            aws_access_key_id="minioadmin",
            aws_secret_access_key="minioadmin",
            region_name="us-east-1",
        )

    def test_star_key_stored_byte_faithfully(self):
        client = static_client()
        prefix = f"faithful-{uuid.uuid4()}"
        key = f"{prefix}/report*.pdf"

        client.put_object(Bucket="private-uploads", Key=key, Body=b"star")

        backend_keys = [
            o["Key"]
            for o in self._backend_client()
            .list_objects_v2(Bucket="private-uploads", Prefix=prefix)
            .get("Contents", [])
        ]
        assert backend_keys == [key], "backend object must carry the exact key"

        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == b"star"

        client.delete_object(Bucket="private-uploads", Key=key)
        assert (
            client.list_objects_v2(Bucket="private-uploads", Prefix=prefix).get(
                "KeyCount", 0
            )
            == 0
        )

    def test_percent_keys_are_distinct_objects(self):
        # `100%.txt` and `100%25.txt` must never alias to one backend object.
        client = static_client()
        prefix = f"faithful-{uuid.uuid4()}"
        k1, k2 = f"{prefix}/100%.txt", f"{prefix}/100%25.txt"

        client.put_object(Bucket="private-uploads", Key=k1, Body=b"A")
        client.put_object(Bucket="private-uploads", Key=k2, Body=b"B")

        assert client.get_object(Bucket="private-uploads", Key=k1)["Body"].read() == b"A"
        assert client.get_object(Bucket="private-uploads", Key=k2)["Body"].read() == b"B"

        for k in (k1, k2):
            client.delete_object(Bucket="private-uploads", Key=k)

    def test_multipart_write_presigned_read_agree(self):
        # Multipart (raw-signed) writes byte-faithfully; GET (presigned) must
        # address the same backend key.
        client = static_client()
        key = f"faithful-{uuid.uuid4()}/mp*.bin"
        body = b"y" * (6 * MIB)
        config = TransferConfig(
            multipart_threshold=5 * MIB,
            multipart_chunksize=5 * MIB,
            max_concurrency=1,
            use_threads=False,
        )

        client.upload_fileobj(BytesIO(body), "private-uploads", key, Config=config)
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == body

        client.delete_object(Bucket="private-uploads", Key=key)

    def test_degenerate_keys_rejected_on_every_path(self):
        # `Path::from` silently collapsed `a//b` to `a/b` and `dir/` to `dir`
        # (different keys); the shared validator makes these loud 400s on
        # every keyed operation — including the raw-signed multipart path,
        # which would otherwise accept keys the presigned path can't address.
        # Real S3 accepts such keys; the proxy is deliberately stricter.
        # (`..` segments are collapsed by WHATWG URL parsing at the edge
        # before the proxy sees them, so only the unit tests cover those.)
        client = static_client()
        for key in ("faithful/a//b.txt", "faithful/dir/"):
            with pytest.raises(ClientError) as exc_info:
                client.put_object(Bucket="private-uploads", Key=key, Body=b"x")
            assert exc_info.value.response["Error"]["Code"] == "InvalidRequest"

        with pytest.raises(ClientError) as exc_info:
            client.create_multipart_upload(
                Bucket="private-uploads", Key="faithful/a//b.txt"
            )
        assert exc_info.value.response["Error"]["Code"] == "InvalidRequest"


# ---------------------------------------------------------------------------
# Static credential reads
# ---------------------------------------------------------------------------

class TestStaticCredentialReads:
    """Verify read operations on seed data using static credentials."""

    def test_get_seed_object(self):
        client = static_client()
        resp = client.get_object(Bucket="public-data", Key="hello.txt")
        content = resp["Body"].read().decode()
        assert "Hello from s3-proxy!" in content

    def test_list_public_data(self):
        client = static_client()
        resp = client.list_objects_v2(Bucket="public-data", MaxKeys=10)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert resp["KeyCount"] > 0

    def test_anonymous_get_public_data(self):
        resp = requests.get(f"{PROXY_URL}/public-data/hello.txt")
        assert resp.status_code == 200
        assert "Hello from s3-proxy!" in resp.text

    def test_anonymous_get_private_uploads_denied(self):
        resp = requests.get(f"{PROXY_URL}/private-uploads/docs/secret.txt")
        assert resp.status_code == 403

    def test_bad_credentials_denied(self):
        client = static_client(
            access_key="AKBADKEY0000000000",
            secret_key="BADSECRET00000000000",
        )
        with pytest.raises(ClientError) as exc_info:
            client.list_objects_v2(Bucket="public-data", MaxKeys=1)
        assert exc_info.value.response["Error"]["Code"] in (
            "AccessDenied",
            "InvalidAccessKeyId",
        )


# ---------------------------------------------------------------------------
# OIDC credential access (GitHub Actions only)
# ---------------------------------------------------------------------------

@requires_oidc
class TestOidcCredentialAccess:
    """Verify OIDC-based credential flows (only runs in GitHub Actions)."""

    def test_assume_role_returns_credentials(self, actions_credentials):
        assert actions_credentials["AccessKeyId"]
        assert actions_credentials["SecretAccessKey"]
        assert actions_credentials["SessionToken"]

    def test_put_get_roundtrip(self, actions_credentials):
        client = s3_client(actions_credentials)
        key = f"oidc-test-{uuid.uuid4()}.txt"
        body = b"oidc integration test"

        client.put_object(Bucket="private-uploads", Key=key, Body=body)
        resp = client.get_object(Bucket="private-uploads", Key=key)
        assert resp["Body"].read() == body

        # Cleanup
        client.delete_object(Bucket="private-uploads", Key=key)

    def test_list_objects(self, actions_credentials):
        client = s3_client(actions_credentials)
        resp = client.list_objects_v2(Bucket="public-data", MaxKeys=5)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_no_access_role_denied(self, no_access_credentials):
        client = s3_client(no_access_credentials)
        with pytest.raises(ClientError) as exc_info:
            client.list_objects_v2(Bucket="public-data", MaxKeys=1)
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


# ---------------------------------------------------------------------------
# Anonymous access
# ---------------------------------------------------------------------------

class TestAnonymousAccess:
    """Verify anonymous (unauthenticated) request behavior."""

    def test_anonymous_read_public_data(self):
        resp = requests.get(f"{PROXY_URL}/public-data/hello.txt")
        assert resp.status_code == 200

    def test_anonymous_read_private_denied(self):
        resp = requests.get(f"{PROXY_URL}/private-uploads/docs/secret.txt")
        assert resp.status_code == 403

    def test_anonymous_write_public_denied(self):
        resp = requests.put(
            f"{PROXY_URL}/public-data/should-fail.txt",
            data=b"nope",
        )
        assert resp.status_code == 403

    def test_anonymous_list_public_data(self):
        resp = requests.get(
            f"{PROXY_URL}/public-data/",
            params={"list-type": "2", "max-keys": "1"},
        )
        assert resp.status_code == 200

    def test_anonymous_list_private_denied(self):
        resp = requests.get(
            f"{PROXY_URL}/private-uploads/",
            params={"list-type": "2", "max-keys": "1"},
        )
        assert resp.status_code == 403
