"""Full backend-federation smoke test against the deployed proxy.

The `federated-test` bucket (see examples/cf-workers/wrangler.deploy.toml) is
configured with `auth_type=oidc`: at request time the proxy mints its own OIDC
assertion (`iss` = OIDC_PROVIDER_ISSUER, the *stable staging* issuer) and
assumes an AWS IAM role via `AssumeRoleWithWebIdentity`, then signs the backend
read with the temporary credentials. A successful anonymous GET through the
proxy therefore exercises the whole outbound path end to end:

    mint JWT -> AssumeRoleWithWebIdentity at real AWS STS -> SigV4 GET of a
    private bucket -> stream back to the caller.

It runs on every preview (PR) and staging deploy via the shared smoke-test job.
PR previews reuse the staging issuer (see preview.yml / staging.yml), so AWS
validates against one already-registered IAM OIDC provider — no per-PR provider
or role is created.

There is intentionally no skip path: if federation is not wired up (issuer
unset, provider/role/trust misconfigured, or the placeholder bucket config not
replaced), the GET fails and so does this test — the real path is never silently
reported as green.

Env:
  DEPLOY_URL: deployed proxy URL (set by the smoke-test job)
  FEDERATION_TEST_KEY: object key in the private bucket to GET (default hello.txt)
"""

import os

import requests

DEPLOY_URL = os.environ.get("DEPLOY_URL", "http://localhost:8787").rstrip("/")
FEDERATION_BUCKET = "federated-test"
FEDERATION_TEST_KEY = os.environ.get("FEDERATION_TEST_KEY", "hello.txt")


def test_federation_serves_private_object():
    """Anonymous GET of the federated bucket must return the private object,
    proving the proxy assumed the backend role to read it."""
    url = f"{DEPLOY_URL}/{FEDERATION_BUCKET}/{FEDERATION_TEST_KEY}"
    resp = requests.get(url, timeout=30)

    assert resp.status_code == 200, (
        f"expected 200 from federated GET {url}, got {resp.status_code}: "
        f"{resp.text[:500]}\n"
        "The proxy failed to assume the backend role. Check that:\n"
        "  - the STAGING_OIDC_ISSUER repo variable is set and the AWS IAM OIDC "
        "provider is registered for it (audience sts.amazonaws.com),\n"
        "  - the role's trust policy allows sub=`multistore` and grants "
        "s3:GetObject on the bucket, and\n"
        "  - the federated-test bucket in wrangler.deploy.toml points at your "
        "real role ARN + private bucket."
    )
    assert resp.content, "federated object was empty"
