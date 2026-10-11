import asyncio
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.errors import ServiceError
from app.identity.tokens import USER_SUBJECTS, WORKLOAD_SUBJECT, IdentitySettings, TokenVerifier


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def claims(**changes):
    now = int(time.time())
    return {
        "iss": "http://issuer/realms/learning",
        "aud": "learning-gateway",
        "iat": now,
        "exp": now + 120,
        "sub": next(iter(USER_SUBJECTS)),
        "jti": "test-token",
        "azp": "learning-client",
        "typ": "Bearer",
        "scope": "progress.read evidence.record",
        **changes,
    }


def token(key, **changes):
    return jwt.encode(claims(**changes), key, algorithm="RS256", headers={"kid": "fixture"})


def verifier(key):
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    public.update({"kid": "fixture", "alg": "RS256", "use": "sig"})
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"keys": [public]})
    )
    return TokenVerifier(
        IdentitySettings(
            issuer="http://issuer/realms/learning", jwks_url="http://issuer/certs"
        ),
        transport,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "wrong"},
        {"iss": "http://wrong"},
        {"exp": 1},
        {"sub": None},
        {"sub": ""},
        {"sub": "unknown-tenant-user"},
        {"azp": "agent-adapter"},
        {"typ": "ID"},
        {"scope": ""},
        {"jti": None},
        {"exp": int(time.time()) + 600},
    ],
)
def test_invalid_claims_rejected(signing_key, changes):
    async def scenario():
        client = verifier(signing_key)
        encoded = token(signing_key, **changes)
        with pytest.raises(ServiceError) as error:
            await client.user(encoded)
        assert error.value.status_code == 401
        assert encoded not in error.value.message
        await client.close()

    asyncio.run(scenario())


def test_missing_subject_and_signature_rejected(signing_key):
    async def scenario():
        client = verifier(signing_key)
        values = claims()
        values.pop("sub")
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for encoded in [
            jwt.encode(values, signing_key, algorithm="RS256", headers={"kid": "fixture"}),
            token(other),
        ]:
            with pytest.raises(ServiceError):
                await client.user(encoded)
        await client.close()

    asyncio.run(scenario())


def test_user_and_workload_are_distinct(signing_key):
    async def scenario():
        client = verifier(signing_key)
        user_token = token(signing_key)
        workload_token = token(
            signing_key,
            aud="learning-gateway-workload",
            sub=WORKLOAD_SUBJECT,
            azp="agent-adapter",
            scope="tools.invoke",
        )
        user = await client.user(user_token)
        workload = await client.workload(workload_token)
        assert user.principal.subject == "learner-red-1"
        assert workload.client == "agent-adapter"
        with pytest.raises(ServiceError):
            await client.user(workload_token)
        with pytest.raises(ServiceError):
            await client.workload(user_token)
        await client.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["unavailable", "oversized", "unknown-key", "malformed"])
def test_untrusted_jwks_fails_closed(signing_key, failure):
    async def scenario():
        def response(request):
            if failure == "unavailable":
                raise httpx.ConnectError("Unavailable", request=request)
            if failure == "oversized":
                return httpx.Response(200, content=b" " * 32769)
            if failure == "unknown-key":
                return httpx.Response(200, json={"keys": []})
            return httpx.Response(200, content=b"not-json")

        client = TokenVerifier(
            IdentitySettings(
                issuer="http://issuer/realms/learning", jwks_url="http://issuer/certs"
            ),
            httpx.MockTransport(response),
        )
        with pytest.raises(ServiceError) as error:
            await client.user(token(signing_key))
        assert error.value.status_code == 401
        await client.close()

    asyncio.run(scenario())
