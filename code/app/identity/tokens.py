import os
from dataclasses import dataclass
from typing import Any, Literal

import httpx
import jwt
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, ValidationError

from app.domain import Principal
from app.errors import ServiceError
from app.repositories.memory import demo_principals

USER_SUBJECTS = {
    "a1000000-0000-4000-8000-000000000001": "learner-red-1",
    "a1000000-0000-4000-8000-000000000002": "learner-red-2",
    "b1000000-0000-4000-8000-000000000001": "learner-blue-1",
}
WORKLOAD_SUBJECT = "c1000000-0000-4000-8000-000000000001"


class IdentitySettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    issuer: AnyHttpUrl
    jwks_url: AnyHttpUrl
    user_audience: Literal["learning-gateway"] = "learning-gateway"
    workload_audience: Literal["learning-gateway-workload"] = "learning-gateway-workload"

    @classmethod
    def from_environment(cls) -> "IdentitySettings":
        return cls.model_validate(
            {
                "issuer": os.getenv("LEARNING_ISSUER", "http://localhost:8425/realms/learning"),
                "jwks_url": os.getenv(
                    "LEARNING_JWKS_URL",
                    "http://keycloak:8080/realms/learning/protocol/openid-connect/certs",
                ),
            }
        )


class Claims(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)
    sub: str = Field(min_length=1, max_length=128)
    iss: str
    exp: int
    iat: int
    jti: str = Field(min_length=1, max_length=128)
    azp: str
    typ: Literal["Bearer"]
    scope: str = Field(min_length=1, max_length=512)


@dataclass(frozen=True)
class UserAuthority:
    principal: Principal
    scopes: frozenset[str]
    expires_at: int


@dataclass(frozen=True)
class WorkloadIdentity:
    subject: str
    client: str
    expires_at: int


class TokenVerifier:
    def __init__(
        self, settings: IdentitySettings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.client = httpx.AsyncClient(timeout=0.5, trust_env=False, transport=transport)

    async def claims(self, token: str, audience: str) -> Claims:
        try:
            if not 16 <= len(token) <= 8192 or not token.isascii():
                raise ValueError("Invalid token")
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                raise ValueError("Invalid token")
            if not 1 <= len(header["kid"]) <= 128:
                raise ValueError("Invalid token")
            async with self.client.stream("GET", str(self.settings.jwks_url)) as response:
                response.raise_for_status()
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    payload.extend(chunk)
                    if len(payload) > 32768:
                        raise ValueError("Invalid key set")
            keys = jwt.PyJWKSet.from_json(bytes(payload).decode()).keys
            matching = [
                key
                for key in keys
                if key.key_id == header["kid"] and key.algorithm_name == "RS256"
            ]
            if len(matching) != 1:
                raise ValueError("Invalid signing key")
            decoded: dict[str, Any] = jwt.decode(
                token,
                matching[0].key,
                algorithms=["RS256"],
                issuer=str(self.settings.issuer).rstrip("/"),
                audience=audience,
                leeway=0,
                options={
                    "require": ["iss", "aud", "exp", "iat", "sub", "jti", "azp", "typ", "scope"]
                },
            )
            claims = Claims.model_validate(decoded)
            if not 0 < claims.exp - claims.iat <= 300:
                raise ValueError("Token lifetime exceeds delegation limit")
            return claims
        except (jwt.PyJWTError, httpx.HTTPError, ValueError, TypeError, ValidationError):
            raise ServiceError(
                401, "unauthenticated", "Valid authentication is required"
            ) from None

    async def user(self, token: str) -> UserAuthority:
        claims = await self.claims(token, self.settings.user_audience)
        subject = USER_SUBJECTS.get(claims.sub)
        if claims.azp != "learning-client" or subject is None:
            raise ServiceError(401, "unauthenticated", "Valid authentication is required")
        return UserAuthority(
            demo_principals()[subject], frozenset(claims.scope.split()), claims.exp
        )

    async def workload(self, token: str) -> WorkloadIdentity:
        claims = await self.claims(token, self.settings.workload_audience)
        if (
            claims.sub != WORKLOAD_SUBJECT
            or claims.azp != "agent-adapter"
            or "tools.invoke" not in claims.scope.split()
        ):
            raise ServiceError(
                401, "unauthenticated", "Valid workload authentication is required"
            )
        return WorkloadIdentity(claims.sub, claims.azp, claims.exp)

    async def close(self) -> None:
        await self.client.aclose()
