import asyncio
import json
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from pydantic import ValidationError

from app.auth.demo import require_principal
from app.authz.contracts import CanonicalAction
from app.domain import Principal
from app.errors import ServiceError
from app.identity.tokens import IdentitySettings, TokenVerifier, UserAuthority, WorkloadIdentity
from app.isolation.main import create_app as isolation_app
from learning_tools.contracts import (
    SCHEMAS,
    AssessmentArguments,
    EvidenceArguments,
    ProgressArguments,
    SearchArguments,
)
from learning_tools.repository import ToolRepository
from learning_tools.services import LearningToolsService, PolicyClient

FORGED_HEADERS = frozenset(
    {
        "x-user-id",
        "x-tenant-id",
        "x-principal",
        "x-role",
        "x-owner-id",
        "x-workload-id",
        "x-forwarded-user",
        "x-forwarded-tenant",
        "x-authenticated-user",
    }
)


def bearer(value: str | None) -> str:
    scheme, separator, token = (value or "").partition(" ")
    if not separator or scheme.lower() != "bearer" or " " in token:
        raise ServiceError(401, "unauthenticated", "Valid authentication is required")
    return token


class DelegatedLearningService(LearningToolsService):
    def __init__(
        self,
        repository: ToolRepository,
        policy: PolicyClient,
        authority: UserAuthority,
        workload: WorkloadIdentity,
    ) -> None:
        super().__init__(repository, policy)
        self.authority = authority
        self.workload = workload

    async def authorize(self, principal: Principal, action: CanonicalAction) -> None:
        if principal != self.authority.principal or action not in self.authority.scopes:
            raise ServiceError(403, "insufficient_scope", "Delegated action is not permitted")
        await super().authorize(principal, action)
        if time.time() >= min(self.authority.expires_at, self.workload.expires_at):
            raise ServiceError(401, "unauthenticated", "Delegated authentication expired")


def create_app(
    repository: ToolRepository | None = None,
    verifier: TokenVerifier | None = None,
    policy: PolicyClient | None = None,
    transport: httpx.BaseTransport | None = None,
    service_factory: type[DelegatedLearningService] = DelegatedLearningService,
) -> FastAPI:
    records = repository or ToolRepository()
    identity = verifier or TokenVerifier(IdentitySettings.from_environment())
    decisions = policy or PolicyClient(os.getenv("OPA_URL", "http://opa:8181"))
    application = isolation_app(repository=records, transport=transport)

    async def authenticated_user(request: Request) -> UserAuthority:
        if any(header in request.headers for header in FORGED_HEADERS):
            raise ServiceError(
                400, "untrusted_identity_header", "Identity headers are not accepted"
            )
        authority = await identity.user(bearer(request.headers.get("authorization")))
        if (
            records.get_learner_metadata(
                authority.principal.tenant_id, authority.principal.subject
            )
            is None
        ):
            raise ServiceError(403, "membership_required", "Current membership is required")
        return authority

    async def api_principal(request: Request) -> Principal:
        authority = await authenticated_user(request)
        action = "content.search" if request.url.path == "/v1/content" else "progress.read"
        if action not in authority.scopes:
            raise ServiceError(403, "insufficient_scope", "Action is not permitted")
        return authority.principal

    async def delegated_context(request: Request) -> tuple[UserAuthority, WorkloadIdentity]:
        authority = await authenticated_user(request)
        workload = await identity.workload(
            bearer(request.headers.get("x-workload-authorization"))
        )
        return authority, workload

    application.dependency_overrides[require_principal] = api_principal

    @application.get("/v1/delegated/context")
    async def context(request: Request) -> Principal:
        authority, _ = await delegated_context(request)
        return authority.principal

    @application.post("/v1/delegated/tools/{action}")
    async def call_tool(action: str, request: Request) -> dict[str, object]:
        authority, workload = await delegated_context(request)
        if action not in SCHEMAS:
            raise ServiceError(404, "unknown_tool", "Tool not found")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 1024:
                raise ServiceError(422, "invalid_arguments", "Invalid tool arguments")
        try:
            values = json.loads(body)
            if not isinstance(values, dict) or set(values) != {"args"}:
                raise ValueError("Invalid arguments")
            args = SCHEMAS[action].model_validate(values["args"])
        except (ValueError, TypeError, ValidationError):
            raise ServiceError(422, "invalid_arguments", "Invalid tool arguments") from None
        service = service_factory(records, decisions, authority, workload)
        deadline = time.monotonic() + 2
        try:
            async with asyncio.timeout(2):
                if isinstance(args, SearchArguments):
                    result = await service.search(authority.principal, args)
                elif isinstance(args, ProgressArguments):
                    result = await service.progress(authority.principal, args.learner_id)
                elif isinstance(args, AssessmentArguments):
                    result = await service.create_assessment(
                        authority.principal, args, deadline
                    )
                elif isinstance(args, EvidenceArguments):
                    result = await service.record_evidence(authority.principal, args, deadline)
                else:
                    raise ServiceError(422, "invalid_arguments", "Invalid tool arguments")
            if len(json.dumps(result).encode()) > 4096:
                raise ServiceError(502, "output_limit_exceeded", "Output unavailable")
            return result
        except TimeoutError:
            raise ServiceError(504, "service_timeout", "Service deadline exceeded") from None

    previous_lifespan = application.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            async with previous_lifespan(app):
                yield
        finally:
            await identity.close()
            await decisions.close()

    application.router.lifespan_context = lifespan
    application.title = "PRD 05 Identity and Delegated Learning Gateway"
    return application
