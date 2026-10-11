import asyncio
import json
import logging
import os

import httpx

from app.domain import Principal
from app.errors import ServiceError
from learning_tools.contracts import AssessmentArguments, EvidenceArguments, SearchArguments
from learning_tools.server import create_server
from learning_tools.services import LearningToolsService


class GatewayRelay(LearningToolsService):
    def __init__(self, url: str, user_token: str, workload_token: str) -> None:
        if not user_token or not workload_token:
            raise ValueError("Both configured delegation credentials are required")
        self.client = httpx.AsyncClient(
            base_url=url,
            timeout=1.5,
            trust_env=False,
            headers={
                "Authorization": "Bearer " + user_token,
                "X-Workload-Authorization": "Bearer " + workload_token,
            },
        )

    async def principal(self) -> Principal:
        response = await self.client.get("/v1/delegated/context")
        if response.status_code != 200:
            raise ValueError("Delegated context unavailable")
        return Principal.model_validate_json(response.content)

    async def invoke(self, action: str, args: dict[str, object]) -> dict[str, object]:
        try:
            async with self.client.stream(
                "POST", "/v1/delegated/tools/" + action, json={"args": args}
            ) as response:
                if response.status_code != 200:
                    raise ServiceError(403, "delegation_denied", "Delegated operation denied")
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    payload.extend(chunk)
                    if len(payload) > 4096:
                        raise ServiceError(502, "output_limit_exceeded", "Output unavailable")
            value = json.loads(payload)
            if not isinstance(value, dict):
                raise ValueError("Invalid result")
            result: dict[str, object] = value
            return result
        except (httpx.HTTPError, ValueError):
            raise ServiceError(
                503, "gateway_unavailable", "Delegated service unavailable"
            ) from None

    async def search(self, principal: Principal, args: SearchArguments) -> dict[str, object]:
        return await self.invoke("content.search", args.model_dump())

    async def progress(self, principal: Principal, learner_id: str) -> dict[str, object]:
        return await self.invoke("progress.read", {"learner_id": learner_id})

    async def create_assessment(
        self, principal: Principal, args: AssessmentArguments, deadline: float
    ) -> dict[str, object]:
        return await self.invoke("assessment.create", args.model_dump())

    async def record_evidence(
        self, principal: Principal, args: EvidenceArguments, deadline: float
    ) -> dict[str, object]:
        return await self.invoke("evidence.record", args.model_dump())


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    relay = GatewayRelay(
        os.getenv("LEARNING_GATEWAY_URL", "http://gateway:8000"),
        os.getenv("LEARNING_USER_TOKEN", ""),
        os.getenv("LEARNING_WORKLOAD_TOKEN", ""),
    )
    try:
        principal = await relay.principal()
        await create_server(relay, principal).run_stdio_async()
    finally:
        await relay.client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
