import asyncio
import os
import sys
import uuid

import httpx
from mcp import Client, StdioServerParameters


async def main() -> None:
    issuer = os.environ["LEARNING_IDP_URL"].rstrip("/")
    gateway = os.environ["LEARNING_GATEWAY_URL"]
    async with httpx.AsyncClient(timeout=5, trust_env=False) as http:
        user_response = await http.post(
            issuer + "/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "learning-client",
                "username": "learner-red-1",
                "password": os.environ["LEARNING_DEMO_PASSWORD"],
            },
        )
        assert user_response.status_code == 200, "Keycloak user issuance failed"
        user_token = user_response.json()["access_token"]
        assert user_response.json()["expires_in"] <= 120
        workload_response = await http.post(
            issuer + "/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "agent-adapter",
                "client_secret": os.environ["LEARNING_AGENT_SECRET"],
            },
        )
        assert workload_response.status_code == 200, "Keycloak workload issuance failed"
        workload_token = workload_response.json()["access_token"]
        assert workload_response.json()["expires_in"] <= 120
        headers = {
            "Authorization": "Bearer " + user_token,
            "X-Workload-Authorization": "Bearer " + workload_token,
        }
        context = await http.get(gateway + "/v1/delegated/context", headers=headers)
        assert context.status_code == 200, "Gateway rejected real Keycloak context"
        assert context.json() == {
            "subject": "learner-red-1",
            "tenant_id": "tenant-red",
            "type": "human",
        }
        result = await http.get(
            gateway + "/v1/learners/learner-red-1/progress", headers=headers
        )
        assert result.status_code == 200, "Valid user progress rejected"
        for changed, expected in [
            ({**headers, "X-Tenant-ID": "tenant-blue"}, 400),
            ({**headers, "X-User-ID": "learner-blue-1"}, 400),
            (
                {
                    "Authorization": "Bearer " + workload_token,
                    "X-Workload-Authorization": "Bearer " + user_token,
                },
                401,
            ),
            ({"X-Workload-Authorization": "Bearer " + workload_token}, 401),
            ({"Authorization": "Bearer " + user_token}, 401),
            ({**headers, "Authorization": "Bearer " + user_token[:-8] + "invalidX"}, 401),
        ]:
            denied = await http.get(gateway + "/v1/delegated/context", headers=changed)
            assert denied.status_code == expected
            assert user_token not in denied.text and workload_token not in denied.text
        foreign = await http.post(
            gateway + "/v1/delegated/tools/progress.read",
            headers=headers,
            json={"args": {"learner_id": "learner-blue-1"}},
        )
        assert foreign.status_code == 404 and "completion_percent" not in foreign.text
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "app.identity.relay"],
            env={
                "LEARNING_GATEWAY_URL": gateway,
                "LEARNING_USER_TOKEN": user_token,
                "LEARNING_WORKLOAD_TOKEN": workload_token,
                "PYTHONPATH": "/app/mcp:/app",
            },
        )
        async with Client(params, read_timeout_seconds=5) as client:
            tools = (await client.list_tools()).tools
            assert {tool.name for tool in tools} == {
                "content.search",
                "progress.read",
                "assessment.create",
                "evidence.record",
            }
            for action, args in [
                ("content.search", {"query": "network"}),
                ("progress.read", {"learner_id": "learner-red-1"}),
                (
                    "assessment.create",
                    {"course_id": "course-red", "idempotency_key": uuid.uuid4().hex},
                ),
                (
                    "evidence.record",
                    {
                        "course_id": "course-red",
                        "kind": "content_read",
                        "idempotency_key": uuid.uuid4().hex,
                    },
                ),
            ]:
                result = await client.call_tool(action, {"args": args})
                assert not result.is_error, action
                if action in {"assessment.create", "evidence.record"}:
                    retry = await client.call_tool(action, {"args": args})
                    assert (
                        not retry.is_error
                        and retry.structured_content == result.structured_content
                    )
            denied = await client.call_tool(
                "progress.read", {"args": {"learner_id": "learner-blue-1"}}
            )
            assert denied.is_error
            assert "completion_percent" not in denied.model_dump_json()
            assert (
                user_token not in denied.model_dump_json()
                and workload_token not in denied.model_dump_json()
            )
    print(
        "Real Keycloak + gateway + MCP: short-lived user/workload issuance, "
        "identity separation, spoof/signature denial, four tools, foreign denial "
        "and duplicate writes passed"
    )


if __name__ == "__main__":
    asyncio.run(main())
