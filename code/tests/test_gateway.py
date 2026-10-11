import json
import time

import httpx
from fastapi.testclient import TestClient
from test_tokens import WORKLOAD_SUBJECT, token, verifier
from test_tokens import signing_key as signing_key

from app.identity.main import create_app
from learning_tools.repository import ToolRepository
from learning_tools.services import PolicyClient


def policy_response(request):
    action = json.loads(request.content)["input"]["action"]
    return httpx.Response(
        200,
        json={
            "result": {
                "allow": True,
                "reason_code": "TENANT_APPROVED_CONTENT"
                if action == "content.search"
                else "OWNER_AND_TENANT_MATCH",
                "policy_version": "1.1.0"
                if action in {"assessment.create", "evidence.record"}
                else "1.0.0",
            }
        },
    )


def gateway(key):
    repository = ToolRepository()
    policy = PolicyClient("http://opa", httpx.MockTransport(policy_response))
    application = create_app(
        repository, verifier(key), policy, httpx.MockTransport(policy_response)
    )
    return repository, application


def headers(key, scope="progress.read evidence.record assessment.create content.search"):
    return {
        "Authorization": "Bearer " + token(key, scope=scope),
        "X-Workload-Authorization": "Bearer "
        + token(
            key,
            aud="learning-gateway-workload",
            sub=WORKLOAD_SUBJECT,
            azp="agent-adapter",
            scope="tools.invoke",
        ),
    }


def test_gateway_scope_headers_workload_and_foreign_targets(signing_key, caplog):
    repository, application = gateway(signing_key)
    auth = headers(signing_key)
    body = {
        "args": {"course_id": "course-red", "kind": "content_read", "idempotency_key": "one"}
    }
    with TestClient(application) as client:
        assert (
            client.post(
                "/v1/delegated/tools/evidence.record", headers=auth, json=body
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/v1/delegated/tools/evidence.record", headers=auth, json=body
            ).status_code
            == 200
        )
        assert repository.evidence_count() == 1
        for changed, code in [
            ({**auth, "X-Tenant-ID": "tenant-blue"}, 400),
            ({**auth, "X-User-ID": "learner-blue-1"}, 400),
            ({"X-Workload-Authorization": auth["X-Workload-Authorization"]}, 401),
            ({"Authorization": auth["Authorization"]}, 401),
            (headers(signing_key, scope="progress.read"), 403),
        ]:
            assert (
                client.post(
                    "/v1/delegated/tools/evidence.record", headers=changed, json=body
                ).status_code
                == code
            )
        assert (
            client.post(
                "/v1/delegated/tools/progress.read",
                headers=auth,
                json={"args": {"learner_id": "learner-blue-1"}},
            ).status_code
            == 404
        )
        assert (
            client.get("/v1/learners/learner-red-1/progress", headers=auth).status_code == 200
        )
        assert (
            client.get(
                "/v1/learners/learner-red-1/progress",
                headers={"Authorization": "Bearer demo-learner-red"},
            ).status_code
            == 401
        )
        assert repository.evidence_count() == 1
        assert all(value not in caplog.text for value in auth.values())


def test_membership_revoked_between_steps(signing_key):
    repository, application = gateway(signing_key)
    auth = headers(signing_key)
    with TestClient(application) as client:
        result = client.post(
            "/v1/delegated/tools/progress.read",
            headers=auth,
            json={"args": {"learner_id": "learner-red-1"}},
        )
        assert result.status_code == 200
        repository.revoke_membership("tenant-red", "learner-red-1")
        result = client.post(
            "/v1/delegated/tools/evidence.record",
            headers=auth,
            json={
                "args": {
                    "course_id": "course-red",
                    "kind": "content_read",
                    "idempotency_key": "after-revoke",
                }
            },
        )
        assert result.status_code == 403
        assert repository.evidence_count() == repository.write_count() == 0
        assert "completion_percent" not in result.text


def test_signed_tenant_claim_is_not_authority(signing_key):
    _, application = gateway(signing_key)
    auth = headers(signing_key)
    auth["Authorization"] = "Bearer " + token(signing_key, tenant_id="unknown-tenant")
    with TestClient(application) as client:
        result = client.get("/v1/delegated/context", headers=auth)
        assert result.status_code == 200
        assert result.json()["tenant_id"] == "tenant-red"


def test_valid_workload_for_unauthorized_user_has_no_effect(signing_key):
    repository, application = gateway(signing_key)
    auth = headers(signing_key)
    auth["Authorization"] = "Bearer " + token(
        signing_key, sub="b1000000-0000-4000-8000-000000000001"
    )
    with TestClient(application) as client:
        response = client.post(
            "/v1/delegated/tools/evidence.record",
            headers=auth,
            json={
                "args": {
                    "course_id": "course-red",
                    "kind": "content_read",
                    "idempotency_key": "foreign",
                }
            },
        )
        assert response.status_code == 404
        auth["Authorization"] = "Bearer " + token(signing_key, sub="unknown-tenant-user")
        assert client.get("/v1/delegated/context", headers=auth).status_code == 401
        assert repository.write_count() == repository.evidence_count() == 0


def test_expiry_during_policy_lookup_has_no_effect(signing_key, monkeypatch):
    repository = ToolRepository()
    future = time.time() + 301

    def expire_during_policy(request):
        monkeypatch.setattr("app.identity.main.time.time", lambda: future)
        return policy_response(request)

    application = create_app(
        repository,
        verifier(signing_key),
        PolicyClient("http://opa", httpx.MockTransport(expire_during_policy)),
        httpx.MockTransport(policy_response),
    )
    auth = headers(signing_key)
    with TestClient(application) as client:
        response = client.post(
            "/v1/delegated/tools/evidence.record",
            headers=auth,
            json={
                "args": {
                    "course_id": "course-red",
                    "kind": "content_read",
                    "idempotency_key": "expired",
                }
            },
        )
        assert response.status_code == 401
        assert repository.write_count() == repository.evidence_count() == 0
