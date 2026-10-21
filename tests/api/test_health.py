"""Unit tests for the health check API endpoint.
"""
from fastapi.testclient import TestClient


def test_health_check_returns_ok(test_client: TestClient):
    """Ensure GET /api/v1/health returns status 200 and expected payload."""
    response = test_client.get("/api/v1/health")
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "ok"
    assert "app_name" in payload
    assert "version" in payload
    assert "environment" in payload
    assert "timestamp" in payload


def test_docs_accessible(test_client: TestClient):
    """Ensure OpenAPI docs are accessible."""
    response = test_client.get("/docs")
    assert response.status_code == 200
