"""
Health check and root route automated tests.
"""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """Verify that root endpoint returns lab metadata and available routes."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["lab"] == "IDOR Security Research Lab"
    assert "endpoints" in data


def test_health_check_endpoint(client: TestClient) -> None:
    """Verify application health check returns healthy status and Phase 1 tag."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "IDOR Security Research Lab"
    assert "Phase 1" in data["phase"]
    assert data["version"] == "0.1.0"
