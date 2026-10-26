"""
Authentication mechanism automated tests.

Validates that:
1. Missing authentication credentials return HTTP 401 Unauthorized.
2. Invalid tokens return HTTP 401 Unauthorized.
3. Valid tokens for Alice and Bob correctly resolve to their respective user identities.
4. Both X-Lab-Token and Authorization Bearer headers are supported.
"""

from fastapi.testclient import TestClient


def test_auth_me_missing_token_returns_401(client: TestClient) -> None:
    """Requests to protected endpoints without tokens must be rejected."""
    response = client.get("/auth/me")
    assert response.status_code == 401
    assert "detail" in response.json()


def test_auth_me_invalid_token_returns_401(client: TestClient) -> None:
    """Requests with unrecognized tokens must be rejected."""
    headers = {"X-Lab-Token": "invalid-token-xyz-9999"}
    response = client.get("/auth/me", headers=headers)
    assert response.status_code == 401
    assert "Authentication failed" in response.json()["detail"]


def test_auth_me_alice_token_succeeds(
    client: TestClient, alice_headers: dict
) -> None:
    """Valid Alice token resolves to Alice's profile."""
    response = client.get("/auth/me", headers=alice_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "user_alice_01"
    assert data["username"] == "alice"
    assert data["role"] == "Security Research Intern"
    assert data["department"] == "Product Security"


def test_auth_me_bob_token_succeeds(
    client: TestClient, bob_headers: dict
) -> None:
    """Valid Bob token resolves to Bob's profile."""
    response = client.get("/auth/me", headers=bob_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "user_bob_02"
    assert data["username"] == "bob"
    assert data["role"] == "DevOps Engineer"
    assert data["department"] == "Cloud Infrastructure"


def test_auth_me_bearer_header_succeeds(
    client: TestClient, alice_bearer_headers: dict
) -> None:
    """Authorization header with Bearer token is supported."""
    response = client.get("/auth/me", headers=alice_bearer_headers)
    assert response.status_code == 200
    assert response.json()["id"] == "user_alice_01"
