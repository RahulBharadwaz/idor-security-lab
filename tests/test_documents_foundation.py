"""
Tests for document resource endpoints and baseline authorization in Phase 1.

Validates:
1. Endpoints require authentication (unauthenticated calls return 401).
2. Users can list their own documents (/documents/me returns only their resources).
3. Users can read their own documents by ID (/documents/{id}).
4. Non-existent documents return 404 Not Found.
5. Baseline object-level authorization is enforced on the protected endpoint
   (requesting another user's document returns 403 Forbidden).
"""

from fastapi.testclient import TestClient


def test_list_documents_unauthenticated_returns_401(client: TestClient) -> None:
    """Accessing document list without credentials must be rejected."""
    response = client.get("/documents/me")
    assert response.status_code == 401


def test_list_documents_alice_returns_only_alice_docs(
    client: TestClient, alice_headers: dict
) -> None:
    """Alice should only see documents she owns."""
    response = client.get("/documents/me", headers=alice_headers)
    assert response.status_code == 200
    docs = response.json()
    assert len(docs) == 2
    for doc in docs:
        assert doc["owner_id"] == "user_alice_01"
    doc_ids = {doc["id"] for doc in docs}
    assert doc_ids == {"doc-alice-101", "doc-alice-102"}


def test_list_documents_bob_returns_only_bob_docs(
    client: TestClient, bob_headers: dict
) -> None:
    """Bob should only see documents he owns."""
    response = client.get("/documents/me", headers=bob_headers)
    assert response.status_code == 200
    docs = response.json()
    assert len(docs) == 2
    for doc in docs:
        assert doc["owner_id"] == "user_bob_02"
    doc_ids = {doc["id"] for doc in docs}
    assert doc_ids == {"doc-bob-201", "doc-bob-202"}


def test_get_own_document_alice_succeeds(
    client: TestClient, alice_headers: dict
) -> None:
    """Alice can successfully access her own document by ID."""
    response = client.get("/documents/doc-alice-101", headers=alice_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "doc-alice-101"
    assert data["owner_id"] == "user_alice_01"
    assert "Alice - Q3 Vulnerability Research Strategy" in data["title"]


def test_get_own_document_bob_succeeds(
    client: TestClient, bob_headers: dict
) -> None:
    """Bob can successfully access his own document by ID."""
    response = client.get("/documents/doc-bob-201", headers=bob_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "doc-bob-201"
    assert data["owner_id"] == "user_bob_02"
    assert "Bob - CI/CD Pipeline Hardening Audit" in data["title"]


def test_get_nonexistent_document_returns_404(
    client: TestClient, alice_headers: dict
) -> None:
    """Requesting an ID that does not exist returns 404."""
    response = client.get("/documents/doc-nonexistent-999", headers=alice_headers)
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_baseline_authorization_alice_cannot_access_bob_document(
    client: TestClient, alice_headers: dict
) -> None:
    """
    BASELINE AUTHORIZATION CHECK:
    Alice is authenticated (who she is is established), but she is NOT authorized
    to view Bob's document 'doc-bob-201'. The protected endpoint must return 403 Forbidden.
    """
    response = client.get("/documents/doc-bob-201", headers=alice_headers)
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]


def test_baseline_authorization_bob_cannot_access_alice_document(
    client: TestClient, bob_headers: dict
) -> None:
    """
    BASELINE AUTHORIZATION CHECK:
    Bob is authenticated, but is NOT authorized to view Alice's document 'doc-alice-101'.
    The protected endpoint must return 403 Forbidden.
    """
    response = client.get("/documents/doc-alice-101", headers=bob_headers)
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]
