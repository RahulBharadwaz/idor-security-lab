"""
Phase 3 — Automated IDOR / BOLA Proof-of-Concept Tests.

EDUCATIONAL & LOCAL ONLY:
=========================
These tests demonstrate the Insecure Direct Object Reference (IDOR) vulnerability
using the intentionally insecure endpoint at /documents/vulnerable/{document_id}.

The vulnerable endpoint authenticates the caller but deliberately omits the
object-level authorization check (document.owner_id == current_user.id). This
allows any authenticated user to read any document by supplying its ID.

These tests use only synthetic lab data (Alice, Bob, and fictional documents).
No real users, credentials, or external services are involved.

Test Summary:
    Test A: Alice legitimately accesses her own document via the vulnerable route.
    Test B: Alice accesses Bob's confidential document via the vulnerable route (IDOR).
    Test C: The existing secure endpoint still rejects Alice's cross-tenant request.
    Test D: Unauthenticated requests to the vulnerable endpoint are rejected.
    Test E: Authenticated requests for nonexistent documents return 404.
"""

from fastapi.testclient import TestClient


# ==========================================================================
# Test A: Legitimate access still works through the vulnerable endpoint
# ==========================================================================

def test_vulnerable_endpoint_alice_accesses_own_document(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Alice requests her own document through the vulnerable endpoint.

    Even though the endpoint lacks an authorization check, accessing your own
    document is still a legitimate operation. This test confirms the endpoint
    functions correctly for the happy path.

    Expected: HTTP 200 with Alice's document data.
    """
    response = client.get(
        "/documents/vulnerable/doc-alice-101", headers=alice_headers
    )
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == "doc-alice-101"
    assert data["owner_id"] == "user_alice_01"
    assert "Alice - Q3 Vulnerability Research Strategy" in data["title"]
    assert data["is_confidential"] is True


# ==========================================================================
# Test B: IDOR / BOLA — Alice reads Bob's confidential document
# ==========================================================================

def test_vulnerable_endpoint_alice_reads_bob_confidential_document(
    client: TestClient, alice_headers: dict
) -> None:
    """
    IDOR PROOF-OF-CONCEPT — INTENTIONALLY VULNERABLE DEMONSTRATION.

    Alice is authenticated with her own valid lab token. She requests Bob's
    confidential performance review (doc-bob-202) through the vulnerable
    endpoint. Because the endpoint does not check document.owner_id against
    current_user.id, the server returns Bob's private data to Alice.

    This is the core demonstration of Broken Object Level Authorization:
    - Authentication PASSED (the server knows the caller is Alice).
    - Authorization SKIPPED (the server never checked if Alice owns doc-bob-202).

    Expected: HTTP 200 with Bob's document, proving the data leak.
    """
    response = client.get(
        "/documents/vulnerable/doc-bob-202", headers=alice_headers
    )

    # The vulnerable endpoint returns 200 instead of 403 — this IS the flaw.
    assert response.status_code == 200

    data = response.json()
    # Verify that Alice received Bob's document, not her own.
    assert data["id"] == "doc-bob-202"
    assert data["owner_id"] == "user_bob_02"  # Bob owns this, not Alice!
    assert "Bob - Performance Review & Compensation Summary" in data["title"]
    assert "Restricted HR Evaluation" in data["category"]
    # Alice can now read Bob's confidential performance review content.
    assert "performance review scores" in data["content"].lower()
    assert data["is_confidential"] is True


# ==========================================================================
# Test C: The secure baseline endpoint still protects Bob's document
# ==========================================================================

def test_secure_endpoint_still_blocks_cross_tenant_access(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Confirms that the EXISTING secure endpoint (/documents/{document_id})
    correctly rejects Alice's attempt to access Bob's document.

    This test exists to prove that the secure endpoint was NOT weakened by
    adding the vulnerable endpoint. The authorization check at
    app/routers/documents.py (document.owner_id != current_user.id) remains
    intact and functional.

    Expected: HTTP 403 Forbidden.
    """
    response = client.get(
        "/documents/doc-bob-202", headers=alice_headers
    )

    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]


# ==========================================================================
# Test D: Unauthenticated requests to the vulnerable endpoint are rejected
# ==========================================================================

def test_vulnerable_endpoint_requires_authentication(
    client: TestClient,
) -> None:
    """
    Even the intentionally vulnerable endpoint requires authentication.

    The IDOR flaw is about missing AUTHORIZATION, not missing AUTHENTICATION.
    A caller who provides no token at all should still receive HTTP 401.

    This test proves that authentication and authorization are separate
    responsibilities: the vulnerable endpoint enforces one but not the other.

    Expected: HTTP 401 Unauthorized.
    """
    response = client.get("/documents/vulnerable/doc-bob-202")

    assert response.status_code == 401
    assert "detail" in response.json()


# ==========================================================================
# Test E: Nonexistent resources return 404 through the vulnerable endpoint
# ==========================================================================

def test_vulnerable_endpoint_nonexistent_document_returns_404(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Requesting a document ID that does not exist in the datastore should
    return 404 Not Found, even on the vulnerable endpoint.

    The IDOR flaw only applies when a real document exists and belongs to
    another user. If the document simply does not exist, there is nothing
    to leak.

    Expected: HTTP 404 Not Found.
    """
    response = client.get(
        "/documents/vulnerable/doc-nonexistent-999", headers=alice_headers
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
