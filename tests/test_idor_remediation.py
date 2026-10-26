"""
Phase 4 — IDOR Remediation and Authorization Regression Test Suite.

EDUCATIONAL & RESEARCH CONTEXT:
================================
This test suite establishes and validates the secure remediation of Broken Object
Level Authorization (BOLA / IDOR) in the IDOR Security Research Lab.

Behaviors Validated (Phase 4 Requirements):
1. Alice can access Alice's document (/documents/{id}).
2. Bob can access Bob's document (/documents/{id}).
3. Alice cannot access Bob's document through the secure endpoint (HTTP 403 Forbidden).
4. Bob cannot access Alice's document through the secure endpoint (HTTP 403 Forbidden).
5. Unauthenticated requests are rejected (HTTP 401 Unauthorized).
6. Nonexistent resources return the appropriate response (HTTP 404 Not Found).
7. A client cannot bypass authorization by supplying another user's ID
   (via query parameters, spoofed headers, or body fields).
8. Existing functionality continues to work, preserving the contrast with the
   isolated vulnerable endpoint (/documents/vulnerable/{id}) for local educational study.
"""

import pytest
from fastapi.testclient import TestClient


# ==============================================================================
# Behavior 1: Alice can access Alice's document (Authorized Happy Path)
# ==============================================================================

def test_remediation_alice_can_access_own_document(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Validation: Alice requests her own document via the remediated endpoint.

    Flow:
    1. Authentication: Server validates Alice's token -> current_user is Alice.
    2. Lookup: Server fetches doc-alice-101.
    3. Authorization: doc.owner_id ('user_alice_01') == current_user.id ('user_alice_01') -> PASS.

    Expected: HTTP 200 with Alice's document data.
    """
    response = client.get("/documents/doc-alice-101", headers=alice_headers)
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == "doc-alice-101"
    assert data["owner_id"] == "user_alice_01"
    assert "Alice - Q3 Vulnerability Research Strategy" in data["title"]
    assert "Confidential Research Plan" in data["category"]
    assert data["is_confidential"] is True


def test_remediation_alice_can_access_her_second_document(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Validation: Alice can also access her second private document (doc-alice-102).
    """
    response = client.get("/documents/doc-alice-102", headers=alice_headers)
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == "doc-alice-102"
    assert data["owner_id"] == "user_alice_01"
    assert "Alice - Personal Internship Objectives" in data["title"]


# ==============================================================================
# Behavior 2: Bob can access Bob's document (Authorized Happy Path)
# ==============================================================================

def test_remediation_bob_can_access_own_document(
    client: TestClient, bob_headers: dict
) -> None:
    """
    Validation: Bob requests his own confidential document via the remediated endpoint.

    Flow:
    1. Authentication: Server validates Bob's token -> current_user is Bob.
    2. Lookup: Server fetches doc-bob-202.
    3. Authorization: doc.owner_id ('user_bob_02') == current_user.id ('user_bob_02') -> PASS.

    Expected: HTTP 200 with Bob's document data.
    """
    response = client.get("/documents/doc-bob-202", headers=bob_headers)
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == "doc-bob-202"
    assert data["owner_id"] == "user_bob_02"
    assert "Bob - Performance Review & Compensation Summary" in data["title"]
    assert "Restricted HR Evaluation" in data["category"]
    assert "performance review scores" in data["content"].lower()
    assert data["is_confidential"] is True


def test_remediation_bob_can_access_his_first_document(
    client: TestClient, bob_headers: dict
) -> None:
    """
    Validation: Bob can also access his infrastructure audit document (doc-bob-201).
    """
    response = client.get("/documents/doc-bob-201", headers=bob_headers)
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == "doc-bob-201"
    assert data["owner_id"] == "user_bob_02"
    assert "Bob - CI/CD Pipeline Hardening Audit" in data["title"]


# ==============================================================================
# Behavior 3: Alice cannot access Bob's document through the secure endpoint
# ==============================================================================

def test_remediation_alice_cannot_access_bob_document(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Validation: Alice attempts an IDOR attack against Bob's confidential performance review.

    Flow:
    1. Authentication: Server validates Alice's token -> current_user is user_alice_01.
    2. Lookup: Server retrieves doc-bob-202.
    3. Authorization: doc.owner_id ('user_bob_02') != current_user.id ('user_alice_01') -> FAIL.

    Expected:
    - HTTP 403 Forbidden.
    - Error detail clearly indicates access is denied.
    - Response body must NOT leak Bob's document title, category, or content.
    """
    response = client.get("/documents/doc-bob-202", headers=alice_headers)
    assert response.status_code == 403

    body = response.json()
    assert "Forbidden" in body["detail"]
    assert "permission" in body["detail"].lower()

    # Verify no data leakage in response
    assert "title" not in body
    assert "content" not in body
    assert "Compensation" not in response.text
    assert "performance review" not in response.text.lower()


# ==============================================================================
# Behavior 4: Bob cannot access Alice's document through the secure endpoint
# ==============================================================================

def test_remediation_bob_cannot_access_alice_document(
    client: TestClient, bob_headers: dict
) -> None:
    """
    Validation: Bob attempts cross-tenant access against Alice's confidential research plan.

    Flow:
    1. Authentication: Server validates Bob's token -> current_user is user_bob_02.
    2. Lookup: Server retrieves doc-alice-101.
    3. Authorization: doc.owner_id ('user_alice_01') != current_user.id ('user_bob_02') -> FAIL.

    Expected:
    - HTTP 403 Forbidden.
    - Response body must NOT leak Alice's research strategy or objectives.
    """
    response = client.get("/documents/doc-alice-101", headers=bob_headers)
    assert response.status_code == 403

    body = response.json()
    assert "Forbidden" in body["detail"]
    assert "title" not in body
    assert "content" not in body
    assert "Vulnerability Research Strategy" not in response.text


# ==============================================================================
# Behavior 5: Unauthenticated requests are rejected
# ==============================================================================

def test_remediation_unauthenticated_request_missing_token_rejected(
    client: TestClient,
) -> None:
    """
    Validation: Request without any authentication header is rejected.

    Expected: HTTP 401 Unauthorized.
    """
    response = client.get("/documents/doc-alice-101")
    assert response.status_code == 401

    body = response.json()
    assert "Authentication required" in body["detail"]


def test_remediation_unauthenticated_request_invalid_token_rejected(
    client: TestClient,
) -> None:
    """
    Validation: Request with a forged or non-existent token is rejected.

    Expected: HTTP 401 Unauthorized.
    """
    headers = {"X-Lab-Token": "forged-token-evil-99999"}
    response = client.get("/documents/doc-alice-101", headers=headers)
    assert response.status_code == 401

    body = response.json()
    assert "Authentication failed" in body["detail"]


# ==============================================================================
# Behavior 6: Nonexistent resources return 404 Not Found
# ==============================================================================

def test_remediation_nonexistent_resource_returns_404(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Validation: Request for an ID that does not exist in the database returns 404.

    Flow:
    1. Authentication: Alice is authenticated.
    2. Lookup: get_document_by_id('doc-nonexistent-999') returns None.
    3. Server raises HTTP 404 before reaching authorization check.

    Expected: HTTP 404 Not Found with descriptive detail message.
    """
    response = client.get("/documents/doc-nonexistent-999", headers=alice_headers)
    assert response.status_code == 404

    body = response.json()
    assert "not found" in body["detail"].lower()
    assert "doc-nonexistent-999" in body["detail"]


# ==============================================================================
# Behavior 7: Client cannot bypass authorization by supplying another user's ID
# ==============================================================================

def test_remediation_bypass_attempt_query_param_user_id_ignored(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Vulnerability Vector: Query Parameter Tampering (?user_id=user_bob_02).

    An attacker might attempt to bypass authorization by supplying the target user's ID
    as a query parameter, hoping the backend compares document.owner_id against the
    query parameter instead of the authenticated session identity.

    The remediated endpoint resolves identity STRICTLY from the verified token
    (current_user.id) and ignores all client-supplied identity parameters.

    Expected: HTTP 403 Forbidden.
    """
    response = client.get(
        "/documents/doc-bob-202?user_id=user_bob_02", headers=alice_headers
    )
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]


def test_remediation_bypass_attempt_query_param_owner_id_ignored(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Vulnerability Vector: Query Parameter Tampering (?owner_id=user_bob_02).

    Similar to user_id tampering, the attacker supplies ?owner_id=user_bob_02.

    Expected: HTTP 403 Forbidden.
    """
    response = client.get(
        "/documents/doc-bob-202?owner_id=user_bob_02", headers=alice_headers
    )
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]


def test_remediation_bypass_attempt_spoofed_identity_headers_ignored(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Vulnerability Vector: HTTP Header Spoofing (X-User-Id / X-Remote-User).

    An attacker authenticated as Alice sends custom headers claiming to be Bob:
    - X-User-Id: user_bob_02
    - X-Owner-Id: user_bob_02
    - X-Forwarded-User: bob

    The server must NOT trust client-supplied identity headers. The only source
    of truth for identity is the validated authentication token.

    Expected: HTTP 403 Forbidden.
    """
    spoofed_headers = {
        **alice_headers,
        "X-User-Id": "user_bob_02",
        "X-Owner-Id": "user_bob_02",
        "X-Forwarded-User": "bob",
    }
    response = client.get("/documents/doc-bob-202", headers=spoofed_headers)
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]


def test_remediation_bypass_attempt_claiming_ownership_of_victim_document(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Vulnerability Vector: Inverted Ownership Claim (?owner_id=user_alice_01).

    An attacker supplies Bob's document ID while claiming via parameter that
    the owner is Alice: GET /documents/doc-bob-202?owner_id=user_alice_01.

    Because the server fetches doc-bob-202 from the database (where doc.owner_id
    is 'user_bob_02') and checks doc.owner_id against the authenticated user's ID
    ('user_alice_01'), the mismatch is detected and rejected.

    Expected: HTTP 403 Forbidden.
    """
    response = client.get(
        "/documents/doc-bob-202?owner_id=user_alice_01", headers=alice_headers
    )
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]


def test_remediation_bypass_attempt_unauthenticated_with_identity_headers(
    client: TestClient,
) -> None:
    """
    Vulnerability Vector: Unauthenticated request relying solely on identity headers.

    A client sends no authentication token, but supplies X-User-Id: user_alice_01.
    The server must reject the request at Step 1 (Authentication), never granting
    access based on untrusted identity assertions.

    Expected: HTTP 401 Unauthorized.
    """
    headers = {"X-User-Id": "user_alice_01"}
    response = client.get("/documents/doc-alice-101", headers=headers)
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


# ==============================================================================
# Behavior 8: Preservation of contrast — Educational Vulnerable Route vs Secure Route
# ==============================================================================

def test_remediation_preserves_contrast_with_isolated_vulnerable_route(
    client: TestClient, alice_headers: dict
) -> None:
    """
    Educational Contrast Demonstration:

    This test directly contrasts the vulnerable endpoint with the remediated secure endpoint
    using the exact same input parameters:
    - Caller: Alice (user_alice_01)
    - Target: Bob's confidential review (doc-bob-202)

    1. Vulnerable route (/documents/vulnerable/doc-bob-202):
       Returns HTTP 200 (IDOR flaw exists for local educational comparison).
    2. Remediated route (/documents/doc-bob-202):
       Returns HTTP 403 Forbidden (Object-Level Authorization enforced).

    This proves that the remediation fix is active and distinct, while preserving
    the laboratory's controlled demonstration.
    """
    # 1. Vulnerable endpoint demonstrates the flaw (local educational use only)
    vuln_response = client.get(
        "/documents/vulnerable/doc-bob-202", headers=alice_headers
    )
    assert vuln_response.status_code == 200
    assert vuln_response.json()["owner_id"] == "user_bob_02"

    # 2. Secure remediated endpoint blocks the attack
    secure_response = client.get(
        "/documents/doc-bob-202", headers=alice_headers
    )
    assert secure_response.status_code == 403
    assert "Forbidden" in secure_response.json()["detail"]
