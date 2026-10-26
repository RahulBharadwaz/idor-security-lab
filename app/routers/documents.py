"""
Resource endpoints for documents in the IDOR Security Research Lab.

Architectural Design (Phase 1, Phase 3 & Phase 4):
--------------------------------------------------
Phase 1 established the secure baseline:
1. Authentication works: the API knows who is calling (current_user).
2. Data modeling works: Alice and Bob have distinct private documents.
3. Protected baseline works: Accessing an object verifies BOTH existence and ownership.

Phase 3 — Controlled IDOR Demonstration:
-----------------------------------------
A deliberately vulnerable endpoint (/documents/vulnerable/{document_id}) was added
to demonstrate what happens when authentication is present but object-level authorization
is omitted. This endpoint exists solely for local educational use.

Phase 4 — Remediation & Defense-in-Depth Verification:
------------------------------------------------------
The secure endpoint (/documents/{document_id}) enforces object-level authorization:
1. Validates identity via the server-side authentication dependency (current_user).
2. Retrieves the resource and verifies existence (404 if not found).
3. Verifies ownership on the server: document.owner_id == current_user.id (403 if mismatch).
4. Never trusts client-supplied user parameters (e.g., query params, spoofed headers).
5. Complemented by data-access layer owner scoping (get_document_by_id_and_owner) for defense-in-depth.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from app.auth import get_current_user
from app.database import (
    get_document_by_id,
    get_document_by_id_and_owner,
    get_documents_by_owner,
)
from app.models import DocumentResponse, User

router = APIRouter(prefix="/documents", tags=["Documents"])


@router.get(
    "/me",
    response_model=List[DocumentResponse],
    summary="List all documents owned by the authenticated user",
    description=(
        "Retrieves the collection of documents belonging strictly to the currently "
        "authenticated user. Uses current_user.id to query the datastore safely."
    ),
)
def list_my_documents(
    current_user: User = Depends(get_current_user),
) -> List[DocumentResponse]:
    """
    Returns all documents owned by the currently authenticated user.
    """
    documents = get_documents_by_owner(current_user.id)
    return [
        DocumentResponse(
            id=doc.id,
            owner_id=doc.owner_id,
            title=doc.title,
            category=doc.category,
            content=doc.content,
            created_at=doc.created_at,
            is_confidential=doc.is_confidential,
        )
        for doc in documents
    ]


# ==============================================================================
# INTENTIONALLY VULNERABLE ENDPOINT — LOCAL EDUCATIONAL DEMONSTRATION ONLY
# ==============================================================================
#
# WARNING: This endpoint is DELIBERATELY INSECURE.
#
# It authenticates the caller (Step 3 in the request flow) but intentionally
# OMITS the object-level authorization check (Step 5). This means any
# authenticated user can read ANY document by guessing or knowing its ID,
# regardless of who owns the document.
#
# This pattern demonstrates OWASP API Security Top 10 — API1: Broken Object
# Level Authorization (BOLA), also known as Insecure Direct Object Reference
# (IDOR).
#
# DO NOT use this pattern in any production application.
# DO NOT expose this endpoint on a public network.
#
# This route is registered BEFORE the catch-all /{document_id} route so that
# FastAPI matches /vulnerable/{document_id} correctly instead of treating
# "vulnerable" as a document_id value.
# ==============================================================================

@router.get(
    "/vulnerable/{document_id}",
    response_model=DocumentResponse,
    summary="[VULNERABLE — DEMO ONLY] Retrieve a document without authorization",
    description=(
        "INTENTIONALLY INSECURE endpoint for local IDOR/BOLA demonstration. "
        "Authenticates the caller but does NOT verify that the caller owns the "
        "requested document. Any authenticated user can access any document by ID."
    ),
    tags=["Documents", "Vulnerable Demo"],
)
def get_document_by_id_vulnerable(
    document_id: str,
    current_user: User = Depends(get_current_user),
) -> DocumentResponse:
    """
    INTENTIONALLY VULNERABLE — LOCAL EDUCATIONAL DEMONSTRATION ONLY.

    This endpoint demonstrates the IDOR / BOLA flaw:
    - Step 1 (Authentication): current_user is established by get_current_user dependency.
    - Step 2 (Resource Lookup): Document is retrieved from the datastore by direct ID.
    - Step 3 (Authorization Check): *** DELIBERATELY OMITTED ***

    Because the ownership check is missing, Alice can request doc-bob-202 and
    receive Bob's confidential performance review, even though she does not own it.

    Compare this function with get_document_by_id_secure() below to see the
    exact lines of code that prevent this vulnerability.
    """
    # Step 1: Authentication — current_user is already resolved by the dependency.
    # At this point, the server knows WHO is calling (e.g., Alice).

    # Step 2: Resource Lookup — retrieve the document using the client-supplied ID.
    document = get_document_by_id(document_id)

    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' was not found.",
        )

    # *** CRITICAL FLAW: Step 3 (Authorization) is MISSING here. ***
    #
    # The secure version checks:
    #     if document.owner_id != current_user.id:
    #         raise HTTPException(status_code=403, ...)
    #
    # Without that check, the server returns the document to ANY authenticated
    # user, even if they do not own it. This is the root cause of IDOR/BOLA.

    return DocumentResponse(
        id=document.id,
        owner_id=document.owner_id,
        title=document.title,
        category=document.category,
        content=document.content,
        created_at=document.created_at,
        is_confidential=document.is_confidential,
    )


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Retrieve a document by ID (Secure Remediation)",
    description=(
        "Enforces robust object-level authorization (BOLA/IDOR remediation): "
        "1. Authenticates the caller via server-verified token dependency. "
        "2. Retrieves the resource by ID. "
        "3. Validates existence (returns 404 if not found). "
        "4. Enforces authorization on the server: verifies document.owner_id == current_user.id "
        "   (returns 403 Forbidden on mismatch). "
        "5. Rejects any attempt to spoof identity through client-supplied user IDs."
    ),
)
def get_document_by_id_secure(
    document_id: str,
    current_user: User = Depends(get_current_user),
) -> DocumentResponse:
    """
    Secure resource retrieval enforcing Object-Level Authorization (Remediated):
    - Step 1 (Authentication): current_user is established by get_current_user dependency.
      Client-supplied user IDs in headers or query params are strictly ignored.
    - Step 2 (Resource Lookup): Document is retrieved from the datastore by direct ID.
    - Step 3 (Existence Validation): If document is not found, return HTTP 404 Not Found.
    - Step 4 (Authorization Check): Verify document.owner_id matches current_user.id.
      If ownership does not match, return HTTP 403 Forbidden without leaking resource data.
    """
    document = get_document_by_id(document_id)

    # Step 3: Existence Check — return 404 if the document does not exist
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' was not found.",
        )

    # Step 4: Authorization Check — Does the authenticated caller own this resource?
    # This prevents IDOR/BOLA by ensuring users can only access their own objects.
    if document.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to access this document.",
        )

    return DocumentResponse(
        id=document.id,
        owner_id=document.owner_id,
        title=document.title,
        category=document.category,
        content=document.content,
        created_at=document.created_at,
        is_confidential=document.is_confidential,
    )
