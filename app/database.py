"""
In-memory synthetic database for the IDOR Security Research Lab.

This module provides simulated persistence using Python dictionaries.
All user accounts and document records use fictional, non-sensitive data
designed strictly for educational and security research testing.
"""

from copy import deepcopy
from typing import Dict, List, Optional
from app.models import Document, User

# ==============================================================================
# Synthetic Seed Data
# ==============================================================================

INITIAL_USERS: Dict[str, User] = {
    "user_alice_01": User(
        id="user_alice_01",
        username="alice",
        full_name="Alice Smith",
        email="alice.smith@example.lab",
        role="Security Research Intern",
        department="Product Security",
    ),
    "user_bob_02": User(
        id="user_bob_02",
        username="bob",
        full_name="Bob Jones",
        email="bob.jones@example.lab",
        role="DevOps Engineer",
        department="Cloud Infrastructure",
    ),
}

# Educational Token-to-User Mapping (Lab-only authentication simulation)
# Maps simulated tokens to user IDs. Real-world systems use signed JWTs or session stores.
INITIAL_TOKENS: Dict[str, str] = {
    "lab-token-alice-12345": "user_alice_01",
    "lab-token-bob-67890": "user_bob_02",
}

INITIAL_DOCUMENTS: Dict[str, Document] = {
    # Documents owned by Alice (owner_id="user_alice_01")
    "doc-alice-101": Document(
        id="doc-alice-101",
        owner_id="user_alice_01",
        title="Alice - Q3 Vulnerability Research Strategy",
        category="Confidential Research Plan",
        content=(
            "Synthetic Lab Content: Planned evaluation of broken object-level "
            "authorization patterns in microservice architectures and automated detection rules."
        ),
        created_at="2026-10-20T09:00:00Z",
        is_confidential=True,
    ),
    "doc-alice-102": Document(
        id="doc-alice-102",
        owner_id="user_alice_01",
        title="Alice - Personal Internship Objectives",
        category="Internal HR Notes",
        content=(
            "Synthetic Lab Content: Target skill development in API security, "
            "automated regression testing, and security advisory documentation."
        ),
        created_at="2026-10-22T14:30:00Z",
        is_confidential=True,
    ),
    # Documents owned by Bob (owner_id="user_bob_02")
    "doc-bob-201": Document(
        id="doc-bob-201",
        owner_id="user_bob_02",
        title="Bob - CI/CD Pipeline Hardening Audit",
        category="Infrastructure Audit",
        content=(
            "Synthetic Lab Content: Review of container signing, artifact provenance, "
            "and service account privilege boundaries across internal test runners."
        ),
        created_at="2026-10-18T11:15:00Z",
        is_confidential=True,
    ),
    "doc-bob-202": Document(
        id="doc-bob-202",
        owner_id="user_bob_02",
        title="Bob - Performance Review & Compensation Summary",
        category="Restricted HR Evaluation",
        content=(
            "Synthetic Lab Content: Annual performance review scores, bonus calculation "
            "breakdown, and personal professional development plan for 2026-2027."
        ),
        created_at="2026-10-24T16:45:00Z",
        is_confidential=True,
    ),
}

# Active in-memory data tables (mutable runtime state)
_users: Dict[str, User] = deepcopy(INITIAL_USERS)
_tokens: Dict[str, str] = deepcopy(INITIAL_TOKENS)
_documents: Dict[str, Document] = deepcopy(INITIAL_DOCUMENTS)


# ==============================================================================
# Database Access Helpers
# ==============================================================================

def get_user_by_id(user_id: str) -> Optional[User]:
    """Retrieve a user by their unique user ID."""
    return _users.get(user_id)


def get_user_by_token(token: str) -> Optional[User]:
    """Resolve a simulated lab authentication token to a User model."""
    user_id = _tokens.get(token)
    if not user_id:
        return None
    return _users.get(user_id)


def get_document_by_id(doc_id: str) -> Optional[Document]:
    """Retrieve a document record by its object identifier."""
    return _documents.get(doc_id)


def get_documents_by_owner(owner_id: str) -> List[Document]:
    """Retrieve all documents belonging to a given user ID."""
    return [doc for doc in _documents.values() if doc.owner_id == owner_id]


def get_document_by_id_and_owner(doc_id: str, owner_id: str) -> Optional[Document]:
    """
    Retrieve a document record by its object identifier scoped strictly to the specified owner.

    Provides defense-in-depth by enforcing object-level authorization at the data-access layer.
    In a relational database (e.g., PostgreSQL / SQLAlchemy), this corresponds to:
        SELECT * FROM documents WHERE id = :doc_id AND owner_id = :owner_id;
    """
    doc = _documents.get(doc_id)
    if doc and doc.owner_id == owner_id:
        return doc
    return None


def reset_db() -> None:
    """Reset the database to its initial synthetic seed state (useful in test fixtures)."""
    global _users, _tokens, _documents
    _users = deepcopy(INITIAL_USERS)
    _tokens = deepcopy(INITIAL_TOKENS)
    _documents = deepcopy(INITIAL_DOCUMENTS)
