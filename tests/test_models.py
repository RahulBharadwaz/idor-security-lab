"""
Unit tests for data models and in-memory store helper functions.
"""

from app.database import (
    get_document_by_id,
    get_document_by_id_and_owner,
    get_documents_by_owner,
    get_user_by_id,
    get_user_by_token,
)
from app.models import Document, User


def test_user_model_instantiation() -> None:
    """Validate User Pydantic model serialization and fields."""
    user = User(
        id="user_test_99",
        username="tester",
        full_name="Test User",
        email="test@example.lab",
        role="Auditor",
        department="Security",
    )
    assert user.id == "user_test_99"
    assert user.username == "tester"


def test_document_model_instantiation() -> None:
    """Validate Document Pydantic model serialization and defaults."""
    doc = Document(
        id="doc-test-1",
        owner_id="user_test_99",
        title="Test Document",
        category="Test Category",
        content="Test synthetic text content",
        created_at="2026-10-26T12:00:00Z",
    )
    assert doc.is_confidential is True
    assert doc.owner_id == "user_test_99"


def test_database_helpers_user_lookup() -> None:
    """Verify user lookup by token and by user ID."""
    user = get_user_by_token("lab-token-alice-12345")
    assert user is not None
    assert user.id == "user_alice_01"

    user_by_id = get_user_by_id("user_bob_02")
    assert user_by_id is not None
    assert user_by_id.username == "bob"

    assert get_user_by_token("non-existent-token") is None
    assert get_user_by_id("non-existent-id") is None


def test_database_helpers_document_lookup() -> None:
    """Verify document lookup by ID and filtering by owner."""
    doc = get_document_by_id("doc-alice-101")
    assert doc is not None
    assert doc.owner_id == "user_alice_01"

    alice_docs = get_documents_by_owner("user_alice_01")
    assert len(alice_docs) == 2
    assert all(d.owner_id == "user_alice_01" for d in alice_docs)

    bob_docs = get_documents_by_owner("user_bob_02")
    assert len(bob_docs) == 2
    assert all(d.owner_id == "user_bob_02" for d in bob_docs)


def test_database_helpers_document_lookup_scoped_by_owner() -> None:
    """Verify owner-scoped document lookup helper (defense-in-depth)."""
    # Owner match returns the document
    alice_doc = get_document_by_id_and_owner("doc-alice-101", "user_alice_01")
    assert alice_doc is not None
    assert alice_doc.id == "doc-alice-101"
    assert alice_doc.owner_id == "user_alice_01"

    # Cross-owner mismatch returns None (defense-in-depth at data layer)
    cross_owner_doc = get_document_by_id_and_owner("doc-bob-201", "user_alice_01")
    assert cross_owner_doc is None

    # Nonexistent document returns None
    assert get_document_by_id_and_owner("doc-nonexistent-999", "user_alice_01") is None
