"""
Pytest configuration and shared test fixtures for IDOR Security Research Lab.
"""

from typing import Dict, Generator
import pytest
from fastapi.testclient import TestClient
from app.database import reset_db
from app.main import app


@pytest.fixture(autouse=True)
def clean_database() -> Generator[None, None, None]:
    """
    Ensures that every test starts with an isolated, clean copy of synthetic test data.
    """
    reset_db()
    yield
    reset_db()


@pytest.fixture
def client() -> TestClient:
    """
    Provides an HTTP test client (built on HTTPX) for exercising FastAPI endpoints.
    """
    return TestClient(app)


@pytest.fixture
def alice_headers() -> Dict[str, str]:
    """
    Headers containing Alice's synthetic authentication token.
    """
    return {"X-Lab-Token": "lab-token-alice-12345"}


@pytest.fixture
def bob_headers() -> Dict[str, str]:
    """
    Headers containing Bob's synthetic authentication token.
    """
    return {"X-Lab-Token": "lab-token-bob-67890"}


@pytest.fixture
def alice_bearer_headers() -> Dict[str, str]:
    """
    Headers containing Alice's token in standard Bearer format.
    """
    return {"Authorization": "Bearer lab-token-alice-12345"}
