"""
Pydantic data models for the IDOR Security Research Lab.

This module defines data structures for users and private resources (documents).
Pydantic handles runtime validation, type hinting, and schema generation for FastAPI.
"""

from typing import Optional
from pydantic import BaseModel, Field


class User(BaseModel):
    """
    Internal model representing a lab user.

    Contains identity information used for authentication and authorization.
    """
    id: str = Field(..., description="Unique synthetic user identifier (e.g., user_alice_01)")
    username: str = Field(..., description="User login handle")
    full_name: str = Field(..., description="Full name of synthetic test user")
    email: str = Field(..., description="Fictional contact email")
    role: str = Field(..., description="Educational lab role (e.g., Security Research Intern)")
    department: str = Field(..., description="Synthetic organization department")


class UserPublic(BaseModel):
    """
    Public representation of a user profile returned by API endpoints.
    """
    id: str
    username: str
    full_name: str
    email: str
    role: str
    department: str


class Document(BaseModel):
    """
    Internal model representing a private resource owned by a specific user.

    Each document has an `owner_id` linking it to a specific `User.id`.
    In an IDOR vulnerability, an attacker manipulates the `id` field to access
    documents where `owner_id` does NOT match the requesting user's ID.
    """
    id: str = Field(..., description="Direct object identifier (e.g., doc-alice-101)")
    owner_id: str = Field(..., description="Identifier of the user who owns this resource")
    title: str = Field(..., description="Document title")
    category: str = Field(..., description="Resource category/classification")
    content: str = Field(..., description="Synthetic confidential document body")
    created_at: str = Field(..., description="Creation date timestamp string")
    is_confidential: bool = Field(default=True, description="Flag indicating restricted access")


class DocumentResponse(BaseModel):
    """
    API response schema for returning a document to an authorized client.
    """
    id: str
    owner_id: str
    title: str
    category: str
    content: str
    created_at: str
    is_confidential: bool


class HealthResponse(BaseModel):
    """
    Response schema for the service health check endpoint.
    """
    status: str
    app: str
    phase: str
    version: str
