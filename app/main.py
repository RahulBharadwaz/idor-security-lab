"""
Main FastAPI application entry point for the IDOR Security Research Lab.

This module initializes the FastAPI app, registers core middleware and routes,
and exposes health and user profile endpoints.
"""

from fastapi import Depends, FastAPI
from app.auth import get_current_user
from app.models import HealthResponse, User, UserPublic
from app.routers import documents

# Initialize FastAPI application with comprehensive metadata
app = FastAPI(
    title="IDOR Security Research Lab",
    description=(
        "An educational, reproducible research environment demonstrating "
        "Insecure Direct Object Reference (IDOR) vulnerabilities and secure authorization patterns."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Register resource routers
app.include_router(documents.router)


@app.get("/", tags=["General"])
def root_summary():
    """
    Lab summary and active phase overview.
    """
    return {
        "lab": "IDOR Security Research Lab",
        "phase": "Phase 1: Project Foundation & Data Models",
        "description": (
            "Local educational lab simulating multi-tenant resources and object-level "
            "authorization boundaries."
        ),
        "docs_url": "/docs",
        "endpoints": {
            "health": "/health",
            "current_user_profile": "/auth/me",
            "my_documents": "/documents/me",
            "get_document_by_id": "/documents/{document_id}",
        },
    }


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["General"],
    summary="Application Health Check",
)
def health_check() -> HealthResponse:
    """
    Returns application status and active phase identifier.
    Used for automated startup validation and deployment health checks.
    """
    return HealthResponse(
        status="healthy",
        app="IDOR Security Research Lab",
        phase="Phase 1: Project Foundation & Data Models",
        version="0.1.0",
    )


@app.get(
    "/auth/me",
    response_model=UserPublic,
    tags=["Authentication"],
    summary="Get Current Authenticated User Profile",
    description=(
        "Validates the incoming token using the get_current_user dependency and returns "
        "the caller's public profile."
    ),
)
def get_my_profile(current_user: User = Depends(get_current_user)) -> UserPublic:
    """
    Returns the profile of the user currently authenticated via X-Lab-Token or Authorization header.
    """
    return UserPublic(
        id=current_user.id,
        username=current_user.username,
        full_name=current_user.full_name,
        email=current_user.email,
        role=current_user.role,
        department=current_user.department,
    )
