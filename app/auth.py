"""
Authentication mechanism for the IDOR Security Research Lab.

CONCEPT CLARIFICATION:
======================
1. Authentication (AuthN): Answers the question: "WHO ARE YOU?"
   Validates credentials (such as an API token, password, or session) to establish
   the caller's identity. In this module, the `get_current_user` dependency performs
   authentication.

2. Authorization (AuthZ): Answers the question: "ARE YOU ALLOWED TO ACCESS THIS SPECIFIC OBJECT?"
   Determines whether the authenticated user has permission to view, edit, or delete a
   particular resource. Object-level authorization happens after authentication.

LAB SECURITY NOTICE:
===================
This lab uses a simplified header-based token mechanism (`X-Lab-Token` or `Authorization: Bearer <token>`)
intended purely for local educational experimentation and deterministic test reproducibility.
In production systems, authentication must use robust protocols such as OAuth 2.0 / OIDC with
cryptographically verified, short-lived JSON Web Tokens (JWT) or server-side session stores with
secure HTTP-only cookies.
"""

from typing import Optional
from fastapi import Header, HTTPException, status
from app.database import get_user_by_token
from app.models import User


def get_current_user(
    x_lab_token: Optional[str] = Header(
        default=None,
        alias="X-Lab-Token",
        description="Educational token header identifying test caller (e.g. lab-token-alice-12345)"
    ),
    authorization: Optional[str] = Header(
        default=None,
        alias="Authorization",
        description="Standard Authorization header (e.g. Bearer lab-token-alice-12345)"
    ),
) -> User:
    """
    FastAPI dependency that extracts and validates the caller's authentication token.

    Authentication Flow:
    1. Check for `X-Lab-Token` header.
    2. If absent, check for `Authorization: Bearer <token>`.
    3. If no token provided, raise HTTP 401 Unauthorized.
    4. Look up token in the lab user database.
    5. If token is invalid or unmapped, raise HTTP 401 Unauthorized.
    6. Return the validated User object to the route handler.

    Returns:
        User: The authenticated synthetic user making the request.

    Raises:
        HTTPException(401): If authentication fails due to missing or invalid token.
    """
    token: Optional[str] = None

    if x_lab_token:
        token = x_lab_token.strip()
    elif authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
        elif len(parts) == 1:
            token = parts[0].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: Missing 'X-Lab-Token' or 'Authorization' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Provided lab token is invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
