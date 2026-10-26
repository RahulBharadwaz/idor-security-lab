# IDOR / BOLA Security Research Lab

An educational, local research lab demonstrating **Insecure Direct Object Reference (IDOR)** — cataloged in the OWASP API Security Top 10 as **API1: Broken Object Level Authorization (BOLA)** — and its architectural remediation in modern Python and FastAPI.

---

> [!CAUTION]
> **EDUCATIONAL SECURITY RESEARCH NOTICE**  
> **"This repository is an educational security lab. The vulnerable endpoint deliberately omits object-level authorization. It must never be deployed or exposed as a production service."**  
> All user accounts, authentication tokens, and document records are 100% fictional synthetic data. The project runs strictly on `127.0.0.1` (localhost) with an in-memory datastore and must never be bound to `0.0.0.0` or deployed to a public network.

---

## 1. Project Overview

In multi-tenant web applications and APIs, **Insecure Direct Object Reference (IDOR)** occurs when an application exposes a direct identifier to an internal object (such as a database key or filename) and fails to verify that the authenticated requester has permission to access that specific object.

This repository provides a hands-on, reproducible environment designed to:
1. Demonstrate how an authenticated user can access another user's private records simply by altering a path parameter in an API request.
2. Implement server-side object-level authorization and data-access layer scoping (defense-in-depth) to eliminate the vulnerability.
3. Validate the remediation and prevent regression through a comprehensive automated test suite (40 tests).

---

## 2. Learning Objectives

By exploring this lab, security researchers, interns, and developers will learn:
* **The distinction between Authentication (AuthN) and Authorization (AuthZ):** Why authenticating a user does not automatically make their actions safe.
* **The anatomy of BOLA/IDOR:** How omitting a single ownership check (`document.owner_id == current_user.id`) creates a data breach vector.
* **Defense-in-Depth at the Data-Access Layer:** How owner-scoped lookups (`get_document_by_id_and_owner`) guarantee tenant isolation even if controller-level checks are missed.
* **Parameter Tampering Vectors:** Why client-supplied identity assertions (`?user_id=...`, `X-User-Id` headers) must never be trusted.
* **API Error Semantics:** The architectural trade-off between `HTTP 403 Forbidden` and `HTTP 404 Not Found` regarding resource enumeration oracles.
* **Defensive Regression Testing:** Writing negative authorization tests that verify payload suppression.

---

## 3. Technology Stack

* **Language:** Python 3.10+ (tested on Python 3.13.2)
* **Web Framework:** [FastAPI](https://fastapi.tiangolo.com/) (modern, type-safe REST APIs with dependency injection)
* **Data Validation:** [Pydantic v2](https://docs.pydantic.dev/) (schema enforcement and runtime validation)
* **ASGI Server:** [Uvicorn](https://www.uvicorn.org/) (high-performance local ASGI development server)
* **Testing Framework:** [Pytest](https://docs.pytest.org/) & [HTTPX](https://www.python-httpx.org/) (automated API testing with isolated fixtures)
* **Persistence:** In-memory Python dictionaries with per-test atomic state reset

---

## 4. Architecture & Request Flow

```
                      Client Request
                            │
                            ▼
               ┌────────────────────────┐
               │ FastAPI ASGI Pipeline  │
               └────────────┬───────────┘
                            │
                     [1. Authentication]
                            │
                            ▼
               ┌────────────────────────┐
               │   get_current_user()   │  ──> Extracts 'X-Lab-Token' / 'Authorization'
               │    (app/auth.py)       │  ──> Resolves token to synthetic User model
               └────────────┬───────────┘
                            │
            ┌───────────────┴───────────────┐
            │                               │
            ▼                               ▼
┌────────────────────────┐      ┌────────────────────────┐
│  Vulnerable Endpoint   │      │   Remediated Endpoint  │
│ /documents/vulnerable/ │      │      /documents/       │
│      {document_id}     │      │     {document_id}      │
└───────────┬────────────┘      └───────────┬────────────┘
            │                               │
    [2. Direct Lookup]              [2. Direct Lookup]
            │                               │
            ▼                               ▼
┌────────────────────────┐      ┌────────────────────────┐
│  get_document_by_id()  │      │  get_document_by_id()  │
└───────────┬────────────┘      └───────────┬────────────┘
            │                               │
  [3. Missing Check!]             [3. Existence Check]
            │                               │ (if not found -> 404)
            │                               ▼
            │                   [4. Server-Side AuthZ]
            │                               │
            │                   Does document.owner_id
            │                   == current_user.id?
            │                               │
            │                    ┌──────────┴──────────┐
            │                    │ No                  │ Yes
            │                    ▼                     ▼
            │               403 Forbidden         200 OK
            │             (Payload Blocked)   (DocumentResponse)
            ▼                                          ▲
     200 OK (LEAK!)                                    │
(Bob's private document                                │
   returned to Alice)                                  │
            │                                          │
            └──────────────────────────────────────────┘
```

---

## 5. Authentication vs. Authorization

| Concept | Question Answered | Implementation in Lab | Real-World Production Analogy |
| :--- | :--- | :--- | :--- |
| **Authentication (AuthN)** | *"Who are you?"* | [`app/auth.py:get_current_user`](app/auth.py) validates the token header and resolves it to a synthetic `User`. | Proving identity via OAuth 2.0 / OIDC, JWT signature verification, or secure session cookies. |
| **Authorization (AuthZ)** | *"Are you permitted to touch this specific object?"* | [`app/routers/documents.py:get_document_by_id_secure`](app/routers/documents.py) compares `document.owner_id == current_user.id`. | Access control policies (RBAC, ABAC, database Row-Level Security) determining user permissions on resource records. |

> **Key Rule:** Authentication must precede authorization, but authentication alone does not grant resource access. An application that identifies the user but skips object-level authorization is inherently vulnerable to IDOR/BOLA.

---

## 6. Synthetic Lab Data & Threat Model (Alice & Bob Scenario)

The lab provides two synthetic personas with isolated private documents:

| User | User ID | Lab Token | Role | Seed Documents |
| :--- | :--- | :--- | :--- | :--- |
| **Alice** | `user_alice_01` | `lab-token-alice-12345` | Security Research Intern | `doc-alice-101` (Research Strategy)<br>`doc-alice-102` (Internship Objectives) |
| **Bob** | `user_bob_02` | `lab-token-bob-67890` | DevOps Engineer | `doc-bob-201` (CI/CD Pipeline Audit)<br>`doc-bob-202` (Restricted Performance Review) |

### The Threat Scenario
* **Alice** is legitimately authenticated with her own valid token (`lab-token-alice-12345`).
* **Bob** owns a sensitive, confidential document: `doc-bob-202` (*Bob - Performance Review & Compensation Summary*).
* Alice modifies the URL parameter from `doc-alice-101` to `doc-bob-202`.

---

## 7. The Intentionally Insecure Endpoint

**Route:** `GET /documents/vulnerable/{document_id}`  
**Handler:** [`get_document_by_id_vulnerable()`](app/routers/documents.py#L93-L140)

```python
# app/routers/documents.py (Lines 114-140)
@router.get("/vulnerable/{document_id}", response_model=DocumentResponse)
def get_document_by_id_vulnerable(
    document_id: str,
    current_user: User = Depends(get_current_user),  # Step 1: Authentication succeeds
) -> DocumentResponse:
    # Step 2: Resource lookup by client-supplied ID
    document = get_document_by_id(document_id)

    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' was not found.",
        )

    # *** CRITICAL FLAW: Step 3 (Authorization Check) is OMITTED ***
    # The server never checks if document.owner_id == current_user.id.
    return DocumentResponse(
        id=document.id,
        owner_id=document.owner_id,
        title=document.title,
        category=document.category,
        content=document.content,
        created_at=document.created_at,
        is_confidential=document.is_confidential,
    )
```

### Exploit Demonstration
When Alice executes:
```http
GET /documents/vulnerable/doc-bob-202 HTTP/1.1
Host: 127.0.0.1:8000
X-Lab-Token: lab-token-alice-12345
```
The server responds with `HTTP 200 OK` containing Bob's private salary and performance review:
```json
{
  "id": "doc-bob-202",
  "owner_id": "user_bob_02",
  "title": "Bob - Performance Review & Compensation Summary",
  "category": "Restricted HR Evaluation",
  "content": "Synthetic Lab Content: Annual performance review scores, bonus calculation breakdown...",
  "created_at": "2026-10-24T16:45:00Z",
  "is_confidential": true
}
```
*Alice successfully read Bob's private data despite having no legitimate authorization.*

---

## 8. The Remediated Endpoint & Defense-in-Depth

**Route:** `GET /documents/{document_id}`  
**Handler:** [`get_document_by_id_secure()`](app/routers/documents.py#L154-L200)

```python
# app/routers/documents.py (Lines 165-199)
@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_by_id_secure(
    document_id: str,
    current_user: User = Depends(get_current_user),  # Step 1: Authentication
) -> DocumentResponse:
    # Step 2: Resource lookup
    document = get_document_by_id(document_id)

    # Step 3: Existence validation
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID '{document_id}' was not found.",
        )

    # Step 4: Server-Side Object-Level Authorization Check
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
```

### Defense-in-Depth at the Data-Access Layer
In addition to controller-level checks, [`app/database.py`](app/database.py#L129-L141) implements:
```python
def get_document_by_id_and_owner(doc_id: str, owner_id: str) -> Optional[Document]:
    """
    Retrieve a document record scoped strictly to the specified owner.
    Corresponds to: SELECT * FROM documents WHERE id = :doc_id AND owner_id = :owner_id;
    """
    doc = _documents.get(doc_id)
    if doc and doc.owner_id == owner_id:
        return doc
    return None
```
**Why this matters:** If a developer adds a new route or background worker and forgets the controller check `if document.owner_id != current_user.id:`, querying by owner guarantees that the database engine never returns unauthorized records.

---

## 9. The HTTP 403 vs. 404 Design Decision & Enumeration Trade-Off

In this lab, the secure endpoint implements the following status code contract:
* **Resource does not exist:** `HTTP 404 Not Found`
* **Resource exists but belongs to another user:** `HTTP 403 Forbidden`

### Architectural Analysis:
* **Advantage (Clarity & Diagnostics):** Returning 403 is RESTfully descriptive. It allows legitimate clients, administrative tools, and automated tests to distinguish between broken links/typos (404) and insufficient permissions (403).
* **Limitation (Resource Enumeration Oracle):** By observing the status code difference, an external attacker can sequentially increment document IDs (`/doc-1`, `/doc-2`, `/doc-3`) to discover which IDs exist in the system (those returning 403) versus which are vacant (those returning 404).

### Production Recommendation:
In public multi-tenant APIs handling sensitive object identifiers, returning `HTTP 404 Not Found` for both nonexistent and unauthorized resources—or using cryptographically random, unguessable identifiers (UUIDv4)—eliminates resource enumeration risks.

---

## 10. Installation & Local Execution Guide

### Prerequisites
* Python 3.10 or higher
* Recommended: Virtual environment (`.venv`)

### 1. Setup Virtual Environment
```powershell
# Clone or navigate to the repository root
cd idor-security-lab

# Create virtual environment
python -m venv .venv

# Activate on Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Activate on Linux / macOS
# source .venv/bin/activate
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Run Development Server
Start the local API server bound strictly to localhost (`127.0.0.1`):
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Interactive Documentation
Open your browser to explore the API schemas:
* **Interactive Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **ReDoc Interface:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
* **Health Check:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 11. Automated Testing Suite

The repository contains a 40-test automated verification suite built on Pytest and HTTPX.

### Running the Tests
Execute the full test suite with verbose output:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

### Test Suite Structure (40 Tests)

| Test Module | Tests | Properties Verified |
| :--- | :--- | :--- |
| [`tests/test_auth.py`](tests/test_auth.py) | 5 | Rejection of missing/invalid tokens (401); resolution of Alice and Bob tokens; Bearer header support. |
| [`tests/test_documents_foundation.py`](tests/test_documents_foundation.py) | 8 | Listing own documents (`/documents/me`); reading own documents; nonexistent 404 handling; baseline cross-tenant blocking. |
| [`tests/test_health.py`](tests/test_health.py) | 2 | Root metadata endpoint and service health check responsiveness. |
| [`tests/test_idor_vulnerable.py`](tests/test_idor_vulnerable.py) | 5 | **IDOR PoC:** Alice reads her own doc via vulnerable route (200); Alice reads Bob's doc (200 leak); secure route blocks access (403); unauthenticated rejection (401); nonexistent 404. |
| [`tests/test_idor_remediation.py`](tests/test_idor_remediation.py) | 15 | **Phase 4 Regression Suite:** Alice/Bob own access; cross-tenant rejection (403) with complete payload suppression; parameter tampering bypass rejection (`?user_id=`, `?owner_id=`); header spoofing rejection (`X-User-Id`); side-by-side vulnerable vs secure contrast. |
| [`tests/test_models.py`](tests/test_models.py) | 5 | Pydantic model serialization; database user/document lookups; data-access layer owner-scoped lookup ([`get_document_by_id_and_owner`](app/database.py#L129)). |

---

## 12. Known Limitations & Architectural Assumptions

1. **Static Demonstration Tokens:** Authentication uses pre-shared strings mapped in memory (`INITIAL_TOKENS`). Production systems require signed, expiring JWTs (RS256/ES256) or server-managed sessions with HttpOnly cookies.
2. **In-Memory Volatile Datastore:** Data resides in Python dictionaries (`_documents`). It lacks database transactions, ACID guarantees, and persistent storage.
3. **Single-User Ownership Model:** The lab models simple 1:1 ownership. Real-world platforms require Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), or group/tenant hierarchies.
4. **Read-Only Scope:** The lab implements `GET` endpoints. In production, IDOR vulnerabilities are equally critical on `POST` (tampering with owner fields during creation), `PUT`/`PATCH` (updating others' records), and `DELETE` (deleting others' data).

---

## 13. Security Considerations & Safe Publication Guide

When presenting or hosting this project:
1. **Never Bind to Public Interfaces:** Run exclusively on `127.0.0.1`. Never launch with `--host 0.0.0.0` on an untrusted or internet-facing network.
2. **Prominent Warnings:** Retain all warning banners in `README.md` and `app/routers/documents.py`.
3. **No Real Secrets:** Ensure no production credentials, private keys, or actual personal identifiable information (PII) are added to the code.
4. **Git Hygiene:** Maintain `.gitignore` to prevent committing `.venv/`, `.pytest_cache/`, `__pycache__/`, or local `.env` files.

---

## 14. Conclusion & Key Takeaways

Building and remediating this IDOR security lab demonstrated that **authentication and authorization are distinct, non-fungible security responsibilities**. 

A system can boast multi-factor authentication, cryptographic tokens, and rigorous identity verification, but if its route handlers blindly trust client-supplied object identifiers without verifying object ownership on the server, the application remains completely exposed to Broken Object Level Authorization. Implementing server-side authorization checks and enforcing data-access layer scoping creates a resilient, defense-in-depth architecture.
