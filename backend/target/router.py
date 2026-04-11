"""
router.py — Vulnerable FastAPI target application endpoints.

TODO (Dev B, Phase 1): Implement all endpoints with their vulnerabilities.
TODO (Dev B, Phase 4): Add active_mitigations feature flag checks.

See PROMPT.md Section 8.1 for vulnerability specifications per endpoint.

Endpoints:
  POST /login      SQLi, username enumeration, timing side channel, no rate limit
  GET  /data       IDOR (no ownership check)
  GET  /admin      Weak token check (substring match)
  POST /transfer   No CSRF, no re-auth, mass assignment
  GET  /files      Path traversal
"""

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

from backend.target.vuln_store import (
    USERS, DATA_RECORDS, SESSIONS,
    create_session, get_session_user, validate_user, record_transfer,
)

target_router = APIRouter()


# ── Request models ─────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class TransferRequest(BaseModel):
    amount: float
    to: str
    # NOTE: intentionally accepts extra fields (mass assignment vuln)
    class Config:
        extra = "allow"


# ── Helper to read active_mitigations from shared state ───────────────────────

def _get_mitigations() -> dict:
    """
    Reads active_mitigations from the shared SYSTEM_STATE singleton.
    Import here (not at module level) to avoid circular imports.
    """
    try:
        from backend.main import SYSTEM_STATE
        return SYSTEM_STATE.get("active_mitigations", {})
    except ImportError:
        return {}


# ── Endpoints ──────────────────────────────────────────────────────────────────

@target_router.post("/login")
async def login(body: LoginRequest, request: Request):
    """
    TODO (Dev B): Implement with vulnerabilities:

    VULNERABILITY 1 — SQL Injection simulation:
      If body.username contains SQLI patterns (', --, OR, UNION) AND
      active_mitigations["proper_auth"] is False:
        return 200 with a forged admin session token

    VULNERABILITY 2 — Username enumeration:
      If username exists but password wrong: return {"error": "Invalid password"}
      If username doesn't exist: return {"error": "User not found"}
      (patched behavior: always return {"error": "Authentication failed"})

    VULNERABILITY 3 — Timing side channel:
      Only call validate_user() (which does password comparison) for real users.
      For nonexistent users, return immediately without hashing.
      (patched behavior: always compute hash even for nonexistent users)

    PATCHED BEHAVIOR (when active_mitigations["proper_auth"] == True):
      Use constant-time comparison, generic error message.
    """
    # STUB
    mitigations = _get_mitigations()
    user = validate_user(body.username, body.password)
    if user:
        token = create_session(body.username)
        return {"token": token, "role": user["role"]}
    return JSONResponse(status_code=401, content={"error": "Authentication failed"})


@target_router.get("/data")
async def get_data(id: int, request: Request, authorization: Optional[str] = Header(None)):
    """
    TODO (Dev B): Implement with IDOR vulnerability.

    VULNERABILITY — IDOR:
      Return DATA_RECORDS[id] without checking if the authenticated user owns it.
      Any authenticated user can read any record by guessing the ID.

    PATCHED BEHAVIOR (when active_mitigations["idor_check_enabled"] == True):
      Check that DATA_RECORDS[id]["owner"] == current_user.
      Return 403 if ownership check fails.
    """
    # STUB
    record = DATA_RECORDS.get(id)
    if not record:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return record


@target_router.get("/admin")
async def admin_panel(request: Request, authorization: Optional[str] = Header(None)):
    """
    TODO (Dev B): Implement with weak auth bypass vulnerability.

    VULNERABILITY — Substring token check:
      token = authorization.replace("Bearer ", "") if authorization else ""
      if "admin" in token:  ← substring check, trivially bypassable
          return admin data

    PATCHED BEHAVIOR (when active_mitigations["proper_admin_auth"] == True):
      Validate token cryptographically against SESSIONS dict.
      Check user role == "admin".
    """
    # STUB
    token = (authorization or "").replace("Bearer ", "")
    mitigations = _get_mitigations()
    if mitigations.get("proper_admin_auth"):
        user = get_session_user(token)
        if not user or USERS.get(user, {}).get("role") != "admin":
            return JSONResponse(status_code=403, content={"error": "Forbidden"})
    else:
        if "admin" not in token:
            return JSONResponse(status_code=403, content={"error": "Forbidden"})
    return {"panel": "admin", "users": list(USERS.keys()), "sessions": len(SESSIONS)}


@target_router.post("/transfer")
async def transfer(body: TransferRequest, request: Request, authorization: Optional[str] = Header(None)):
    """
    TODO (Dev B): Implement with CSRF / no-reauth vulnerability.

    VULNERABILITY 1 — No CSRF token required.
    VULNERABILITY 2 — No re-authentication for sensitive action.
    VULNERABILITY 3 — Mass assignment: extra fields in body accepted.

    PATCHED BEHAVIOR (when active_mitigations["csrf_protection"] == True):
      Require X-CSRF-Token header that matches a server-side token.
    """
    # STUB
    token = (authorization or "").replace("Bearer ", "")
    user = get_session_user(token)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    result = record_transfer(user, body.to, body.amount)
    return {"transfer": result, "status": "completed"}


@target_router.get("/files")
async def get_file(path: str, request: Request):
    """
    TODO (Dev B): Implement with path traversal vulnerability.

    VULNERABILITY — No path sanitization:
      open(path) directly without sanitization
      Detectable success: response contains /etc/passwd content patterns

    PATCHED BEHAVIOR (when active_mitigations["path_sanitization"] == True):
      Use os.path.basename(path)
      Validate against ALLOWED_DIR whitelist
    """
    # STUB
    import os
    mitigations = _get_mitigations()
    if mitigations.get("path_sanitization"):
        path = os.path.basename(path)
        allowed = {"readme.txt", "about.txt", "help.txt"}
        if path not in allowed:
            return JSONResponse(status_code=403, content={"error": "Forbidden"})

    # Simulate file content (don't actually read /etc/passwd on real system)
    simulated_files = {
        "readme.txt": "Welcome to CorpApp v1.0",
        "about.txt":  "CorpApp internal application",
        "../../../etc/passwd":      "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "....//....//etc/passwd":   "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd": "root:x:0:0:root:/root:/bin/bash",
    }
    content = simulated_files.get(path, simulated_files.get("readme.txt"))
    return {"path": path, "content": content}
