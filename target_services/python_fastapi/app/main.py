# ============================================================================
# WARNING: THIS FILE IS INTENTIONALLY VULNERABLE FOR SECURITY TESTING PURPOSES
# DO NOT DEPLOY IN PRODUCTION. DO NOT USE AS A REFERENCE FOR SECURE CODE.
# Part of SecureHeal-AI test targets.
# ============================================================================
"""
SecureHeal-AI — Intentionally Vulnerable Python FastAPI Target Service.

Every endpoint marked with `# VULNERABLE: CWE-XXX` contains a deliberate
security flaw for automated detection, root-cause analysis, and repair testing.
"""

import os
import pickle
import subprocess
import urllib.request
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel

from .database import get_db_connection, init_db

# --------------------------------------------------------------------------- #
# VULNERABLE: CWE-798 — Hard-coded credentials
# --------------------------------------------------------------------------- #
DB_USERNAME = "admin"           # VULNERABLE: CWE-798
DB_PASSWORD = "SuperSecret123!" # VULNERABLE: CWE-798
API_SECRET_KEY = "hardcoded-jwt-secret-key-12345"  # VULNERABLE: CWE-798

app = FastAPI(
    title="SecureHeal Target (Python)",
    description="Intentionally vulnerable service for SecureHeal-AI testing",
    version="1.0.0",
)


@app.on_event("startup")
async def startup():
    init_db()


# -- Request models --------------------------------------------------------- #

class SearchRequest(BaseModel):
    query: str
    field: str = "username"


class ProxyRequest(BaseModel):
    url: str


class ExecuteRequest(BaseModel):
    command: str


class ImportRequest(BaseModel):
    data: str  # base64-encoded pickled object


# --------------------------------------------------------------------------- #
# POST /api/users/search — VULNERABLE: CWE-89 (SQL Injection)
# --------------------------------------------------------------------------- #
@app.post("/api/users/search")
async def search_users(req: SearchRequest):
    """Search users — vulnerable to SQL injection via unsanitised input."""
    conn = get_db_connection()
    try:
        # VULNERABLE: CWE-89 — string formatting directly into SQL
        sql = f"SELECT id, username, email, role FROM users WHERE {req.field} LIKE '%{req.query}%'"
        cursor = conn.execute(sql)
        rows = [dict(r) for r in cursor.fetchall()]
        return {"results": rows, "query": sql}
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# GET /api/users/{user_id}/profile — VULNERABLE: CWE-79 (XSS)
# --------------------------------------------------------------------------- #
@app.get("/api/users/{user_id}/profile", response_class=HTMLResponse)
async def get_user_profile(user_id: int):
    """Render a user profile — vulnerable to reflected/stored XSS."""
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        # VULNERABLE: CWE-79 — user-controlled data rendered without escaping
        html = f"""
        <html><body>
        <h1>Profile: {user['username']}</h1>
        <p>Email: {user['email']}</p>
        <p>Role: {user['role']}</p>
        <p>Bio: {user['bio']}</p>
        </body></html>
        """
        return HTMLResponse(content=html)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# GET /api/admin/reports — VULNERABLE: CWE-862 (Missing Authorization)
# --------------------------------------------------------------------------- #
@app.get("/api/admin/reports")
async def get_admin_reports():
    """Return admin reports — no authentication or authorization check."""
    # VULNERABLE: CWE-862 — no auth check; any caller gets admin data
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT id, username, email, role FROM users")
        users = [dict(r) for r in cursor.fetchall()]
        return {
            "report": "Full User Report (Admin Only)",
            "total_users": len(users),
            "users": users,
            "secret_config": {
                "db_password": DB_PASSWORD,
                "api_key": API_SECRET_KEY,
            },
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# POST /api/proxy/fetch — VULNERABLE: CWE-918 (SSRF)
# --------------------------------------------------------------------------- #
@app.post("/api/proxy/fetch")
async def proxy_fetch(req: ProxyRequest):
    """Fetch a URL on behalf of the caller — vulnerable to SSRF."""
    # VULNERABLE: CWE-918 — no URL validation; internal resources reachable
    try:
        response = urllib.request.urlopen(req.url, timeout=10)
        content = response.read().decode("utf-8", errors="replace")
        return {"url": req.url, "status": response.status, "content": content[:5000]}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# --------------------------------------------------------------------------- #
# GET /api/files/download — VULNERABLE: CWE-22 (Path Traversal)
# --------------------------------------------------------------------------- #
UPLOADS_DIR = Path(__file__).parent / "uploads"


@app.get("/api/files/download")
async def download_file(filename: str = Query(...)):
    """Download a file from uploads — vulnerable to path traversal."""
    # VULNERABLE: CWE-22 — filename is not sanitised; ../ sequences allowed
    file_path = UPLOADS_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(str(file_path))


# --------------------------------------------------------------------------- #
# POST /api/system/execute — VULNERABLE: CWE-78 (OS Command Injection)
# --------------------------------------------------------------------------- #
@app.post("/api/system/execute")
async def execute_command(req: ExecuteRequest):
    """Execute a system command — vulnerable to command injection."""
    # VULNERABLE: CWE-78 — shell=True with unsanitised user input
    try:
        result = subprocess.run(
            req.command, shell=True, capture_output=True, text=True, timeout=10
        )
        return {
            "command": req.command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Command timed out")


# --------------------------------------------------------------------------- #
# POST /api/data/import — VULNERABLE: CWE-502 (Insecure Deserialization)
# --------------------------------------------------------------------------- #
@app.post("/api/data/import")
async def import_data(req: ImportRequest):
    """Import serialised data — vulnerable to insecure deserialization."""
    import base64
    try:
        # VULNERABLE: CWE-502 — pickle.loads on untrusted input
        raw = base64.b64decode(req.data)
        obj = pickle.loads(raw)
        return {"imported": str(obj), "type": type(obj).__name__}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Import failed: {exc}")


# --------------------------------------------------------------------------- #
# Health check (safe)
# --------------------------------------------------------------------------- #
@app.get("/health")
async def health():
    return {"status": "ok", "service": "python-fastapi-target"}
