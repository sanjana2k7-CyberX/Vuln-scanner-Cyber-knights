"""
fix_engine.py — Maps vulnerabilities to fix suggestions with code snippets.
"""

from typing import List, Dict, Any

FIX_DATABASE = {
    "IDOR": {
        "title": "Implement Authorization Checks",
        "description": (
            "Verify that the currently authenticated user is authorized to access "
            "the requested resource. Never rely solely on the ID in the request."
        ),
        "steps": [
            "Fetch the resource by its ID from the database",
            "Compare the resource's owner/user_id with the authenticated user's ID",
            "Return 403 Forbidden if they don't match",
            "Use indirect references (UUIDs or tokens) instead of sequential integers",
        ],
        "code_snippet": """# Python / FastAPI example
@app.get("/api/orders/{order_id}")
async def get_order(order_id: int, current_user = Depends(get_current_user)):
    order = db.get_order(order_id)
    if not order:
        raise HTTPException(404)
    # ✅ Authorization check: ensure THIS user owns this order
    if order.user_id != current_user.id:
        raise HTTPException(403, "Forbidden: access denied")
    return order""",
        "references": ["OWASP A01:2021", "CWE-639"],
    },

    "Missing Authentication": {
        "title": "Add Authentication Middleware",
        "description": (
            "Protect all sensitive API endpoints with authentication. "
            "Use JWT, OAuth2, or session tokens."
        ),
        "steps": [
            "Add an authentication middleware or decorator to sensitive routes",
            "Validate tokens on every request",
            "Return 401 Unauthorized for missing/invalid tokens",
            "Use HTTPS to protect tokens in transit",
        ],
        "code_snippet": """# FastAPI JWT auth example
from fastapi.security import HTTPBearer
security = HTTPBearer()

@app.get("/api/users/{user_id}")
async def get_user(user_id: int, token: str = Depends(security)):
    payload = verify_jwt(token.credentials)  # raises 401 if invalid
    if payload["user_id"] != user_id and not payload.get("is_admin"):
        raise HTTPException(403, "Forbidden")
    return db.get_user(user_id)""",
        "references": ["OWASP A07:2021", "RFC 7519"],
    },

    "Excessive Data Exposure": {
        "title": "Use Response DTOs / Serializers",
        "description": (
            "Never return raw database models. Define explicit response schemas "
            "that only include fields the client actually needs."
        ),
        "steps": [
            "Create dedicated response schemas (DTOs) for each endpoint",
            "Explicitly list allowed fields — never use SELECT * or return full objects",
            "Remove sensitive fields: passwords, tokens, internal IDs, salts",
            "Use field-level access control for role-based visibility",
        ],
        "code_snippet": """# Pydantic response schema (FastAPI)
class UserPublicResponse(BaseModel):
    id: int
    username: str
    email: str
    # ❌ Omitted: password_hash, salt, api_key, role, internal_flags

@app.get("/api/users/{user_id}", response_model=UserPublicResponse)
async def get_user(user_id: int):
    return db.get_user(user_id)  # Pydantic auto-strips extra fields""",
        "references": ["OWASP A03:2021", "CWE-213"],
    },

    "Privilege Escalation Risk": {
        "title": "Enforce Role-Based Access Control",
        "description": (
            "Admin endpoints must verify both authentication AND admin role. "
            "Implement RBAC at the route level."
        ),
        "steps": [
            "Tag every route with required permission level",
            "Verify role in middleware before handler executes",
            "Log all access attempts to admin endpoints",
            "Use allowlists, not denylists, for route access",
        ],
        "code_snippet": """# RBAC decorator example
def require_role(*roles):
    def decorator(func):
        async def wrapper(*args, current_user=Depends(get_current_user), **kwargs):
            if current_user.role not in roles:
                raise HTTPException(403, "Insufficient permissions")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

@app.get("/api/admin/users")
@require_role("admin", "superuser")
async def list_all_users(current_user=Depends(get_current_user)):
    return db.get_all_users()""",
        "references": ["OWASP A01:2021", "CWE-269"],
    },

    "Information Disclosure": {
        "title": "Suppress Verbose Error Messages",
        "description": (
            "Configure your framework to return generic error messages in production. "
            "Log details server-side but never expose them to clients."
        ),
        "steps": [
            "Set DEBUG=False in production",
            "Return generic 500 error messages to clients",
            "Log full stack traces to a secure logging service",
            "Use structured error responses with error codes, not raw exceptions",
        ],
        "code_snippet": """# FastAPI production error handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    # ✅ Log internally
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    # ✅ Return generic message to client
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "code": "ERR_500"}
    )""",
        "references": ["OWASP A05:2021", "CWE-209"],
    },

    "XSS": {
        "title": "Sanitize All User Input & Use CSP",
        "description": "Encode output and implement Content Security Policy.",
        "steps": [
            "HTML-encode all user-supplied data before rendering",
            "Use a templating engine with auto-escaping (Jinja2, Handlebars)",
            "Set Content-Security-Policy headers",
            "Validate and allowlist input on the server side",
        ],
        "code_snippet": """// JavaScript: sanitize before innerHTML
function sanitize(str) {
    const div = document.createElement('div');
    div.textContent = str;  // auto-encodes HTML entities
    return div.innerHTML;
}
// Never do: element.innerHTML = userInput
// Always do: element.innerHTML = sanitize(userInput)
// Or better: element.textContent = userInput""",
        "references": ["OWASP A03:2021", "CWE-79"],
    },

    "SQLi": {
        "title": "Use Parameterized Queries",
        "description": "Never concatenate user input into SQL strings.",
        "steps": [
            "Use parameterized queries or prepared statements",
            "Use an ORM (SQLAlchemy, Django ORM, Prisma)",
            "Validate and sanitize all inputs",
            "Apply principle of least privilege to DB users",
        ],
        "code_snippet": """# ❌ Vulnerable
query = f"SELECT * FROM users WHERE id = {user_input}"

# ✅ Safe — parameterized
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))

# ✅ Safe — ORM
user = db.session.query(User).filter_by(id=user_input).first()""",
        "references": ["OWASP A03:2021", "CWE-89"],
    },
}


class FixSuggestionEngine:
    def attach_fixes(self, findings: List[Dict]) -> List[Dict]:
        return [self._attach(f) for f in findings]

    def _attach(self, finding: Dict) -> Dict:
        vuln_type = finding.get("type", "Unknown")
        fix = FIX_DATABASE.get(vuln_type, {
            "title": "Review and Remediate",
            "description": "Review this finding and apply appropriate security controls.",
            "steps": ["Analyze the vulnerability", "Apply security best practices"],
            "code_snippet": "# Consult OWASP guidelines for remediation",
            "references": ["OWASP Top 10"],
        })
        finding["fix"] = fix
        return finding