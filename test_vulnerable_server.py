"""
test_vulnerable_server.py — A deliberately vulnerable API server for testing VulnPlatform.

Run: python test_vulnerable_server.py (starts on port 9000)
Then scan: http://localhost:9000

Intentional vulnerabilities:
1. IDOR — /api/users/{id} returns ANY user's data without auth check
2. Missing auth — /api/admin/users accessible without any token
3. Excessive data exposure — returns password_hash, api_key in responses
4. Information disclosure — verbose stack traces on errors
"""

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
import random

app = FastAPI(title="Vulnerable Test App — DO NOT USE IN PRODUCTION")

# Fake user database
USERS = {
    1: {"id": 1, "username": "alice",   "email": "alice@example.com",   "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99", "api_key": "sk-alice-secret-key-12345", "role": "user",  "salary": 85000, "ssn": "123-45-6789"},
    2: {"id": 2, "username": "bob",     "email": "bob@example.com",     "password_hash": "8cb2237d0679ca88db6464eac60da96345513964", "api_key": "sk-bob-key-99887766", "role": "user",  "salary": 92000, "ssn": "987-65-4321"},
    3: {"id": 3, "username": "charlie", "email": "charlie@example.com", "password_hash": "sha256:abc123xyz", "api_key": "sk-charlie-key-aabbcc", "role": "admin", "salary": 150000, "ssn": "555-12-3456"},
    4: {"id": 4, "username": "dave",    "email": "dave@corp.com",       "password_hash": "pbkdf2:sha256:xyz", "api_key": "sk-dave-internal-key", "role": "user",  "salary": 78000, "ssn": "111-22-3333"},
}

ORDERS = {
    101: {"id": 101, "user_id": 1, "item": "Laptop", "amount": 1299.99, "status": "shipped", "card_last4": "4242"},
    102: {"id": 102, "user_id": 2, "item": "Phone",  "amount": 899.00,  "status": "pending", "card_last4": "1234"},
    103: {"id": 103, "user_id": 3, "item": "Monitor","amount": 549.00,  "status": "delivered","card_last4": "9876"},
}


# ── VULNERABLE ENDPOINTS ──────────────────────────────────────────────────────

# 🔴 IDOR: No authorization check! Any user can access any other user's profile.
@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    user = USERS.get(user_id)
    if not user:
        return JSONResponse({"error": "User not found"}, status_code=404)
    return user  # 🔴 Returns password_hash, api_key, ssn — excessive data exposure!


# 🔴 IDOR: Orders accessible by anyone changing the account_id param
@app.get("/api/profile")
async def get_profile(user_id: int = 1):
    user = USERS.get(user_id)
    if not user:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return {"profile": user, "orders": [o for o in ORDERS.values() if o["user_id"] == user_id]}


# 🔴 Missing auth: Admin endpoint with no authentication
@app.get("/api/admin/users")
async def admin_list_users():
    return {"users": list(USERS.values()), "total": len(USERS)}  # 🔴 All users + sensitive data


# 🔴 IDOR on orders
@app.get("/api/orders")
async def get_orders(account_id: int = 101):
    order = ORDERS.get(account_id)
    if not order:
        return JSONResponse({"message": "No orders", "account_id": account_id}, status_code=200)
    return order


# 🔴 Verbose error (information disclosure)
@app.get("/api/search")
async def search(q: str = ""):
    try:
        if "'" in q or ";" in q:
            # Simulate SQL error leaking
            raise Exception(f"DatabaseError: You have an error in your SQL syntax near '{q}' at line 1 (MySQL 8.0.32)\nTraceback: /var/www/app/models.py line 142")
        results = [u for u in USERS.values() if q.lower() in u["username"].lower()]
        return {"results": results, "query": q}
    except Exception as e:
        return JSONResponse({"error": str(e), "debug": True, "server": "werkzeug/2.3.0 Python/3.11"}, status_code=500)


# 🔴 Document IDOR
@app.get("/api/documents/{doc_id}/download")
async def download_doc(doc_id: int):
    return {
        "doc_id": doc_id,
        "owner_id": random.randint(1, 4),  # 🔴 No ownership check — random user!
        "filename": f"sensitive_report_{doc_id}.pdf",
        "content": "CONFIDENTIAL: Q4 financial projections...",
        "download_url": f"/files/doc_{doc_id}.pdf",
    }


@app.get("/")
async def root():
    return {"app": "Vulnerable Test Server", "version": "1.0", "endpoints": [
        "/api/users/{id}", "/api/profile?user_id=1", "/api/admin/users",
        "/api/orders?account_id=101", "/api/search?q=alice",
        "/api/documents/{id}/download",
    ]}


if __name__ == "__main__":
    print("\n  ⚠️  VULNERABLE TEST SERVER — For VulnPlatform testing only!")
    print("  URL: http://localhost:9000")
    print("  Scan this with VulnPlatform to see IDOR detection in action.\n")
    uvicorn.run(app, host="0.0.0.0", port=9000)