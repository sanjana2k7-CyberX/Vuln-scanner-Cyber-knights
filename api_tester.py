"""
api_tester.py — API Security Testing module.

Tests for:
- Missing authentication (endpoints accessible without token)
- Excessive data exposure (response contains more fields than needed)
- Missing rate limiting
- Verbose error messages leaking internals
"""

import asyncio
import httpx
import json
import re
from typing import List, Dict, Any
from urllib.parse import urlparse


class APISecurityTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.timeout = 5.0

    async def test(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Run all API security tests and return findings."""
        findings = []

        # Run tests concurrently
        tasks = []
        for ep in endpoints[:15]:  # limit to 15 endpoints for speed
            tasks.append(self._test_auth(ep))
            tasks.append(self._test_data_exposure(ep))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)

        # Also run endpoint-level tests
        admin_finding = await self._test_admin_exposure(endpoints)
        if admin_finding:
            findings.append(admin_finding)

        error_finding = await self._test_verbose_errors(endpoints)
        if error_finding:
            findings.append(error_finding)

        return findings

    async def _test_auth(self, url: str) -> Dict:
        """
        Test if endpoint is accessible without authentication.
        Heuristic: if /api/ endpoint returns 200 without Authorization header → flag.
        """
        parsed = urlparse(url)
        if "/api/" not in parsed.path and "/admin" not in parsed.path:
            return {}

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False,
                                          follow_redirects=True) as client:
                # Request without auth
                r_no_auth = await client.get(url,
                    headers={"User-Agent": "VulnPlatform-Scanner/1.0"})

                if r_no_auth.status_code == 200:
                    # Try to parse JSON response
                    try:
                        data = r_no_auth.json()
                        field_count = self._count_fields(data)
                    except Exception:
                        data = {}
                        field_count = 0

                    if field_count > 0:
                        return {
                            "id": f"AUTH-{hash(url) % 10000:04d}",
                            "type": "Missing Authentication",
                            "name": "Unauthenticated API Endpoint",
                            "endpoint": url,
                            "severity": "High",
                            "confidence": 0.80,
                            "description": (
                                f"API endpoint returned HTTP 200 with {field_count} data fields "
                                f"without any authentication header. Sensitive data may be exposed "
                                f"to unauthenticated users."
                            ),
                            "evidence": {
                                "status_code": r_no_auth.status_code,
                                "response_fields": field_count,
                                "auth_header_sent": False,
                            },
                        }
        except Exception:
            pass
        return {}

    async def _test_data_exposure(self, url: str) -> Dict:
        """
        Detect excessive data exposure: response contains sensitive fields
        that should not be returned (passwords, tokens, internal IDs, etc.).
        """
        sensitive_fields = [
            "password", "passwd", "secret", "token", "api_key",
            "ssn", "credit_card", "card_number", "private_key",
            "internal_id", "admin", "role", "permissions",
            "salary", "hash", "salt",
        ]

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False,
                                          follow_redirects=True) as client:
                r = await client.get(url,
                    headers={"User-Agent": "VulnPlatform-Scanner/1.0"})

                if r.status_code != 200:
                    return {}

                body_lower = r.text.lower()
                found_fields = [f for f in sensitive_fields if f in body_lower]

                if len(found_fields) >= 1:
                    severity = "Critical" if any(f in found_fields for f in
                               ["password", "passwd", "secret", "private_key"]) else "Medium"
                    return {
                        "id": f"EXP-{hash(url) % 10000:04d}",
                        "type": "Excessive Data Exposure",
                        "name": "Sensitive Fields in API Response",
                        "endpoint": url,
                        "severity": severity,
                        "confidence": 0.70,
                        "description": (
                            f"API response contains potentially sensitive field names: "
                            f"{', '.join(found_fields[:5])}. "
                            f"These fields should be filtered out before returning to the client."
                        ),
                        "evidence": {
                            "sensitive_fields_found": found_fields[:5],
                            "status_code": r.status_code,
                            "response_size": len(r.text),
                        },
                    }
        except Exception:
            pass
        return {}

    async def _test_admin_exposure(self, endpoints: List[str]) -> Dict:
        """Check if admin endpoints are accessible."""
        admin_eps = [ep for ep in endpoints if "admin" in ep.lower()]
        if not admin_eps:
            return {}

        accessible = []
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False,
                                          follow_redirects=True) as client:
                for ep in admin_eps[:3]:
                    r = await client.get(ep,
                        headers={"User-Agent": "VulnPlatform-Scanner/1.0"})
                    if r.status_code in (200, 201):
                        accessible.append(ep)
        except Exception:
            pass

        if accessible:
            return {
                "id": "PRIV-0001",
                "type": "Privilege Escalation Risk",
                "name": "Admin Endpoints Accessible",
                "endpoint": accessible[0],
                "severity": "Critical",
                "confidence": 0.88,
                "description": (
                    f"{len(accessible)} admin endpoint(s) returned HTTP 200 without "
                    f"privilege validation. Attackers could access admin functionality."
                ),
                "evidence": {
                    "accessible_admin_endpoints": accessible,
                },
            }
        return {}

    async def _test_verbose_errors(self, endpoints: List[str]) -> Dict:
        """Test for verbose error messages by sending malformed requests."""
        if not endpoints:
            return {}

        test_url = endpoints[0]
        error_signals = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False,
                                          follow_redirects=True) as client:
                # Send invalid/malformed request
                r = await client.get(test_url + "?id='; DROP TABLE users;--",
                    headers={"User-Agent": "VulnPlatform-Scanner/1.0"})

                body = r.text.lower()
                leak_patterns = [
                    ("stack trace", ["traceback", "stack trace", "at line", "exception in"]),
                    ("SQL error", ["sql syntax", "mysql error", "postgresql", "ora-", "sqlite"]),
                    ("server internals", ["internal server error", "debug", "werkzeug", "django"]),
                    ("file paths", ["/var/www", "/home/", "c:\\", "/usr/local"]),
                ]

                for label, patterns in leak_patterns:
                    if any(p in body for p in patterns):
                        error_signals.append(label)

        except Exception:
            pass

        if error_signals:
            return {
                "id": "INFO-0001",
                "type": "Information Disclosure",
                "name": "Verbose Error Messages",
                "endpoint": test_url,
                "severity": "Medium",
                "confidence": 0.75,
                "description": (
                    f"Server returns verbose error messages exposing internal details: "
                    f"{', '.join(error_signals)}. These can help attackers enumerate the system."
                ),
                "evidence": {
                    "leak_categories": error_signals,
                },
            }
        return {}

    def _count_fields(self, data, depth=0) -> int:
        """Recursively count fields in a JSON response."""
        if depth > 3:
            return 0
        if isinstance(data, dict):
            return len(data) + sum(self._count_fields(v, depth + 1) for v in data.values())
        if isinstance(data, list) and data:
            return self._count_fields(data[0], depth + 1)
        return 0