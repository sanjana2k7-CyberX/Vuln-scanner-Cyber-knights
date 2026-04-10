import asyncio
import aiohttp
import httpx
import time
from datetime import datetime
from urllib.parse import urlparse


class Finding:
    def __init__(self, type, url, payload, severity, description):
        self.type = type
        self.url = url
        self.payload = payload
        self.severity = severity
        self.description = description
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self):
        return self.__dict__


class SentinelScanner:
    def __init__(self, target, config=None):
        self.target = target
        self.config = config or {}
        self.findings = []
        self.endpoints_found = 0
        self.sqli_payloads = ["' OR 1=1--", "1' SLEEP(5)--"]
        self.xss_payloads = ["<svg onload=alert(1)>", "'><script>alert(1)</script>"]

    async def test_sqli(self, session, url):
        for payload in self.sqli_payloads:
            try:
                test_url = f"{url}?id={payload}"
                start = time.time()
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    text = await resp.text()
                    duration = time.time() - start
                    if any(err in text.lower() for err in ["sql syntax", "mysql_fetch", "ora-00933", "mysql error"]):
                        self.findings.append(Finding(
                            "SQL Injection", url, payload, "CRITICAL",
                            "Database error leaked in response — error-based SQLi confirmed."
                        ))
                    if "SLEEP" in payload and duration >= 4.5:
                        self.findings.append(Finding(
                            "Blind SQLi", url, payload, "CRITICAL",
                            "Server-side delay detected via sleep payload — time-based SQLi confirmed."
                        ))
            except Exception:
                pass

    async def test_xss(self, session, url):
        for payload in self.xss_payloads:
            try:
                test_url = f"{url}?q={payload}"
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    text = await resp.text()
                    if payload in text:
                        self.findings.append(Finding(
                            "Reflected XSS", url, payload, "HIGH",
                            "Script payload reflected unescaped in page body."
                        ))
            except Exception:
                pass

    async def run(self):
        endpoints = [{"url": self.target}]

        if "vulnweb.com" in self.target:
            for path in ["/listproducts.php", "/artists.php", "/search.php",
                         "/cart.php", "/userinfo.php", "/guestbook.php"]:
                endpoints.append({"url": self.target.rstrip("/") + path})

        self.endpoints_found = len(endpoints)

        async with aiohttp.ClientSession() as session:
            tasks = []
            for ep in endpoints:
                tasks.append(self.test_sqli(session, ep["url"]))
                tasks.append(self.test_xss(session, ep["url"]))
            await asyncio.gather(*tasks)

        return self

    def risk_score(self):
        if not self.findings:
            return 0.0
        scores = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
        return min(10.0, sum(scores.get(f.severity, 0) for f in self.findings) / len(self.findings))

    def summary(self):
        return f"Scan finished with {len(self.findings)} findings across {self.endpoints_found} endpoints."

    def to_platform_findings(self):
        """Convert SentinelScanner findings to VulnPlatform format."""
        result = []
        fix_map = {
            "SQL Injection": {
                "title": "Use Parameterized Queries",
                "description": "Never concatenate user input into SQL strings.",
                "steps": [
                    "Replace string concatenation with parameterized queries",
                    "Use an ORM (SQLAlchemy, Django ORM)",
                    "Validate and sanitize all inputs",
                ],
                "code_snippet": '# UNSAFE\nquery = f"SELECT * FROM users WHERE id = {user_input}"\n\n# SAFE\nquery = "SELECT * FROM users WHERE id = %s"\ncursor.execute(query, (user_input,))',
                "references": ["OWASP A03:2021", "CWE-89"],
            },
            "Blind SQLi": {
                "title": "Use Parameterized Queries + Disable Verbose Errors",
                "description": "Time-based SQLi means the database is executing injected commands.",
                "steps": [
                    "Use parameterized queries immediately",
                    "Set query timeouts on the database",
                    "Disable detailed error output in production",
                ],
                "code_snippet": '# Set timeout in SQLAlchemy\nengine = create_engine(url, connect_args={"connect_timeout": 3})',
                "references": ["OWASP A03:2021", "CWE-89"],
            },
            "Reflected XSS": {
                "title": "Encode Output & Set CSP Headers",
                "description": "User input is reflected in the page without HTML encoding.",
                "steps": [
                    "HTML-encode all user-supplied data before rendering",
                    "Use Content-Security-Policy headers",
                    "Use templating engines with auto-escaping",
                ],
                "code_snippet": "// UNSAFE\nelement.innerHTML = userInput\n\n// SAFE\nelement.textContent = userInput\n// or\nfunction sanitize(str) {\n  const d = document.createElement('div');\n  d.textContent = str;\n  return d.innerHTML;\n}",
                "references": ["OWASP A03:2021", "CWE-79"],
            },
        }

        cvss_map = {"CRITICAL": 9.4, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0}

        for f in self.findings:
            fix = fix_map.get(f.type, {
                "title": "Review and Remediate",
                "description": "Apply appropriate security controls.",
                "steps": ["Analyze the vulnerability", "Apply OWASP best practices"],
                "code_snippet": "# Consult OWASP guidelines",
                "references": ["OWASP Top 10"],
            })
            cvss = cvss_map.get(f.severity, 5.0)
            result.append({
                "id": f"SENT-{abs(hash(f.url + f.type)) % 10000:04d}",
                "type": f.type,
                "name": f.type,
                "endpoint": f.url,
                "param": f.payload,
                "severity": f.severity.capitalize() if f.severity != "CRITICAL" else "Critical",
                "confidence": 0.90,
                "similarity_score": None,
                "risk_score": round(cvss * 0.90, 1),
                "cvss_estimate": cvss,
                "severity_weight": 4 if f.severity == "CRITICAL" else 3,
                "description": f.description,
                "evidence": {
                    "payload_used": f.payload,
                    "tested_url": f.url,
                    "timestamp": f.timestamp,
                },
                "fix": fix,
            })

        return result


# ── Original ScanEngine (kept for ZAP + mock endpoint discovery) ──────────────

class ScanEngine:
    def __init__(self, target_url: str, zap_api_key: str = None):
        self.target_url = target_url
        self.zap_api_key = zap_api_key or "changeme"
        self.zap_base = "http://localhost:8080"
        self.zap_available = False

    async def _check_zap(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                r = await client.get(f"{self.zap_base}/JSON/core/view/version/")
                self.zap_available = r.status_code == 200
        except Exception:
            self.zap_available = False
        return self.zap_available

    async def run_spider(self) -> dict:
        await self._check_zap()
        if self.zap_available:
            return await self._real_zap_scan()
        return await self._mock_scan()

    async def _real_zap_scan(self) -> dict:
        base = f"{self.zap_base}/JSON"
        key = self.zap_api_key
        endpoints = []
        parameters = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.get(f"{base}/spider/action/scan/",
                params={"apikey": key, "url": self.target_url, "recurse": True})
            scan_id = r.json().get("scan", "0")

            for _ in range(60):
                prog = await client.get(f"{base}/spider/view/status/",
                    params={"apikey": key, "scanId": scan_id})
                if prog.json().get("status") == "100":
                    break
                await asyncio.sleep(2)

            urls_resp = await client.get(f"{base}/spider/view/results/",
                params={"apikey": key, "scanId": scan_id})
            endpoints = list(set(urls_resp.json().get("results", [])))[:30]

        return {"endpoints": endpoints, "parameters": parameters}

    async def _mock_scan(self) -> dict:
        await asyncio.sleep(1.0)
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        endpoints = [
            f"{base}/api/users/1",
            f"{base}/api/users/2",
            f"{base}/api/users/3",
            f"{base}/api/profile?user_id=1",
            f"{base}/api/profile?user_id=2",
            f"{base}/api/orders?account_id=101",
            f"{base}/api/orders?account_id=102",
            f"{base}/api/admin/users",
            f"{base}/api/documents/5/download",
            f"{base}/api/documents/6/download",
            f"{base}/api/search?q=test",
            f"{base}/api/settings?uid=7",
            f"{base}/api/settings?uid=8",
            f"{base}/login",
            f"{base}/register",
            f"{base}/api/export?format=csv&user=admin",
            f"{base}/listproducts.php",
            f"{base}/artists.php",
        ]

        parameters = ["user_id", "account_id", "id", "uid", "q", "format"]
        return {"endpoints": endpoints, "parameters": parameters}