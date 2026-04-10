"""
ai_analyzer.py — Optional AI analysis layer.
Sends vulnerability findings to an LLM for deeper analysis.
"""

import httpx
import json
from typing import List, Dict, Any


class AIAnalyzer:
    def __init__(self, api_key: str, provider: str = "openai"):
        self.api_key = api_key
        self.provider = provider

    async def analyze(self, findings: List[Dict], target_url: str) -> Dict:
        """Send top findings to LLM for analysis."""
        if not findings:
            return {"summary": "No findings to analyze.", "attack_chains": []}

        # Focus on critical/high findings
        top_findings = sorted(
            findings,
            key=lambda f: f.get("risk_score", 0),
            reverse=True
        )[:5]

        prompt = self._build_prompt(top_findings, target_url)

        try:
            if self.provider == "openai":
                return await self._call_openai(prompt)
            else:
                return await self._call_claude(prompt)
        except Exception as e:
            return {
                "summary": f"AI analysis unavailable: {str(e)}",
                "attack_chains": [],
                "error": str(e)
            }

    def _build_prompt(self, findings: List[Dict], target: str) -> str:
        findings_text = json.dumps([{
            "type": f.get("type"),
            "endpoint": f.get("endpoint"),
            "severity": f.get("severity"),
            "description": f.get("description"),
            "evidence": f.get("evidence", {}),
        } for f in findings], indent=2)

        return f"""You are a senior web application security analyst.

Target URL: {target}

The following vulnerabilities were detected by an automated scanner:

{findings_text}

Please provide:
1. An executive summary of the security posture (2-3 sentences)
2. Is sensitive/unauthorized data likely exposed? Why?
3. What is the most critical attack scenario an attacker could exploit?
4. A possible attack chain combining these vulnerabilities
5. Priority order for fixing

Be concise and technical. Format as JSON with keys:
- executive_summary (string)
- data_exposure_assessment (string)
- critical_attack_scenario (string)
- attack_chain (list of steps)
- priority_fixes (list of vuln types in priority order)
"""

    async def _call_openai(self, prompt: str) -> Dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "response_format": {"type": "json_object"},
                    "max_tokens": 800,
                }
            )
            data = r.json()
            content = data["choices"][0]["message"]["content"]
            return json.loads(content)

    async def _call_claude(self, prompt: str) -> Dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 800,
                    "messages": [{"role": "user", "content": prompt}],
                }
            )
            data = r.json()
            content = data["content"][0]["text"]
            # Strip markdown fences if present
            content = content.strip().lstrip("```json").rstrip("```").strip()
            return json.loads(content)