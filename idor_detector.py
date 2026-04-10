"""
idor_detector.py — IDOR vulnerability detection using Sentence-BERT.
Fixed version: properly handles localhost targets and connection errors.
"""

import re
import asyncio
import httpx
import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from typing import List, Dict, Any

try:
    from sentence_transformers import SentenceTransformer, util
    SBERT_AVAILABLE = True
    _model = None

    def get_model():
        global _model
        if _model is None:
            _model = SentenceTransformer("all-MiniLM-L6-v2")
        return _model

except ImportError:
    SBERT_AVAILABLE = False

ID_PARAM_PATTERNS = re.compile(
    r"\b(user_id|userid|account_id|accountid|order_id|orderid|"
    r"document_id|doc_id|thread_id|message_id|id|uid|pid|"
    r"profile_id|customer_id|invoice_id|file_id|report_id)\b",
    re.IGNORECASE,
)

PATH_ID_PATTERN = re.compile(r"/(\d+)(/|$)")


class IDORDetector:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.timeout = 8.0

    async def detect(self, endpoints: List[str], parameters: List[str]) -> List[Dict[str, Any]]:
        findings = []

        param_candidates = self._find_param_endpoints(endpoints)
        for ep, param in param_candidates[:5]:
            result = await self._test_param_endpoint(ep, param)
            if result:
                findings.append(result)

        groups = self._group_candidates(endpoints)
        for group in groups[:5]:
            result = await self._test_group(group)
            if result:
                findings.append(result)

        if not findings:
            findings = await self._direct_test_known_patterns(endpoints)

        return findings

    def _group_candidates(self, endpoints: List[str]) -> List[List[str]]:
        pattern_map: Dict[str, List[str]] = {}
        for url in endpoints:
            normalized = PATH_ID_PATTERN.sub(r"/{id}\2", url)
            if "{id}" in normalized:
                pattern_map.setdefault(normalized, []).append(url)
        return [urls for urls in pattern_map.values() if len(urls) >= 2]

    def _find_param_endpoints(self, endpoints: List[str]) -> List[tuple]:
        candidates = []
        for url in endpoints:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for key in params:
                if ID_PARAM_PATTERNS.search(key):
                    candidates.append((url, key))
        return candidates

    async def _direct_test_known_patterns(self, endpoints: List[str]) -> List[Dict]:
        findings = []
        base = self.target_url.rstrip("/")

        seen = set()
        for ep in endpoints[:10]:
            parsed = urlparse(ep)
            path = parsed.path

            if PATH_ID_PATTERN.search(path) and ep not in seen:
                seen.add(ep)
                urls = [f"{base}{PATH_ID_PATTERN.sub(f'/{i}\\2', path)}" for i in [1, 2, 3]]
                result = await self._test_url_list(urls, ep, "Path ID Traversal")
                if result:
                    findings.append(result)

            params = parse_qs(parsed.query)
            for key in params:
                if ID_PARAM_PATTERNS.search(key) and ep not in seen:
                    seen.add(ep + key)
                    result = await self._test_param_endpoint(ep, key)
                    if result:
                        findings.append(result)

        return findings

    async def _test_group(self, url_group: List[str]) -> Dict:
        return await self._test_url_list(url_group[:3], url_group[0], "Path ID Traversal")

    async def _test_url_list(self, urls: List[str], base_url: str, vuln_name: str) -> Dict:
        responses = []
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            for url in urls[:3]:
                try:
                    r = await client.get(url, headers={"User-Agent": "VulnPlatform-Scanner/1.0"})
                    responses.append({"url": url, "status": r.status_code, "body": r.text[:3000], "length": len(r.text)})
                except Exception as e:
                    responses.append({"url": url, "status": 0, "body": "", "length": 0})

        valid = [r for r in responses if r["status"] == 200 and r["body"]]
        if len(valid) < 2:
            return {}
        return self._evaluate_idor(base_url, valid, vuln_name)

    async def _test_param_endpoint(self, base_url: str, param_key: str) -> Dict:
        parsed = urlparse(base_url)
        params_dict = parse_qs(parsed.query)
        original_val = params_dict.get(param_key, ["1"])[0]
        test_ids = self._generate_test_ids(original_val)

        responses = []
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            for test_id in test_ids[:3]:
                try:
                    new_params = dict(params_dict)
                    new_params[param_key] = [str(test_id)]
                    new_query = urlencode({k: v[0] for k, v in new_params.items()})
                    test_url = urlunparse(parsed._replace(query=new_query))
                    r = await client.get(test_url, headers={"User-Agent": "VulnPlatform-Scanner/1.0"})
                    responses.append({"url": test_url, "status": r.status_code, "body": r.text[:3000], "length": len(r.text)})
                except Exception:
                    pass

        valid = [r for r in responses if r["status"] == 200 and r["body"]]
        if len(valid) < 2:
            return {}
        return self._evaluate_idor(base_url, valid, f"Parameter IDOR ({param_key})", param=param_key)

    def _generate_test_ids(self, original: str) -> List:
        try:
            base = int(original)
            return [base, base + 1, base + 2, base - 1 if base > 1 else base + 3]
        except ValueError:
            return [original, 1, 2, 3]

    def _evaluate_idor(self, base_url: str, responses: List[Dict], vuln_name: str, param: str = None) -> Dict:
        if len(responses) < 2:
            return {}

        bodies = [r["body"] for r in responses]
        similarity = self._compute_similarity(bodies[0], bodies[1])

        if similarity < 0.4:
            confidence, severity = 0.92, "Critical"
        elif similarity < 0.6:
            confidence, severity = 0.78, "High"
        elif similarity < 0.82:
            confidence, severity = 0.55, "Medium"
        else:
            return {}

        sensitive_signals = self._detect_sensitive_data(bodies)
        if sensitive_signals and severity == "Medium":
            severity = "High"
            confidence = min(0.92, confidence + 0.1)

        return {
            "id": f"IDOR-{abs(hash(base_url)) % 10000:04d}",
            "type": "IDOR",
            "name": vuln_name,
            "endpoint": base_url,
            "param": param,
            "severity": severity,
            "confidence": confidence,
            "similarity_score": round(similarity, 3),
            "description": (
                f"Potential Insecure Direct Object Reference detected. "
                f"Responses for different {'parameter' if param else 'path'} IDs show "
                f"{round((1 - similarity) * 100)}% semantic divergence. "
                f"Tested: {[r['url'] for r in responses[:3]]}. "
                f"Status codes: {[r['status'] for r in responses[:3]]}. "
                f"Sizes: {[r['length'] for r in responses[:3]]} bytes."
            ),
            "evidence": {
                "urls_tested": [r["url"] for r in responses[:3]],
                "status_codes": [r["status"] for r in responses[:3]],
                "response_lengths": [r["length"] for r in responses[:3]],
                "sbert_similarity": round(similarity, 3),
                "similarity_method": "sentence-bert" if SBERT_AVAILABLE else "jaccard-heuristic",
                "sensitive_data_signals": sensitive_signals,
            },
        }

    def _compute_similarity(self, text1: str, text2: str) -> float:
        if not text1 or not text2:
            return 0.0
        if SBERT_AVAILABLE:
            try:
                model = get_model()
                emb1 = model.encode(text1[:512], convert_to_tensor=True)
                emb2 = model.encode(text2[:512], convert_to_tensor=True)
                return float(util.cos_sim(emb1, emb2)[0][0])
            except Exception:
                pass
        return self._jaccard_similarity(text1, text2)

    def _jaccard_similarity(self, a: str, b: str) -> float:
        tokens_a = set(re.findall(r'\w+', a.lower()))
        tokens_b = set(re.findall(r'\w+', b.lower()))
        if not tokens_a and not tokens_b:
            return 1.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union) if union else 0.0

    def _detect_sensitive_data(self, bodies: List[str]) -> List[str]:
        signals = []
        combined = " ".join(bodies).lower()
        patterns = {
            "email addresses":  r'\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b',
            "SSN patterns":     r'\b\d{3}-\d{2}-\d{4}\b',
            "password fields":  r'"password[_]?hash"\s*:',
            "API keys":         r'"api[_]?key"\s*:\s*"[a-zA-Z0-9\-_]{8,}"',
            "salary data":      r'"salary"\s*:',
            "credit card":      r'"card[_]',
        }
        import re as _re
        for label, pattern in patterns.items():
            if _re.search(pattern, combined, _re.IGNORECASE):
                signals.append(label)
        return signals
