"""
risk_scorer.py — Risk scoring system.
Assigns severity and confidence based on finding attributes.
"""

from typing import List, Dict, Any


SEVERITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}

CVSS_BASE = {
    "IDOR": 8.8,
    "Missing Authentication": 9.1,
    "Excessive Data Exposure": 7.5,
    "Privilege Escalation Risk": 9.8,
    "Information Disclosure": 5.3,
    "XSS": 6.1,
    "SQLi": 9.4,
}


class RiskScorer:
    def score_all(self, findings: List[Dict]) -> List[Dict]:
        return [self._score(f) for f in findings]

    def _score(self, finding: Dict) -> Dict:
        vuln_type = finding.get("type", "Unknown")
        severity = finding.get("severity", "Medium")
        confidence = finding.get("confidence", 0.5)

        cvss = CVSS_BASE.get(vuln_type, 5.0)
        risk_score = round(cvss * confidence, 1)

        # Boost score if sensitive data detected
        evidence = finding.get("evidence", {})
        if evidence.get("sensitive_data_signals"):
            risk_score = min(10.0, risk_score + 0.5)
        if evidence.get("sensitive_fields_found"):
            risk_score = min(10.0, risk_score + 0.8)

        finding["risk_score"] = risk_score
        finding["cvss_estimate"] = cvss
        finding["severity_weight"] = SEVERITY_WEIGHTS.get(severity, 1)
        return finding