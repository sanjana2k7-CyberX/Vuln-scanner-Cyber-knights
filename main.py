"""
Intelligent Web Application Vulnerability Detection & Analysis Platform
Backend: FastAPI + OWASP ZAP + Sentence-BERT + AI Analysis
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import asyncio
import json
import os
import uuid
import time
import hashlib
from datetime import datetime
from pathlib import Path

# Import our modules
from scanner import ScanEngine
from idor_detector import IDORDetector
from api_tester import APISecurityTester
from risk_scorer import RiskScorer
from fix_engine import FixSuggestionEngine
from auth import verify_token, create_token, fake_users_db

app = FastAPI(title="VulnPlatform API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
# Mount static files
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")

DATA_DIR = BASE_DIR / "data"
SCANS_DIR = DATA_DIR / "scans"
HISTORY_FILE = DATA_DIR / "history" / "scan_history.json"

# Ensure dirs exist
SCANS_DIR.mkdir(parents=True, exist_ok=True)
(DATA_DIR / "history").mkdir(parents=True, exist_ok=True)
if not HISTORY_FILE.exists():
    HISTORY_FILE.write_text("[]")


# ── Pydantic Models ──────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    scan_type: str = "full"          # full | quick | idor_only
    use_ai: bool = False
    zap_api_key: Optional[str] = None
    openai_key: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/")
async def serve_index():
    return FileResponse(str(BASE_DIR / "frontend" / "templates" / "index.html"))

@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse(str(BASE_DIR / "frontend" / "templates" / "dashboard.html"))


@app.post("/api/auth/login")
async def login(req: LoginRequest):
    user = fake_users_db.get(req.username)
    if not user or user["password"] != hashlib.sha256(req.password.encode()).hexdigest():
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(req.username)
    return {"token": token, "username": req.username}


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    """
    Main scan endpoint. Orchestrates:
    1. ZAP spider + active scan (or mock)
    2. IDOR detection with Sentence-BERT
    3. API security testing
    4. Risk scoring
    5. Fix suggestions
    6. Optional AI analysis
    """
    scan_id = str(uuid.uuid4())[:8]
    target_url = req.url.rstrip("/")

    try:
        # Step 1: Spider
        engine = ScanEngine(target_url, zap_api_key=req.zap_api_key)
        crawl_results = await engine.run_spider()
        endpoints = crawl_results["endpoints"]
        parameters = crawl_results["parameters"]

        # Step 1b: SentinelScanner (SQLi + XSS)
        from scanner import SentinelScanner
        sentinel = SentinelScanner(target_url)
        await sentinel.run()
        sentinel_findings = sentinel.to_platform_findings()


        # ── Step 2: IDOR Detection ────────────────────────────────────────────
        idor_detector = IDORDetector(target_url)
        idor_findings = await idor_detector.detect(endpoints, parameters)

        # ── Step 3: API Security Testing ──────────────────────────────────────
        api_tester = APISecurityTester(target_url)
        api_findings = await api_tester.test(endpoints)

        # ── Step 4: Combine all findings ─────────────────────────────────────
        all_findings = idor_findings + api_findings + sentinel_findings

        # ── Step 5: Risk Scoring ──────────────────────────────────────────────
        scorer = RiskScorer()
        scored_findings = scorer.score_all(all_findings)

        # ── Step 6: Fix Suggestions ───────────────────────────────────────────
        fix_engine = FixSuggestionEngine()
        final_findings = fix_engine.attach_fixes(scored_findings)

        # ── Step 7: AI Analysis (optional) ────────────────────────────────────
        ai_summary = None
        if req.use_ai and req.openai_key:
            from ai_analyzer import AIAnalyzer
            analyzer = AIAnalyzer(req.openai_key)
            ai_summary = await analyzer.analyze(final_findings, target_url)

        # ── Assemble result ───────────────────────────────────────────────────
        result = {
            "scan_id": scan_id,
            "target_url": target_url,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_endpoints": len(endpoints),
                "total_findings": len(final_findings),
                "critical": sum(1 for f in final_findings if f["severity"] == "Critical"),
                "high": sum(1 for f in final_findings if f["severity"] == "High"),
                "medium": sum(1 for f in final_findings if f["severity"] == "Medium"),
                "low": sum(1 for f in final_findings if f["severity"] == "Low"),
            },
            "endpoints_found": endpoints[:20],
            "findings": final_findings,
            "ai_summary": ai_summary,
        }

        # ── Save scan result ──────────────────────────────────────────────────
        scan_file = SCANS_DIR / f"{scan_id}.json"
        scan_file.write_text(json.dumps(result, indent=2))

        # ── Update history ────────────────────────────────────────────────────
        history = json.loads(HISTORY_FILE.read_text())
        history.insert(0, {
            "scan_id": scan_id,
            "url": target_url,
            "timestamp": result["timestamp"],
            "findings_count": len(final_findings),
            "critical": result["summary"]["critical"],
        })
        history = history[:50]  # keep last 50
        HISTORY_FILE.write_text(json.dumps(history, indent=2))

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    return json.loads(scan_file.read_text())


@app.get("/api/history")
async def get_history():
    if not HISTORY_FILE.exists():
        return []
    return json.loads(HISTORY_FILE.read_text())


@app.get("/api/export/{scan_id}")
async def export_scan(scan_id: str, fmt: str = "json"):
    scan_file = SCANS_DIR / f"{scan_id}.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    data = json.loads(scan_file.read_text())
    if fmt == "json":
        return JSONResponse(content=data, headers={
            "Content-Disposition": f"attachment; filename=vulnscan_{scan_id}.json"
        })
    raise HTTPException(status_code=400, detail="Only JSON export supported in this build")