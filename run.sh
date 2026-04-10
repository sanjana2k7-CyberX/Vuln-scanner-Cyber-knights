#!/bin/bash
# ── VulnPlatform Startup Script ──────────────────────────────────────────────
set -e

echo ""
echo "  ⬡  VulnPlatform — Intelligent Vulnerability Detection"
echo "  ──────────────────────────────────────────────────────"
echo ""

# Navigate to project root
cd "$(dirname "$0")"

# Check Python
python3 --version || { echo "❌ Python 3 required."; exit 1; }

# Create venv if not exists
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment…"
    python3 -m venv .venv
fi

# Activate
source .venv/bin/activate

# Install deps
echo "📦 Installing dependencies…"
pip install -q -r requirements.txt

echo ""
echo "✅ Starting VulnPlatform…"
echo "   URL: http://localhost:8000"
echo "   ZAP: If running on :8080, real scans enabled. Otherwise mock mode."
echo ""

# Run from backend folder (FastAPI needs to find modules)
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload