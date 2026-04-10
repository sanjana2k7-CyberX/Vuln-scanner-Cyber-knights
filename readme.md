# ⬡ VulnPlatform — Intelligent Web Application Vulnerability Detection

A prototype security platform combining **OWASP ZAP**, **Sentence-BERT**, and **AI analysis** to detect IDOR and API vulnerabilities.

---

## 📁 Project Structure

```
vulnplatform/
├── backend/
│   ├── main.py              # FastAPI app + all routes
│   ├── scanner.py           # ZAP integration + mock fallback
│   ├── idor_detector.py     # IDOR detection using Sentence-BERT
│   ├── api_tester.py        # API security testing
│   ├── risk_scorer.py       # CVSS-based risk scoring
│   ├── fix_engine.py        # Fix suggestions + code snippets
│   ├── ai_analyzer.py       # OpenAI / Claude AI analysis
│   └── auth.py              # JWT authentication
├── frontend/
│   ├── templates/
│   │   └── index.html       # Single-page UI
│   └── static/
│       ├── css/main.css     # Dark cybersecurity theme
│       └── js/main.js       # Scan flow, results, modals
├── data/
│   ├── scans/               # Saved scan results (JSON)
│   └── history/             # Scan history log
├── test_vulnerable_server.py  # Deliberately vulnerable target
├── requirements.txt
└── run.sh
```

---

## 🚀 Quick Start

### Step 1 — Clone and install

```bash
cd vulnplatform
python3 -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — Run the platform

```bash
cd backend
uvicorn main:app --port 8000 --reload
```

Or use the convenience script:
```bash
chmod +x run.sh && ./run.sh
```

Open: **http://localhost:8000**

---

### Step 3 — Run the test target (recommended)

In a second terminal:

```bash
source .venv/bin/activate
python test_vulnerable_server.py
```

Now scan **http://localhost:9000** in VulnPlatform to see real IDOR detection.

---

### Step 4 — Optional: Connect OWASP ZAP

1. Download ZAP from https://zaproxy.org
2. Start ZAP → Tools → Options → API → Enable API
3. Note your API key
4. Platform auto-detects ZAP on `localhost:8080`
5. Enter your API key in the scan form if needed

**Without ZAP:** Platform uses realistic mock data automatically.

---

## 🔐 Login Credentials

| Username | Password    | Role    |
|----------|-------------|---------|
| admin    | admin123    | Admin   |
| analyst  | analyst123  | Analyst |

---

## 🧠 How IDOR Detection Works

```
Target URL → Spider crawl → Extract endpoints with IDs
                                        ↓
                          Group similar endpoints
                          e.g. /api/users/1, /api/users/2
                                        ↓
                          Send HTTP requests for each ID
                                        ↓
                          Sentence-BERT encodes response bodies
                                        ↓
                          Compute cosine similarity
                                        ↓
              similarity < 0.4  →  Critical IDOR (responses very different)
              similarity < 0.6  →  High IDOR
              similarity < 0.8  →  Medium IDOR
              similarity > 0.8  →  Skip (same template, not IDOR)
```

---

## 🤖 AI Analysis (Optional)

Add an OpenAI or Anthropic API key in the scan form to enable:
- Executive security summary
- Attack chain simulation
- Prioritized fix list
- Data exposure assessment

---

## 📦 API Endpoints

| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| GET    | `/`                   | Serve frontend UI        |
| POST   | `/api/scan`           | Start a scan             |
| GET    | `/api/scan/{id}`      | Get scan results         |
| GET    | `/api/history`        | Scan history             |
| GET    | `/api/export/{id}`    | Export results as JSON   |
| POST   | `/api/auth/login`     | Login                    |

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Only scan applications you own or have explicit permission to test. The test_vulnerable_server.py is intentionally insecure — run it only in isolated environments.