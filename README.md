# CyberTrace – Digital Forensics & Cyber Incident Investigation Platform

CyberTrace is a web-based digital forensics platform designed for cybersecurity analysts, incident response teams, and forensic investigators. It provides full lifecycle evidence handling, automated threat detection, log correlation, and court-grade reporting.

---

## Key Modules

1. **Dashboard**: High-level incident telemetry, attack frequency graphs, and threat metrics.
2. **Evidence Collection**: Secure file ingestion with instant SHA-256, SHA-1, and MD5 calculation.
3. **Evidence Integrity Verification**: Real-time hash comparison detecting any byte-level tampering.
4. **Chain of Custody (COC)**: Immutable audit history tracking every handler and action.
5. **Log Analysis**: Multi-format parsing (Web server logs, Linux syslog, Windows Event Logs).
6. **Threat Detection**: Automated detection of Brute Force, SQL Injection, XSS, Path Traversal, and MITRE ATT&CK mapping.
7. **IP Investigation**: Public vs RFC 1918 classification, ASN, geolocation, and responsible attribution notices.
8. **File Forensics**: Magic bytes verification, Shannon entropy calculation, string extraction, and YARA signature matching.
9. **Attack Timeline Reconstruction**: Chronological unification of logs, file MACB timestamps, and network flows.
10. **Investigation Case Management**: Case lifecycle tracking, severity assignment, and evidence association.
11. **Automated Report Generation**: Court-grade PDF reports generated dynamically via ReportLab.
12. **AI-Assisted Investigation Summary**: Incident narrative, root cause analysis, and remediation suggestions.

---

## Architecture

```text
CyberTrace/
│
├── frontend/               # React 18, Tailwind CSS, Recharts, Lucide React
│   ├── src/
│   │   ├── components/     # Reusable UI widgets, badges, tables
│   │   ├── pages/          # 12 specialized forensic modules
│   │   ├── layouts/        # Cyberpunk dark sidebar & header shell
│   │   ├── services/       # Axios API client modules
│   │   ├── hooks/          # Custom React hooks
│   │   ├── assets/         # Branding and SVGs
│   │   └── App.jsx         # Application routing
│   ├── public/
│   └── package.json
│
├── backend/                # FastAPI, SQLite, SQLAlchemy, Pandas, Scapy, ReportLab
│   ├── app/
│   │   ├── routes/         # Modular REST endpoints
│   │   ├── models/         # SQLAlchemy database models
│   │   ├── services/       # Forensic business logic
│   │   ├── forensic/       # Hasher, entropy, magic bytes, parsers
│   │   ├── database/       # SQLite engine and session management
│   │   ├── utils/          # Sanitization, file safety, constants
│   │   └── main.py         # App factory and middleware
│   │
│   ├── uploads/            # Isolated evidence vault
│   ├── reports/            # Generated PDF report vault
│   ├── tests/              # Automated unit and integration tests
│   └── requirements.txt
│
├── sample_data/            # Real-world forensic logs and test artifacts
│   ├── logs/               # Sample auth.log, web access log, windows events
│   └── files/              # Test payloads for safe file inspection
│
├── documentation/          # Architecture, API specs, security guidelines
├── .gitignore
└── README.md
```

---

## Quick Start & Running CyberTrace

CyberTrace supports two operational modes:

### Mode 1: Instant Native Launch (Zero Dependencies Required)
CyberTrace comes with an integrated standalone forensic engine implemented in pure Python Standard Library (SQLite3, Hashlib, Http.server, Re, Math). It requires zero external pip packages and runs out-of-the-box on standard Python 3.8+:

```cmd
# Double click or run the launch script from workspace root:
start_cybertrace.bat
```
Or manually run:
```bash
python backend/app/standalone_server.py 8000
```
This automatically initializes the SQLite database (`backend/cybertrace.db`), provisions the isolated `.vault` evidence directory, and serves the complete CyberTrace Forensics Platform at:
👉 **`http://127.0.0.1:8000/`**

### Mode 2: Enterprise FastAPI + React Dev Server
For deployment in production environments with full FastAPI and Node.js tooling:

#### Backend (FastAPI + Uvicorn)
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```
- Swagger UI Docs: `http://localhost:8000/docs`
- ReDoc API Reference: `http://localhost:8000/redoc`

#### Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
```
Accessible at: `http://localhost:5173/`

### Automated Integration Test Suite
To verify all 11 modules and forensic guarantees:
```bash
python backend/tests/test_evidence_collection.py
```
Or run the in-process verification suite:
```bash
python scratch/test_inprocess.py
```

---

## Security & Forensic Principles
- **Zero Execution Guarantee**: All uploaded files are stored non-executable with randomized UUID filenames.
- **Immediate Ingestion Hashing**: SHA-256 hashes are calculated on upload streams before persistence.
- **Responsible Attribution**: IP investigation displays clear forensic caveats regarding proxies/NAT and attribution ethics.

