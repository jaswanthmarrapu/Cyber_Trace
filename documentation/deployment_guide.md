# CyberTrace - Production Deployment Reference

For full details, see the official [Deployment Readiness Report](file:///C:/Users/jaswa/.gemini/antigravity/brain/3f83b3f1-9e28-498d-81a5-38ae3d19349c/deployment_readiness_report.md).

## Quick Deployment Summary

### Frontend (Vercel)
- **Directory**: `frontend`
- **Framework**: `Vite`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Environment Variable**: `VITE_API_URL=https://<your-render-service>.onrender.com/api/v1`
- **Config File**: `frontend/vercel.json` (Handles SPA rewrites, reverse proxy `/api/*` to Render, and security headers)

### Backend (Render)
- **Directory**: `backend`
- **Runtime**: `Python 3`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT app.main:app`
- **Health Check**: `/api/v1/health`
- **Config File**: `render.yaml` (Render Blueprint with 1GB persistent disk mount)
- **Container Alternative**: `backend/Dockerfile`

---

## Render Persistent Storage & Database Configuration

To prevent data loss when Render instances restart, spin down, or redeploy, CyberTrace requires a persistent disk attached to the web service.

### 1. Persistent Disk Setup on Render
In your **Render Dashboard**:
1. Select your **`cybertrace-api`** Web Service.
2. Navigate to **Disks** in the left sidebar.
3. Click **Add Disk** (or use the blueprint definition in `render.yaml`):
   - **Disk Name**: `cybertrace-data`
   - **Mount Path**: `/var/data`
   - **Size**: `1 GB` (minimum; scale up as forensic evidence storage demands grow).

### 2. Required Environment Variables on Render
Navigate to **Environment** in your service settings and configure:

| Variable | Recommended Production Value | Description |
|---|---|---|
| `DATABASE_PATH` | `/var/data/cybertrace.db` | Explicit persistent path to SQLite forensic database |
| `DATA_DIR` | `/var/data` | Root folder for persistent evidence vault and generated PDF reports |
| `DATABASE_URL` | `sqlite:////var/data/cybertrace.db` | SQLAlchemy connection URL matching the persistent database |
| `ENVIRONMENT` | `production` | Enables production security, optimized logging, and CORS safeguards |
| `CORS_ORIGINS` | `https://cyber-trace-gamma.vercel.app,http://localhost:5173` | Whitelisted frontend origins |
| `ADMIN_INITIAL_USERNAME` | `admin_examiner` | Initial examiner username |
| `ADMIN_INITIAL_PASSWORD` | `<your-secure-password>` | Initial administrative password (hashed with PBKDF2 on first boot) |

### 3. Data Persistence Guarantees
- **No Data Reset on Startup**: CyberTrace checks `count() == 0` before seeding default records. Once initialized, existing user accounts, investigation cases, evidence hashes, and attack timelines are preserved across all container restarts.
- **ACID Integrity**: SQLite WAL mode and 30-second busy timeout protect against database lock contention during concurrent examiner access.
- **Evidence Vault Protection**: Evidence uploads reside in `/var/data/uploads` with non-executable permissions and immutable SHA-256 baselines.
- **Verification**: Query `GET /api/v1/health` to verify that `database_path` reports `/var/data/cybertrace.db` and `database_healthy` returns `true`.
