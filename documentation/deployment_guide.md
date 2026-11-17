# CyberTrace - Production Deployment Reference

For full details, see the official [Deployment Readiness Report](file:///C:/Users/jaswa/.gemini/antigravity/brain/3f83b3f1-9e28-498d-81a5-38ae3d19349c/deployment_readiness_report.md).

## Quick Deployment Summary

### Frontend (Vercel)
- **Directory**: `frontend`
- **Framework**: `Vite`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Environment Variable**: `VITE_API_URL=https://<your-render-service>.onrender.com/api/v1`
- **Config File**: `frontend/vercel.json` (Handles SPA rewrites and security headers)

### Backend (Render)
- **Directory**: `backend`
- **Runtime**: `Python 3`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT app.main:app`
- **Health Check**: `/api/v1/health`
- **Config File**: `render.yaml` (Render Blueprint with 1GB persistent disk mount)
- **Container Alternative**: `backend/Dockerfile`
