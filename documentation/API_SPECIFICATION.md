# CyberTrace - API Specification

Base URL: `http://localhost:8000/api/v1`

## Endpoints

### System & Telemetry
- `GET /health` : Health check and service readiness.
- `GET /dashboard/stats` : Aggregated statistics across cases, evidence, threats, and timeline events.

### Case Management
- `GET /cases` : Retrieve all investigation cases.
- `POST /cases` : Create a new case (`case_number`, `title`, `investigator_name`, `severity`, etc.).
- `GET /cases/{case_id}` : Get full case details with associated evidence and logs.
- `PATCH /cases/{case_id}` : Update case status or notes.
- `DELETE /cases/{case_id}` : Archive or delete case.

### Evidence & Chain of Custody
- `POST /evidence/upload` : Upload file evidence with automatic SHA-256 computation.
- `GET /evidence` : List evidence artifacts.
- `GET /evidence/{evidence_id}` : Get evidence detail.
- `POST /evidence/{evidence_id}/verify` : Recalculate hash and verify integrity.
- `GET /evidence/{evidence_id}/chain-of-custody` : Get chain of custody records.
- `POST /evidence/{evidence_id}/chain-of-custody` : Record custody transfer.

### Log Analysis
- `POST /logs/upload` : Ingest and parse log files.
- `GET /logs/events` : Query parsed log events with filters.

### IP Investigation
- `POST /ip/investigate` : Enrich IP with geo, ASN, threat score, and forensic disclaimer.

### File Forensics & YARA
- `POST /forensics/analyze/{evidence_id}` : Run magic bytes check, entropy, string extraction, and YARA scan.

### Threat Detection
- `GET /threats/detections` : List all detected attacks mapped to MITRE ATT&CK.

### Timeline Reconstruction
- `GET /timeline/{case_id}` : Retrieve unified chronological event sequence.
- `POST /timeline/{case_id}/add-event` : Add manual milestone.

### Reports & AI Summary
- `POST /reports/generate/{case_id}` : Generate court-grade PDF report.
- `GET /reports/{report_id}/download` : Stream downloaded PDF.
- `POST /ai/summary/{case_id}` : Generate structured executive forensic brief.

