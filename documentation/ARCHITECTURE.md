# CyberTrace - System Architecture

CyberTrace is an end-to-end digital forensics and cyber incident investigation platform.

## Architecture Overview

```text
[ React Frontend SPA (Tailwind + Recharts + Lucide) ]
                      |
                      |  REST API / Multipart Uploads
                      v
         [ FastAPI Application Gateway ]
         /          |          \          \
        v           v           v          v
   [Forensic]   [Threat]    [Timeline]   [ReportLab]
   [Hasher  ]   [Detector]  [Engine  ]   [PDF Gen  ]
        \           |           /          /
         v          v          v          v
     [ SQLite DB via SQLAlchemy ] + [ Secure Evidence Vault ]
```

## Core Modules

1. **Dashboard**: High-level telemetry, attack distribution, case loads, severity breakdown.
2. **Evidence Collection**: Ingestion into isolated storage with SHA-256/SHA-1/MD5 calculation.
3. **Evidence Integrity Verification**: Real-time hash comparison detecting tampering.
4. **Chain of Custody (COC)**: Immutable audit history for evidence transfers and examinations.
5. **Log Analysis**: Multi-format log parser (Syslog, Nginx/Apache, Windows Event, Suricata).
6. **Threat Detection**: Automated detection of Brute Force, SQL Injection, XSS, Path Traversal, Port Scans.
7. **IP Investigation**: Geolocation, ASN, RFC 1918 classification, and forensic attribution caveats.
8. **File Forensics**: Static analysis, Shannon entropy, magic bytes verification, printable string extraction, and YARA rule matching.
9. **Attack Timeline Reconstruction**: Chronological unification of log, file, and network milestones.
10. **Investigation Case Management**: Case lifecycle (Open -> Investigating -> Closed) with artifact binding.
11. **Automated PDF Report Generation**: Court-grade forensic reports via ReportLab.
12. **AI-Assisted Investigation Summary**: Executive narrative, attack vector identification, and containment suggestions.

