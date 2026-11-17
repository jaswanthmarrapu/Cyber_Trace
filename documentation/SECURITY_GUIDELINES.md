# CyberTrace - Security Guidelines & Forensic Principles

## 1. Zero Execution Guarantee
- Uploaded evidence files are strictly stored in an isolated directory (`backend/uploads/`).
- Stored files are assigned random UUID identifiers on disk without executable permissions.
- File analysis is performed in passive memory mode (reading byte streams, computing entropy, regex scanning). No file is executed.

## 2. Evidence Integrity & Chain of Custody
- When evidence is received, the SHA-256 cryptographic hash is calculated immediately on the incoming stream.
- An initial Chain of Custody record is generated at the moment of acquisition.
- Hash recalculation is executed on-demand and logged permanently in the audit trail.

## 3. Responsible IP Attribution
- In digital forensics (ISO/IEC 27037 standards), an IP address is an indicator of network route or intermediate hop (NAT, VPN, Tor exit node, or compromised host).
- It must never be presented as proof of an individual's personal identity without corroborating telecommunications records, subscriber logs, and legal warrants.
- All IP intelligence outputs must display a standardized attribution caveat.

## 4. Size & Format Validation
- Uploads are bound to safe thresholds (e.g. 50MB per evidence item in web UI).
- Magic byte detection verifies the actual binary header against claimed file extensions.

