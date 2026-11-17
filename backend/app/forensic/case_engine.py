"""
CyberTrace Investigation Case Management Engine
Standards: ISO/IEC 27037 & NIST SP 800-86 Digital Evidence Handling.

Features:
1. Create investigation cases.
2. Generate unique case IDs (e.g. CT-YYYYMMDD-XXXX or UUID).
3. Add case titles and descriptions.
4. Assign investigators.
5. Attach evidence files.
6. Add investigation notes (with timestamp and investigator tag).
7. Track case status:
   - Open
   - Under Investigation
   - Evidence Review
   - Completed
8. Display case history / activity audit trail.
9. Link suspicious events to cases.
10. Generate comprehensive case summaries.
Maintain an audit trail for important case activities.
"""

import sqlite3
import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

VALID_CASE_STATUSES = [
    "Open",
    "Under Investigation",
    "Evidence Review",
    "Completed"
]

def generate_unique_case_number() -> str:
    """Generate human-readable unique case number, e.g. CT-2026-XXXX."""
    date_prefix = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_suffix = uuid.uuid4().hex[:6].upper()
    return f"CT-{date_prefix}-{random_suffix}"

def init_case_management_tables(db_path: str):
    """Ensure database schema supports case management, notes, audit trails, and event links."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        case_number TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        investigator_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Open',
        severity TEXT NOT NULL DEFAULT 'Medium',
        incident_type TEXT NOT NULL DEFAULT 'Malware Infection',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        closed_at TEXT
    );
    """)

    # Schema migration safeguard for pre-existing tables
    cur.execute("PRAGMA table_info(cases)")
    existing_cols = [row[1] for row in cur.fetchall()]
    if "updated_at" not in existing_cols:
        cur.execute("ALTER TABLE cases ADD COLUMN updated_at TEXT")
    if "closed_at" not in existing_cols:
        cur.execute("ALTER TABLE cases ADD COLUMN closed_at TEXT")

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS case_notes (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        author TEXT NOT NULL,
        note_text TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS case_audit_log (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        action TEXT NOT NULL,
        performed_by TEXT NOT NULL,
        details TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS case_event_links (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        event_summary TEXT NOT NULL,
        linked_by TEXT NOT NULL,
        linked_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );
    """)
    conn.commit()
    conn.close()

def log_case_audit_action(
    db_path: str,
    case_id: str,
    action: str,
    performed_by: str,
    details: str
) -> str:
    """Record an immutable audit log entry for case activities."""
    init_case_management_tables(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    log_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    cur.execute("""
    INSERT INTO case_audit_log (id, case_id, action, performed_by, details, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (log_id, case_id, action, performed_by, details, now_iso))
    conn.commit()
    conn.close()
    return log_id

def create_investigation_case(
    db_path: str,
    title: str,
    description: Optional[str] = "",
    investigator_name: str = "Senior Forensic Examiner",
    severity: str = "Medium",
    incident_type: str = "Data Breach",
    case_number: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new case with unique ID and log audit entry."""
    init_case_management_tables(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    case_id = str(uuid.uuid4())
    case_num = case_number or generate_unique_case_number()
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute("""
    INSERT INTO cases (
        id, case_number, title, description, investigator_name,
        status, severity, incident_type, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_id,
        case_num,
        title,
        description or "",
        investigator_name,
        "Open",
        severity,
        incident_type,
        now_iso,
        now_iso
    ))
    conn.commit()
    conn.close()

    # Record Audit Trail
    log_case_audit_action(
        db_path,
        case_id=case_id,
        action="Case Created",
        performed_by=investigator_name,
        details=f"Created case {case_num}: '{title}' [Severity: {severity}, Type: {incident_type}]"
    )

    return {
        "id": case_id,
        "case_number": case_num,
        "title": title,
        "description": description or "",
        "investigator_name": investigator_name,
        "status": "Open",
        "severity": severity,
        "incident_type": incident_type,
        "created_at": now_iso,
        "updated_at": now_iso
    }

def update_case_lifecycle_status(
    db_path: str,
    case_id: str,
    new_status: str,
    investigator_name: str = "Senior Forensic Examiner",
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """Update case status ensuring it matches one of the 4 valid statuses and logs audit trail."""
    init_case_management_tables(db_path)
    if new_status not in VALID_CASE_STATUSES:
        raise ValueError(f"Invalid case status '{new_status}'. Must be one of: {', '.join(VALID_CASE_STATUSES)}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise LookupError(f"Case with ID/Number '{case_id}' not found.")

    actual_id = row["id"]
    old_status = row["status"]
    now_iso = datetime.now(timezone.utc).isoformat()
    closed_at = now_iso if new_status == "Completed" else None

    cur.execute("""
    UPDATE cases
    SET status = ?, updated_at = ?, closed_at = ?
    WHERE id = ?
    """, (new_status, now_iso, closed_at, actual_id))
    conn.commit()
    conn.close()

    # Log audit entry
    details = f"Status transitioned from '{old_status}' to '{new_status}'."
    if notes:
        details += f" Notes: {notes}"
    log_case_audit_action(
        db_path,
        case_id=actual_id,
        action="Status Changed",
        performed_by=investigator_name,
        details=details
    )

    return {
        "id": actual_id,
        "case_number": row["case_number"],
        "old_status": old_status,
        "status": new_status,
        "updated_at": now_iso
    }

def assign_case_investigator(
    db_path: str,
    case_id: str,
    new_investigator: str,
    assigned_by: str = "Lead Forensic Examiner"
) -> Dict[str, Any]:
    """Reassign or assign investigator to an active case."""
    init_case_management_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise LookupError(f"Case '{case_id}' not found.")

    actual_id = row["id"]
    prev_investigator = row["investigator_name"]
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute("""
    UPDATE cases SET investigator_name = ?, updated_at = ? WHERE id = ?
    """, (new_investigator, now_iso, actual_id))
    conn.commit()
    conn.close()

    log_case_audit_action(
        db_path,
        case_id=actual_id,
        action="Investigator Assigned",
        performed_by=assigned_by,
        details=f"Assigned primary investigator to '{new_investigator}' (previously '{prev_investigator}')."
    )

    return {
        "id": actual_id,
        "case_number": row["case_number"],
        "previous_investigator": prev_investigator,
        "investigator_name": new_investigator,
        "updated_at": now_iso
    }

def add_case_investigation_note(
    db_path: str,
    case_id: str,
    author: str,
    note_text: str
) -> Dict[str, Any]:
    """Attach an investigator's analytical notes to the case."""
    init_case_management_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise LookupError(f"Case '{case_id}' not found.")

    actual_id = row["id"]
    note_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute("""
    INSERT INTO case_notes (id, case_id, author, note_text, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (note_id, actual_id, author, note_text, now_iso))
    conn.commit()
    conn.close()

    log_case_audit_action(
        db_path,
        case_id=actual_id,
        action="Investigation Note Added",
        performed_by=author,
        details=f"Note recorded ({len(note_text)} chars): {note_text[:80]}..."
    )

    return {
        "id": note_id,
        "case_id": actual_id,
        "author": author,
        "note_text": note_text,
        "created_at": now_iso
    }

def link_suspicious_event_to_case(
    db_path: str,
    case_id: str,
    event_id: str,
    event_type: str,
    event_summary: str,
    linked_by: str = "Senior Forensic Examiner"
) -> Dict[str, Any]:
    """Link a suspicious log event, alert, or IP finding to an investigation case."""
    init_case_management_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise LookupError(f"Case '{case_id}' not found.")

    actual_id = row["id"]
    link_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute("""
    INSERT INTO case_event_links (id, case_id, event_id, event_type, event_summary, linked_by, linked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (link_id, actual_id, event_id, event_type, event_summary, linked_by, now_iso))
    conn.commit()
    conn.close()

    log_case_audit_action(
        db_path,
        case_id=actual_id,
        action="Suspicious Event Linked",
        performed_by=linked_by,
        details=f"Linked {event_type} '{event_id}': {event_summary}"
    )

    return {
        "id": link_id,
        "case_id": actual_id,
        "event_id": event_id,
        "event_type": event_type,
        "event_summary": event_summary,
        "linked_by": linked_by,
        "linked_at": now_iso
    }

def get_case_audit_history(db_path: str, case_id: str) -> List[Dict[str, Any]]:
    """Retrieve full chronological audit trail for a case."""
    init_case_management_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        return []

    actual_id = row["id"]
    cur.execute("""
    SELECT * FROM case_audit_log WHERE case_id = ? ORDER BY timestamp DESC
    """, (actual_id,))
    logs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return logs

def generate_case_summary_dossier(db_path: str, case_id: str) -> Dict[str, Any]:
    """Generate a comprehensive case summary with statistics, attached evidence, notes, and events."""
    init_case_management_tables(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM cases WHERE id = ? OR case_number = ?", (case_id, case_id))
    case_row = cur.fetchone()
    if not case_row:
        conn.close()
        raise LookupError(f"Case '{case_id}' not found.")

    case_data = dict(case_row)
    actual_id = case_data["id"]

    # 1. Attached Evidence
    cur.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY upload_timestamp DESC", (actual_id,))
    evidence_list = [dict(r) for r in cur.fetchall()]

    # 2. Case Notes
    cur.execute("SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at DESC", (actual_id,))
    notes_list = [dict(r) for r in cur.fetchall()]

    # 3. Linked Suspicious Events
    cur.execute("SELECT * FROM case_event_links WHERE case_id = ? ORDER BY linked_at DESC", (actual_id,))
    linked_events = [dict(r) for r in cur.fetchall()]

    # 4. Audit Log
    cur.execute("SELECT * FROM case_audit_log WHERE case_id = ? ORDER BY timestamp DESC", (actual_id,))
    audit_trail = [dict(r) for r in cur.fetchall()]

    # 5. Timeline Events Count
    cur.execute("SELECT COUNT(*) as count FROM timeline_events WHERE case_id = ?", (actual_id,))
    timeline_count = cur.fetchone()["count"]

    # 6. Log Events Count
    cur.execute("SELECT COUNT(*) as count FROM log_events WHERE case_id = ?", (actual_id,))
    log_count = cur.fetchone()["count"]

    conn.close()

    summary = {
        "case": case_data,
        "metrics": {
            "total_attached_evidence": len(evidence_list),
            "total_investigation_notes": len(notes_list),
            "total_linked_suspicious_events": len(linked_events),
            "total_audit_events": len(audit_trail),
            "total_timeline_events": timeline_count,
            "total_log_events": log_count
        },
        "evidence": evidence_list,
        "notes": notes_list,
        "linked_events": linked_events,
        "audit_trail": audit_trail,
        "summary_narrative": (
            f"Case {case_data['case_number']} ('{case_data['title']}') is currently '{case_data['status']}' "
            f"under the supervision of {case_data['investigator_name']}. The incident is categorized as "
            f"'{case_data['incident_type']}' with {case_data['severity']} severity. "
            f"To date, {len(evidence_list)} evidence artifacts have been securely vaulted, "
            f"{len(linked_events)} suspicious events linked, and {len(notes_list)} analytical notes documented."
        )
    }
    return summary
