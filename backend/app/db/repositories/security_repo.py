import json
import sqlite3
from datetime import datetime, timezone
from typing import List, Optional

from backend.app.db.session import get_db
from backend.app.schemas.security import SecurityEventItem


class SecurityRepository:
    """SQLite repository for persisting and querying security events and alerts."""

    @classmethod
    def save_event(cls, event: SecurityEventItem) -> None:
        """Persists a detected security event."""
        with get_db() as conn:
            cursor = conn.cursor()
            first_iso = event.first_seen.isoformat() if event.first_seen else datetime.now(timezone.utc).isoformat()
            last_iso = event.last_seen.isoformat() if event.last_seen else datetime.now(timezone.utc).isoformat()
            notes_json = json.dumps(event.analyst_notes)
            trail_json = json.dumps(event.audit_trail)

            # Ensure foreign key session exists in capture_sessions
            if event.session_id:
                cursor.execute("SELECT 1 FROM capture_sessions WHERE session_id = ?", (event.session_id,))
                if not cursor.fetchone():
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO capture_sessions (
                            session_id, interface_id, interface_name, status, filter_bpf, buffer_limit, started_at
                        ) VALUES (?, 'mock', 'mock', 'STOPPED', '', 1000, ?)
                        """,
                        (event.session_id, first_iso),
                    )

            try:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO security_events (
                        event_id, session_id, rule_id, title, category, severity,
                        first_seen, last_seen, event_count, source_ip, destination_ip,
                        mitre_attack_id, summary, recommendation, state,
                        analyst_notes, audit_trail
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.session_id,
                        event.rule_id,
                        event.detection_name,
                        event.category,
                        event.severity,
                        first_iso,
                        last_iso,
                        event.observation_count,
                        event.source_ip,
                        event.destination_ip,
                        event.correlation_id or "",
                        event.evidence_summary,
                        event.recommended_action,
                        event.status,
                        notes_json,
                        trail_json,
                    ),
                )
            except sqlite3.OperationalError:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO security_events (
                        event_id, session_id, rule_id, title, category, severity,
                        first_seen, last_seen, event_count, source_ip, destination_ip,
                        mitre_attack_id, summary, recommendation, state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.session_id,
                        event.rule_id,
                        event.detection_name,
                        event.category,
                        event.severity,
                        first_iso,
                        last_iso,
                        event.observation_count,
                        event.source_ip,
                        event.destination_ip,
                        event.correlation_id or "",
                        event.evidence_summary,
                        event.recommended_action,
                        event.status,
                    ),
                )

    @classmethod
    def get_event(cls, event_id: str) -> Optional[SecurityEventItem]:
        """Queries a single security event from SQLite by event_id."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return cls._row_to_item(r)

    @classmethod
    def update_status(
        cls,
        event_id: str,
        new_status: str,
        audit_entry: Optional[str] = None,
    ) -> bool:
        """Updates lifecycle status and appends audit log in SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            if not row:
                return False

            trail: List[str] = []
            if "audit_trail" in row.keys() and row["audit_trail"]:
                try:
                    trail = json.loads(row["audit_trail"])
                except Exception:
                    trail = [row["audit_trail"]]
            if audit_entry:
                trail.append(audit_entry)

            trail_json = json.dumps(trail)
            try:
                cursor.execute(
                    "UPDATE security_events SET state = ?, audit_trail = ? WHERE event_id = ?",
                    (new_status, trail_json, event_id),
                )
            except sqlite3.OperationalError:
                cursor.execute(
                    "UPDATE security_events SET state = ? WHERE event_id = ?",
                    (new_status, event_id),
                )
            return True

    @classmethod
    def list_events(
        cls, session_id: Optional[str] = None, limit: int = 100
    ) -> List[SecurityEventItem]:
        """Queries security events from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            if session_id:
                cursor.execute(
                    """
                    SELECT * FROM security_events
                    WHERE session_id = ?
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (session_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM security_events
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            return [cls._row_to_item(r) for r in rows]

    @staticmethod
    def _row_to_item(r: sqlite3.Row) -> SecurityEventItem:
        keys = r.keys()
        notes: List[str] = []
        if "analyst_notes" in keys and r["analyst_notes"]:
            try:
                notes = json.loads(r["analyst_notes"])
            except Exception:
                notes = [r["analyst_notes"]]
        trail: List[str] = []
        if "audit_trail" in keys and r["audit_trail"]:
            try:
                trail = json.loads(r["audit_trail"])
            except Exception:
                trail = [r["audit_trail"]]

        return SecurityEventItem(
            event_id=r["event_id"],
            session_id=r["session_id"],
            rule_id=r["rule_id"],
            detection_name=r["title"],
            category=r["category"],
            severity=r["severity"],
            confidence=0.9,
            risk_score=75 if r["severity"] in ("CRITICAL", "HIGH") else 35,
            source_ip=r["source_ip"],
            destination_ip=r["destination_ip"],
            first_seen=datetime.fromisoformat(r["first_seen"]),
            last_seen=datetime.fromisoformat(r["last_seen"]),
            observation_count=r["event_count"],
            evidence_summary=r["summary"],
            detection_threshold="default",
            observed_value="flagged",
            recommended_action=r["recommendation"] or "Inspect source IP traffic",
            status=r["state"],
            analyst_notes=notes,
            audit_trail=trail,
        )
