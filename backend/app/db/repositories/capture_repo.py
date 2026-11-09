import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

from backend.app.db.session import get_db
from backend.app.schemas.analytics import AnalyticsOverviewResponse, ConnectionFlowItem
from backend.app.schemas.capture import CaptureSessionResponse, CaptureStatistics


class CaptureRepository:
    """SQLite repository for persisting packet capture sessions, telemetry, and connection flows."""

    @classmethod
    def save_capture_session(cls, session: CaptureSessionResponse) -> None:
        """Persists initial capture session details into SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            started_iso = session.started_at.isoformat() if session.started_at else datetime.now(timezone.utc).isoformat()
            stopped_iso = session.stopped_at.isoformat() if session.stopped_at else None

            cursor.execute(
                """
                INSERT OR REPLACE INTO capture_sessions (
                    session_id, interface_id, interface_name, status, filter_bpf,
                    buffer_limit, started_at, stopped_at, duration_seconds,
                    total_captured, bytes_captured, dropped_packets
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.interface_id,
                    session.interface_name,
                    session.status,
                    session.filter_bpf,
                    session.buffer_limit,
                    started_iso,
                    stopped_iso,
                    session.duration_seconds,
                    session.statistics.total_captured,
                    session.statistics.bytes_captured,
                    session.statistics.dropped_packets,
                ),
            )

    @classmethod
    def update_capture_session(
        cls,
        session_id: str,
        status: str,
        stopped_at: Optional[datetime],
        duration_seconds: float,
        total_captured: int,
        bytes_captured: int,
        dropped_packets: int = 0,
        session_digest: Optional[str] = None,
    ) -> None:
        """Updates capture session state, final metrics, and integrity digest upon session closure."""
        with get_db() as conn:
            cursor = conn.cursor()
            stopped_iso = stopped_at.isoformat() if stopped_at else datetime.now(timezone.utc).isoformat()
            cursor.execute(
                """
                UPDATE capture_sessions
                SET status = ?, stopped_at = ?, duration_seconds = ?,
                    total_captured = ?, bytes_captured = ?, dropped_packets = ?,
                    session_digest = COALESCE(?, session_digest)
                WHERE session_id = ?
                """,
                (
                    status,
                    stopped_iso,
                    duration_seconds,
                    total_captured,
                    bytes_captured,
                    dropped_packets,
                    session_digest,
                    session_id,
                ),
            )

    @classmethod
    def save_analytics_snapshot(
        cls,
        session_id: str,
        overview: AnalyticsOverviewResponse,
        protocol_distribution_json: Optional[str] = None,
        top_talkers_json: Optional[str] = None,
    ) -> None:
        """Persists frozen analytics overview snapshot for historical reporting."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO analytics_snapshots (
                    session_id, duration_seconds, total_packets, total_bytes,
                    peak_bps, peak_pps, active_flows_count, dns_queries_count,
                    top_protocol, top_talker_ip, inbound_bytes, outbound_bytes,
                    local_bytes, protocol_distribution_json, top_talkers_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    overview.duration_seconds,
                    overview.total_packets,
                    overview.total_bytes,
                    overview.peak_bps,
                    overview.peak_pps,
                    overview.active_flows_count,
                    overview.dns_queries_count,
                    overview.top_protocol,
                    overview.top_talker_ip,
                    overview.inbound_bytes,
                    overview.outbound_bytes,
                    overview.local_bytes,
                    protocol_distribution_json,
                    top_talkers_json,
                ),
            )

    @classmethod
    def save_connection_flows(cls, session_id: str, flows: List[ConnectionFlowItem]) -> None:
        """Persists connection flows into SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            for flow in flows:
                first_iso = flow.first_seen.isoformat() if flow.first_seen else datetime.now(timezone.utc).isoformat()
                last_iso = flow.last_seen.isoformat() if flow.last_seen else datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO connection_flows (
                        flow_id, session_id, protocol, src_ip, src_port, dst_ip, dst_port,
                        service, packet_count, byte_count, first_seen, last_seen,
                        duration_seconds, is_bidirectional, state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        flow.flow_id,
                        session_id,
                        flow.protocol,
                        flow.src_ip,
                        flow.src_port,
                        flow.dst_ip,
                        flow.dst_port,
                        flow.service,
                        flow.packet_count,
                        flow.byte_count,
                        first_iso,
                        last_iso,
                        flow.duration_seconds,
                        1 if flow.is_bidirectional else 0,
                        flow.state,
                    ),
                )

    @classmethod
    def list_capture_sessions(cls, limit: int = 50) -> List[Dict]:
        """Returns recent capture session summaries from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT session_id, interface_id, interface_name, status, started_at,
                       stopped_at, duration_seconds, total_captured, bytes_captured
                FROM capture_sessions
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    @classmethod
    def get_capture_session(cls, session_id: str) -> Optional[Dict]:
        """Retrieves a capture session row and its analytics snapshot."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM capture_sessions WHERE session_id = ?", (session_id,))
            session_row = cursor.fetchone()
            if not session_row:
                return None

            result = dict(session_row)
            cursor.execute("SELECT * FROM analytics_snapshots WHERE session_id = ?", (session_id,))
            snap_row = cursor.fetchone()
            if snap_row:
                result["analytics"] = dict(snap_row)
            return result

