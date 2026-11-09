import sqlite3
from datetime import datetime, timezone
from typing import List, Optional

from backend.app.db.session import get_db
from backend.app.schemas.discovery import (
    DiscoveredHostItem,
    DiscoveryHistoryItem,
    HostDiscoveryResponse,
)


class DiscoveryRepository:
    """SQLite repository for persisting and querying subnet host discoveries."""

    @classmethod
    def save_discovery(
        cls,
        discovery: HostDiscoveryResponse,
        concurrency: int = 30,
        timeout: float = 1.0,
    ) -> None:
        """Persists a completed host discovery session and all probed host findings."""
        with get_db() as conn:
            cursor = conn.cursor()

            started_iso = discovery.started_at.isoformat() if discovery.started_at else datetime.now(timezone.utc).isoformat()
            completed_iso = discovery.completed_at.isoformat() if discovery.completed_at else datetime.now(timezone.utc).isoformat()
            no_response = max(0, discovery.total_probed - discovery.online_hosts_count)

            cursor.execute(
                """
                INSERT OR REPLACE INTO host_discoveries (
                    discovery_id, cidr, method, status, started_at, completed_at,
                    duration_seconds, total_probed, online_count, no_response_count,
                    concurrency, timeout_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    discovery.discovery_id,
                    discovery.cidr,
                    discovery.method,
                    discovery.status,
                    started_iso,
                    completed_iso,
                    discovery.duration_seconds,
                    discovery.total_probed,
                    discovery.online_hosts_count,
                    no_response,
                    concurrency,
                    timeout,
                ),
            )

            cursor.execute("DELETE FROM discovered_hosts WHERE discovery_id = ?", (discovery.discovery_id,))
            for host in discovery.hosts:
                first_seen_iso = host.first_seen.isoformat() if host.first_seen else started_iso
                cursor.execute(
                    """
                    INSERT INTO discovered_hosts (
                        discovery_id, ip_address, status, mac_address, hostname,
                        hostname_source, latency_ms, probe_method, neighbor_state, first_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        discovery.discovery_id,
                        host.ip_address,
                        host.status,
                        host.mac_address,
                        host.hostname,
                        host.hostname_source,
                        host.response_time_ms,
                        host.discovery_method,
                        host.neighbor_state,
                        first_seen_iso,
                    ),
                )

    @classmethod
    def get_discovery(cls, discovery_id: str) -> Optional[HostDiscoveryResponse]:
        """Retrieves a discovery session with all host findings from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM host_discoveries WHERE discovery_id = ?", (discovery_id,))
            row = cursor.fetchone()
            if not row:
                return None

            cursor.execute(
                "SELECT * FROM discovered_hosts WHERE discovery_id = ? ORDER BY ip_address ASC",
                (discovery_id,),
            )
            host_rows = cursor.fetchall()

            started_at = datetime.fromisoformat(row["started_at"])
            completed_at = datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else started_at

            hosts: List[DiscoveredHostItem] = []
            for h in host_rows:
                first_seen = datetime.fromisoformat(h["first_seen"]) if h["first_seen"] else started_at
                hosts.append(
                    DiscoveredHostItem(
                        ip_address=h["ip_address"],
                        hostname=h["hostname"],
                        hostname_source=h["hostname_source"],
                        discovery_method=h["probe_method"],
                        status=h["status"],
                        response_time_ms=h["latency_ms"],
                        mac_address=h["mac_address"],
                        neighbor_state=h["neighbor_state"],
                        first_seen=first_seen,
                    )
                )

            return HostDiscoveryResponse(
                discovery_id=row["discovery_id"],
                cidr=row["cidr"],
                method=row["method"],
                status=row["status"],
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=row["duration_seconds"],
                total_probed=row["total_probed"],
                online_hosts_count=row["online_count"],
                hosts=hosts,
            )

    @classmethod
    def list_history(cls, limit: int = 50) -> List[DiscoveryHistoryItem]:
        """Returns recent discovery job history from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT discovery_id, cidr, method, started_at, duration_seconds, online_count, total_probed, status
                FROM host_discoveries
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                DiscoveryHistoryItem(
                    discovery_id=r["discovery_id"],
                    cidr=r["cidr"],
                    method=r["method"],
                    started_at=datetime.fromisoformat(r["started_at"]),
                    duration_seconds=r["duration_seconds"],
                    online_count=r["online_count"],
                    total_probed=r["total_probed"],
                    status=r["status"],
                )
                for r in rows
            ]

    @classmethod
    def get_latest_discovery(cls) -> Optional[HostDiscoveryResponse]:
        """Returns the most recent discovery run from SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT discovery_id FROM host_discoveries ORDER BY started_at DESC LIMIT 1")
            row = cursor.fetchone()
            if not row:
                return None
            return cls.get_discovery(row["discovery_id"])

