import sqlite3
from backend.app.core.logging import logger
from backend.app.db.session import get_db

CURRENT_SCHEMA_VERSION = 1

SCHEMA_V1_SQL = """
-- 1. TCP and UDP Port Scan Executions
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL,                        -- 'TCP_CONNECT' | 'UDP_DGRAM'
    target TEXT NOT NULL,
    status TEXT NOT NULL,                           -- 'running' | 'completed' | 'failed'
    started_at TEXT NOT NULL,                       -- ISO 8601 UTC
    completed_at TEXT,                              -- ISO 8601 UTC
    duration_seconds REAL NOT NULL DEFAULT 0.0,
    total_ports INTEGER NOT NULL DEFAULT 0,
    open_ports INTEGER NOT NULL DEFAULT 0,
    closed_ports INTEGER NOT NULL DEFAULT 0,
    filtered_ports INTEGER NOT NULL DEFAULT 0,
    no_response_ports INTEGER NOT NULL DEFAULT 0,
    concurrency INTEGER NOT NULL DEFAULT 100,
    timeout_seconds REAL NOT NULL DEFAULT 1.0,
    session_digest TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);

-- 2. Port Finding Details
CREATE TABLE IF NOT EXISTS scan_findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,                         -- 'TCP' | 'UDP'
    state TEXT NOT NULL,                            -- 'OPEN' | 'CLOSED' | 'FILTERED' | 'OPEN|FILTERED' | 'NO_RESPONSE'
    service_name TEXT,
    latency_ms REAL,
    banner TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_state ON scan_findings(state);

-- 3. Subnet Host Discoveries
CREATE TABLE IF NOT EXISTS host_discoveries (
    discovery_id TEXT PRIMARY KEY,
    cidr TEXT NOT NULL,
    method TEXT NOT NULL,                           -- 'AUTO' | 'ARP' | 'ICMP' | 'TCP'
    status TEXT NOT NULL,                           -- 'running' | 'completed' | 'failed'
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_seconds REAL NOT NULL DEFAULT 0.0,
    total_probed INTEGER NOT NULL DEFAULT 0,
    online_count INTEGER NOT NULL DEFAULT 0,
    no_response_count INTEGER NOT NULL DEFAULT 0,
    concurrency INTEGER NOT NULL DEFAULT 30,
    timeout_seconds REAL NOT NULL DEFAULT 1.0,
    session_digest TEXT
);

CREATE INDEX IF NOT EXISTS idx_discoveries_started_at ON host_discoveries(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_discoveries_cidr ON host_discoveries(cidr);

-- 4. Discovered Hosts
CREATE TABLE IF NOT EXISTS discovered_hosts (
    host_id INTEGER PRIMARY KEY AUTOINCREMENT,
    discovery_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    status TEXT NOT NULL,                           -- 'ONLINE' | 'NO_RESPONSE' | 'UNREACHABLE' | 'UNKNOWN'
    mac_address TEXT,
    vendor TEXT,
    hostname TEXT,
    hostname_source TEXT,                           -- 'DNS_PTR' | 'HOSTS_FILE' | 'UNRESOLVED'
    latency_ms REAL,
    probe_method TEXT NOT NULL,                     -- 'ARP' | 'ICMP' | 'TCP'
    neighbor_state TEXT,
    first_seen TEXT NOT NULL,
    FOREIGN KEY(discovery_id) REFERENCES host_discoveries(discovery_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_discovered_hosts_discovery_id ON discovered_hosts(discovery_id);
CREATE INDEX IF NOT EXISTS idx_discovered_hosts_ip ON discovered_hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_discovered_hosts_status ON discovered_hosts(status);

-- 5. Passive Capture Sessions
CREATE TABLE IF NOT EXISTS capture_sessions (
    session_id TEXT PRIMARY KEY,
    interface_id TEXT NOT NULL,
    interface_name TEXT NOT NULL,
    status TEXT NOT NULL,                           -- 'CAPTURING' | 'STOPPED' | 'ERROR'
    filter_bpf TEXT,
    buffer_limit INTEGER NOT NULL DEFAULT 1000,
    started_at TEXT NOT NULL,
    stopped_at TEXT,
    duration_seconds REAL NOT NULL DEFAULT 0.0,
    total_captured INTEGER NOT NULL DEFAULT 0,
    bytes_captured INTEGER NOT NULL DEFAULT 0,
    dropped_packets INTEGER NOT NULL DEFAULT 0,
    session_digest TEXT
);

CREATE INDEX IF NOT EXISTS idx_capture_sessions_started_at ON capture_sessions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_capture_sessions_status ON capture_sessions(status);

-- 6. Frozen Analytics Telemetry Snapshots
CREATE TABLE IF NOT EXISTS analytics_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    duration_seconds REAL NOT NULL,
    total_packets INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    peak_bps REAL NOT NULL DEFAULT 0.0,
    peak_pps REAL NOT NULL DEFAULT 0.0,
    active_flows_count INTEGER NOT NULL DEFAULT 0,
    dns_queries_count INTEGER NOT NULL DEFAULT 0,
    top_protocol TEXT,
    top_talker_ip TEXT,
    inbound_bytes INTEGER NOT NULL DEFAULT 0,
    outbound_bytes INTEGER NOT NULL DEFAULT 0,
    local_bytes INTEGER NOT NULL DEFAULT 0,
    protocol_distribution_json TEXT,
    top_talkers_json TEXT,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(session_id) ON DELETE CASCADE
);

-- 7. Parsed DNS Records
CREATE TABLE IF NOT EXISTS dns_records (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    transaction_id TEXT,
    record_type TEXT NOT NULL,                      -- 'QUERY' | 'RESPONSE'
    query_name TEXT NOT NULL,
    qtype TEXT NOT NULL,
    rcode INTEGER,
    latency_ms REAL,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dns_records_session_id ON dns_records(session_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_query_name ON dns_records(query_name);

-- 8. Connection Flows (Layer-4 5-Tuple)
CREATE TABLE IF NOT EXISTS connection_flows (
    flow_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    protocol TEXT NOT NULL,                         -- 'TCP' | 'UDP' | 'ICMP'
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    service TEXT,
    packet_count INTEGER NOT NULL DEFAULT 0,
    byte_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    duration_seconds REAL NOT NULL DEFAULT 0.0,
    is_bidirectional INTEGER NOT NULL DEFAULT 0,
    state TEXT,                                     -- 'ESTABLISHED', 'CLOSED', etc.
    FOREIGN KEY(session_id) REFERENCES capture_sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_connection_flows_session_id ON connection_flows(session_id);
CREATE INDEX IF NOT EXISTS idx_connection_flows_endpoints ON connection_flows(src_ip, dst_ip);

-- 9. Security Events & Alerts
CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,                         -- 'PORT_SCAN', 'DNS_ANOMALY', etc.
    severity TEXT NOT NULL,                         -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1,
    source_ip TEXT,
    destination_ip TEXT,
    mitre_attack_id TEXT,
    summary TEXT NOT NULL,
    recommendation TEXT,
    state TEXT NOT NULL DEFAULT 'ACTIVE',           -- 'ACTIVE', 'RESOLVED', 'DISMISSED'
    analyst_notes TEXT DEFAULT '[]',
    audit_trail TEXT DEFAULT '[]',
    FOREIGN KEY(session_id) REFERENCES capture_sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_events_session_id ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_last_seen ON security_events(last_seen DESC);

-- 10. Exported Reports Registry
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    report_type TEXT NOT NULL,                      -- 'tcp_scan', 'udp_scan', 'host_discovery', etc.
    report_format TEXT NOT NULL,                    -- 'pdf', 'csv', 'json'
    source_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    item_count INTEGER NOT NULL,
    filename TEXT NOT NULL UNIQUE,
    session_digest TEXT NOT NULL,
    raw_payload_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_source ON reports(source_id);

-- 11. Interface Snapshots & Application Settings
CREATE TABLE IF NOT EXISTS interface_snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    guid TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    mac_address TEXT,
    ipv4_addresses_json TEXT,
    ipv6_addresses_json TEXT,
    speed_mbps INTEGER,
    interface_type TEXT,
    can_capture INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def init_db(conn: sqlite3.Connection) -> None:
    """Initializes the database schema and executes version migrations."""
    cursor = conn.cursor()
    cursor.execute("PRAGMA user_version;")
    version_row = cursor.fetchone()
    current_version = version_row[0] if version_row else 0

    if current_version < 1:
        logger.info("Initializing SQLite database schema v%d...", CURRENT_SCHEMA_VERSION)
        cursor.executescript(SCHEMA_V1_SQL)
        cursor.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION};")
        conn.commit()
        logger.info("SQLite database schema initialized successfully (user_version=%d).", CURRENT_SCHEMA_VERSION)
    else:
        logger.debug("Database schema is up to date (version=%d).", current_version)

    # Ensure analyst_notes and audit_trail columns exist in security_events for existing DBs
    for col in ("analyst_notes", "audit_trail"):
        try:
            cursor.execute(f"ALTER TABLE security_events ADD COLUMN {col} TEXT DEFAULT '[]'")
            conn.commit()
        except sqlite3.OperationalError:
            pass

