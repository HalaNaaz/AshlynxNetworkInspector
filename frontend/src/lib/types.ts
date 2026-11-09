/**
 * Ashlynx Network Inspector (ANI) - Type Definitions
 */

export interface ApiResponse<T> {
  success: boolean;
  message?: string;
  data: T;
  timestamp: string;
}

export interface ApiErrorDetail {
  code: string;
  detail: string;
}

export interface ApiErrorResponse {
  success: false;
  error: ApiErrorDetail;
  timestamp: string;
}

export interface HealthData {
  application_name: string;
  version: string;
  backend_status: string;
  operating_system: string;
  python_version: string;
}

export interface NetworkInterface {
  name: string;
  ipv4_address: string | null;
  mac_address: string | null;
  is_up: boolean | null;
  speed_mbps: number | null;
}

export interface NetworkInterfacesData {
  total_interfaces: number;
  interfaces: NetworkInterface[];
}

export interface NetworkSummaryData {
  bytes_sent: number;
  bytes_recv: number;
  packets_sent: number;
  packets_recv: number;
  errin: number;
  errout: number;
  dropin: number;
  dropout: number;
}

export interface ScannerStatusData {
  available: boolean;
  status: string;
  message: string;
  engine_version: string;
  supported_methods: string[];
  max_concurrent_targets: number;
  safe_mode_enforced: boolean;
}

export interface TrafficStatusData {
  available: boolean;
  status: string;
  message: string;
  engine_version: string;
  supported_protocols: string[];
  live_capture_ready: boolean;
  payload_storage_enabled: boolean;
}

// ==================== TCP SCANNER TYPES ====================
export interface PortScanResultItem {
  port: number;
  protocol: string;
  state: "OPEN" | "CLOSED" | "FILTERED" | "NO_RESPONSE" | "UNKNOWN";
  service: string;
  service_confidence: string;
  response_time_ms: number;
}

export interface PortScanRequest {
  target: string;
  ports?: number[];
  port_range?: string;
  preset?: string;
  timeout?: number;
  concurrency?: number;
}

export interface ScanExecutionResponse {
  scan_id: string;
  target: string;
  scan_type: string;
  status: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  total_ports: number;
  open_ports: number;
  closed_ports: number;
  filtered_or_unknown_ports: number;
  no_response_ports?: number;
  results: PortScanResultItem[];
}

export interface ScanValidationRequest {
  target: string;
  ports?: number[];
  port_range?: string;
  preset?: string;
}

export interface ScanValidationResponse {
  valid: boolean;
  target_ip: string | null;
  resolved_ports_count: number;
  resolved_ports_preview: number[];
  target_authorized: boolean;
  error: string | null;
}

export interface ScanHistoryItem {
  scan_id: string;
  target: string;
  scan_type: string;
  started_at: string;
  duration_seconds: number;
  total_ports: number;
  open_ports: number;
  status: string;
}

// ==================== UDP SCANNER TYPES ====================
export interface UdpScanResultItem {
  port: number;
  protocol: string;
  state: "OPEN" | "CLOSED" | "OPEN|FILTERED" | "UNKNOWN";
  service: string;
  service_confidence: string;
  response_time_ms: number;
  response_details?: string | null;
}

export interface UdpScanRequest {
  target: string;
  ports?: number[];
  port_range?: string;
  preset?: string;
  timeout?: number;
  concurrency?: number;
}

export interface UdpScanExecutionResponse {
  scan_id: string;
  target: string;
  scan_type: string;
  status: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  total_ports: number;
  open_ports: number;
  closed_ports: number;
  open_or_filtered_ports: number;
  unknown_ports: number;
  results: UdpScanResultItem[];
}

// ==================== HOST DISCOVERY TYPES ====================
export interface DiscoveredHostItem {
  ip_address: string;
  hostname: string | null;
  hostname_source?: string | null;
  discovery_method: string;
  status: "ONLINE" | "NO_RESPONSE" | "UNREACHABLE" | "UNKNOWN" | string;
  response_time_ms: number | null;
  mac_address: string | null;
  neighbor_state?: string | null;
  first_seen: string;
}

export interface HostDiscoveryRequest {
  cidr: string;
  method?: "AUTO" | "ICMP_ECHO" | "TCP_CONNECT" | "ARP";
  timeout?: number;
  max_hosts?: number;
  concurrency?: number;
}

export interface HostDiscoveryResponse {
  discovery_id: string;
  cidr: string;
  method: string;
  status: string;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  total_probed: number;
  online_hosts_count: number;
  hosts: DiscoveredHostItem[];
}

export interface DiscoveryValidationRequest {
  cidr: string;
}

export interface DiscoveryValidationResponse {
  valid: boolean;
  normalized_cidr: string | null;
  network_address: string | null;
  broadcast_address: string | null;
  total_usable_hosts: number;
  is_authorized: boolean;
  error: string | null;
}

export interface DiscoveryHistoryItem {
  discovery_id: string;
  cidr: string;
  method: string;
  started_at: string;
  duration_seconds: number;
  online_count: number;
  total_probed: number;
  status: string;
}

export interface HostDiscoveryStatusData {
  available: boolean;
  status: string;
  message: string;
  engine_version: string;
  supported_methods: string[];
  safe_mode_enforced: boolean;
}

// ==================== PHASE 4: PACKET CAPTURE TYPES ====================
export interface CaptureEnvironmentData {
  capability_status:
    | "CAPTURE_READY"
    | "NPCAP_MISSING"
    | "SCAPY_MISSING"
    | "PERMISSION_DENIED"
    | "NO_INTERFACES"
    | "CAPTURE_UNAVAILABLE";
  scapy_installed: boolean;
  scapy_version: string | null;
  npcap_installed: boolean;
  driver_service_running: boolean;
  can_capture: boolean;
  message: string;
  remediation_guide: string | null;
}

export interface CaptureInterfaceItem {
  id: string;
  name: string;
  description: string | null;
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  mac_address: string | null;
  is_up: boolean;
  speed_mbps: number | null;
  interface_type: "physical" | "virtual" | "loopback" | "unknown";
  can_capture: boolean;
}

export interface PacketMetadataItem {
  packet_id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  tcp_flags: string | null;
  dns_summary: string | null;
  interface: string;
  session_id: string;
}

export interface CaptureStatistics {
  total_captured: number;
  retained_in_buffer: number;
  dropped_packets: number;
  tcp_count: number;
  udp_count: number;
  icmp_count: number;
  arp_count: number;
  other_count: number;
  bytes_captured: number;
  capture_duration_seconds: number;
}

export interface CaptureStartRequest {
  interface_id: string;
  filter_preset?: string;
  custom_bpf_filter?: string;
  buffer_limit?: number;
}

export interface CaptureSessionResponse {
  session_id: string;
  interface_id: string;
  interface_name: string;
  status: "READY" | "CAPTURING" | "STOPPED" | "ERROR";
  filter_bpf: string;
  buffer_limit: number;
  started_at: string;
  stopped_at: string | null;
  duration_seconds: number;
  statistics: CaptureStatistics;
}

export interface CapturePacketsResponse {
  session_id: string;
  total_matching: number;
  offset: number;
  limit: number;
  packets: PacketMetadataItem[];
}

// ==================== PHASE 5: REAL-TIME TRAFFIC ANALYTICS ====================

export interface ProtocolDistributionItem {
  protocol: string;
  packet_count: number;
  byte_count: number;
  percentage: number;
}

export interface ApplicationProtocolItem {
  name: string;
  packet_count: number;
  byte_count: number;
  transport_layer: string;
  is_inferred?: boolean;
}

export interface ProtocolAnalyticsResponse {
  session_id: string;
  total_packets: number;
  total_bytes: number;
  transport_distribution: ProtocolDistributionItem[];
  application_breakdown: ApplicationProtocolItem[];
}

export interface BandwidthDataPoint {
  timestamp: string;
  window_seconds: number;
  bytes_total: number;
  packets_total: number;
  bits_per_second: number;
  packets_per_second: number;
  bytes_inbound: number;
  bytes_outbound: number;
  bytes_local: number;
  bytes_unknown: number;
}

export interface BandwidthAnalyticsResponse {
  session_id: string;
  current_window: number;
  current_bps: number;
  current_pps: number;
  peak_bps: number;
  peak_pps: number;
  average_packet_size_bytes: number;
  total_bytes: number;
  total_packets: number;
  data_points: BandwidthDataPoint[];
}

export interface TopTalkerItem {
  ip_address: string;
  hostname: string | null;
  packet_count: number;
  byte_count: number;
  bytes_sent: number;
  bytes_received: number;
  percentage: number;
  is_private: boolean;
  ip_category: string;
  is_local_host: boolean;
}

export interface TopTalkersResponse {
  session_id: string;
  total_unique_ips: number;
  top_sources: TopTalkerItem[];
  top_destinations: TopTalkerItem[];
  top_combined: TopTalkerItem[];
}

export interface ConnectionFlowItem {
  flow_id: string;
  protocol: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  service: string | null;
  packet_count: number;
  byte_count: number;
  first_seen: string;
  last_seen: string;
  duration_seconds: number;
  is_bidirectional: boolean;
  tcp_flags_observed: string[];
  state: "ACTIVE" | "ESTABLISHED" | "CLOSED" | "RESET" | "TIMED_OUT" | string;
}

export interface ConnectionsAnalyticsResponse {
  session_id: string;
  total_active_flows: number;
  total_flows_tracked: number;
  flows: ConnectionFlowItem[];
}

export interface DnsQueryItem {
  query_name: string;
  count: number;
  percentage: number;
}

export interface DnsQueryTypeItem {
  qtype: string;
  count: number;
}

export interface DnsResponseCodeItem {
  rcode: number;
  rcode_name: string;
  count: number;
}

export interface DnsAnalyticsResponse {
  session_id: string;
  total_dns_packets: number;
  total_queries: number;
  total_responses: number;
  unmatched_queries: number;
  top_domains: DnsQueryItem[];
  query_types: DnsQueryTypeItem[];
  response_codes: DnsResponseCodeItem[];
}

export interface TrafficTimelinePoint {
  timestamp: string;
  second_offset: number;
  pps: number;
  bps: number;
  tcp_bytes: number;
  udp_bytes: number;
  icmp_bytes: number;
  arp_bytes: number;
  other_bytes: number;
  inbound_bytes: number;
  outbound_bytes: number;
  local_bytes: number;
  unknown_bytes: number;
}

export interface TrafficTimelineResponse {
  session_id: string;
  total_seconds: number;
  points: TrafficTimelinePoint[];
}

export interface AnalyticsOverviewResponse {
  session_id: string;
  status: string;
  duration_seconds: number;
  total_packets: number;
  total_bytes: number;
  current_bps: number;
  current_pps: number;
  peak_bps: number;
  peak_pps: number;
  active_flows_count: number;
  dns_queries_count: number;
  top_protocol: string;
  top_talker_ip: string | null;
  inbound_bytes: number;
  outbound_bytes: number;
  local_bytes: number;
  unknown_bytes: number;
}

// ==================== PHASE 6: SECURITY INTELLIGENCE & ANOMALIES ====================

export interface SecurityEventItem {
  event_id: string;
  session_id: string;
  rule_id: string;
  detection_name: string;
  category: "PORT_SCAN" | "CONNECTION" | "TRAFFIC_SPIKE" | "DNS" | "SUSPICIOUS_SERVICE" | string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  risk_score: number;
  source_ip: string | null;
  destination_ip: string | null;
  target_port: number | null;
  related_ports: number[];
  related_ips: string[];
  first_seen: string;
  last_seen: string;
  observation_count: number;
  evidence_summary: string;
  detection_threshold: string;
  observed_value: string;
  recommended_action: string;
  status: "NEW" | "ACKNOWLEDGED" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE" | string;
  analyst_notes: string[];
  audit_trail: string[];
  correlation_id: string | null;
}

export interface SecurityStatusResponse {
  is_enabled: boolean;
  active_rules_count: number;
  baseline_status: "WARMING_UP" | "READY" | "ACTIVE" | string;
  baseline_samples: number;
  baseline_min_samples: number;
  total_events_detected: number;
  critical_events: number;
  high_events: number;
  medium_events: number;
  low_events: number;
  info_events: number;
  active_investigations: number;
  resolved_events: number;
}

export interface RuleConfigItem {
  rule_id: string;
  name: string;
  category: string;
  description: string;
  enabled: boolean;
  threshold: number;
  window_seconds: number;
  cooldown_seconds: number;
  severity_default: string;
  is_baseline_dependent?: boolean;
  web_port_threshold?: number;
}

export interface RuleUpdateRequest {
  enabled?: boolean;
  threshold?: number;
  web_port_threshold?: number;
  window_seconds?: number;
  cooldown_seconds?: number;
}

export interface EventStatusUpdateRequest {
  status: string;
  analyst_name?: string;
}

export interface AddEventNoteRequest {
  note: string;
  author?: string;
}

export interface SecurityEventsListResponse {
  total: number;
  session_id: string | null;
  events: SecurityEventItem[];
}

export interface TopThreatSourceItem {
  source_ip: string;
  event_count: number;
  highest_severity: string;
  associated_rules: string[];
}

export interface SecurityOverviewResponse {
  session_id: string | null;
  status: SecurityStatusResponse;
  category_breakdown: Record<string, number>;
  top_sources: TopThreatSourceItem[];
  recent_events: SecurityEventItem[];
}

export interface SecurityTimelinePoint {
  timestamp: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
}

export interface SecurityTimelineResponse {
  total_points: number;
  points: SecurityTimelinePoint[];
}

// ==================== REPORTING & ANALYTICS TYPES ====================
export type ReportType =
  | "system_baseline"
  | "tcp_scan"
  | "udp_scan"
  | "host_discovery"
  | "capture_session"
  | "traffic_analytics"
  | "security_events";

export type ReportFormat = "pdf" | "csv" | "json";

export interface ReportGenerateRequest {
  report_type: ReportType;
  report_format: ReportFormat;
  source_id?: string;
  title?: string;
  notes?: string;
  include_raw_details?: boolean;
}

export interface ReportMetadataItem {
  report_id: string;
  title: string;
  report_type: ReportType;
  report_format: ReportFormat;
  source_id: string | null;
  created_at: string;
  file_size_bytes: number;
  item_count: number;
  filename: string;
  download_url: string;
}

export interface ReportPreviewResponse {
  report_id: string;
  title: string;
  report_type: ReportType;
  report_format: ReportFormat;
  created_at: string;
  summary: Record<string, any>;
  headers: string[];
  preview_rows: any[][];
  total_rows: number;
  json_preview?: Record<string, any> | null;
  raw_content?: string | null;
}

export interface ReportSourceOption {
  source_type: ReportType;
  source_id: string;
  label: string;
  timestamp: string | null;
  item_count: number;
  is_latest: boolean;
}

export interface ReportSourcesResponse {
  sources: ReportSourceOption[];
}

// ==================== SYSTEM OVERVIEW ====================
export interface SystemOverview {
  health: HealthData | null;
  interfaces: NetworkInterface[];
  summary: NetworkSummaryData | null;
  scanner: ScannerStatusData | null;
  traffic: TrafficStatusData | null;
  discovery?: HostDiscoveryStatusData | null;
  latestScan?: ScanExecutionResponse | null;
  latestUdpScan?: UdpScanExecutionResponse | null;
  latestDiscovery?: HostDiscoveryResponse | null;
  loading: boolean;
  error: string | null;
}
