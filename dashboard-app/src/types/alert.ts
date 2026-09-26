// Mirrors src/alert_schema.py's Alert model and adds enterprise SOC Dashboards types

export interface FlowIdentifier {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
}

export interface MitreAttack {
  tactic: string;
  technique_id: string;
  technique_name: string;
}

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatClass =
  | 'VOLUMETRIC_DDOS'
  | 'SLOWLORIS'
  | 'C2_BEACONING'
  | 'DGA_DOMAIN'
  | 'DNS_TUNNELING'
  | 'ENCRYPTED_MALWARE'
  | 'RECONNAISSANCE'
  | 'DATA_EXFILTRATION'
  | 'ICS_UNAUTHORIZED_CONTROL_COMMAND'
  | 'MALICIOUS_FILE_DETECTED'
  | 'NETWORK_INTRUSION_ATTEMPT';

export interface Alert {
  alert_id: string;
  timestamp: number;
  severity: Severity;
  confidence_score: number;
  threat_class: ThreatClass;
  flow_identifier: FlowIdentifier;
  mitre_attack: MitreAttack;
  evidence: Record<string, unknown>;
  forensics: Record<string, unknown>;
  detection_mode: 'rule' | 'xgboost' | 'isolation_forest';
  model_scores?: Record<string, number> | null;
  top_contributing_features?: Array<Record<string, unknown>> | null;
}

export interface PacketSummary {
  conn_flows: number;
  dns_queries: number;
  tls_sessions: number;
  modbus_records: number;
  dnp3_records?: number;
  http_requests?: number;
  kerberos_events?: number;
  cip_events?: number;
  files_yara_scanned: number | null;
}

export interface ToolCoverage {
  ran?: boolean;
  records_parsed?: number;
  records_processed?: number;
  files_scanned?: number;
  alerts_fired?: number;
}

export interface AnalysisResponse {
  analysis_id: string;
  inspectable?: boolean;
  capture_bytes?: number;
  filename: string;
  parser_used: 'zeek' | 'scapy_fallback';
  packet_summary: PacketSummary;
  pipeline_coverage?: Record<string, ToolCoverage>;
  timing: { parse_seconds: number; detection_seconds: number };
  models_active: string[];
  yara_active: boolean;
  suricata_alert_count?: number;
  alert_count: number;
  severity_counts: Partial<Record<Severity, number>>;
  threat_class_counts: Partial<Record<ThreatClass, number>>;
  detection_mode_counts: Partial<Record<'rule' | 'xgboost' | 'isolation_forest', number>>;
  alerts: Alert[];
}

export interface IndexField {
  name: string;
  type: 'string' | 'number' | 'date' | 'ip' | 'boolean';
  searchable: boolean;
  aggregatable: boolean;
  sample: string;
}

export interface IndexPattern {
  id: string;
  title: string;
  timeFieldName: string;
  description: string;
  fields: IndexField[];
}

export interface PipelineEngine {
  id: string;
  name: string;
  threat_class: string;
  algorithm: string;
  protocol: string;
  status: 'active' | 'standby' | 'degraded';
}

export interface PipelineService {
  name: string;
  status: 'active' | 'connected' | 'standby' | 'degraded';
  type: string;
  details: string;
}

export interface PipelineStatus {
  services: Record<string, PipelineService>;
  engines: PipelineEngine[];
}

export interface TemporalRange {
  label: string;
  startIso: string;
  endIso: string;
  isCustom: boolean;
  refreshSeconds: number;
}

export type ActiveNavTab =
  | 'dashboard'
  | 'discover'
  | 'visualizers'
  | 'index_patterns'
  | 'ai_models'
  | 'json_studio'
  | 'upload'
  | 'packets'
  | 'live_capture';

export type LiveTab = 'overview' | 'alerts' | 'hosts' | 'flows' | 'packets' | 'capture';
export type Workspace = 'pcap' | 'live';

// ── Live capture (src/api/live_capture.py) ──────────────────────────────
export interface CaptureInterface {
  name: string;
  description: string;
  mac: string;
  ipv4: string[];
  ipv6: string[];
  is_up: boolean;
  is_loopback: boolean;
  speed_mbps: number;
  mtu: number;
  capture_name: string;
  kernel_capture: boolean;
}

export interface CaptureThroughput {
  pps?: number;
  mbps?: number;
  peak_pps?: number;
  peak_mbps?: number;
  kernel_drop_total?: number;
  kernel_drop_delta?: number;
  high_speed?: boolean;
  high_speed_flags?: string[];
}

export interface CaptureLatency {
  samples?: number;
  p50_ms?: number | null;
  p95_ms?: number | null;
  p99_ms?: number | null;
  max_ms?: number | null;
}

export interface CaptureStatus {
  running: boolean;
  interface?: string;
  capture_name?: string;
  bpf?: string | null;
  buffer_mb?: number;
  promisc?: boolean;
  backend?: string | null;
  kernel_level?: boolean;
  kernel_buffer_set?: boolean | null;
  uptime_s?: number;
  queue_depth?: number;
  active_flows?: number;
  dropped?: number;
  alerts?: number;
  snapshot_interval_s?: number;
  ml_families?: string[];
  throughput?: CaptureThroughput;
  detection_latency?: CaptureLatency;
  assembler?: Record<string, number>;
  finished?: boolean;
  native?: boolean;
  source?: 'interface' | 'pcap-replay' | 'python';
  capture?: CaptureEngineStats | null;
  capture_error?: string | null;
  num_workers?: number;
}

export interface CaptureEngineStats {
  packets: number; recv: number; bytes: number; non_ip: number; flows_seen: number;
  active_flows: number; hosts: number; hosts_dropped: number;
  dns: number; ssl: number; http: number; modbus: number; dnp3: number; conn: number;
  kernel_recv: number; kernel_drop: number; if_drop: number;
  records_dropped: number; pending_records: number; unsupported_frames: number;
  ring_first_id: number; ring_last_id: number; ring_len: number;
  last_ts: number; loops_done: number; running: boolean; finished: boolean;
}

// ── Live dashboard data ─────────────────────────────────────────────────
export interface SeriesPoint {
  t: number; pps: number; mbps: number; flows: number; pending: number;
  kdrop: number; alerts: number; udrop: number;
}

export interface HostRow {
  ip: string; mac: string | null; first: number; last: number;
  tx_pkts: number; rx_pkts: number; tx_bytes: number; rx_bytes: number;
  tcp: number; udp: number; other: number; via_arp: boolean;
  local: boolean; gateway_for_remote: boolean;
}

export interface ProtoRow { name: string; packets: number; bytes: number }

export interface FlowRow {
  uid: string; ts: number; 'id.orig_h': string; 'id.orig_p': number;
  'id.resp_h': string; 'id.resp_p': number; proto: string; duration: number;
  orig_bytes: number; resp_bytes: number; orig_pkts: number; resp_pkts: number;
}

export interface AlertSummary {
  alerts_by_class: Record<string, number>;
  alerts_by_severity: Record<string, number>;
}

// ── Packet inspector ────────────────────────────────────────────────────
export interface PacketRow {
  id: number; ts: number; len: number; proto: string;
  src: string; dst: string; sport: number; dport: number; info: string;
}

export interface PacketLayerField { name: string; value: string }
export interface PacketLayer { name: string; start: number; end: number; fields: PacketLayerField[] }
export interface PacketDetail {
  id: number; ts: number; wire_len: number; captured: number; truncated?: boolean;
  layers: PacketLayer[]; hex: Array<{ off: number; hex: string; ascii: string }>; error?: string;
}

