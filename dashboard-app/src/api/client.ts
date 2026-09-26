import type {
  AnalysisResponse,
  PipelineStatus,
  IndexPattern,
  CaptureInterface,
  CaptureStatus,
  Alert,
  SeriesPoint,
  HostRow,
  ProtoRow,
  FlowRow,
  AlertSummary,
  PacketRow,
  PacketDetail,
} from '../types/alert';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000';
// Live capture can run as its own host-side service (see
// `python -m src.capture.live_agent serve`). Defaults to the main API.
const LIVE_DEFAULT = import.meta.env.VITE_LIVE_API_BASE ?? 'http://localhost:8100';
const LIVE_KEY = 'stealthtap-live-base';
/** The live sensor endpoint. Defaults to this server; can be pointed at a separate (e.g. elevated) sensor process. */
export function liveBase(): string {
  try { return localStorage.getItem(LIVE_KEY) ?? LIVE_DEFAULT; } catch { return LIVE_DEFAULT; }
}
export function setLiveBase(url: string | null): void {
  try { if (url === null) localStorage.removeItem(LIVE_KEY); else localStorage.setItem(LIVE_KEY, url.replace(/\/+$/, '')); } catch { /* ignore */ }
}
export const LIVE_DEFAULT_BASE = LIVE_DEFAULT;

export class ApiError extends Error {}

async function j<T>(resp: Response, fallbackMsg: string): Promise<T> {
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new ApiError(typeof body.detail === 'string' ? body.detail : fallbackMsg);
  }
  return resp.json();
}

// ── PCAP analysis pipeline ──────────────────────────────────────────────
export async function analyzePcap(file: File): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);
  const resp = await fetch(`${API_BASE}/analyze/pcap`, { method: 'POST', body: formData });
  return j<AnalysisResponse>(resp, 'Analysis failed');
}

// Large captures: submit, then poll (the API answers 202 immediately and keeps serving).
export async function analyzePcapJob(file: File, onProgress?: (elapsedS: number) => void): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append('file', file);
  const sub = await fetch(`${API_BASE}/analyze/pcap/async`, { method: 'POST', body: formData });
  const { job_id } = await j<{ job_id: string }>(sub, 'Could not submit the capture');
  for (;;) {
    await new Promise((r) => setTimeout(r, 1500));
    const resp = await fetch(`${API_BASE}/analyze/jobs/${job_id}`);
    const body = await resp.json().catch(() => ({}));
    if (body.status === 'done') return body.result as AnalysisResponse;
    if (body.status === 'error' || !resp.ok) throw new ApiError(body.error ?? body.detail ?? 'Analysis failed');
    onProgress?.(body.elapsed_s ?? 0);
  }
}

// ── Packet inspector over an uploaded capture ──────────────────────────
export const pcapInspector = {
  page: (analysisId: string, start: number, limit: number, filter: string) =>
    fetch(`${API_BASE}/analyze/${analysisId}/packets?start=${start}&limit=${limit}&filter=${encodeURIComponent(filter)}`)
      .then((r) => j<{ total: number; next: number; rows: PacketRow[]; first_ts: number; last_ts: number }>(r, 'packet list failed')),
  detail: (analysisId: string, n: number) =>
    fetch(`${API_BASE}/analyze/${analysisId}/packet/${n}`).then((r) => j<PacketDetail>(r, 'packet detail failed')),
  exportUrl: (analysisId: string, filter: string) =>
    `${API_BASE}/analyze/${analysisId}/export.pcap?filter=${encodeURIComponent(filter)}`,
};

// ── Pipeline & model introspection ─────────────────────────────────────
export async function fetchPipelineStatus(): Promise<PipelineStatus> {
  const resp = await fetch(`${API_BASE}/api/pipeline/status`);
  return j<PipelineStatus>(resp, 'Failed to fetch pipeline status');
}

export async function fetchIndexPatterns(): Promise<IndexPattern[]> {
  const resp = await fetch(`${API_BASE}/api/index-patterns`);
  return j<IndexPattern[]>(resp, 'Failed to fetch index patterns');
}

export async function fetchModelsManifest(): Promise<unknown[]> {
  const resp = await fetch(`${API_BASE}/models/manifest`);
  if (!resp.ok) return [];
  return resp.json();
}

export async function fetchHealth(): Promise<Record<string, unknown>> {
  const resp = await fetch(`${API_BASE}/health`);
  return j<Record<string, unknown>>(resp, 'health check failed');
}

// Score one flow/domain against a family's hybrid model (real inference).
export async function scoreFlow(
  family: 'dns' | 'flow' | 'tls' | 'modbus',
  flow: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const resp = await fetch(`${API_BASE}/score/${family}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ flow }),
  });
  return j<Record<string, unknown>>(resp, 'scoring failed');
}

// ── Stored alerts (shared by upload + live-capture ingest) ─────────────
export async function fetchAlerts(params?: {
  threat_class?: string;
  severity?: string;
  since?: string;
  limit?: number;
}): Promise<Alert[]> {
  const q = new URLSearchParams();
  if (params?.threat_class) q.set('threat_class', params.threat_class);
  if (params?.severity) q.set('severity', params.severity);
  if (params?.since) q.set('since', params.since);
  q.set('limit', String(params?.limit ?? 500));
  const resp = await fetch(`${API_BASE}/alerts?${q.toString()}`);
  if (!resp.ok) return [];
  const rows = await resp.json();
  // /alerts returns DB rows; normalise to the Alert shape the UI expects
  return (rows as Array<Record<string, unknown>>).map(dbRowToAlert);
}

function dbRowToAlert(r: Record<string, any>): Alert {
  return {
    alert_id: r.alert_id,
    timestamp: r.ts ? new Date(r.ts).getTime() / 1000 : Date.now() / 1000,
    severity: r.severity,
    confidence_score: r.confidence_score,
    threat_class: r.threat_class,
    flow_identifier: {
      src_ip: r.src_ip, src_port: r.src_port,
      dst_ip: r.dst_ip, dst_port: r.dst_port, protocol: r.protocol,
    },
    mitre_attack: {
      tactic: r.mitre_tactic, technique_id: r.mitre_technique_id, technique_name: r.mitre_technique_name,
    },
    evidence: r.evidence ?? {},
    forensics: r.forensics ?? {},
    detection_mode: r.detection_mode ?? 'rule',
    model_scores: r.model_scores ?? null,
    top_contributing_features: r.top_contributing_features ?? null,
  };
}

// ── Live capture pipeline (kernel-level NIC tap) ───────────────────────
export const live = {
  interfaces: () =>
    fetch(`${liveBase()}/capture/interfaces`).then((r) => j<CaptureInterface[]>(r, 'interface list failed')),
  capabilities: () =>
    fetch(`${liveBase()}/capture/capabilities`).then((r) => j<Record<string, unknown>>(r, 'capabilities failed')),
  status: () =>
    fetch(`${liveBase()}/capture/status`).then((r) => j<CaptureStatus>(r, 'status failed')),
  alerts: (limit = 200) =>
    fetch(`${liveBase()}/capture/alerts?limit=${limit}`).then((r) => (r.ok ? r.json() : [])) as Promise<Alert[]>,
  start: (interfaceName: string, bpf: string, preferKernel: boolean, bufferMb = 64) =>
    fetch(`${liveBase()}/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interface: interfaceName, bpf: bpf || null,
        prefer_kernel: preferKernel, buffer_mb: bufferMb,
      }),
    }).then((r) => j<CaptureStatus>(r, 'could not start capture')),
  stop: () => fetch(`${liveBase()}/capture/stop`, { method: 'POST' }).then((r) => j<CaptureStatus>(r, 'stop failed')),
  replay: (path: string, loops: number, speed: number) =>
    fetch(`${liveBase()}/capture/replay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, loops, speed }),
    }).then((r) => j<CaptureStatus>(r, 'could not start replay')),
  series: (seconds = 300) =>
    fetch(`${liveBase()}/capture/series?seconds=${seconds}`).then((r) => (r.ok ? (r.json() as Promise<SeriesPoint[]>) : [])),
  summary: () =>
    fetch(`${liveBase()}/capture/summary`).then((r) => (r.ok ? (r.json() as Promise<AlertSummary>) : { alerts_by_class: {}, alerts_by_severity: {} })),
  hosts: (limit = 500) =>
    fetch(`${liveBase()}/capture/hosts?limit=${limit}`).then((r) => (r.ok ? (r.json() as Promise<HostRow[]>) : [])),
  protocols: () =>
    fetch(`${liveBase()}/capture/protocols`).then((r) => (r.ok ? (r.json() as Promise<ProtoRow[]>) : [])),
  flows: (n = 60) =>
    fetch(`${liveBase()}/capture/flows?n=${n}`).then((r) => (r.ok ? (r.json() as Promise<FlowRow[]>) : [])),
  packets: (after: number, limit: number, filter: string) =>
    fetch(`${liveBase()}/capture/packets?after=${after}&limit=${limit}&filter=${encodeURIComponent(filter)}`)
      .then((r) => j<PacketRow[]>(r, 'packet list failed')),
  packet: (id: number) => fetch(`${liveBase()}/capture/packet/${id}`).then((r) => j<PacketDetail>(r, 'packet detail failed')),
  exportUrl: (filter: string) => `${liveBase()}/capture/export.pcap?filter=${encodeURIComponent(filter)}`,
  streamUrl: () => `${liveBase()}/capture/stream`,
};

export type { Alert };
