import type {
  AnalysisResponse,
  PipelineStatus,
  IndexPattern,
  CaptureInterface,
  CaptureStatus,
  Alert,
} from '../types/alert';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000';
// Live capture can run as its own host-side service (see
// `python -m src.capture.live_agent serve`). Defaults to the main API.
export const LIVE_BASE = import.meta.env.VITE_LIVE_API_BASE ?? API_BASE;

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

export async function fetchSampleAnalysis(): Promise<AnalysisResponse> {
  const resp = await fetch(`${API_BASE}/api/sample/analysis`);
  return j<AnalysisResponse>(resp, 'Could not load sample analysis');
}

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
    fetch(`${LIVE_BASE}/capture/interfaces`).then((r) => j<CaptureInterface[]>(r, 'interface list failed')),
  capabilities: () =>
    fetch(`${LIVE_BASE}/capture/capabilities`).then((r) => j<Record<string, unknown>>(r, 'capabilities failed')),
  status: () =>
    fetch(`${LIVE_BASE}/capture/status`).then((r) => j<CaptureStatus>(r, 'status failed')),
  alerts: (limit = 200) =>
    fetch(`${LIVE_BASE}/capture/alerts?limit=${limit}`).then((r) => (r.ok ? r.json() : [])) as Promise<Alert[]>,
  start: (interfaceName: string, bpf: string, preferKernel: boolean, bufferMb = 64) =>
    fetch(`${LIVE_BASE}/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interface: interfaceName, bpf: bpf || null,
        prefer_kernel: preferKernel, buffer_mb: bufferMb,
      }),
    }).then((r) => j<CaptureStatus>(r, 'could not start capture')),
  stop: () => fetch(`${LIVE_BASE}/capture/stop`, { method: 'POST' }).then((r) => j<CaptureStatus>(r, 'stop failed')),
  streamUrl: () => `${LIVE_BASE}/capture/stream`,
};

export type { Alert };
