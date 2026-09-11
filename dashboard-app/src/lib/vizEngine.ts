// Aggregation engine for the Visualization Builder.
//
// Every chart the builder (or a saved dashboard panel) renders is computed
// live from the CURRENT AnalysisResponse — the real result of the PCAP
// upload, the loaded sample, or live-capture alerts — never from a fixed
// demo array. Re-running the same VizConfig against a new `data` object
// (a new upload, a filtered result) always reproduces the current numbers.

import type { AnalysisResponse, Alert, PacketSummary } from '../types/alert';

// ── Index patterns the builder can source from ──────────────────────────
// 'stealthtap-alerts-*' is row-level: every alert this session actually
// raised, so bucket/metric/filter all operate on real detections. The
// other three only have summary counters available client-side (the raw
// Zeek/Suricata records live server-side in Postgres/OpenSearch) — the
// builder is honest about that and only offers document counts for them.
export const INDEX_PATTERN_IDS = ['stealthtap-alerts-*', 'zeek-conn-*', 'zeek-dns-*', 'zeek-ot-*'] as const;
export type IndexPatternId = (typeof INDEX_PATTERN_IDS)[number];

export interface FieldDef {
  name: string;
  label: string;
  kind: 'string' | 'number' | 'date';
}

export const ALERT_FIELDS: FieldDef[] = [
  { name: 'severity', label: 'severity', kind: 'string' },
  { name: 'threat_class', label: 'threat_class', kind: 'string' },
  { name: 'protocol', label: 'flow_identifier.protocol', kind: 'string' },
  { name: 'detection_mode', label: 'detection_mode', kind: 'string' },
  { name: 'src_ip', label: 'flow_identifier.src_ip', kind: 'string' },
  { name: 'dst_ip', label: 'flow_identifier.dst_ip', kind: 'string' },
  { name: 'dst_port', label: 'flow_identifier.dst_port', kind: 'number' },
  { name: 'mitre_tactic', label: 'mitre_attack.tactic', kind: 'string' },
  { name: 'mitre_technique', label: 'mitre_attack.technique_id', kind: 'string' },
  { name: 'confidence_score', label: 'confidence_score', kind: 'number' },
  { name: 'timestamp', label: '@timestamp', kind: 'date' },
];

const NUMERIC_FIELDS = new Set(['confidence_score', 'dst_port']);

const COUNTER_CATALOG: Record<Exclude<IndexPatternId, 'stealthtap-alerts-*'>, Array<{ key: keyof PacketSummary; label: string }>> = {
  'zeek-conn-*': [
    { key: 'conn_flows', label: 'conn_flows' },
    { key: 'http_requests', label: 'http_requests' },
  ],
  'zeek-dns-*': [
    { key: 'dns_queries', label: 'dns_queries' },
    { key: 'tls_sessions', label: 'tls_sessions' },
  ],
  'zeek-ot-*': [
    { key: 'modbus_records', label: 'modbus_records' },
    { key: 'dnp3_records', label: 'dnp3_records' },
    { key: 'cip_events', label: 'cip_events' },
  ],
};

export function fieldsForIndexPattern(pattern: IndexPatternId): FieldDef[] {
  return pattern === 'stealthtap-alerts-*' ? ALERT_FIELDS : [];
}

export function isNumericField(name: string): boolean {
  return NUMERIC_FIELDS.has(name);
}

export function getFieldValue(a: Alert, field: string): string | number {
  switch (field) {
    case 'severity': return a.severity;
    case 'threat_class': return a.threat_class;
    case 'protocol': return a.flow_identifier.protocol;
    case 'detection_mode': return a.detection_mode;
    case 'src_ip': return a.flow_identifier.src_ip;
    case 'dst_ip': return a.flow_identifier.dst_ip;
    case 'dst_port': return a.flow_identifier.dst_port;
    case 'mitre_tactic': return a.mitre_attack.tactic;
    case 'mitre_technique': return a.mitre_attack.technique_id;
    case 'confidence_score': return a.confidence_score;
    case 'timestamp': return a.timestamp;
    default: return '';
  }
}

// ── Visualization types (OpenSearch Dashboards' own Visualize vocabulary) ──
export type VizType =
  | 'vertical_bar' | 'horizontal_bar' | 'line' | 'area'
  | 'pie' | 'donut' | 'data_table' | 'metric' | 'gauge' | 'heat_map';

export const VIZ_TYPES: Array<{ id: VizType; label: string; hint: string }> = [
  { id: 'vertical_bar', label: 'Vertical Bar', hint: 'Compare a metric across categories' },
  { id: 'horizontal_bar', label: 'Horizontal Bar', hint: 'Ranked comparison, long labels' },
  { id: 'line', label: 'Line', hint: 'Trend of a metric over time' },
  { id: 'area', label: 'Area', hint: 'Volume trend over time' },
  { id: 'pie', label: 'Pie', hint: 'Proportional share of a whole' },
  { id: 'donut', label: 'Donut', hint: 'Proportional share, center total' },
  { id: 'data_table', label: 'Data Table', hint: 'Exact values, sortable rows' },
  { id: 'metric', label: 'Metric', hint: 'Single headline number' },
  { id: 'gauge', label: 'Gauge', hint: 'Top bucket vs. the whole' },
  { id: 'heat_map', label: 'Heat Map', hint: 'Two-dimensional density matrix' },
];

export type MetricFn = 'count' | 'avg' | 'sum' | 'min' | 'max' | 'cardinality';

export const METRIC_FNS: Array<{ id: MetricFn; label: string; needsField: boolean }> = [
  { id: 'count', label: 'Count', needsField: false },
  { id: 'avg', label: 'Average', needsField: true },
  { id: 'sum', label: 'Sum', needsField: true },
  { id: 'min', label: 'Min', needsField: true },
  { id: 'max', label: 'Max', needsField: true },
  { id: 'cardinality', label: 'Unique Count', needsField: true },
];

export type BucketInterval = 'minute' | '5min' | 'hour' | 'day';
const INTERVAL_SECONDS: Record<BucketInterval, number> = { minute: 60, '5min': 300, hour: 3600, day: 86400 };

export interface FilterClause { field: string; value: string }

export interface VizConfig {
  id: string;
  title: string;
  indexPattern: IndexPatternId;
  type: VizType;
  metric: { fn: MetricFn; field?: string };
  bucket: { kind: 'terms' | 'date_histogram'; field: string; size?: number; interval?: BucketInterval };
  split?: { field: string } | null;
  filters: FilterClause[];
}

export interface AggRow {
  bucket: string;
  value: number;
  series?: Record<string, number>;
}

export interface AggResult {
  rows: AggRow[];
  seriesKeys: string[];
  documentCount: number;
  totalDocuments: number;
}

function metricLabel(fn: MetricFn, field?: string): string {
  const def = METRIC_FNS.find((m) => m.id === fn)!;
  if (!def.needsField) return def.label;
  const fieldLabel = ALERT_FIELDS.find((f) => f.name === field)?.label || field || '';
  return `${def.label} of ${fieldLabel}`;
}

function bucketLabel(config: VizConfig): string {
  if (config.bucket.kind === 'date_histogram') return `time (${config.bucket.interval || 'hour'})`;
  return ALERT_FIELDS.find((f) => f.name === config.bucket.field)?.label || config.bucket.field;
}

export function defaultTitle(config: VizConfig): string {
  if (config.indexPattern !== 'stealthtap-alerts-*') {
    return `${config.indexPattern} document counts`;
  }
  return `${metricLabel(config.metric.fn, config.metric.field)} by ${bucketLabel(config)}`;
}

function computeMetric(items: Alert[], metric: VizConfig['metric']): number {
  if (metric.fn === 'count') return items.length;
  const field = metric.field || 'confidence_score';
  if (metric.fn === 'cardinality') {
    return new Set(items.map((a) => String(getFieldValue(a, field)))).size;
  }
  const vals = items.map((a) => Number(getFieldValue(a, field))).filter((v) => Number.isFinite(v));
  if (vals.length === 0) return 0;
  switch (metric.fn) {
    case 'avg': return vals.reduce((s, v) => s + v, 0) / vals.length;
    case 'sum': return vals.reduce((s, v) => s + v, 0);
    case 'min': return Math.min(...vals);
    case 'max': return Math.max(...vals);
    default: return 0;
  }
}

function computeSplit(items: Alert[], field: string): Record<string, number> {
  const out: Record<string, number> = {};
  items.forEach((a) => {
    const k = String(getFieldValue(a, field) ?? 'unknown');
    out[k] = (out[k] || 0) + 1;
  });
  return out;
}

function formatBucketTime(epochSeconds: number, interval: BucketInterval): string {
  const d = new Date(epochSeconds * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  if (interval === 'day') return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

/** Run one VizConfig against the current analysis result. Always live — never cached demo data. */
export function runAggregation(data: AnalysisResponse, config: VizConfig): AggResult {
  const totalDocuments = (data.alerts || []).length;

  if (config.indexPattern !== 'stealthtap-alerts-*') {
    const counters = COUNTER_CATALOG[config.indexPattern];
    const rows = counters.map((c) => ({ bucket: c.label, value: Number(data.packet_summary?.[c.key] ?? 0) || 0 }));
    return { rows, seriesKeys: [], documentCount: rows.reduce((s, r) => s + r.value, 0), totalDocuments };
  }

  const filtered = (data.alerts || []).filter((a) =>
    config.filters.every((f) => !f.value || String(getFieldValue(a, f.field)) === f.value)
  );

  let rows: AggRow[];
  const seriesSet = new Set<string>();

  if (config.bucket.kind === 'date_histogram') {
    const interval = config.bucket.interval || 'hour';
    const sec = INTERVAL_SECONDS[interval];
    const groups = new Map<number, Alert[]>();
    filtered.forEach((a) => {
      const start = Math.floor(a.timestamp / sec) * sec;
      if (!groups.has(start)) groups.set(start, []);
      groups.get(start)!.push(a);
    });
    rows = [...groups.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([t, items]) => {
        const series = config.split ? computeSplit(items, config.split.field) : undefined;
        if (series) Object.keys(series).forEach((k) => seriesSet.add(k));
        return { bucket: formatBucketTime(t, interval), value: computeMetric(items, config.metric), series };
      });
  } else {
    const groups = new Map<string, Alert[]>();
    filtered.forEach((a) => {
      const key = String(getFieldValue(a, config.bucket.field) ?? 'unknown');
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(a);
    });
    rows = [...groups.entries()].map(([bucket, items]) => {
      const series = config.split ? computeSplit(items, config.split.field) : undefined;
      if (series) Object.keys(series).forEach((k) => seriesSet.add(k));
      return { bucket, value: computeMetric(items, config.metric), series };
    });
    rows.sort((a, b) => b.value - a.value);
    if (config.bucket.size) rows = rows.slice(0, config.bucket.size);
  }

  return { rows, seriesKeys: [...seriesSet].sort(), documentCount: filtered.length, totalDocuments };
}

/** Distinct values a field currently holds — used to populate filter-value pickers from real data. */
export function distinctValues(data: AnalysisResponse, field: string, limit = 30): string[] {
  const set = new Set<string>();
  (data.alerts || []).forEach((a) => set.add(String(getFieldValue(a, field))));
  return [...set].sort().slice(0, limit);
}

let counter = 0;
export function newVizId(): string {
  counter += 1;
  return `viz-${Date.now().toString(36)}-${counter}`;
}

export function emptyConfig(): VizConfig {
  return {
    id: newVizId(),
    title: '',
    indexPattern: 'stealthtap-alerts-*',
    type: 'donut',
    metric: { fn: 'count' },
    bucket: { kind: 'terms', field: 'severity', size: 10 },
    split: null,
    filters: [],
  };
}

export interface VizPreset {
  label: string;
  description: string;
  build: () => VizConfig;
}

export const VIZ_PRESETS: VizPreset[] = [
  {
    label: 'Alerts by Severity',
    description: 'Donut — proportional severity mix of the current result set',
    build: () => ({ ...emptyConfig(), type: 'donut', bucket: { kind: 'terms', field: 'severity', size: 10 }, title: 'Alerts by Severity' }),
  },
  {
    label: 'Alerts by Threat Class',
    description: 'Vertical Bar — detection volume per threat classification',
    build: () => ({ ...emptyConfig(), type: 'vertical_bar', bucket: { kind: 'terms', field: 'threat_class', size: 12 }, title: 'Alerts by Threat Class' }),
  },
  {
    label: 'Detections Over Time',
    description: 'Area — alert volume trend across the capture window',
    build: () => ({ ...emptyConfig(), type: 'area', bucket: { kind: 'date_histogram', field: 'timestamp', interval: 'hour' }, title: 'Detections Over Time' }),
  },
  {
    label: 'Top Source IPs',
    description: 'Data Table — most active suspicious source addresses',
    build: () => ({ ...emptyConfig(), type: 'data_table', bucket: { kind: 'terms', field: 'src_ip', size: 10 }, title: 'Top Source IPs' }),
  },
  {
    label: 'MITRE Tactic Coverage',
    description: 'Horizontal Bar — ATT&CK tactics observed this session',
    build: () => ({ ...emptyConfig(), type: 'horizontal_bar', bucket: { kind: 'terms', field: 'mitre_tactic', size: 12 }, title: 'MITRE Tactic Coverage' }),
  },
  {
    label: 'Average Confidence by Detection Mode',
    description: 'Vertical Bar — model vs. rule confidence comparison',
    build: () => ({ ...emptyConfig(), type: 'vertical_bar', metric: { fn: 'avg', field: 'confidence_score' }, bucket: { kind: 'terms', field: 'detection_mode', size: 5 }, title: 'Average Confidence by Detection Mode' }),
  },
  {
    label: 'Severity Mix Over Time',
    description: 'Heat Map — severity intensity across the capture window',
    build: () => ({ ...emptyConfig(), type: 'heat_map', bucket: { kind: 'date_histogram', field: 'timestamp', interval: 'hour' }, split: { field: 'severity' }, title: 'Severity Mix Over Time' }),
  },
  {
    label: 'Capture Document Counts',
    description: 'Metric — real record counts from this analysis, not alerts',
    build: () => ({ ...emptyConfig(), type: 'metric', indexPattern: 'zeek-conn-*', bucket: { kind: 'terms', field: '' }, title: 'zeek-conn-* document counts' }),
  },
];
