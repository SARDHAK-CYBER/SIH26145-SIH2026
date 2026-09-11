import React from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from 'recharts';
import type { AnalysisResponse, Alert, Severity, ThreatClass } from '../types/alert';
import type { VizConfig, BucketInterval } from '../lib/vizEngine';
import { VIZ_TYPES, runAggregation } from '../lib/vizEngine';
import { VizChart } from './VizChart';

interface MainDashboardProps {
  data: AnalysisResponse;
  onSelectAlert: (alert: Alert) => void;
  onFilterByThreat: (threatClass: ThreatClass) => void;
  panels: VizConfig[];
  onRemovePanel: (id: string) => void;
  onCreateVisualization: () => void;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#FF3366',
  HIGH: '#FF7828',
  MEDIUM: '#FBBF24',
  LOW: '#38BDF8',
};

const THREAT_COLORS: string[] = [
  '#00E5FF', '#8B5CF6', '#EC4899', '#10B981', '#F59E0B', '#38BDF8', '#F43F5E', '#A855F7'
];

export const MainDashboard: React.FC<MainDashboardProps> = ({
  data,
  onSelectAlert,
  onFilterByThreat,
  panels,
  onRemovePanel,
  onCreateVisualization,
}) => {
  // Severity pie data
  const severityPie = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[])
    .map((sev) => ({ name: sev, value: data.severity_counts[sev] || 0 }))
    .filter((d) => d.value > 0);

  // Threat class pie data
  const threatClassPie = Object.entries(data.threat_class_counts || {}).map(([name, value], i) => ({
    name,
    value,
    fill: THREAT_COLORS[i % THREAT_COLORS.length],
  }));

  // Top talker IPs aggregation
  const srcIpCounts: Record<string, number> = {};
  const dstPortCounts: Record<number, number> = {};
  data.alerts.forEach((a) => {
    srcIpCounts[a.flow_identifier.src_ip] = (srcIpCounts[a.flow_identifier.src_ip] || 0) + 1;
    dstPortCounts[a.flow_identifier.dst_port] = (dstPortCounts[a.flow_identifier.dst_port] || 0) + 1;
  });

  const topSources = Object.entries(srcIpCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const topPorts = Object.entries(dstPortCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Real alert-volume-over-time, split by severity -- computed live from
  // this analysis result (auto-picks a bucket granularity from the actual
  // timestamp span instead of a fixed interval, since an upload can be a
  // few seconds of traffic or several hours).
  const alertTimes = data.alerts.map((a) => a.timestamp);
  const span = alertTimes.length > 1 ? Math.max(...alertTimes) - Math.min(...alertTimes) : 0;
  const timelineInterval: BucketInterval = span <= 600 ? 'minute' : span <= 6 * 3600 ? '5min' : span <= 3 * 86400 ? 'hour' : 'day';
  const timelineResult = runAggregation(data, {
    id: 'main-dashboard-timeline', title: 'Alerts over time', indexPattern: 'stealthtap-alerts-*',
    type: 'area', metric: { fn: 'count' },
    bucket: { kind: 'date_histogram', field: 'timestamp', interval: timelineInterval },
    split: { field: 'severity' }, filters: [],
  });

  const flaggedPct = data.packet_summary.conn_flows > 0
    ? ((data.alert_count / data.packet_summary.conn_flows) * 100).toFixed(1)
    : '0.0';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Executive KPI Cards Row (SOCRadar & Fortinet style) */}
      <div className="kpi-grid">
        {/* Card 1: Total Packets/Flows */}
        <div className="glass kpi-card">
          <div className="kpi-label">Analyzed Flows</div>
          <div className="kpi-value mono" style={{ color: 'var(--accent-cyan)' }}>
            {data.packet_summary.conn_flows.toLocaleString()}
          </div>
          <div className="kpi-sub">
            <span style={{ color: 'var(--accent-emerald)' }}>{flaggedPct}% flagged</span>
            <span>{data.packet_summary.dns_queries} DNS • {data.packet_summary.tls_sessions} TLS</span>
          </div>
        </div>

        {/* Card 2: Critical Threats */}
        <div className="glass kpi-card" style={{ borderColor: 'rgba(255, 51, 102, 0.4)' }}>
          <div className="kpi-label">Critical Incidents</div>
          <div className="kpi-value mono" style={{ color: 'var(--sev-critical)' }}>
            {data.severity_counts.CRITICAL || 0}
          </div>
          <div className="kpi-sub">
            <span style={{ color: 'var(--sev-critical)' }}>● Active</span>
            <span>Immediate Triage Req.</span>
          </div>
        </div>

        {/* Card 3: High Severity */}
        <div className="glass kpi-card" style={{ borderColor: 'rgba(255, 120, 40, 0.35)' }}>
          <div className="kpi-label">High Severity Alerts</div>
          <div className="kpi-value mono" style={{ color: 'var(--sev-high)' }}>
            {data.severity_counts.HIGH || 0}
          </div>
          <div className="kpi-sub">
            <span>Medium: {data.severity_counts.MEDIUM || 0}</span>
            <span>• Low: {data.severity_counts.LOW || 0}</span>
          </div>
        </div>

        {/* Card 4: AI Model Inferences */}
        <div className="glass kpi-card">
          <div className="kpi-label">AI-Scored Inferences</div>
          <div className="kpi-value mono" style={{ color: 'var(--accent-violet)' }}>
            {(data.detection_mode_counts.xgboost || 0) + (data.detection_mode_counts.isolation_forest || 0)}
          </div>
          <div className="kpi-sub">
            <span>XGBoost + Isolation Forest</span>
          </div>
        </div>

        {/* Card 5: YARA File Detections */}
        <div className="glass kpi-card">
          <div className="kpi-label">YARA Signatures</div>
          <div className="kpi-value mono" style={{ color: 'var(--accent-pink)' }}>
            {data.packet_summary.files_yara_scanned !== null ? data.packet_summary.files_yara_scanned : 'Active'}
          </div>
          <div className="kpi-sub">
            <span style={{ color: 'var(--accent-emerald)' }}>{data.yara_active ? 'Rules Loaded' : 'Standby'}</span>
            <span>Exploit / Maldocs</span>
          </div>
        </div>

        {/* Card 6: Ingest Latency */}
        <div className="glass kpi-card">
          <div className="kpi-label">Ingest Latency</div>
          <div className="kpi-value mono" style={{ color: 'var(--accent-teal)' }}>
            {(data.timing.parse_seconds + data.timing.detection_seconds).toFixed(2)}s
          </div>
          <div className="kpi-sub">
            <span>Parse: {data.timing.parse_seconds.toFixed(2)}s • Eval: {data.timing.detection_seconds.toFixed(2)}s</span>
          </div>
        </div>
      </div>

      {/* Row 2: Alert Timeline & Threat Donut */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 20 }}>
        {/* Alert volume over time, by severity -- real, from this result */}
        <div className="glass" style={{ padding: 20 }}>
          <div style={{ marginBottom: 14 }}>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>
              Alert Volume Over Time
            </h2>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {data.alert_count} alerts from this analysis, bucketed per {timelineInterval === '5min' ? '5 minutes' : timelineInterval} and split by severity
            </div>
          </div>

          <div style={{ height: 240, width: '100%' }}>
            <VizChart result={timelineResult} type="area" height={240} />
          </div>
        </div>

        {/* Threat Activity by Category (Donut Chart) */}
        <div className="glass" style={{ padding: 20 }}>
          <div style={{ marginBottom: 14 }}>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Activity by Category</h2>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Breakdown of {data.alert_count} threat detections across categories
            </div>
          </div>

          <div style={{ height: 180, width: '100%', position: 'relative' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={threatClassPie.length > 0 ? threatClassPie : [{ name: 'None', value: 1, fill: '#334155' }]}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                >
                  {threatClassPie.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={entry.fill}
                      stroke="none"
                      style={{ cursor: 'pointer' }}
                      onClick={() => onFilterByThreat(entry.name as ThreatClass)}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: 'var(--tooltip-bg)',
                    border: '1px solid var(--glass-border)',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            {/* Center Callout */}
            <div style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              textAlign: 'center',
              pointerEvents: 'none',
            }}>
              <div className="mono" style={{ fontSize: 20, fontWeight: 700, color: 'var(--text)' }}>
                {data.alert_count}
              </div>
              <div style={{ fontSize: 9, color: 'var(--text-dim)', textTransform: 'uppercase' }}>Threats</div>
            </div>
          </div>

          {/* Quick Category Legend */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
            {threatClassPie.slice(0, 4).map((c) => (
              <span
                key={c.name}
                onClick={() => onFilterByThreat(c.name as ThreatClass)}
                style={{
                  fontSize: 10,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                  padding: '3px 8px',
                  borderRadius: 4,
                  background: 'rgba(255,255,255,0.04)',
                  cursor: 'pointer',
                }}
              >
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: c.fill }} />
                <span style={{ color: 'var(--text-muted)' }}>{c.name}: {c.value}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: Top Talkers / Vectors */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 20 }}>
        {/* Top Talker IPs & Target Ports */}
        <div className="glass" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Top Threat Sources & Target Ports</h2>
            <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>TOP 5 TALKERS</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            {/* Top Sources */}
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 6 }}>
                Suspicious Source IPs
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {topSources.map(([ip, count]) => (
                  <div key={ip} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    padding: '6px 10px',
                    borderRadius: 6,
                    background: 'rgba(255,255,255,0.03)',
                    fontSize: 12,
                  }}>
                    <span className="mono" style={{ color: 'var(--accent-cyan)' }}>{ip}</span>
                    <span className="mono" style={{ color: 'var(--text-dim)' }}>{count} hits</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Ports */}
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 6 }}>
                Target Service Ports
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {topPorts.map(([port, count]) => (
                  <div key={port} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    padding: '6px 10px',
                    borderRadius: 6,
                    background: 'rgba(255,255,255,0.03)',
                    fontSize: 12,
                  }}>
                    <span className="mono" style={{ color: 'var(--accent-pink)' }}>Port {port}</span>
                    <span className="mono" style={{ color: 'var(--text-dim)' }}>{count} flows</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Custom Visualizers — built in Visualizer Studio, computed live from this result */}
      <div className="glass" style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: panels.length ? 16 : 0 }}>
          <div>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Custom Visualizers</h2>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Aggregations over the current analysis result — built in Visualizer Studio, saved on this device.
            </div>
          </div>
          <button className="btn-primary" onClick={onCreateVisualization} style={{ fontSize: 12, padding: '7px 14px' }}>
            + Create Visualization
          </button>
        </div>

        {panels.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-dim)', padding: '10px 0' }}>
            No visualizations yet. Build one in Visualizer Studio — pick an index pattern, a metric, a bucket and
            filters — then “Add to Dashboard” to pin it here.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 16 }}>
            {panels.map((cfg) => (
              <div key={cfg.id} className="glass-raised" style={{ padding: 18, borderRadius: 'var(--radius-md)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12, gap: 8 }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>{cfg.title}</div>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 2 }}>
                      {VIZ_TYPES.find((t) => t.id === cfg.type)?.label} · {cfg.indexPattern}
                    </div>
                  </div>
                  <button
                    className="btn-ghost"
                    onClick={() => onRemovePanel(cfg.id)}
                    style={{ fontSize: 11, padding: '4px 10px', flexShrink: 0 }}
                    aria-label={`Remove ${cfg.title} panel`}
                  >
                    Remove
                  </button>
                </div>
                <VizChart result={runAggregation(data, cfg)} type={cfg.type} height={260} />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Row 4: Live Threat Feed Table */}
      <div className="glass" style={{ overflow: 'hidden' }}>
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--glass-border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>Active Incident & Threat Feed</h2>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Click any alert row to open forensic analysis drawer
            </div>
          </div>
          <span className="mono" style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>
            {data.alerts.length} ALERTS RAISED
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Threat Class</th>
                <th>Source Endpoint</th>
                <th>Destination</th>
                <th>Confidence</th>
                <th>Detection Mode</th>
                <th>MITRE Technique</th>
              </tr>
            </thead>
            <tbody>
              {data.alerts.map((a) => (
                <tr key={a.alert_id} onClick={() => onSelectAlert(a)}>
                  <td>
                    <span className={`sev-badge sev-${a.severity}`}>{a.severity}</span>
                  </td>
                  <td className="mono" style={{ fontWeight: 600, color: 'var(--text)' }}>
                    {a.threat_class}
                  </td>
                  <td className="mono" style={{ color: 'var(--accent-cyan)' }}>
                    {a.flow_identifier.src_ip}:{a.flow_identifier.src_port}
                  </td>
                  <td className="mono" style={{ color: 'var(--text-muted)' }}>
                    {a.flow_identifier.dst_ip}:{a.flow_identifier.dst_port}
                  </td>
                  <td className="mono" style={{
                    color: a.confidence_score > 90 ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                    fontWeight: 600,
                  }}>
                    {a.confidence_score.toFixed(1)}%
                  </td>
                  <td className="mono" style={{ color: 'var(--text-dim)' }}>
                    {a.detection_mode}
                  </td>
                  <td className="mono" style={{ color: 'var(--accent-violet)' }}>
                    {a.mitre_attack.technique_id}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
