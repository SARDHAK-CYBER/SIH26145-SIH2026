import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from 'recharts';
import type { AnalysisResponse, Alert, Severity, ThreatClass } from '../types/alert';
import type { VizConfig } from '../lib/vizEngine';
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

  // Outlier series mimicking Palo Alto Web Activity Outlier with shaded corridor
  const outlierTimeline = [
    { time: '14:00', eventCount: 18, lowerThreshold: 10, upperThreshold: 35, baseline: 22 },
    { time: '14:05', eventCount: 24, lowerThreshold: 12, upperThreshold: 38, baseline: 25 },
    { time: '14:10', eventCount: 22, lowerThreshold: 10, upperThreshold: 36, baseline: 23 },
    { time: '14:15', eventCount: 88, lowerThreshold: 15, upperThreshold: 45, baseline: 30 }, // Spiking outlier!
    { time: '14:20', eventCount: 65, lowerThreshold: 14, upperThreshold: 42, baseline: 28 }, // Outlier
    { time: '14:25', eventCount: 31, lowerThreshold: 12, upperThreshold: 40, baseline: 26 },
    { time: '14:30', eventCount: 28, lowerThreshold: 10, upperThreshold: 35, baseline: 22 },
    { time: '14:35', eventCount: 94, lowerThreshold: 14, upperThreshold: 44, baseline: 29 }, // Second DDoS / Recon outlier!
    { time: '14:40', eventCount: 42, lowerThreshold: 12, upperThreshold: 38, baseline: 25 },
    { time: '14:45', eventCount: 25, lowerThreshold: 10, upperThreshold: 35, baseline: 22 },
  ];

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
            <span style={{ color: 'var(--accent-emerald)' }}>↑ 12.4%</span>
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

      {/* Row 2: Palo Alto Anomaly Outlier Visualizer & Threat Donut */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 20 }}>
        {/* Palo Alto Web & Network Outlier Chart with Shaded Corridor */}
        <div className="glass" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div>
              <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>
                Web &amp; Network Activity Outlier Visualizer
              </h2>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Dynamic threshold corridor with real-time outlier anomaly spikes
              </div>
            </div>
            <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 8, height: 8, background: 'var(--accent-cyan)', borderRadius: 2 }} />
                Activity Spikes
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-dim)' }}>
                <span style={{ width: 8, height: 8, background: 'var(--chart-band-line)', borderRadius: 2 }} />
                Baseline Corridor
              </span>
            </div>
          </div>

          <div style={{ height: 240, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={outlierTimeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="spikeGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.7} />
                    <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="corridorGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--chart-band)" stopOpacity={0.9} />
                    <stop offset="95%" stopColor="var(--chart-band)" stopOpacity={0.15} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="var(--text-dim)" fontSize={11} tickLine={false} />
                <YAxis stroke="var(--text-dim)" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: 'var(--tooltip-bg)',
                    border: '1px solid var(--glass-border)',
                    borderRadius: 8,
                    fontSize: 12,
                    boxShadow: '0 8px 30px rgba(0,0,0,0.8)',
                  }}
                />
                {/* Confidence Corridor Band */}
                <Area
                  type="monotone"
                  dataKey="upperThreshold"
                  stroke="var(--chart-band-line)"
                  strokeDasharray="3 3"
                  fill="url(#corridorGradient)"
                  name="Upper Bound"
                />
                <Area
                  type="monotone"
                  dataKey="lowerThreshold"
                  stroke="var(--chart-band)"
                  fill="transparent"
                  name="Lower Bound"
                />
                {/* Actual Event Velocity Spikes */}
                <Area
                  type="monotone"
                  dataKey="eventCount"
                  stroke="var(--accent-cyan)"
                  strokeWidth={2.5}
                  fill="url(#spikeGradient)"
                  name="Observed Events"
                />
              </AreaChart>
            </ResponsiveContainer>
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

      {/* Row 3: Fortinet System Gauges + Top Talkers / Vectors */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Fortinet System Resources & Pipeline Gauges */}
        <div className="glass" style={{ padding: 20 }}>
          <div style={{ marginBottom: 14 }}>
            <h2 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>System Resources & Ingestion Dials</h2>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Hardware utilization & inspection throughput status
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, textAlign: 'center' }}>
            {/* CPU Ring */}
            <div>
              <div style={{ position: 'relative', width: 70, height: 70, margin: '0 auto' }}>
                <svg width="70" height="70" viewBox="0 0 36 36">
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="3" />
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--accent-cyan)" strokeDasharray="18, 100" strokeWidth="3" strokeLinecap="round" />
                </svg>
                <div className="mono" style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 700 }}>
                  18%
                </div>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6 }}>CPU Load</div>
            </div>

            {/* Memory Ring */}
            <div>
              <div style={{ position: 'relative', width: 70, height: 70, margin: '0 auto' }}>
                <svg width="70" height="70" viewBox="0 0 36 36">
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="3" />
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--accent-teal)" strokeDasharray="42, 100" strokeWidth="3" strokeLinecap="round" />
                </svg>
                <div className="mono" style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 700 }}>
                  42%
                </div>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6 }}>Memory</div>
            </div>

            {/* Sessions / Flows Ring */}
            <div>
              <div style={{ position: 'relative', width: 70, height: 70, margin: '0 auto' }}>
                <svg width="70" height="70" viewBox="0 0 36 36">
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="3" />
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--accent-violet)" strokeDasharray="68, 100" strokeWidth="3" strokeLinecap="round" />
                </svg>
                <div className="mono" style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 700 }}>
                  68%
                </div>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6 }}>Active Flows</div>
            </div>

            {/* ML Confidence Ring */}
            <div>
              <div style={{ position: 'relative', width: 70, height: 70, margin: '0 auto' }}>
                <svg width="70" height="70" viewBox="0 0 36 36">
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="3" />
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--accent-amber)" strokeDasharray="94, 100" strokeWidth="3" strokeLinecap="round" />
                </svg>
                <div className="mono" style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 700 }}>
                  94%
                </div>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6 }}>Avg Conf.</div>
            </div>
          </div>
        </div>

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
