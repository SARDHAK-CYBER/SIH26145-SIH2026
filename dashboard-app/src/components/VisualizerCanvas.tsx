import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from 'recharts';
import type { AnalysisResponse, VisualizerType } from '../types/alert';

export const VISUALIZERS: Array<{ id: VisualizerType; label: string; description: string }> = [
  { id: 'outlier', label: 'Outlier Band', description: 'Baseline confidence corridor with anomaly threshold spikes' },
  { id: 'donut', label: 'Category & Protocol Donut', description: 'Radial activity distribution and proportion breakdown' },
  { id: 'timeline', label: 'Temporal Spline Waves', description: 'Multi-series attack velocity and event progression over time' },
  { id: 'stacked_bar', label: 'Stacked Bar Intervals', description: 'Traffic breakdown by severity buckets over time' },
  { id: 'top_talkers', label: 'Top N Rankings & Vectors', description: 'Top suspicious IPs, targeted ports, domains, and JA4 hashes' },
  { id: 'mitre_matrix', label: 'MITRE ATT&CK Navigator', description: 'Tactical matrix mapping coverage across kill-chain stages' },
  { id: 'gauges', label: 'Security Fabric Dials', description: 'Capture utilization, engine health, and confidence gauges' },
  { id: 'ai_explain', label: 'AI Explainability & SHAP', description: 'XGBoost vs Isolation Forest feature contribution ranking' },
];

export const VISUALIZER_LABEL: Record<VisualizerType, string> = VISUALIZERS.reduce(
  (acc, v) => { acc[v.id] = v.label; return acc; },
  {} as Record<VisualizerType, string>,
);

const TOOLTIP_STYLE = {
  background: 'var(--tooltip-bg)',
  border: '1px solid var(--glass-border)',
  borderRadius: 8,
  fontSize: 12,
} as const;

// ── Demonstration series (shared by Studio + Dashboard panels) ──────────
const outlierData = [
  { time: '14:00', eventCount: 22, lowerThreshold: 10, upperThreshold: 35 },
  { time: '14:05', eventCount: 28, lowerThreshold: 12, upperThreshold: 38 },
  { time: '14:10', eventCount: 30, lowerThreshold: 10, upperThreshold: 36 },
  { time: '14:15', eventCount: 110, lowerThreshold: 15, upperThreshold: 45 },
  { time: '14:20', eventCount: 85, lowerThreshold: 14, upperThreshold: 42 },
  { time: '14:25', eventCount: 34, lowerThreshold: 12, upperThreshold: 40 },
  { time: '14:30', eventCount: 26, lowerThreshold: 10, upperThreshold: 35 },
  { time: '14:35', eventCount: 125, lowerThreshold: 14, upperThreshold: 44 },
  { time: '14:40', eventCount: 45, lowerThreshold: 12, upperThreshold: 38 },
  { time: '14:45', eventCount: 28, lowerThreshold: 10, upperThreshold: 35 },
];

const stackedBarData = [
  { time: '14:00', CRITICAL: 0, HIGH: 2, MEDIUM: 4, LOW: 8 },
  { time: '14:10', CRITICAL: 1, HIGH: 3, MEDIUM: 2, LOW: 10 },
  { time: '14:20', CRITICAL: 4, HIGH: 6, MEDIUM: 3, LOW: 5 },
  { time: '14:30', CRITICAL: 2, HIGH: 5, MEDIUM: 4, LOW: 7 },
  { time: '14:40', CRITICAL: 5, HIGH: 4, MEDIUM: 2, LOW: 6 },
  { time: '14:50', CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 9 },
];

const featureImportance = [
  { name: 'Shannon Entropy', score: 0.38, family: 'dns' },
  { name: 'Domain Length', score: 0.24, family: 'dns' },
  { name: 'Consonant Ratio', score: 0.18, family: 'dns' },
  { name: 'Flow Duration', score: 0.12, family: 'flow' },
  { name: 'Asym Byte Ratio', score: 0.08, family: 'flow' },
];

const mitreTactics = [
  { tactic: 'Reconnaissance', count: 1, tech: 'T1046: Network Service Discovery', desc: 'ENG-05 Recon Scan' },
  { tactic: 'Initial Access', count: 0, tech: 'T1190: Exploit Public App', desc: 'No active detections' },
  { tactic: 'Defense Evasion', count: 1, tech: 'T1027: Encrypted Malware', desc: 'ENG-04 JA4 Match' },
  { tactic: 'Command & Control', count: 3, tech: 'T1568.002: DGA & T1071', desc: 'ENG-02/03 C2 & DGA' },
  { tactic: 'Exfiltration', count: 1, tech: 'T1048.003: Alt Protocol', desc: 'ENG-06 14,000:1 Exfil Ratio' },
  { tactic: 'Impact', count: 2, tech: 'T1498: Network Denial of Service', desc: 'ENG-01 SYN Flood & Slowloris' },
  { tactic: 'Impair Process Control', count: 1, tech: 'T0855: Unauthorized Command', desc: 'ENG-07 Modbus Write' },
];

const DONUT_COLORS = ['#00E5FF', '#8B5CF6', '#EC4899', '#10B981', '#F59E0B', '#38BDF8'];

interface VisualizerCanvasProps {
  type: VisualizerType;
  data: AnalysisResponse;
  /** Hide the built-in heading block (Dashboard panels supply their own). */
  bare?: boolean;
}

const Heading: React.FC<{ show: boolean; title: string; sub: string }> = ({ show, title, sub }) =>
  show ? (
    <div style={{ marginBottom: 16 }}>
      <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>{title}</h3>
      <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '2px 0 0' }}>{sub}</p>
    </div>
  ) : null;

export const VisualizerCanvas: React.FC<VisualizerCanvasProps> = ({ type, data, bare = false }) => {
  const showHead = !bare;

  if (type === 'outlier') {
    return (
      <div>
        <Heading show={showHead} title="Web & Network Activity Outlier Model"
          sub="Baseline confidence corridor (shaded bounds) with traffic spikes exceeding statistical deviation" />
        <div style={{ height: 320, width: '100%' }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={outlierData}>
              <defs>
                <linearGradient id="vcOutlierGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="vcBandGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--chart-band)" stopOpacity={0.9} />
                  <stop offset="95%" stopColor="var(--chart-band)" stopOpacity={0.15} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="var(--text-dim)" fontSize={12} />
              <YAxis stroke="var(--text-dim)" fontSize={12} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area type="monotone" dataKey="upperThreshold" stroke="var(--chart-band-line)" strokeDasharray="4 4" fill="url(#vcBandGrad)" name="Upper Baseline Limit" />
              <Area type="monotone" dataKey="lowerThreshold" stroke="var(--chart-band)" fill="transparent" name="Lower Baseline Limit" />
              <Area type="monotone" dataKey="eventCount" stroke="var(--accent-cyan)" strokeWidth={3} fill="url(#vcOutlierGrad)" name="Observed Activity Spike" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  }

  if (type === 'donut') {
    const entries = Object.entries(data.threat_class_counts || {});
    return (
      <div>
        <Heading show={showHead} title="Threat Distribution by Class & Protocol Split"
          sub="Segmented donut with percentage share and incident totals" />
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          <div style={{ height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={entries.map(([name, value], i) => ({ name, value, fill: DONUT_COLORS[i % DONUT_COLORS.length] }))}
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {entries.map((_, i) => (
                    <Cell key={i} fill={DONUT_COLORS[i % DONUT_COLORS.length]} stroke="none" />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 8 }}>
            {entries.map(([name, count]) => (
              <div key={name} style={{
                display: 'flex', justifyContent: 'space-between', padding: '8px 14px',
                borderRadius: 8, background: 'var(--bg-surface-hover)', fontSize: 12,
              }}>
                <span className="mono" style={{ color: 'var(--text)' }}>{name}</span>
                <span className="mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                  {count} ({data.alert_count ? ((count / data.alert_count) * 100).toFixed(0) : 0}%)
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (type === 'timeline') {
    return (
      <div>
        <Heading show={showHead} title="Multi-Wave Traffic & Threat Velocity"
          sub="Spline wave curves showing network flow volume versus anomalous burst rates" />
        <div style={{ height: 320, width: '100%' }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={outlierData}>
              <defs>
                <linearGradient id="vcWave1" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-violet)" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="var(--accent-violet)" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="vcWave2" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-pink)" stopOpacity={0.7} />
                  <stop offset="95%" stopColor="var(--accent-pink)" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="var(--text-dim)" fontSize={12} />
              <YAxis stroke="var(--text-dim)" fontSize={12} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Area type="natural" dataKey="eventCount" stroke="var(--accent-violet)" strokeWidth={3} fill="url(#vcWave1)" name="Threat Events" />
              <Area type="natural" dataKey="upperThreshold" stroke="var(--accent-pink)" strokeWidth={2} fill="url(#vcWave2)" name="Predicted Trend" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  }

  if (type === 'stacked_bar') {
    return (
      <div>
        <Heading show={showHead} title="Severity Distribution Across Time Intervals"
          sub="Temporal stacked bars breaking alerts into Critical, High, Medium and Low buckets" />
        <div style={{ height: 320, width: '100%' }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={stackedBarData}>
              <XAxis dataKey="time" stroke="var(--text-dim)" fontSize={12} />
              <YAxis stroke="var(--text-dim)" fontSize={12} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend />
              <Bar dataKey="CRITICAL" stackId="a" fill="var(--sev-critical)" />
              <Bar dataKey="HIGH" stackId="a" fill="var(--sev-high)" />
              <Bar dataKey="MEDIUM" stackId="a" fill="var(--sev-medium)" />
              <Bar dataKey="LOW" stackId="a" fill="var(--sev-low)" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    );
  }

  if (type === 'top_talkers') {
    const srcIpCounts: Record<string, number> = {};
    const dstPortCounts: Record<number, number> = {};
    (data.alerts || []).forEach((a) => {
      srcIpCounts[a.flow_identifier.src_ip] = (srcIpCounts[a.flow_identifier.src_ip] || 0) + 1;
      dstPortCounts[a.flow_identifier.dst_port] = (dstPortCounts[a.flow_identifier.dst_port] || 0) + 1;
    });
    const topSrc = Object.entries(srcIpCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topPort = Object.entries(dstPortCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topClass = Object.entries(data.threat_class_counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const col = (title: string, rows: Array<[string, number]>, color: string, unit: string) => (
      <div className="glass" style={{ padding: 16 }}>
        <h4 style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 10, textTransform: 'uppercase' }}>{title}</h4>
        {rows.length === 0 && <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>No data</div>}
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--glass-border-subtle)', fontSize: 12 }}>
            <span className="mono" style={{ color }}>{k}</span>
            <span className="mono" style={{ color: 'var(--text-dim)' }}>{v} {unit}</span>
          </div>
        ))}
      </div>
    );
    return (
      <div>
        <Heading show={showHead} title="Top Talkers, Target Ports & Threat Classes"
          sub="Aggregated telemetry ranking the most active entities in the current result set" />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
          {col('Suspicious Source IPs', topSrc, 'var(--accent-cyan)', 'hits')}
          {col('Target Service Ports', topPort.map(([k, v]) => [`Port ${k}`, v]) as Array<[string, number]>, 'var(--accent-pink)', 'flows')}
          {col('Threat Classes', topClass, 'var(--accent-violet)', 'alerts')}
        </div>
      </div>
    );
  }

  if (type === 'mitre_matrix') {
    return (
      <div>
        <Heading show={showHead} title="MITRE ATT&CK Matrix & Heatmap Navigator"
          sub="Adversary kill-chain mapping with active technique tags and engine coverage" />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
          {mitreTactics.map((m) => (
            <div key={m.tactic} className="glass" style={{
              padding: 16,
              borderTop: `3px solid ${m.count > 0 ? 'var(--accent-cyan)' : 'var(--glass-border)'}`,
              background: m.count > 0 ? 'color-mix(in srgb, var(--accent-cyan) 6%, transparent)' : 'transparent',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>{m.tactic}</span>
                <span className="mono" style={{
                  fontSize: 10, padding: '2px 6px', borderRadius: 4,
                  background: m.count > 0 ? 'color-mix(in srgb, var(--accent-cyan) 20%, transparent)' : 'var(--bg-surface-hover)',
                  color: m.count > 0 ? 'var(--accent-cyan)' : 'var(--text-dim)',
                }}>
                  {m.count} hit{m.count === 1 ? '' : 's'}
                </span>
              </div>
              <div className="mono" style={{ fontSize: 11, color: 'var(--accent-violet)', marginBottom: 4 }}>{m.tech}</div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{m.desc}</div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (type === 'gauges') {
    const dials = [
      { label: 'Sniffer CPU', sub: 'Zero-IP TAP core', pct: 24, color: 'var(--accent-cyan)' },
      { label: 'Redis Bloom Load', sub: 'Count-Min Sketch', pct: 38, color: 'var(--accent-teal)' },
      { label: 'Model Accuracy', sub: 'XGBoost ROC-AUC 97%', pct: 92, color: 'var(--accent-violet)' },
      { label: 'Packet Drop Rate', sub: 'Zero-loss ingestion', pct: 0, color: 'var(--accent-emerald)' },
    ];
    return (
      <div>
        <Heading show={showHead} title="Security Fabric Resource Dials"
          sub="Circular telemetry for compute load, capture buffer and confidence distribution" />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 20, textAlign: 'center', padding: '24px 0' }}>
          {dials.map((d) => (
            <div key={d.label}>
              <div style={{ position: 'relative', width: 110, height: 110, margin: '0 auto' }}>
                <svg width="110" height="110" viewBox="0 0 36 36">
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--chart-band)" strokeWidth="3" />
                  <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke={d.color} strokeDasharray={`${d.pct}, 100`} strokeWidth="3" strokeLinecap="round" />
                </svg>
                <div className="mono" style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20, fontWeight: 700 }}>
                  {d.pct}%
                </div>
              </div>
              <div style={{ fontSize: 13, fontWeight: 600, marginTop: 10 }}>{d.label}</div>
              <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{d.sub}</div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // ai_explain
  return (
    <div>
      <Heading show={showHead} title="Hybrid AI Explainability & Feature Contribution"
        sub="Feature importance across lexical, structural and flow variables (train/serve parity v1.0.0)" />
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 24 }}>
        <div>
          <h4 style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12, textTransform: 'uppercase' }}>
            Top Contributing Features (SHAP / Gini Importance)
          </h4>
          {featureImportance.map((f) => (
            <div key={f.name} style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                <span>{f.name}</span>
                <span className="mono" style={{ color: 'var(--accent-cyan)' }}>{(f.score * 100).toFixed(0)}%</span>
              </div>
              <div style={{ height: 7, background: 'var(--chart-band)', borderRadius: 999, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${f.score * 100}%`, background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-violet))' }} />
              </div>
            </div>
          ))}
        </div>
        <div className="glass" style={{ padding: 18 }}>
          <h4 style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12, textTransform: 'uppercase' }}>
            Hybrid Model Contract Summary
          </h4>
          <div style={{ fontSize: 12, lineHeight: 1.6, color: 'var(--text-muted)' }}>
            <p style={{ marginBottom: 10 }}>
              <strong style={{ color: 'var(--text)' }}>XGBoost Classifier:</strong> supervised detector trained on 674,898 domains. Precision 93.5%, Recall 88.0%, ROC-AUC 97.2%.
            </p>
            <p style={{ marginBottom: 10 }}>
              <strong style={{ color: 'var(--text)' }}>Isolation Forest:</strong> unsupervised outlier detector for zero-day anomalous query structures (advisory).
            </p>
            <p style={{ margin: 0 }}>
              <strong style={{ color: 'var(--text)' }}>Zero train/serve skew:</strong> offline training and live inference both import{' '}
              <span className="mono" style={{ color: 'var(--accent-teal)' }}>src.features.feature_extraction</span> v1.0.0.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
