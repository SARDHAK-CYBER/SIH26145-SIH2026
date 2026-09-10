import { useState, type CSSProperties } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import type { AnalysisResponse, Severity, Alert } from '../types/alert';

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: '#F4576D',
  HIGH: '#F4964F',
  MEDIUM: '#EFC65C',
  LOW: '#7C87A0',
};

interface Props {
  result: AnalysisResponse;
}

export function ResultsView({ result }: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showFullJson, setShowFullJson] = useState(false);

  const pieData = SEVERITY_ORDER
    .map((sev) => ({ name: sev, value: result.severity_counts[sev] ?? 0 }))
    .filter((d) => d.value > 0);

  const sortedAlerts = [...result.alerts].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <div style={{ marginTop: 36 }}>
      {/* Pipeline status -- shows which engines actually ran, not just claimed */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        <PipelineBadge
          label={result.parser_used === 'zeek' ? 'Zeek (real parse)' : 'scapy (fallback)'}
          active={result.parser_used === 'zeek'}
        />
        <PipelineBadge
          label={result.models_active.length ? `ML: ${result.models_active.join(', ')}` : 'ML: none loaded'}
          active={result.models_active.length > 0}
        />
        <PipelineBadge label={result.yara_active ? 'YARA active' : 'YARA: no rules loaded'} active={result.yara_active} />
        {result.packet_summary.files_yara_scanned !== null && (
          <PipelineBadge label={`${result.packet_summary.files_yara_scanned} file(s) YARA-scanned`} active neutral />
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 220px', gap: 16, marginBottom: 28 }}>
        <StatCard label="Flows parsed" value={result.packet_summary.conn_flows} />
        <StatCard label="DNS queries" value={result.packet_summary.dns_queries} />
        <StatCard label="Alerts raised" value={result.alert_count} accent={result.alert_count > 0} />
        <div className="glass" style={{ padding: 16, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={110}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={28} outerRadius={48} paddingAngle={3}>
                  {pieData.map((d) => (
                    <Cell key={d.name} fill={SEVERITY_COLOR[d.name as Severity]} stroke="none" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#12161E', border: '1px solid var(--glass-border)', borderRadius: 8, fontSize: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>No alerts to chart</span>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '0 4px 12px' }}>
        <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>DETECTED ALERTS</span>
        <button className="ghost" style={{ fontSize: 12, padding: '6px 12px' }} onClick={() => setShowFullJson((v) => !v)}>
          {showFullJson ? 'Hide' : 'View'} full response JSON
        </button>
      </div>

      {showFullJson && (
        <pre className="glass mono" style={{
          padding: 16, marginBottom: 20, fontSize: 11, lineHeight: 1.5,
          maxHeight: 400, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}

      <div className="glass" style={{ padding: 0, overflow: 'hidden' }}>
        {sortedAlerts.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)', fontSize: 13 }}>
            No alerts raised for this capture.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr>
                {['Severity', 'Threat class', 'Source', 'Destination', 'Confidence', 'Detected by', 'MITRE'].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: 'left', fontWeight: 500, color: 'var(--text-dim)', fontSize: 11,
                      padding: '10px 14px', borderBottom: '1px solid var(--glass-border)',
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sortedAlerts.map((a) => (
                <AlertRow
                  key={a.alert_id}
                  alert={a}
                  expanded={expandedId === a.alert_id}
                  onToggle={() => setExpandedId(expandedId === a.alert_id ? null : a.alert_id)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function AlertRow({ alert: a, expanded, onToggle }: { alert: Alert; expanded: boolean; onToggle: () => void }) {
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: 'pointer' }}>
        <td style={cellStyle}><span className={`sev-badge sev-${a.severity}`}>{a.severity}</span></td>
        <td className="mono" style={cellStyle}>{a.threat_class}</td>
        <td className="mono" style={cellStyle}>{a.flow_identifier.src_ip}:{a.flow_identifier.src_port}</td>
        <td className="mono" style={cellStyle}>{a.flow_identifier.dst_ip}:{a.flow_identifier.dst_port}</td>
        <td className="mono" style={cellStyle}>{a.confidence_score.toFixed(1)}%</td>
        <td className="mono" style={cellStyle}>{a.detection_mode}</td>
        <td className="mono" style={cellStyle}>{a.mitre_attack.technique_id}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} style={{ padding: 0, borderBottom: '1px solid var(--glass-border)' }}>
            <pre className="mono" style={{
              margin: 0, padding: '14px 18px', fontSize: 11, lineHeight: 1.5,
              background: 'rgba(0,0,0,0.2)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>
              {JSON.stringify(a, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

function PipelineBadge({ label, active, neutral }: { label: string; active: boolean; neutral?: boolean }) {
  const color = neutral ? 'var(--text-dim)' : active ? 'var(--accent-teal)' : 'var(--sev-medium)';
  return (
    <span className="mono" style={{
      fontSize: 11, padding: '4px 10px', borderRadius: 999,
      border: `1px solid ${color}`, color,
    }}>
      {neutral ? '' : active ? '● ' : '○ '}{label}
    </span>
  );
}

const cellStyle: CSSProperties = {
  padding: '11px 14px',
  borderBottom: '1px solid var(--glass-border)',
  fontSize: 12,
};

function StatCard({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="glass" style={{ padding: 18 }}>
      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 6 }}>{label}</div>
      <div className="mono" style={{ fontSize: 24, fontWeight: 600, color: accent ? 'var(--sev-high)' : 'var(--text)' }}>
        {value}
      </div>
    </div>
  );
}
