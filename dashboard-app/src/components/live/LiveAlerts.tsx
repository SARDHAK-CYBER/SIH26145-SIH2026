import { useMemo, useState } from 'react';
import type { Alert } from '../../types/alert';

const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

interface Props {
  alerts: Alert[];
  running: boolean;
  onSelect: (a: Alert) => void;
  onOpenPackets: (a: Alert) => void;
}

export function LiveAlerts({ alerts, running, onSelect, onOpenPackets }: Props) {
  const [sev, setSev] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return alerts.filter((a) => (!sev || a.severity === sev)
      && (!t || `${a.threat_class} ${a.flow_identifier.src_ip} ${a.flow_identifier.dst_ip} ${a.mitre_attack.technique_id}`.toLowerCase().includes(t)));
  }, [alerts, sev, q]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="glass" style={{ padding: 12, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        {SEVS.map((s) => (
          <button key={s} className={`filter-tag ${sev === s ? 'active' : ''}`} onClick={() => setSev(sev === s ? null : s)}>
            {s} {alerts.filter((a) => a.severity === s).length}
          </button>
        ))}
        <input className="pk-input mono" style={{ maxWidth: 300 }} placeholder="search class, IP, MITRE id" value={q} onChange={(e) => setQ(e.target.value)} />
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-dim)' }}>{running ? <><span className="pulse-dot" style={{ display: 'inline-block', marginRight: 6 }} />streaming</> : 'stream closed'} · {rows.length} shown</span>
      </div>
      <div className="glass" style={{ padding: 0, overflow: 'auto', maxHeight: '70vh' }}>
        <table className="glass-table">
          <thead>
            <tr><th>Time</th><th>Severity</th><th>Threat</th><th>Flow</th><th>MITRE</th><th>Mode</th><th style={{ textAlign: 'right' }}>Conf.</th><th style={{ textAlign: 'right' }}>Latency</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const lat = (a.evidence as Record<string, unknown>)?.detection_latency_ms as number | undefined;
              return (
                <tr key={a.alert_id} onClick={() => onSelect(a)}>
                  <td className="mono">{new Date(a.timestamp * 1000).toLocaleTimeString([], { hour12: false })}</td>
                  <td><span className={`sev-badge sev-${a.severity}`}>{a.severity}</span></td>
                  <td><strong>{a.threat_class.replace(/_/g, ' ')}</strong></td>
                  <td className="mono">{a.flow_identifier.src_ip}:{a.flow_identifier.src_port} → {a.flow_identifier.dst_ip}:{a.flow_identifier.dst_port}</td>
                  <td className="mono">{a.mitre_attack.technique_id}</td>
                  <td>{a.detection_mode}</td>
                  <td className="mono" style={{ textAlign: 'right' }}>{a.confidence_score}</td>
                  <td className="mono" style={{ textAlign: 'right', color: 'var(--accent-cyan)' }}>{lat !== undefined ? `${lat} ms` : '—'}</td>
                  <td><button className="btn-ghost" style={{ padding: '3px 9px', fontSize: 11 }} onClick={(e) => { e.stopPropagation(); onOpenPackets(a); }}>Packets</button></td>
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan={9} style={{ padding: 28, color: 'var(--text-dim)', cursor: 'default' }}>
              {alerts.length === 0 ? 'No alerts yet. When an engine or model fires, it appears here the moment it happens.' : 'No alert matches.'}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
