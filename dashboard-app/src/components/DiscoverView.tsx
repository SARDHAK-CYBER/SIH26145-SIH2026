import React, { useMemo, useState } from 'react';
import type { AnalysisResponse, Alert } from '../types/alert';

interface DiscoverViewProps {
  data: AnalysisResponse;
  onSelectAlert: (alert: Alert) => void;
}

type FieldKey = 'severity' | 'threat_class' | 'protocol' | 'detection_mode' | 'src_ip' | 'dst_ip' | 'mitre';

const FIELDS: Array<{ key: FieldKey; label: string; get: (a: Alert) => string }> = [
  { key: 'severity', label: 'severity', get: (a) => a.severity },
  { key: 'threat_class', label: 'threat_class', get: (a) => a.threat_class },
  { key: 'protocol', label: 'flow.protocol', get: (a) => a.flow_identifier.protocol },
  { key: 'detection_mode', label: 'detection_mode', get: (a) => a.detection_mode },
  { key: 'src_ip', label: 'flow.src_ip', get: (a) => a.flow_identifier.src_ip },
  { key: 'dst_ip', label: 'flow.dst_ip', get: (a) => a.flow_identifier.dst_ip },
  { key: 'mitre', label: 'mitre.technique_id', get: (a) => a.mitre_attack.technique_id },
];

export const DiscoverView: React.FC<DiscoverViewProps> = ({ data, onSelectAlert }) => {
  const [query, setQuery] = useState('');
  const [pinned, setPinned] = useState<Record<string, string>>({});
  const [expanded, setExpanded] = useState<string | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data.alerts || [])
      .filter((a) => {
        for (const [k, v] of Object.entries(pinned)) {
          const f = FIELDS.find((x) => x.key === (k as FieldKey));
          if (f && f.get(a) !== v) return false;
        }
        if (!q) return true;
        return JSON.stringify(a).toLowerCase().includes(q);
      })
      .sort((a, b) => b.timestamp - a.timestamp);
  }, [data.alerts, query, pinned]);

  // time histogram — 12 buckets across the span of matching docs
  const histo = useMemo(() => {
    if (rows.length === 0) return [];
    const times = rows.map((r) => r.timestamp);
    const min = Math.min(...times);
    const max = Math.max(...times);
    const span = Math.max(max - min, 1);
    const buckets = new Array(12).fill(0);
    rows.forEach((r) => {
      const i = Math.min(11, Math.floor(((r.timestamp - min) / span) * 12));
      buckets[i] += 1;
    });
    const peak = Math.max(...buckets, 1);
    return buckets.map((c) => ({ c, h: (c / peak) * 100 }));
  }, [rows]);

  const fieldValues = (f: (typeof FIELDS)[number]) => {
    const counts: Record<string, number> = {};
    rows.forEach((a) => { const v = f.get(a); counts[v] = (counts[v] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Query bar */}
      <div className="glass" style={{ padding: 14, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter documents — free text over the full alert JSON"
          style={{
            flex: '1 1 320px', minWidth: 240, padding: '8px 12px', fontSize: 13,
            borderRadius: 'var(--radius-sm)', background: 'var(--bg-inset)',
            border: '1px solid var(--glass-border-subtle)', color: 'var(--text)', outline: 'none', fontFamily: 'inherit',
          }}
        />
        <span className="mono" style={{ fontSize: 12, color: 'var(--text-dim)' }}>
          {rows.length.toLocaleString()} / {(data.alerts || []).length.toLocaleString()} hits
        </span>
        {Object.keys(pinned).length > 0 && (
          <button className="btn-ghost" style={{ fontSize: 11, padding: '4px 10px' }} onClick={() => setPinned({})}>
            Clear {Object.keys(pinned).length} filter{Object.keys(pinned).length === 1 ? '' : 's'}
          </button>
        )}
      </div>

      {/* Time histogram */}
      <div className="glass" style={{ padding: '14px 18px' }}>
        <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-dim)', marginBottom: 8 }}>
          Documents over time
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 70 }}>
          {histo.length === 0 && <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>No documents match.</span>}
          {histo.map((b, i) => (
            <div key={i} title={`${b.c} docs`} style={{
              flex: 1, height: `${Math.max(b.h, b.c > 0 ? 6 : 0)}%`,
              background: 'linear-gradient(180deg, var(--accent-cyan), color-mix(in srgb, var(--accent-cyan) 30%, transparent))',
              borderRadius: '3px 3px 0 0', minHeight: b.c > 0 ? 4 : 0,
            }} />
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '240px minmax(0, 1fr)', gap: 16 }}>
        {/* Field list */}
        <div className="glass" style={{ padding: 14, alignSelf: 'start' }}>
          <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-dim)', marginBottom: 10 }}>
            Selected fields
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {FIELDS.map((f) => (
              <div key={f.key}>
                <div className="mono" style={{ fontSize: 11, color: 'var(--text)', fontWeight: 600, marginBottom: 4 }}>{f.label}</div>
                {fieldValues(f).map(([val, count]) => {
                  const active = pinned[f.key] === val;
                  return (
                    <div
                      key={val}
                      onClick={() => setPinned((p) => {
                        const next = { ...p };
                        if (active) delete next[f.key]; else next[f.key] = val;
                        return next;
                      })}
                      style={{
                        display: 'flex', justifyContent: 'space-between', gap: 8, cursor: 'pointer',
                        fontSize: 11, padding: '3px 6px', borderRadius: 4,
                        background: active ? 'color-mix(in srgb, var(--accent-cyan) 16%, transparent)' : 'transparent',
                        color: active ? 'var(--accent-cyan)' : 'var(--text-muted)',
                      }}
                    >
                      <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{val}</span>
                      <span className="mono" style={{ color: 'var(--text-dim)' }}>{count}</span>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>

        {/* Document table */}
        <div className="glass" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="glass-table">
              <thead>
                <tr>
                  <th style={{ width: 32 }} />
                  <th>Time (UTC)</th>
                  <th>severity</th>
                  <th>threat_class</th>
                  <th>flow</th>
                  <th>detection_mode</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => {
                  const open = expanded === a.alert_id;
                  return (
                    <React.Fragment key={a.alert_id}>
                      <tr onClick={() => setExpanded(open ? null : a.alert_id)}>
                        <td className="mono" style={{ color: 'var(--text-dim)' }}>{open ? '▾' : '▸'}</td>
                        <td className="mono" style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                          {new Date(a.timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ')}
                        </td>
                        <td><span className={`sev-badge sev-${a.severity}`}>{a.severity}</span></td>
                        <td className="mono" style={{ fontWeight: 600 }}>{a.threat_class}</td>
                        <td className="mono" style={{ color: 'var(--text-muted)' }}>
                          {a.flow_identifier.src_ip}:{a.flow_identifier.src_port} → {a.flow_identifier.dst_ip}:{a.flow_identifier.dst_port} / {a.flow_identifier.protocol}
                        </td>
                        <td className="mono" style={{ color: 'var(--text-dim)' }}>{a.detection_mode}</td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={6} style={{ background: 'var(--bg-inset)' }}>
                            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
                              <button className="btn-ghost" style={{ fontSize: 11, padding: '4px 10px' }} onClick={() => onSelectAlert(a)}>
                                Open forensic drawer
                              </button>
                            </div>
                            <pre className="mono" style={{
                              fontSize: 11, lineHeight: 1.5, margin: 0, maxHeight: 320, overflow: 'auto',
                              color: 'var(--text-muted)',
                            }}>
                              {JSON.stringify(a, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
                {rows.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: 24 }}>No documents match the current query.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
