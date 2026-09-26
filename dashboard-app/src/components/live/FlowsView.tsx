import { useMemo, useState } from 'react';
import type { FlowRow } from '../../types/alert';
import { fmtBytes, fmtDuration, fmtNum } from '../../lib/format';

interface Props {
  flows: FlowRow[];
  onOpenFlow: (filter: string) => void;
}

export function FlowsView({ flows, onOpenFlow }: Props) {
  const [q, setQ] = useState('');
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return flows.filter((f) => !t || `${f['id.orig_h']} ${f['id.resp_h']} ${f['id.orig_p']} ${f['id.resp_p']} ${f.proto}`.toLowerCase().includes(t));
  }, [flows, q]);
  const maxBytes = flows.length ? flows[0].orig_bytes + flows[0].resp_bytes : 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="glass" style={{ padding: 12, display: 'flex', gap: 10, alignItems: 'center' }}>
        <input className="pk-input mono" style={{ maxWidth: 320 }} placeholder="filter flows: ip, port, tcp/udp" value={q} onChange={(e) => setQ(e.target.value)} />
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-dim)' }}>heaviest active conversations · {rows.length} shown</span>
      </div>
      <div className="glass" style={{ padding: 0, overflow: 'auto', maxHeight: '70vh' }}>
        <table className="glass-table">
          <thead>
            <tr><th>Originator</th><th>Responder</th><th>Proto</th><th style={{ width: 170 }}>Bytes</th>
              <th style={{ textAlign: 'right' }}>Out / In</th><th style={{ textAlign: 'right' }}>Packets</th><th style={{ textAlign: 'right' }}>Duration</th></tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const tot = f.orig_bytes + f.resp_bytes;
              return (
                <tr key={f.uid} onClick={() => onOpenFlow(`${f['id.orig_h']} ${f['id.resp_h']} ${f['id.resp_p']}`)} title="Open this conversation's packets">
                  <td className="mono">{f['id.orig_h']}<span style={{ color: 'var(--text-dim)' }}>:{f['id.orig_p']}</span></td>
                  <td className="mono">{f['id.resp_h']}<span style={{ color: 'var(--text-dim)' }}>:{f['id.resp_p']}</span></td>
                  <td>{f.proto.toUpperCase()}</td>
                  <td>
                    <div style={{ fontSize: 11 }} className="mono">{fmtBytes(tot)}</div>
                    <div className="bar"><div style={{ width: `${Math.max(2, (tot / maxBytes) * 100)}%`, background: 'var(--accent-cyan)' }} /></div>
                  </td>
                  <td className="mono" style={{ textAlign: 'right' }}>{fmtBytes(f.orig_bytes)} / {fmtBytes(f.resp_bytes)}</td>
                  <td className="mono" style={{ textAlign: 'right' }}>{fmtNum(f.orig_pkts + f.resp_pkts)}</td>
                  <td className="mono" style={{ textAlign: 'right' }}>{fmtDuration(f.duration)}</td>
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan={7} style={{ padding: 28, color: 'var(--text-dim)', cursor: 'default' }}>No active flows.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
