import { useMemo, useState } from 'react';
import type { HostRow } from '../../types/alert';
import { ago, fmtBytes, fmtNum } from '../../lib/format';

type Scope = 'all' | 'local' | 'remote';
type SortKey = 'bytes' | 'pkts' | 'last' | 'ip';

interface Props {
  hosts: HostRow[];
  running: boolean;
  onOpenHost: (ip: string) => void;
}

function ipKey(ip: string): string {
  return ip.includes('.') ? ip.split('.').map((x) => x.padStart(3, '0')).join('.') : ip;
}

export function HostsView({ hosts, running, onOpenHost }: Props) {
  const [scope, setScope] = useState<Scope>('all');
  const [q, setQ] = useState('');
  const [sort, setSort] = useState<SortKey>('bytes');

  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    const f = hosts.filter((h) => (scope === 'all' || (scope === 'local') === h.local)
      && (!t || h.ip.toLowerCase().includes(t) || (h.mac ?? '').includes(t)));
    const by: Record<SortKey, (a: HostRow, b: HostRow) => number> = {
      bytes: (a, b) => b.tx_bytes + b.rx_bytes - (a.tx_bytes + a.rx_bytes),
      pkts: (a, b) => b.tx_pkts + b.rx_pkts - (a.tx_pkts + a.rx_pkts),
      last: (a, b) => b.last - a.last,
      ip: (a, b) => ipKey(a.ip).localeCompare(ipKey(b.ip)),
    };
    return [...f].sort(by[sort]);
  }, [hosts, scope, q, sort]);

  const localCount = hosts.filter((h) => h.local).length;
  const macs = hosts.filter((h) => h.local && h.mac).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="glass" style={{ padding: 14, fontSize: 12.5, color: 'var(--text-muted)', lineHeight: 1.55 }}>
        <strong style={{ color: 'var(--text)' }}>What this sees.</strong> Every host that sent or received a packet on the monitored link, plus every
        device that announced itself by ARP. On a mirror/SPAN port, a TAP, or a gateway this is the whole network; on a plain Wi-Fi client it is this
        machine, its peers' broadcast/multicast traffic, and everything it talks to. Nothing is guessed: rows appear only when packets were seen.
      </div>

      <div className="glass" style={{ padding: 12, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        {(['all', 'local', 'remote'] as Scope[]).map((s) => (
          <button key={s} className={`filter-tag ${scope === s ? 'active' : ''}`} onClick={() => setScope(s)}>
            {s === 'all' ? `All ${hosts.length}` : s === 'local' ? `Local ${localCount}` : `Remote ${hosts.length - localCount}`}
          </button>
        ))}
        <input className="pk-input mono" style={{ maxWidth: 260 }} placeholder="search IP or MAC" value={q} onChange={(e) => setQ(e.target.value)} />
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-dim)' }}>
          sort&nbsp;
          <select className="pk-input" style={{ width: 'auto' }} value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
            <option value="bytes">bytes</option><option value="pkts">packets</option><option value="last">last seen</option><option value="ip">address</option>
          </select>
        </span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>{macs} local MACs learned{running ? ' · live' : ''}</span>
      </div>

      <div className="glass" style={{ padding: 0, overflow: 'auto', maxHeight: '68vh' }}>
        <table className="glass-table">
          <thead>
            <tr><th>Host</th><th>Scope</th><th>MAC</th><th style={{ textAlign: 'right' }}>Sent</th><th style={{ textAlign: 'right' }}>Received</th>
              <th style={{ textAlign: 'right' }}>Packets</th><th>TCP / UDP / other</th><th>First seen</th><th>Last seen</th></tr>
          </thead>
          <tbody>
            {rows.map((h) => (
              <tr key={h.ip} onClick={() => onOpenHost(h.ip)} title="Open this host's packets">
                <td className="mono">{h.ip}</td>
                <td>
                  <span className={`tag ${h.local ? 'tag-local' : 'tag-remote'}`}>{h.local ? 'local' : 'remote'}</span>
                  {h.gateway_for_remote && <span className="tag tag-gw">gateway</span>}
                  {h.via_arp && <span className="tag">ARP</span>}
                </td>
                <td className="mono">{h.mac ?? '—'}</td>
                <td className="mono" style={{ textAlign: 'right' }}>{fmtBytes(h.tx_bytes)}</td>
                <td className="mono" style={{ textAlign: 'right' }}>{fmtBytes(h.rx_bytes)}</td>
                <td className="mono" style={{ textAlign: 'right' }}>{fmtNum(h.tx_pkts + h.rx_pkts)}</td>
                <td className="mono">{fmtNum(h.tcp)} / {fmtNum(h.udp)} / {fmtNum(h.other)}</td>
                <td>{ago(h.first)}</td>
                <td>{ago(h.last)}</td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={9} style={{ padding: 28, color: 'var(--text-dim)', cursor: 'default' }}>
              {hosts.length === 0 ? 'No hosts observed yet — start a capture.' : 'No host matches.'}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
