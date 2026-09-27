import { useEffect, useMemo, useState } from 'react';
import { ApiError, network, type Coverage, type DiscoveredHost } from '../../api/client';
import type { HostRow } from '../../types/alert';
import { ago, fmtBytes, fmtNum } from '../../lib/format';
import { can, useSession } from '../../lib/session';

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
      <CoverageCard running={running} />

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

const VERDICT_TEXT: Record<string, { label: string; color: string }> = {
  full: { label: 'Full visibility', color: 'var(--accent-emerald)' },
  partial: { label: 'Partial visibility', color: 'var(--sev-medium)' },
  'own-traffic-only': { label: 'This machine + broadcast only', color: 'var(--sev-high)' },
};

function CoverageCard({ running }: { running: boolean }) {
  const session = useSession();
  const canControl = can(session.role, 'capture');
  const [cov, setCov] = useState<Coverage | null>(null);
  const [found, setFound] = useState<DiscoveredHost[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [mode, setMode] = useState<string | undefined>();

  useEffect(() => {
    let dead = false;
    const pull = () => network.coverage((found ?? []).map((h) => h.ip)).then((c) => { if (!dead) setCov(c); }).catch(() => {});
    pull();
    const t = window.setInterval(pull, 5000);
    return () => { dead = true; window.clearInterval(t); };
  }, [found, running]);

  async function discover() {
    setBusy(true); setErr(null);
    try { const r = await network.discover(); setFound(r.hosts); setMode(r.mode); }
    catch (e) { setErr(e instanceof ApiError ? e.message : 'discovery failed'); }
    finally { setBusy(false); }
  }

  const v = cov ? (VERDICT_TEXT[cov.verdict] ?? { label: cov.verdict, color: 'var(--text-muted)' }) : null;
  return (
    <div className="glass" style={{ padding: 16, display: 'grid', gap: 10 }}>
      <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--text-muted)' }}>Network visibility</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: v?.color }}>{v?.label ?? '—'}
            {cov?.visible_ratio != null && <span className="mono" style={{ fontSize: 13, marginLeft: 10, color: 'var(--text-dim)' }}>{Math.round(cov.visible_ratio * 100)}%</span>}
          </div>
        </div>
        <div className="mono" style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
          {cov ? <>{cov.visible_devices} of {cov.local_devices_known} local devices have visible unicast traffic<br />
            {cov.known_only_devices} known only from ARP / broadcast{found ? ' / active discovery' : ''}</> : 'waiting for capture…'}
        </div>
        <button className="btn-ghost" style={{ marginLeft: 'auto' }} disabled={busy || !canControl} onClick={discover}>
          {busy ? 'Sweeping subnet…' : 'Discover devices on my subnet'}
        </button>
      </div>
      {cov?.advice && <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.55 }}>{cov.advice}</div>}
      {err && <div style={{ fontSize: 12, color: 'var(--sev-critical)' }}>{err}</div>}
      {found && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          Active sweep ({mode}): {found.length} device{found.length === 1 ? '' : 's'} answered ARP
          {cov && cov.silent_discovered.length > 0 ? ` — ${cov.silent_discovered.length} of them never appeared in the captured traffic (blind spot): ` : '.'}
          <span className="mono">{cov?.silent_discovered.slice(0, 12).join(', ')}</span>
        </div>
      )}
    </div>
  );
}
