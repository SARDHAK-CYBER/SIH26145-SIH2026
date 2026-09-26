import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { PacketDetail, PacketRow } from '../types/alert';

export interface PacketSource {
  mode: 'live' | 'pcap';
  /** cursor: pcap = 0-based start index; live = unused (newest rows are returned) */
  list: (cursor: number, limit: number, filter: string) => Promise<{ rows: PacketRow[]; next?: number; total?: number; firstTs?: number }>;
  detail: (id: number) => Promise<PacketDetail>;
  exportUrl: (filter: string) => string;
}

interface Props {
  source: PacketSource;
  /** live: keep refreshing while the capture runs */
  active?: boolean;
  presetFilter?: string;
  emptyHint?: string;
}

const PAGE = 200;
const QUICK: Array<[string, string]> = [
  ['TCP', 'tcp'], ['UDP', 'udp'], ['DNS', 'dns'], ['TLS', 'tls'], ['HTTP', 'http'],
  ['ARP', 'arp'], ['SYN', 'syn'], ['RST', 'rst'], ['not DNS', '!dns'],
];

const PROTO_TINT: Record<string, string> = {
  'HTTPS/TLS': 'rgba(139,92,246,.12)', HTTP: 'rgba(56,189,248,.12)', DNS: 'rgba(16,185,129,.12)', mDNS: 'rgba(16,185,129,.08)',
  ARP: 'rgba(245,158,11,.14)', ICMP: 'rgba(236,72,153,.12)', ICMPv6: 'rgba(236,72,153,.10)', QUIC: 'rgba(139,92,246,.09)',
  Modbus: 'rgba(255,51,102,.14)', DNP3: 'rgba(255,51,102,.14)', 'SMB/NetBIOS': 'rgba(251,191,36,.10)',
};

function fmtTs(ts: number, base: number | null, live: boolean): string {
  if (live || base === null) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
  }
  return (ts - base).toFixed(6);
}

export function PacketInspector({ source, active = true, presetFilter = '', emptyHint }: Props) {
  const live = source.mode === 'live';
  const [filter, setFilter] = useState(presetFilter);
  const [applied, setApplied] = useState(presetFilter);
  const [rows, setRows] = useState<PacketRow[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [cursor, setCursor] = useState(0);
  const [next, setNext] = useState(0);
  const [history, setHistory] = useState<number[]>([]);
  const [firstTs, setFirstTs] = useState<number | null>(null);
  const [follow, setFollow] = useState(true);
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<PacketDetail | null>(null);
  const [layerIdx, setLayerIdx] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const listRef = useRef<HTMLDivElement | null>(null);
  const stick = useRef(true);

  useEffect(() => { setFilter(presetFilter); setApplied(presetFilter); }, [presetFilter]);

  const load = useCallback(async (cur: number, flt: string) => {
    setBusy(true);
    try {
      const r = await source.list(cur, PAGE, flt);
      setRows(r.rows);
      if (r.total !== undefined) setTotal(r.total);
      if (r.next !== undefined) setNext(r.next);
      if (r.firstTs !== undefined) setFirstTs(r.firstTs);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'could not load packets');
    } finally { setBusy(false); }
  }, [source]);

  // pcap: (re)load on filter/cursor change; live: poll while following
  useEffect(() => {
    if (!live) { load(cursor, applied); return; }
    load(0, applied);
    if (!active || !follow) return;
    const t = window.setInterval(() => load(0, applied), 1200);
    return () => window.clearInterval(t);
  }, [live, load, cursor, applied, active, follow]);

  useEffect(() => {
    if (live && follow && stick.current && listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [rows, live, follow]);

  useEffect(() => {
    if (selected === null) { setDetail(null); return; }
    let dead = false;
    source.detail(selected).then((d) => { if (!dead) { setDetail(d); setLayerIdx(null); } })
      .catch((e) => { if (!dead) { setDetail(null); setErr(e instanceof Error ? e.message : 'detail failed'); } });
    return () => { dead = true; };
  }, [selected, source]);

  function apply(f: string) { setApplied(f); setCursor(0); setHistory([]); }
  function toggleQuick(term: string) {
    const parts = filter.split(/\s+/).filter(Boolean);
    const has = parts.includes(term);
    const nextF = (has ? parts.filter((p) => p !== term) : [...parts, term]).join(' ');
    setFilter(nextF); apply(nextF);
  }

  const range = useMemo<[number, number] | null>(() => {
    if (!detail || layerIdx === null) return null;
    const l = detail.layers[layerIdx];
    return l ? [l.start, l.end] : null;
  }, [detail, layerIdx]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="glass" style={{ padding: 12, display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
        <input className="mono pk-input" value={filter} placeholder="filter: tcp 10.0.0.5 syn  ·  !dns  ·  443  ·  ClientHello"
          onChange={(e) => setFilter(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') apply(filter); }} />
        <button className="btn-primary" onClick={() => apply(filter)}>Apply</button>
        {applied && <button className="btn-ghost" onClick={() => { setFilter(''); apply(''); }}>Clear</button>}
        <span style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {QUICK.map(([label, term]) => (
            <button key={term} className={`filter-tag ${filter.split(/\s+/).includes(term) ? 'active' : ''}`} onClick={() => toggleQuick(term)}>{label}</button>
          ))}
        </span>
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center', fontSize: 12, color: 'var(--text-dim)' }}>
          {live ? (
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
              <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
              Follow live {active && follow ? <span className="pulse-dot" /> : null}
            </label>
          ) : (
            <span className="mono">{total !== null ? `${total.toLocaleString()} packets` : ''}</span>
          )}
          <a className="btn-ghost" style={{ textDecoration: 'none' }} href={source.exportUrl(applied)} download>Export .pcap</a>
        </span>
      </div>

      {err && <div className="glass" style={{ padding: 10, fontSize: 12, color: 'var(--sev-critical)' }}>{err}</div>}

      <div className="glass" style={{ padding: 0, overflow: 'hidden' }}>
        <div ref={listRef} className="pk-list"
          onScroll={(e) => { const el = e.currentTarget; stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40; }}>
          <table className="glass-table pk-table">
            <thead>
              <tr><th style={{ width: 70 }}>No.</th><th style={{ width: 118 }}>{live ? 'Time' : 'Time (s)'}</th><th style={{ width: 190 }}>Source</th>
                <th style={{ width: 190 }}>Destination</th><th style={{ width: 96 }}>Protocol</th><th style={{ width: 64 }}>Len</th><th>Info</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={selected === r.id ? 'pk-sel' : ''} style={{ background: selected === r.id ? undefined : PROTO_TINT[r.proto] }}
                  onClick={() => setSelected(r.id)}>
                  <td className="mono">{r.id}</td>
                  <td className="mono">{fmtTs(r.ts, firstTs, live)}</td>
                  <td className="mono">{r.src}{r.sport ? <span style={{ color: 'var(--text-dim)' }}>:{r.sport}</span> : null}</td>
                  <td className="mono">{r.dst}{r.dport ? <span style={{ color: 'var(--text-dim)' }}>:{r.dport}</span> : null}</td>
                  <td>{r.proto}</td>
                  <td className="mono">{r.len}</td>
                  <td className="mono pk-info">{r.info}</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><td colSpan={7} style={{ padding: 28, color: 'var(--text-dim)', cursor: 'default' }}>
                  {busy ? 'Loading…' : applied ? 'No packet matches this filter.' : (emptyHint ?? 'No packets yet.')}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        {!live && (
          <div style={{ display: 'flex', gap: 8, padding: '8px 14px', borderTop: '1px solid var(--glass-border-subtle)', alignItems: 'center', fontSize: 12 }}>
            <button className="btn-ghost" disabled={history.length === 0}
              onClick={() => { const h = [...history]; const prev = h.pop() ?? 0; setHistory(h); setCursor(prev); }}>← Prev</button>
            <button className="btn-ghost" disabled={total !== null && next >= total}
              onClick={() => { setHistory([...history, cursor]); setCursor(next); }}>Next →</button>
            <span className="mono" style={{ color: 'var(--text-dim)' }}>{rows.length ? `#${rows[0].id}–#${rows[rows.length - 1].id}` : ''}</span>
          </div>
        )}
      </div>

      {detail && (
        <div className="pk-detail">
          <div className="glass" style={{ padding: 14, overflow: 'auto', maxHeight: 420 }}>
            <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8 }}>
              Packet {detail.id} · {detail.captured} bytes captured{detail.wire_len !== detail.captured ? ` of ${detail.wire_len} on wire` : ''}
              {detail.truncated ? ' (payload truncated by the ring snap length)' : ''}
            </div>
            {detail.error && <div style={{ color: 'var(--sev-critical)', fontSize: 12 }}>{detail.error}</div>}
            {detail.layers.map((l, i) => (
              <details key={i} open={i < 4} style={{ marginBottom: 6 }}>
                <summary className={`pk-layer ${layerIdx === i ? 'on' : ''}`} onClick={() => setLayerIdx(i)}>
                  {l.name} <span className="mono" style={{ color: 'var(--text-dim)', fontWeight: 400 }}>· bytes {l.start}–{l.end}</span>
                </summary>
                <div style={{ paddingLeft: 16 }}>
                  {l.fields.map((f, k) => (
                    <div key={k} className="mono" style={{ fontSize: 11.5, lineHeight: 1.65, display: 'flex', gap: 8 }}>
                      <span style={{ color: 'var(--code-key)', minWidth: 110 }}>{f.name}</span>
                      <span style={{ color: 'var(--text)', wordBreak: 'break-all' }}>{f.value}</span>
                    </div>
                  ))}
                </div>
              </details>
            ))}
          </div>
          <div className="glass" style={{ padding: 14, overflow: 'auto', maxHeight: 420 }}>
            <div className="mono" style={{ fontSize: 11.5, lineHeight: 1.6 }}>
              {detail.hex.map((row) => {
                const bytes = row.hex.split(' ');
                return (
                  <div key={row.off} style={{ display: 'flex', gap: 14, whiteSpace: 'pre' }}>
                    <span style={{ color: 'var(--text-faint)' }}>{row.off.toString(16).padStart(4, '0')}</span>
                    <span>{bytes.map((b, i) => {
                      const at = row.off + i;
                      const on = range !== null && at >= range[0] && at < range[1];
                      return <span key={i} className={on ? 'pk-hi' : ''}>{b} </span>;
                    })}{' '.repeat(Math.max(0, (16 - bytes.length) * 3))}</span>
                    <span style={{ color: 'var(--text-dim)' }}>{row.ascii}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
