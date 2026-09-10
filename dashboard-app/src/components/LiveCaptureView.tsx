import { useCallback, useEffect, useRef, useState } from 'react';
import { live, ApiError } from '../api/client';
import type { Alert, CaptureInterface, CaptureStatus } from '../types/alert';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--sev-critical)',
  HIGH: 'var(--sev-high)',
  MEDIUM: 'var(--sev-medium)',
  LOW: 'var(--sev-low)',
};

export const LiveCaptureView: React.FC = () => {
  const [ifaces, setIfaces] = useState<CaptureInterface[]>([]);
  const [selected, setSelected] = useState('');
  const [bpf, setBpf] = useState('ip or ip6');
  const [bufferMb, setBufferMb] = useState(64);
  const [preferKernel, setPreferKernel] = useState(true);
  const [caps, setCaps] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<CaptureStatus>({ running: false });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const esRef = useRef<EventSource | null>(null);
  const pollRef = useRef<number | null>(null);
  const seenRef = useRef<Set<string>>(new Set());

  const loadInterfaces = useCallback(async () => {
    try {
      const [list, c] = await Promise.all([live.interfaces(), live.capabilities()]);
      setIfaces(list);
      setCaps(c);
      setSelected((cur) => cur || list.find((i) => i.is_up && !i.is_loopback)?.name || list[0]?.name || '');
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not reach the live-capture service. Start it with:  python -m src.capture.live_agent serve --port 8100');
    }
  }, []);

  useEffect(() => {
    loadInterfaces();
    live.status().then(setStatus).catch(() => {});
  }, [loadInterfaces]);

  const openStream = useCallback(() => {
    esRef.current?.close();
    const es = new EventSource(live.streamUrl());
    es.onmessage = (ev) => {
      if (!ev.data) return;
      try {
        const a: Alert = JSON.parse(ev.data);
        if (seenRef.current.has(a.alert_id)) return;
        seenRef.current.add(a.alert_id);
        setAlerts((prev) => [a, ...prev].slice(0, 300));
      } catch { /* keepalive */ }
    };
    esRef.current = es;
  }, []);

  const startPolling = useCallback(() => {
    if (pollRef.current) return;
    pollRef.current = window.setInterval(() => { live.status().then(setStatus).catch(() => {}); }, 1500);
  }, []);
  const stopPolling = useCallback(() => {
    if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  useEffect(() => () => { esRef.current?.close(); stopPolling(); }, [stopPolling]);
  useEffect(() => {
    if (status.running) { openStream(); startPolling(); }
    else { esRef.current?.close(); esRef.current = null; stopPolling(); }
  }, [status.running, openStream, startPolling, stopPolling]);

  async function handleStart() {
    setBusy(true); setError(null); setAlerts([]); seenRef.current = new Set();
    try { setStatus(await live.start(selected, bpf, preferKernel, bufferMb)); }
    catch (e) { setError(e instanceof ApiError ? e.message : 'Failed to start capture'); }
    finally { setBusy(false); }
  }
  async function handleStop() {
    setBusy(true);
    try { setStatus(await live.stop()); } catch { /* ignore */ } finally { setBusy(false); }
  }

  const tp = status.throughput ?? {};
  const lat = status.detection_latency ?? {};
  const asm = status.assembler ?? {};
  const cur = ifaces.find((i) => i.name === selected);
  const npcap = caps.npcap_installed;
  const platform = String(caps.platform ?? '');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header + capabilities */}
      <div className="glass" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Live NIC Capture — kernel-level tap</h2>
              <span className="mono" style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: 'rgba(0,229,255,.15)', color: 'var(--accent-cyan)' }}>
                AF_PACKET / Npcap
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 0' }}>
              In-kernel BPF + memory-mapped RX ring + PACKET_FANOUT. Same ENG01–13 engines + ONNX models as the PCAP path; alerts land in the shared store.
            </p>
          </div>
          <span className="mono" style={{
            fontSize: 11, padding: '4px 10px', borderRadius: 6,
            background: 'rgba(255,255,255,.05)', color: 'var(--text-muted)', border: '1px solid var(--glass-border-subtle)',
          }}>
            {platform || '—'} · kernel: {String(caps.kernel_backend ?? caps.portable_backend ?? '?')}
            {platform === 'Windows' && ` · Npcap ${npcap === true ? 'OK' : npcap === false ? 'MISSING' : '?'}`}
          </span>
        </div>

        {/* Config */}
        <div style={{ display: 'grid', gap: 12, marginTop: 18 }}>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '.04em' }}>
              Network interface to capture — live capture only
            </span>
            <select value={selected} disabled={status.running} onChange={(e) => setSelected(e.target.value)}
              style={inp}>
              {ifaces.length === 0 && <option value="">— no interfaces found —</option>}
              {ifaces.map((i) => (
                <option key={i.name} value={i.name}>
                  {i.is_up ? '● ' : '○ '}{i.name}{i.description ? ` — ${i.description}` : ''}
                  {i.ipv4[0] ? `  [${i.ipv4[0]}]` : ''}{i.speed_mbps ? `  ${i.speed_mbps}Mb` : ''}
                  {i.kernel_capture ? '  [kernel]' : ''}
                </option>
              ))}
            </select>
          </label>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 130px', gap: 12 }}>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '.04em' }}>
                Kernel BPF filter — compiled into the kernel
              </span>
              <input value={bpf} disabled={status.running} onChange={(e) => setBpf(e.target.value)}
                placeholder="tcp or udp  |  port 502 or port 20000  |  not arp"
                className="mono" style={inp} />
            </label>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '.04em' }}>Buffer (MiB)</span>
              <input type="number" min={0} max={512} value={bufferMb} disabled={status.running}
                onChange={(e) => setBufferMb(Number(e.target.value))} className="mono" style={inp} />
            </label>
          </div>

          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)' }}>
            <input type="checkbox" checked={preferKernel} disabled={status.running}
              onChange={(e) => setPreferKernel(e.target.checked)} />
            Prefer kernel-level capture (AF_PACKET mmap ring + FANOUT on Linux; libpcap/Npcap kernel ring otherwise)
          </label>

          <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
            {!status.running ? (
              <button className="btn-primary" onClick={handleStart} disabled={busy || !selected}>
                {busy ? 'Starting…' : 'Start live capture'}
              </button>
            ) : (
              <button className="btn-primary" onClick={handleStop} disabled={busy}
                style={{ background: 'var(--sev-critical)' }}>
                {busy ? 'Stopping…' : 'Stop capture'}
              </button>
            )}
            <button className="btn-ghost" onClick={loadInterfaces} disabled={status.running}>Refresh</button>
          </div>

          {cur && !cur.is_up && !status.running && (
            <div style={{ fontSize: 12, color: 'var(--sev-medium)' }}>
              “{cur.name}” is down — capture starts but sees no traffic until it’s up.
            </div>
          )}
          {error && (
            <div className="glass" style={{ padding: 12, fontSize: 12, color: 'var(--sev-critical)', border: '1px solid rgba(255,51,102,.35)' }}>
              {error}
            </div>
          )}
        </div>
      </div>

      {/* Live telemetry */}
      {status.running && (
        <>
          {tp.high_speed && (
            <div className="glass mono" style={{ padding: '12px 18px', border: '1px solid var(--sev-high)', color: 'var(--sev-high)', fontSize: 13 }}>
              HIGH-SPEED STREAM — {tp.high_speed_flags?.join(' · ')}
            </div>
          )}
          <div className="glass" style={{ padding: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 16 }}>
              <Stat k="backend" v={`${status.backend}${status.kernel_level ? ' (kernel)' : ''}`} />
              <Stat k="throughput" v={`${fmt(tp.pps)} pps`} sub={`${fmt(tp.mbps, 2)} Mbit/s`} hi />
              <Stat k="peak" v={`${fmt(tp.peak_pps)} pps`} sub={`${fmt(tp.peak_mbps, 2)} Mbit/s`} />
              <Stat k="kernel drop" v={fmt(tp.kernel_drop_total)} warn={(tp.kernel_drop_total ?? 0) > 0}
                sub={tp.kernel_drop_delta ? `+${tp.kernel_drop_delta}` : 'keeping up'} />
              <Stat k="userspace drop" v={fmt(status.dropped)} warn={(status.dropped ?? 0) > 0} />
              <Stat k="active flows" v={fmt(status.active_flows)} sub={`queue ${fmt(status.queue_depth)}`} />
              <Stat k="detection latency" v={lat.p50_ms != null ? `${lat.p50_ms} ms p50` : '—'}
                sub={lat.p95_ms != null ? `${lat.p95_ms} p95 · ${lat.p99_ms ?? '—'} p99` : `${lat.samples ?? 0} samples`} hi />
              <Stat k="dns / tls" v={`${fmt(asm.dns)} / ${fmt(asm.ssl)}`} />
              <Stat k="modbus / dnp3" v={`${fmt(asm.modbus)} / ${fmt(asm.dnp3)}`} />
              <Stat k="alerts" v={fmt(status.alerts)} hi />
              <Stat k="ml families" v={(status.ml_families ?? []).join(', ') || 'none'} />
              <Stat k="re-score every" v={`${status.snapshot_interval_s ?? '?'}s`} />
            </div>
          </div>
        </>
      )}

      {/* Live alert stream */}
      <div className="glass" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="mono" style={{ padding: '12px 18px', borderBottom: '1px solid var(--glass-border-subtle)', fontSize: 12, color: 'var(--text-muted)' }}>
          LIVE ALERT STREAM {status.running ? '● connected' : '○ idle'} — {alerts.length} shown
        </div>
        <div style={{ maxHeight: 460, overflowY: 'auto' }}>
          {alerts.length === 0 && (
            <div style={{ padding: 24, fontSize: 13, color: 'var(--text-dim)' }}>
              {status.running ? 'Capturing… alerts appear here as engines + models fire on the live stream.' : 'Start a capture to see live alerts.'}
            </div>
          )}
          {alerts.map((a) => {
            const latMs = (a.evidence as Record<string, unknown>)?.detection_latency_ms as number | undefined;
            return (
              <div key={a.alert_id} style={{
                padding: '10px 18px', borderBottom: '1px solid var(--glass-border-subtle)', fontSize: 12,
                display: 'grid', gridTemplateColumns: '86px 1fr auto', gap: 12, alignItems: 'center',
              }}>
                <span className="mono" style={{ color: SEV_COLOR[a.severity], fontWeight: 700 }}>{a.severity}</span>
                <span style={{ color: 'var(--text)' }}>
                  <strong>{a.threat_class}</strong>
                  <span style={{ color: 'var(--text-dim)' }}>
                    {' · '}{a.flow_identifier.src_ip}:{a.flow_identifier.src_port} → {a.flow_identifier.dst_ip}:{a.flow_identifier.dst_port}
                    {' · '}{a.detection_mode}{' · '}{a.mitre_attack.technique_id}
                    {latMs != null && <span style={{ color: 'var(--accent-cyan)' }}>{' · '}{latMs} ms</span>}
                  </span>
                </span>
                <span className="mono" style={{ color: 'var(--accent-cyan)' }}>{a.confidence_score}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

const inp: React.CSSProperties = {
  padding: '8px 12px', fontSize: 13, borderRadius: 'var(--radius-sm)',
  background: 'rgba(0,0,0,.3)', border: '1px solid var(--glass-border)', color: 'var(--text)',
  outline: 'none', width: '100%',
};

function fmt(n?: number, d = 0): string {
  if (n == null) return '—';
  return d ? n.toFixed(d) : Math.round(n).toLocaleString();
}

function Stat({ k, v, sub, hi, warn }: { k: string; v: string; sub?: string; hi?: boolean; warn?: boolean }) {
  return (
    <div style={{ display: 'grid', gap: 3 }}>
      <span style={{ color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '.05em', fontSize: 10 }}>{k}</span>
      <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: warn ? 'var(--sev-critical)' : hi ? 'var(--accent-cyan)' : 'var(--text)' }}>{v}</span>
      {sub && <span className="mono" style={{ fontSize: 10, color: 'var(--text-dim)' }}>{sub}</span>}
    </div>
  );
}
