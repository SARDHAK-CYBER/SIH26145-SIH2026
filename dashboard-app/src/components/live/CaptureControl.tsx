import { useCallback, useEffect, useState } from 'react';
import { ApiError, LIVE_DEFAULT_BASE, liveBase, live, setLiveBase } from '../../api/client';
import type { CaptureInterface, CaptureStatus } from '../../types/alert';
import { fmtDuration, fmtNum } from '../../lib/format';

interface Props {
  status: CaptureStatus;
  reachable: boolean;
  onChanged: () => void;
  onStarted: () => void;
}

interface ReplayFile { path: string; name: string; mb: number }

const inp: React.CSSProperties = {
  padding: '8px 12px', fontSize: 13, borderRadius: 'var(--radius-sm)', background: 'var(--bg-inset)',
  border: '1px solid var(--glass-border)', color: 'var(--text)', outline: 'none', width: '100%',
};
const lbl: React.CSSProperties = { fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '.04em' };

export function CaptureControl({ status, reachable, onChanged, onStarted }: Props) {
  const [ifaces, setIfaces] = useState<CaptureInterface[]>([]);
  const [caps, setCaps] = useState<Record<string, unknown>>({});
  const [selected, setSelected] = useState('');
  const [bpf, setBpf] = useState('ip or ip6 or arp');
  const [bufferMb, setBufferMb] = useState(64);
  const [files, setFiles] = useState<ReplayFile[]>([]);
  const [replayPath, setReplayPath] = useState('');
  const [loops, setLoops] = useState(1);
  const [realtime, setRealtime] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [sensorUrl, setSensorUrl] = useState(liveBase());

  const load = useCallback(async () => {
    try {
      const [list, c, f] = await Promise.all([
        live.interfaces(), live.capabilities(),
        fetch(`${liveBase()}/capture/replay-files`).then((r) => (r.ok ? r.json() : [])) as Promise<ReplayFile[]>,
      ]);
      setIfaces(list); setCaps(c); setFiles(f);
      setSelected((cur) => cur || list.find((i) => i.is_up && !i.is_loopback && i.ipv4.length)?.name || list[0]?.name || '');
      setReplayPath((cur) => cur || f[0]?.path || '');
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : `Could not reach the sensor at ${liveBase()}. Start it with:  python stealthtap_app.py  (or python -m src.capture.live_agent serve --port 8100)`);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const cur = ifaces.find((i) => i.name === selected);
  const running = status.running;
  const elevated = caps.elevated as boolean | null | undefined;
  const npcapMissing = caps.platform === 'Windows' && caps.npcap_installed === false;

  async function run(label: string, fn: () => Promise<unknown>, started = false) {
    setBusy(label); setErr(null);
    try { await fn(); onChanged(); if (started) onStarted(); }
    catch (e) { setErr(e instanceof ApiError ? e.message : `Failed to ${label}`); }
    finally { setBusy(null); }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {!reachable && (
        <div className="glass" style={{ padding: 14, fontSize: 13, color: 'var(--sev-critical)', border: '1px solid rgba(255,51,102,.35)' }}>
          The live sensor is not reachable at <span className="mono">{liveBase()}</span>. Start it with <span className="mono">python stealthtap_app.py</span>.
        </div>
      )}
      {err && reachable && <div className="glass" style={{ padding: 14, fontSize: 13, color: 'var(--sev-critical)', border: '1px solid rgba(255,51,102,.35)' }}>{err}</div>}

      <div className="glass" style={{ padding: 14, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', fontSize: 12.5 }}>
        <span style={lbl}>Sensor endpoint</span>
        <input className="mono" style={{ ...inp, maxWidth: 320 }} value={sensorUrl} onChange={(e) => setSensorUrl(e.target.value)} placeholder="(this server)" />
        <button className="btn-ghost" onClick={() => { setLiveBase(sensorUrl); window.location.reload(); }}>Connect</button>
        {sensorUrl !== LIVE_DEFAULT_BASE && <button className="btn-ghost" onClick={() => { setLiveBase(null); window.location.reload(); }}>Reset</button>}
        <span style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>Point at a dedicated (e.g. elevated) sensor process, such as http://127.0.0.1:8101</span>
      </div>

      {running && (
        <div className="glass" style={{ padding: 16, display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="pulse-dot" />
          <div style={{ flex: 1, minWidth: 220 }}>
            <div style={{ fontWeight: 700, fontSize: 14 }}>
              {status.source === 'pcap-replay' ? 'Replaying capture' : `Capturing on ${status.interface}`}
            </div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 3 }}>
              {status.backend} · up {fmtDuration(status.uptime_s)} · {fmtNum(status.capture?.recv)} packets
              {status.bpf ? ` · BPF "${status.bpf}"` : ''}
            </div>
          </div>
          <button className="btn-primary" style={{ background: 'var(--sev-critical)' }} disabled={busy !== null}
            onClick={() => run('stop capture', () => live.stop())}>{busy === 'stop capture' ? 'Stopping…' : 'Stop'}</button>
        </div>
      )}

      <div className="live-grid-2" style={{ alignItems: 'start' }}>
        <div className="glass" style={{ padding: 20, display: 'grid', gap: 14 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700 }}>Capture a network interface</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.5 }}>
              Real packets, straight from the NIC driver, through the native capture engine into all 13 engines and the ML models.
            </div>
          </div>

          {npcapMissing && <div style={{ fontSize: 12, color: 'var(--sev-high)' }}>Npcap is not installed — live capture on Windows needs it (npcap.com).</div>}
          {caps.platform === 'Windows' && elevated === false && (
            <div style={{ fontSize: 12, color: 'var(--sev-medium)', lineHeight: 1.5 }}>
              The sensor is not running elevated. If Npcap was installed in “Administrators only” mode, Windows will show one UAC prompt when the capture opens —
              approve it once, or start the sensor as Administrator.
            </div>
          )}

          <label style={{ display: 'grid', gap: 6 }}>
            <span style={lbl}>Interface</span>
            <select value={selected} disabled={running} onChange={(e) => setSelected(e.target.value)} style={inp}>
              {ifaces.length === 0 && <option value="">— no interfaces found —</option>}
              {ifaces.map((i) => (
                <option key={i.name} value={i.name}>
                  {i.is_up ? '● ' : '○ '}{i.name}{i.ipv4[0] ? `  [${i.ipv4[0]}]` : ''}{i.speed_mbps ? `  ${i.speed_mbps} Mb` : ''}
                </option>
              ))}
            </select>
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px', gap: 12 }}>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={lbl}>Kernel BPF filter</span>
              <input className="mono" style={inp} value={bpf} disabled={running} onChange={(e) => setBpf(e.target.value)} placeholder="ip or ip6 or arp" />
            </label>
            <label style={{ display: 'grid', gap: 6 }}>
              <span style={lbl}>Buffer MiB</span>
              <input className="mono" style={inp} type="number" min={0} max={512} value={bufferMb} disabled={running} onChange={(e) => setBufferMb(Number(e.target.value))} />
            </label>
          </div>
          {cur && !cur.is_up && !running && <div style={{ fontSize: 12, color: 'var(--sev-medium)' }}>“{cur.name}” is down — the capture starts but sees nothing until it is up.</div>}
          <button className="btn-primary" disabled={running || busy !== null || !selected}
            onClick={() => run('start capture', () => live.start(selected, bpf, true, bufferMb), true)}>
            {busy === 'start capture' ? 'Opening the capture driver…' : 'Start live capture'}
          </button>
          <div style={{ fontSize: 11.5, color: 'var(--text-dim)', lineHeight: 1.55 }}>
            Coverage depends on where this machine sits. Connected to a switch <em>mirror port</em>, a network <em>TAP</em>, or acting as the
            <em> gateway</em> (e.g. a hotspot/ICS host or a bridge), it sees every host's traffic. As an ordinary Wi-Fi/Ethernet client it sees its own
            traffic plus broadcast/multicast from the rest of the segment.
          </div>
        </div>

        <div className="glass" style={{ padding: 20, display: 'grid', gap: 14 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700 }}>Replay a recorded capture</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.5 }}>
              Pushes a real .pcap through the exact same live pipeline — same capture thread, engines and dashboard — for validation and load tests.
            </div>
          </div>
          <label style={{ display: 'grid', gap: 6 }}>
            <span style={lbl}>Capture file</span>
            {files.length > 0 && (
              <select style={inp} value={replayPath} disabled={running} onChange={(e) => setReplayPath(e.target.value)}>
                {files.map((f) => <option key={f.path} value={f.path}>{f.name} — {f.mb} MB</option>)}
                {!files.some((f) => f.path === replayPath) && replayPath && <option value={replayPath}>{replayPath}</option>}
              </select>
            )}
            <input className="mono" style={inp} value={replayPath} disabled={running} onChange={(e) => setReplayPath(e.target.value)} placeholder="C:\path\to\capture.pcap" />
          </label>
          <div style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap', fontSize: 12.5 }}>
            <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              Loops
              <select style={{ ...inp, width: 96 }} value={loops} disabled={running} onChange={(e) => setLoops(Number(e.target.value))}>
                <option value={1}>once</option><option value={5}>5×</option><option value={0}>forever</option>
              </select>
            </label>
            <label style={{ display: 'flex', gap: 8, alignItems: 'center', cursor: 'pointer' }}>
              <input type="checkbox" checked={realtime} disabled={running} onChange={(e) => setRealtime(e.target.checked)} /> original timing (else full speed)
            </label>
          </div>
          <button className="btn-primary" disabled={running || busy !== null || !replayPath}
            onClick={() => run('start replay', () => live.replay(replayPath, loops, realtime ? 1 : 0), true)}>
            {busy === 'start replay' ? 'Starting…' : 'Start replay'}
          </button>
          {status.finished && <div style={{ fontSize: 12, color: 'var(--accent-emerald)' }}>Last replay finished — its results stay in the dashboard until you start another capture.</div>}
        </div>
      </div>
    </div>
  );
}
