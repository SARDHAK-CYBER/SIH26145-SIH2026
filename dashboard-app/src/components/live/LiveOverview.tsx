import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { Alert, AlertSummary, CaptureStatus, HostRow, ProtoRow, SeriesPoint } from '../../types/alert';
import { fmtBytes, fmtDuration, fmtMbps, fmtNum, fmtPps } from '../../lib/format';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)', MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)',
};
const PROTO_COLORS = ['#00E5FF', '#8B5CF6', '#EC4899', '#10B981', '#F59E0B', '#38BDF8', '#F43F5E', '#A855F7', '#84CC16', '#FB923C'];

interface Props {
  status: CaptureStatus;
  series: SeriesPoint[];
  summary: AlertSummary;
  hosts: HostRow[];
  protocols: ProtoRow[];
  alerts: Alert[];
  onSelectAlert: (a: Alert) => void;
  onOpenHost: (ip: string) => void;
  onGoto: (tab: 'alerts' | 'hosts' | 'capture') => void;
}

export function LiveOverview({ status, series, summary, hosts, protocols, alerts, onSelectAlert, onOpenHost, onGoto }: Props) {
  const tp = status.throughput ?? {};
  const cap = status.capture;
  const lat = status.detection_latency ?? {};
  const kdrop = cap?.kernel_drop ?? tp.kernel_drop_total ?? 0;
  const dropped = (status.dropped ?? 0) + (cap?.records_dropped ?? 0) + kdrop;
  const critical = summary.alerts_by_severity.CRITICAL ?? 0;
  const totalProtoBytes = protocols.reduce((a, p) => a + p.bytes, 0) || 1;
  const topHosts = [...hosts].sort((a, b) => b.tx_bytes + b.rx_bytes - (a.tx_bytes + a.rx_bytes)).slice(0, 8);
  const maxHostBytes = topHosts.length ? topHosts[0].tx_bytes + topHosts[0].rx_bytes : 1;
  const classes = Object.entries(summary.alerts_by_class).sort((a, b) => b[1] - a[1]);
  const maxClass = classes.length ? classes[0][1] : 1;

  const chart = series.map((p) => ({ ...p, time: new Date(p.t * 1000).toLocaleTimeString([], { hour12: false }) }));
  const idle = !status.running && !status.finished;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {idle && (
        <div className="glass" style={{ padding: 22, display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 260 }}>
            <div style={{ fontSize: 15, fontWeight: 700 }}>No capture running</div>
            <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 4 }}>
              Pick a network interface (or replay a real capture) to start monitoring. Everything on this page is computed from live packets — nothing is simulated.
            </div>
          </div>
          <button className="btn-primary" onClick={() => onGoto('capture')}>Start a capture</button>
        </div>
      )}

      {status.capture_error && (
        <div className="glass" style={{ padding: 12, fontSize: 12.5, color: 'var(--sev-critical)', border: '1px solid rgba(255,51,102,.35)' }}>
          Capture engine error: {status.capture_error}
        </div>
      )}

      <div className="kpi-grid" style={{ marginBottom: 0 }}>
        <div className="glass kpi-card">
          <div className="kpi-label">Throughput</div>
          <div className="kpi-value mono" style={{ color: 'var(--accent-cyan)' }}>{fmtMbps(tp.mbps)}</div>
          <div className="kpi-sub"><span>{fmtPps(tp.pps)}</span><span>peak {fmtMbps(tp.peak_mbps)}</span></div>
        </div>
        <div className="glass kpi-card">
          <div className="kpi-label">Active flows</div>
          <div className="kpi-value mono">{fmtNum(status.active_flows)}</div>
          <div className="kpi-sub"><span>{fmtNum(cap?.flows_seen)} seen</span><span>{fmtNum(cap?.pending_records ?? status.queue_depth)} queued</span></div>
        </div>
        <div className="glass kpi-card" style={{ cursor: 'pointer' }} onClick={() => onGoto('hosts')}>
          <div className="kpi-label">Hosts on the wire</div>
          <div className="kpi-value mono" style={{ color: 'var(--accent-emerald)' }}>{fmtNum(cap?.hosts)}</div>
          <div className="kpi-sub"><span>{hosts.filter((h) => h.local).length} local</span><span>{hosts.filter((h) => !h.local).length} remote (top {hosts.length})</span></div>
        </div>
        <div className="glass kpi-card" style={{ cursor: 'pointer', borderColor: critical ? 'rgba(255,51,102,.45)' : undefined }} onClick={() => onGoto('alerts')}>
          <div className="kpi-label">Alerts</div>
          <div className="kpi-value mono" style={{ color: critical ? 'var(--sev-critical)' : 'var(--text)' }}>{fmtNum(status.alerts)}</div>
          <div className="kpi-sub"><span style={{ color: 'var(--sev-critical)' }}>{critical} critical</span><span>{summary.alerts_by_severity.HIGH ?? 0} high</span></div>
        </div>
        <div className="glass kpi-card" style={{ borderColor: dropped ? 'rgba(255,120,40,.5)' : undefined }}>
          <div className="kpi-label">Packet loss</div>
          <div className="kpi-value mono" style={{ color: dropped ? 'var(--sev-high)' : 'var(--accent-emerald)' }}>{dropped ? fmtNum(dropped) : 'none'}</div>
          <div className="kpi-sub"><span>driver {fmtNum(kdrop)}</span><span>records {fmtNum(cap?.records_dropped)}</span></div>
        </div>
        <div className="glass kpi-card">
          <div className="kpi-label">Detection latency</div>
          <div className="kpi-value mono">{lat.p50_ms != null ? `${lat.p50_ms} ms` : '—'}</div>
          <div className="kpi-sub"><span>p95 {lat.p95_ms ?? '—'} ms</span><span>{fmtNum(lat.samples)} samples</span></div>
        </div>
      </div>

      <div className="live-grid-2">
        <div className="glass" style={{ padding: 16 }}>
          <div className="panel-title">Traffic <span className="mono">last {Math.min(series.length, 600)} s</span></div>
          <div style={{ height: 230 }}>
            <ResponsiveContainer>
              <AreaChart data={chart} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="mbps" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00E5FF" stopOpacity={0.45} /><stop offset="100%" stopColor="#00E5FF" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--chart-band-line)" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: 'var(--text-dim)' }} minTickGap={50} />
                <YAxis tick={{ fontSize: 10, fill: 'var(--text-dim)' }} width={52} tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}G` : `${v}M`)} />
                <Tooltip contentStyle={{ background: 'var(--tooltip-bg)', border: '1px solid var(--glass-border)', borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => [fmtMbps(v), 'throughput']} />
                <Area type="monotone" dataKey="mbps" stroke="#00E5FF" strokeWidth={2} fill="url(#mbps)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div style={{ height: 96, marginTop: 6 }}>
            <ResponsiveContainer>
              <LineChart data={chart} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <XAxis dataKey="time" hide />
                <YAxis tick={{ fontSize: 10, fill: 'var(--text-dim)' }} width={52} tickFormatter={(v) => fmtPps(v).replace(' pps', '')} />
                <Tooltip contentStyle={{ background: 'var(--tooltip-bg)', border: '1px solid var(--glass-border)', borderRadius: 8, fontSize: 12 }}
                  formatter={(v: number) => [fmtPps(v), 'packets']} />
                <Line type="monotone" dataKey="pps" stroke="#8B5CF6" strokeWidth={1.6} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass" style={{ padding: 16 }}>
          <div className="panel-title">Protocol mix <span className="mono">by bytes</span></div>
          {protocols.length === 0 && <div className="empty">Waiting for traffic…</div>}
          <div style={{ display: 'grid', gap: 7 }}>
            {protocols.slice(0, 10).map((p, i) => (
              <div key={p.name} style={{ display: 'grid', gridTemplateColumns: '108px 1fr 62px', gap: 8, alignItems: 'center', fontSize: 12 }}>
                <span>{p.name}</span>
                <div className="bar"><div style={{ width: `${Math.max(2, (p.bytes / totalProtoBytes) * 100)}%`, background: PROTO_COLORS[i % PROTO_COLORS.length] }} /></div>
                <span className="mono" style={{ color: 'var(--text-dim)', textAlign: 'right' }}>{fmtBytes(p.bytes)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="live-grid-3">
        <div className="glass" style={{ padding: 16 }}>
          <div className="panel-title">Top talkers <a onClick={() => onGoto('hosts')} className="link">all hosts →</a></div>
          {topHosts.length === 0 && <div className="empty">No hosts yet.</div>}
          <div style={{ display: 'grid', gap: 8 }}>
            {topHosts.map((h) => (
              <div key={h.ip} style={{ cursor: 'pointer' }} onClick={() => onOpenHost(h.ip)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                  <span className="mono">{h.ip} <span className={`tag ${h.local ? 'tag-local' : 'tag-remote'}`}>{h.local ? 'local' : 'remote'}</span></span>
                  <span className="mono" style={{ color: 'var(--text-dim)' }}>{fmtBytes(h.tx_bytes + h.rx_bytes)}</span>
                </div>
                <div className="bar"><div style={{ width: `${Math.max(2, ((h.tx_bytes + h.rx_bytes) / maxHostBytes) * 100)}%`, background: 'var(--accent-cyan)' }} /></div>
              </div>
            ))}
          </div>
        </div>

        <div className="glass" style={{ padding: 16 }}>
          <div className="panel-title">Alerts by class</div>
          {classes.length === 0 && <div className="empty">No alerts — the engines are watching.</div>}
          <div style={{ display: 'grid', gap: 8 }}>
            {classes.map(([c, n]) => (
              <div key={c} style={{ display: 'grid', gridTemplateColumns: '1fr 44px', gap: 8, alignItems: 'center', fontSize: 12 }}>
                <div>
                  <div style={{ marginBottom: 3 }}>{c.replace(/_/g, ' ')}</div>
                  <div className="bar"><div style={{ width: `${Math.max(3, (n / maxClass) * 100)}%`, background: 'var(--sev-high)' }} /></div>
                </div>
                <span className="mono" style={{ textAlign: 'right' }}>{n}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="glass" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="panel-title" style={{ padding: '14px 16px 8px' }}>Latest alerts <a onClick={() => onGoto('alerts')} className="link">all →</a></div>
          {alerts.length === 0 && <div className="empty" style={{ padding: '0 16px 16px' }}>None yet.</div>}
          {alerts.slice(0, 7).map((a) => (
            <div key={a.alert_id} onClick={() => onSelectAlert(a)} className="alert-row">
              <span className="mono" style={{ color: SEV_COLOR[a.severity], fontWeight: 700, fontSize: 10.5 }}>{a.severity}</span>
              <span style={{ fontSize: 12 }}><strong>{a.threat_class.replace(/_/g, ' ')}</strong>
                <span style={{ color: 'var(--text-dim)' }}> · {a.flow_identifier.src_ip} → {a.flow_identifier.dst_ip}:{a.flow_identifier.dst_port}</span></span>
              <span className="mono" style={{ color: 'var(--accent-cyan)', fontSize: 11 }}>{a.confidence_score}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="glass mono" style={{ padding: '10px 16px', fontSize: 11, color: 'var(--text-dim)', display: 'flex', gap: 18, flexWrap: 'wrap' }}>
        <span>engine: {status.native ? 'native (GIL-free capture + assembly)' : status.backend ?? '—'}</span>
        <span>source: {status.source ?? '—'}{status.source === 'pcap-replay' && cap ? ` · loop ${cap.loops_done + 1}` : ''}</span>
        <span>uptime {fmtDuration(status.uptime_s)}</span>
        <span>packets {fmtNum(cap?.recv)}</span>
        <span>ML: {(status.ml_families ?? []).join(', ') || 'rules only'}</span>
        {(cap?.opcua_encrypted || cap?.opcua_unsecured) ? (
          <span style={{ color: 'var(--sev-medium)' }}>OPC UA: {fmtNum(cap?.opcua_encrypted)} encrypted chunks (not inspectable) · {fmtNum(cap?.opcua_unsecured)} unsecured channels</span>
        ) : null}
        <span>engine threads {cap?.shards ?? 1}</span>
        <span>dns {fmtNum(cap?.dns)} · tls {fmtNum(cap?.ssl)} · http {fmtNum(cap?.http)} · ot {fmtNum((cap?.modbus ?? 0) + (cap?.dnp3 ?? 0))}</span>
      </div>
    </div>
  );
}
