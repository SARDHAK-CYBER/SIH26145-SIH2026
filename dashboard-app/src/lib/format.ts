export function fmtNum(n?: number | null, d = 0): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—';
  return d ? n.toFixed(d) : Math.round(n).toLocaleString();
}

export function fmtBytes(n?: number | null): string {
  if (n === undefined || n === null) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n; let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

/** bits/s from Mbit/s */
export function fmtMbps(m?: number | null): string {
  if (m === undefined || m === null) return '—';
  if (m >= 1000) return `${(m / 1000).toFixed(2)} Gbit/s`;
  if (m >= 1) return `${m.toFixed(1)} Mbit/s`;
  return `${(m * 1000).toFixed(0)} kbit/s`;
}

export function fmtPps(p?: number | null): string {
  if (p === undefined || p === null) return '—';
  if (p >= 1e6) return `${(p / 1e6).toFixed(2)} Mpps`;
  if (p >= 1e3) return `${(p / 1e3).toFixed(1)} kpps`;
  return `${Math.round(p)} pps`;
}

export function fmtDuration(s?: number | null): string {
  if (s === undefined || s === null) return '—';
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 90) return `${s.toFixed(1)} s`;
  if (s < 5400) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export function ago(ts: number): string {
  const d = Date.now() / 1000 - ts;
  if (d < 0) return 'now';
  if (d < 60) return `${Math.round(d)}s ago`;
  if (d < 3600) return `${Math.round(d / 60)}m ago`;
  return `${Math.round(d / 3600)}h ago`;
}
