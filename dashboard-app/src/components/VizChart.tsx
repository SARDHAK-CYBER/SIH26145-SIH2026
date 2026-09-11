import React from 'react';
import {
  ResponsiveContainer, BarChart, Bar, LineChart, Line, AreaChart, Area,
  PieChart, Pie, Cell, XAxis, YAxis, Tooltip, Legend, CartesianGrid,
} from 'recharts';
import type { AggResult } from '../lib/vizEngine';

const PALETTE = ['#00E5FF', '#8B5CF6', '#EC4899', '#10B981', '#F59E0B', '#38BDF8', '#F43F5E', '#A855F7', '#22D3EE', '#FB923C'];
const SEV_COLORS: Record<string, string> = { CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)', MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)' };

function colorFor(key: string, i: number): string {
  return SEV_COLORS[key] || PALETTE[i % PALETTE.length];
}

const TOOLTIP_STYLE = {
  background: 'var(--tooltip-bg)', border: '1px solid var(--glass-border)', borderRadius: 8, fontSize: 12,
} as const;

interface VizChartProps {
  result: AggResult;
  type: string;
  height?: number;
}

export const VizChart: React.FC<VizChartProps> = ({ result, type, height = 300 }) => {
  const { rows, seriesKeys } = result;

  if (rows.length === 0 || rows.every((r) => r.value === 0 && !r.series)) {
    return (
      <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-dim)', fontSize: 13 }}>
        No documents match this query in the current result set.
      </div>
    );
  }

  const chartRows = rows.map((r) => ({ bucket: r.bucket, value: r.value, ...(r.series || {}) }));

  if (type === 'metric') {
    const total = rows.reduce((s, r) => s + r.value, 0);
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height, gap: 6 }}>
        <div className="mono" style={{ fontSize: 44, fontWeight: 700, color: 'var(--accent-cyan)', lineHeight: 1 }}>
          {total.toLocaleString(undefined, { maximumFractionDigits: 2 })}
        </div>
        {rows.length > 1 && (
          <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', justifyContent: 'center', marginTop: 10 }}>
            {rows.map((r, i) => (
              <div key={r.bucket} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: colorFor(r.bucket, i) }} />
                <span className="mono">{r.bucket}</span>
                <span className="mono" style={{ color: 'var(--text)' }}>{r.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (type === 'gauge') {
    const top = rows[0];
    const total = rows.reduce((s, r) => s + r.value, 0);
    const pct = total > 0 ? (top.value / total) * 100 : 0;
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height, gap: 8 }}>
        <div style={{ position: 'relative', width: 180, height: 180 }}>
          <svg width="180" height="180" viewBox="0 0 36 36">
            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--chart-band)" strokeWidth="3" />
            <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--accent-cyan)" strokeDasharray={`${pct.toFixed(1)}, 100`} strokeWidth="3" strokeLinecap="round" />
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div className="mono" style={{ fontSize: 28, fontWeight: 700 }}>{pct.toFixed(0)}%</div>
            <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>of {total.toLocaleString()}</div>
          </div>
        </div>
        <div className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>{top.bucket} — {top.value.toLocaleString()}</div>
      </div>
    );
  }

  if (type === 'data_table') {
    return (
      <div style={{ maxHeight: height, overflow: 'auto' }}>
        <table className="glass-table">
          <thead><tr><th>Bucket</th><th>Value</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.bucket}>
                <td className="mono">{r.bucket}</td>
                <td className="mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{r.value.toLocaleString(undefined, { maximumFractionDigits: 2 })}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (type === 'heat_map') {
    const max = Math.max(1, ...rows.flatMap((r) => Object.values(r.series || { v: r.value })));
    const cols = seriesKeys.length > 0 ? seriesKeys : ['value'];
    return (
      <div style={{ overflowX: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: `120px repeat(${cols.length}, 1fr)`, gap: 3, minWidth: cols.length * 70 + 120 }}>
          <div />
          {cols.map((c) => (
            <div key={c} className="mono" style={{ fontSize: 10, color: 'var(--text-dim)', textAlign: 'center', padding: '0 0 4px' }}>{c}</div>
          ))}
          {rows.map((r) => (
            <React.Fragment key={r.bucket}>
              <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}>{r.bucket}</div>
              {cols.map((c) => {
                const v = seriesKeys.length > 0 ? (r.series?.[c] || 0) : r.value;
                const intensity = Math.min(1, v / max);
                return (
                  <div
                    key={c}
                    title={`${r.bucket} / ${c}: ${v}`}
                    className="mono"
                    style={{
                      height: 32, borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 11, color: intensity > 0.55 ? '#06080E' : 'var(--text-muted)',
                      background: `color-mix(in srgb, var(--accent-cyan) ${Math.round(intensity * 90)}%, var(--bg-inset))`,
                    }}
                  >
                    {v > 0 ? v : ''}
                  </div>
                );
              })}
            </React.Fragment>
          ))}
        </div>
      </div>
    );
  }

  if (type === 'pie' || type === 'donut') {
    return (
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie data={chartRows} dataKey="value" nameKey="bucket" innerRadius={type === 'donut' ? 60 : 0} outerRadius={100} paddingAngle={3}>
            {chartRows.map((r, i) => <Cell key={r.bucket} fill={colorFor(r.bucket, i)} stroke="none" />)}
          </Pie>
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Legend wrapperStyle={{ fontSize: 11 }} />
        </PieChart>
      </ResponsiveContainer>
    );
  }

  if (type === 'line' || type === 'area') {
    const Chart = type === 'line' ? LineChart : AreaChart;
    return (
      <ResponsiveContainer width="100%" height={height}>
        <Chart data={chartRows}>
          <defs>
            <linearGradient id="vizAreaFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.7} />
              <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--glass-border-subtle)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="bucket" stroke="var(--text-dim)" fontSize={11} />
          <YAxis stroke="var(--text-dim)" fontSize={11} />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          {seriesKeys.length > 0 && <Legend wrapperStyle={{ fontSize: 11 }} />}
          {seriesKeys.length > 0 ? (
            seriesKeys.map((k, i) => (
              type === 'line'
                ? <Line key={k} type="monotone" dataKey={k} stroke={colorFor(k, i)} strokeWidth={2} dot={false} />
                : <Area key={k} type="monotone" dataKey={k} stackId="s" stroke={colorFor(k, i)} fill={colorFor(k, i)} fillOpacity={0.35} />
            ))
          ) : (
            type === 'line'
              ? <Line type="monotone" dataKey="value" stroke="var(--accent-cyan)" strokeWidth={2.5} dot={{ r: 3 }} />
              : <Area type="monotone" dataKey="value" stroke="var(--accent-cyan)" strokeWidth={2.5} fill="url(#vizAreaFill)" />
          )}
        </Chart>
      </ResponsiveContainer>
    );
  }

  // vertical_bar / horizontal_bar
  const horizontal = type === 'horizontal_bar';
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={chartRows} layout={horizontal ? 'vertical' : 'horizontal'} margin={horizontal ? { left: 24 } : undefined}>
        <CartesianGrid stroke="var(--glass-border-subtle)" strokeDasharray="3 3" horizontal={!horizontal} vertical={horizontal} />
        {horizontal ? (
          <>
            <XAxis type="number" stroke="var(--text-dim)" fontSize={11} />
            <YAxis type="category" dataKey="bucket" stroke="var(--text-dim)" fontSize={11} width={110} />
          </>
        ) : (
          <>
            <XAxis dataKey="bucket" stroke="var(--text-dim)" fontSize={11} interval={0} angle={chartRows.length > 6 ? -30 : 0} textAnchor={chartRows.length > 6 ? 'end' : 'middle'} height={chartRows.length > 6 ? 50 : 30} />
            <YAxis stroke="var(--text-dim)" fontSize={11} />
          </>
        )}
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'var(--bg-surface-hover)' }} />
        {seriesKeys.length > 0 && <Legend wrapperStyle={{ fontSize: 11 }} />}
        {seriesKeys.length > 0
          ? seriesKeys.map((k, i) => <Bar key={k} dataKey={k} stackId="s" fill={colorFor(k, i)} radius={[3, 3, 0, 0]} />)
          : <Bar dataKey="value" radius={[3, 3, 0, 0]}>
              {chartRows.map((r, i) => <Cell key={r.bucket} fill={colorFor(r.bucket, i)} />)}
            </Bar>}
      </BarChart>
    </ResponsiveContainer>
  );
};
