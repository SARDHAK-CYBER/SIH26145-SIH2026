import React, { useMemo, useState } from 'react';
import type { AnalysisResponse } from '../types/alert';
import {
  ALERT_FIELDS, INDEX_PATTERN_IDS, VIZ_TYPES, VIZ_PRESETS, METRIC_FNS,
  isNumericField, emptyConfig, defaultTitle, distinctValues, runAggregation, newVizId,
} from '../lib/vizEngine';
import type { VizConfig, IndexPatternId, VizType, MetricFn, BucketInterval } from '../lib/vizEngine';
import { VizChart } from './VizChart';

interface VisualizationBuilderProps {
  data: AnalysisResponse;
  onAddToDashboard: (config: VizConfig) => void;
}

const fieldLabel = (name: string) => ALERT_FIELDS.find((f) => f.name === name)?.label || name;

const selectStyle: React.CSSProperties = {
  fontSize: 12, padding: '7px 10px', borderRadius: 'var(--radius-sm)',
  background: 'var(--bg-inset)', color: 'var(--text)', border: '1px solid var(--glass-border)',
  fontFamily: 'inherit', width: '100%',
};
const labelStyle: React.CSSProperties = { fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-dim)', marginBottom: 5, display: 'block' };

export const VisualizationBuilder: React.FC<VisualizationBuilderProps> = ({ data, onAddToDashboard }) => {
  const [config, setConfig] = useState<VizConfig>(emptyConfig);
  const [titleTouched, setTitleTouched] = useState(false);
  const [added, setAdded] = useState(false);

  const isAlerts = config.indexPattern === 'stealthtap-alerts-*';
  const metricDef = METRIC_FNS.find((m) => m.id === config.metric.fn)!;
  const title = titleTouched && config.title ? config.title : defaultTitle(config);

  const result = useMemo(() => runAggregation(data, config), [data, config]);

  function patch(fn: (c: VizConfig) => VizConfig) {
    setConfig((c) => fn({ ...c }));
    setAdded(false);
  }

  function applyPreset(build: () => VizConfig) {
    setConfig(build());
    setTitleTouched(true);
    setAdded(false);
  }

  function handleAdd() {
    onAddToDashboard({ ...config, id: newVizId(), title });
    setAdded(true);
  }

  const showSplit = ['vertical_bar', 'area', 'line', 'heat_map'].includes(config.type);
  const showBucketControls = isAlerts && config.type !== 'metric';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Quick-start presets */}
      <div className="glass" style={{ padding: 18 }}>
        <h2 style={{ fontSize: 16, fontWeight: 700, margin: '0 0 4px' }}>New Visualization</h2>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
          Every chart below is computed live from the current analysis result — pick an index pattern, an
          aggregation, and add it to the dashboard. Or start from a preset:
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {VIZ_PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              className="btn-ghost"
              title={p.description}
              onClick={() => applyPreset(p.build)}
              style={{ fontSize: 11, padding: '6px 12px' }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 360px) minmax(0, 1fr)', gap: 20, alignItems: 'start' }}>
        {/* ── Config panel ── */}
        <div className="glass" style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Index pattern */}
          <div>
            <label style={labelStyle}>Index pattern</label>
            <select
              style={selectStyle}
              value={config.indexPattern}
              onChange={(e) => patch((c) => ({
                ...c,
                indexPattern: e.target.value as IndexPatternId,
                bucket: e.target.value === 'stealthtap-alerts-*' ? { kind: 'terms', field: 'severity', size: 10 } : { kind: 'terms', field: '' },
                filters: [],
                split: null,
              }))}
            >
              {INDEX_PATTERN_IDS.map((id) => <option key={id} value={id}>{id}</option>)}
            </select>
            {!isAlerts && (
              <div style={{ fontSize: 10.5, color: 'var(--text-dim)', marginTop: 6, lineHeight: 1.4 }}>
                Row-level records for this index live server-side (Postgres / OpenSearch). This pattern exposes
                real document counts from the current capture — for row-level exploration, use{' '}
                <strong style={{ color: 'var(--text-muted)' }}>stealthtap-alerts-*</strong>.
              </div>
            )}
          </div>

          {/* Visualization type gallery */}
          <div>
            <label style={labelStyle}>Visualization type</label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
              {VIZ_TYPES.map((t) => {
                const disabled = !isAlerts && !['metric', 'data_table', 'vertical_bar', 'pie', 'donut'].includes(t.id);
                const active = config.type === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    disabled={disabled}
                    title={t.hint}
                    onClick={() => patch((c) => ({ ...c, type: t.id as VizType }))}
                    style={{
                      fontSize: 11, padding: '8px 8px', borderRadius: 'var(--radius-sm)', textAlign: 'left',
                      background: active ? 'color-mix(in srgb, var(--accent-cyan) 16%, transparent)' : 'var(--bg-inset)',
                      border: `1px solid ${active ? 'var(--accent-cyan)' : 'var(--glass-border-subtle)'}`,
                      color: disabled ? 'var(--text-faint)' : active ? 'var(--accent-cyan)' : 'var(--text-muted)',
                      cursor: disabled ? 'not-allowed' : 'pointer', fontWeight: active ? 700 : 500,
                    }}
                  >
                    {t.label}
                  </button>
                );
              })}
            </div>
          </div>

          {showBucketControls && (
            <>
              {/* Metric */}
              <div>
                <label style={labelStyle}>Metric (Y-axis)</label>
                <div style={{ display: 'grid', gridTemplateColumns: metricDef.needsField ? '1fr 1fr' : '1fr', gap: 6 }}>
                  <select style={selectStyle} value={config.metric.fn} onChange={(e) => patch((c) => ({ ...c, metric: { fn: e.target.value as MetricFn, field: c.metric.field || 'confidence_score' } }))}>
                    {METRIC_FNS.map((m) => <option key={m.id} value={m.id}>{m.label}</option>)}
                  </select>
                  {metricDef.needsField && (
                    <select style={selectStyle} value={config.metric.field || 'confidence_score'} onChange={(e) => patch((c) => ({ ...c, metric: { ...c.metric, field: e.target.value } }))}>
                      {ALERT_FIELDS.filter((f) => config.metric.fn === 'cardinality' || isNumericField(f.name)).map((f) => (
                        <option key={f.name} value={f.name}>{f.label}</option>
                      ))}
                    </select>
                  )}
                </div>
              </div>

              {/* Bucket */}
              <div>
                <label style={labelStyle}>Bucket (X-axis)</label>
                <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                  <select
                    style={selectStyle}
                    value={config.bucket.kind}
                    onChange={(e) => patch((c) => ({
                      ...c,
                      bucket: e.target.value === 'date_histogram'
                        ? { kind: 'date_histogram', field: 'timestamp', interval: 'hour' }
                        : { kind: 'terms', field: 'severity', size: 10 },
                    }))}
                  >
                    <option value="terms">Terms</option>
                    <option value="date_histogram">Date Histogram</option>
                  </select>
                </div>
                {config.bucket.kind === 'terms' ? (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px', gap: 6 }}>
                    <select style={selectStyle} value={config.bucket.field} onChange={(e) => patch((c) => ({ ...c, bucket: { ...c.bucket, field: e.target.value } }))}>
                      {ALERT_FIELDS.filter((f) => f.kind !== 'date').map((f) => <option key={f.name} value={f.name}>{f.label}</option>)}
                    </select>
                    <input
                      type="number" min={1} max={50} className="mono" style={selectStyle}
                      value={config.bucket.size ?? 10}
                      onChange={(e) => patch((c) => ({ ...c, bucket: { ...c.bucket, size: Number(e.target.value) } }))}
                    />
                  </div>
                ) : (
                  <select style={selectStyle} value={config.bucket.interval} onChange={(e) => patch((c) => ({ ...c, bucket: { ...c.bucket, interval: e.target.value as BucketInterval } }))}>
                    <option value="minute">Per minute</option>
                    <option value="5min">Per 5 minutes</option>
                    <option value="hour">Per hour</option>
                    <option value="day">Per day</option>
                  </select>
                )}
              </div>

              {/* Split series */}
              {showSplit && (
                <div>
                  <label style={labelStyle}>Split series by <span style={{ color: 'var(--text-faint)', textTransform: 'none' }}>(optional)</span></label>
                  <select
                    style={selectStyle}
                    value={config.split?.field || ''}
                    onChange={(e) => patch((c) => ({ ...c, split: e.target.value ? { field: e.target.value } : null }))}
                  >
                    <option value="">— none —</option>
                    {ALERT_FIELDS.filter((f) => f.kind === 'string' && f.name !== config.bucket.field).map((f) => (
                      <option key={f.name} value={f.name}>{f.label}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* Filters */}
              <div>
                <label style={labelStyle}>Filters</label>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {config.filters.map((f, idx) => {
                    const values = distinctValues(data, f.field);
                    return (
                      <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 26px', gap: 6 }}>
                        <select style={selectStyle} value={f.field} onChange={(e) => patch((c) => {
                          const filters = [...c.filters]; filters[idx] = { field: e.target.value, value: '' }; return { ...c, filters };
                        })}>
                          {ALERT_FIELDS.filter((fl) => fl.kind === 'string').map((fl) => <option key={fl.name} value={fl.name}>{fl.label}</option>)}
                        </select>
                        <select style={selectStyle} value={f.value} onChange={(e) => patch((c) => {
                          const filters = [...c.filters]; filters[idx] = { ...filters[idx], value: e.target.value }; return { ...c, filters };
                        })}>
                          <option value="">is…</option>
                          {values.map((v) => <option key={v} value={v}>{v}</option>)}
                        </select>
                        <button
                          type="button" className="btn-ghost" style={{ padding: 0, fontSize: 13 }}
                          onClick={() => patch((c) => ({ ...c, filters: c.filters.filter((_, i) => i !== idx) }))}
                          aria-label="Remove filter"
                        >×</button>
                      </div>
                    );
                  })}
                  <button
                    type="button" className="btn-ghost" style={{ fontSize: 11, padding: '5px 10px', alignSelf: 'flex-start' }}
                    onClick={() => patch((c) => ({ ...c, filters: [...c.filters, { field: 'severity', value: '' }] }))}
                  >
                    + Add filter
                  </button>
                </div>
              </div>
            </>
          )}

          {/* Title */}
          <div>
            <label style={labelStyle}>Title</label>
            <input
              type="text" style={selectStyle} value={title}
              onChange={(e) => { setTitleTouched(true); patch((c) => ({ ...c, title: e.target.value })); }}
              placeholder={defaultTitle(config)}
            />
          </div>

          <button type="button" className="btn-primary" onClick={handleAdd} style={{ fontSize: 13, padding: '10px 16px' }}>
            {added ? '✓ Added to Dashboard' : '+ Add to Dashboard'}
          </button>
        </div>

        {/* ── Live preview ── */}
        <div className="glass" style={{ padding: 20, minHeight: 420 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, gap: 10, flexWrap: 'wrap' }}>
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>{title}</h3>
              <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                {VIZ_TYPES.find((t) => t.id === config.type)?.label} · {config.indexPattern} ·{' '}
                {isAlerts
                  ? `${result.documentCount.toLocaleString()} of ${result.totalDocuments.toLocaleString()} alerts`
                  : 'live capture counters'}
              </div>
            </div>
          </div>
          <VizChart result={result} type={config.type} height={360} />
        </div>
      </div>
    </div>
  );
};
