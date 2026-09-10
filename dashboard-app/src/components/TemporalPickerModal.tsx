import React, { useState } from 'react';
import type { TemporalRange } from '../types/alert';

interface TemporalPickerModalProps {
  currentRange: TemporalRange;
  onApply: (newRange: TemporalRange) => void;
  onClose: () => void;
}

const PRESETS = [
  { label: 'Last 15 Minutes', minutes: 15 },
  { label: 'Last 1 Hour', minutes: 60 },
  { label: 'Last 4 Hours', minutes: 240 },
  { label: 'Last 24 Hours', minutes: 1440 },
  { label: 'Last 7 Days', minutes: 10080 },
  { label: 'Full Capture Range', minutes: 0 },
];

export const TemporalPickerModal: React.FC<TemporalPickerModalProps> = ({
  currentRange,
  onApply,
  onClose,
}) => {
  const [selectedPreset, setSelectedPreset] = useState(currentRange.label);
  const [startIso, setStartIso] = useState(currentRange.startIso);
  const [endIso, setEndIso] = useState(currentRange.endIso);
  const [refreshSeconds, setRefreshSeconds] = useState(currentRange.refreshSeconds);

  function handlePresetClick(label: string, minutes: number) {
    setSelectedPreset(label);
    const now = new Date();
    const end = now.toISOString();
    let start = new Date(now.getTime() - minutes * 60 * 1000).toISOString();
    if (minutes === 0) {
      // Full capture range
      start = new Date(now.getTime() - 86400 * 1000 * 30).toISOString();
    }
    setStartIso(start);
    setEndIso(end);
  }

  function handleSave() {
    onApply({
      label: selectedPreset,
      startIso,
      endIso,
      isCustom: selectedPreset === 'Custom Range',
      refreshSeconds,
    });
    onClose();
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(12px)',
        zIndex: 1050,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        className="glass glass-raised"
        style={{
          width: 580,
          maxWidth: '100%',
          padding: 24,
          borderRadius: 'var(--radius-xl)',
          border: '1px solid rgba(0, 229, 255, 0.3)',
          boxShadow: '0 20px 50px rgba(0,0,0,0.8), 0 0 30px rgba(0,229,255,0.15)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: 'rgba(0, 229, 255, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-cyan)',
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <polyline points="12 6 12 12 16 14" />
              </svg>
            </div>
            <div>
              <h3 style={{ fontSize: 16, fontWeight: 600, margin: 0 }}>Temporal Selection</h3>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: 0 }}>Time range filter & telemetry sync</p>
            </div>
          </div>
          <button onClick={onClose} className="btn-ghost" style={{ padding: '4px 10px', fontSize: 13 }}>
            ✕
          </button>
        </div>

        {/* Quick Presets Grid */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-dim)', marginBottom: 10, textTransform: 'uppercase' }}>
            Quick Temporal Presets
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
            {PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => handlePresetClick(p.label, p.minutes)}
                className="glass-interactive"
                style={{
                  padding: '9px 12px',
                  fontSize: 12,
                  borderRadius: 'var(--radius-sm)',
                  background: selectedPreset === p.label ? 'rgba(0, 229, 255, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                  border: `1px solid ${selectedPreset === p.label ? 'var(--accent-cyan)' : 'var(--glass-border-subtle)'}`,
                  color: selectedPreset === p.label ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  fontWeight: selectedPreset === p.label ? 600 : 400,
                  textAlign: 'center',
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Custom Start / End Timestamps */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-dim)', marginBottom: 10, textTransform: 'uppercase' }}>
            Absolute Temporal Range (ISO / UTC)
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                Start Time (From)
              </label>
              <input
                type="text"
                className="mono"
                value={startIso}
                onChange={(e) => {
                  setStartIso(e.target.value);
                  setSelectedPreset('Custom Range');
                }}
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  fontSize: 12,
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid var(--glass-border)',
                  color: 'var(--text)',
                }}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                End Time (To)
              </label>
              <input
                type="text"
                className="mono"
                value={endIso}
                onChange={(e) => {
                  setEndIso(e.target.value);
                  setSelectedPreset('Custom Range');
                }}
                style={{
                  width: '100%',
                  padding: '8px 10px',
                  fontSize: 12,
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid var(--glass-border)',
                  color: 'var(--text)',
                }}
              />
            </div>
          </div>
        </div>

        {/* Auto Refresh Toggle */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-dim)', marginBottom: 10, textTransform: 'uppercase' }}>
            Live Stream Auto-Refresh
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {[
              { label: 'Off', sec: 0 },
              { label: '5s', sec: 5 },
              { label: '10s', sec: 10 },
              { label: '30s', sec: 30 },
              { label: '1m', sec: 60 },
            ].map((r) => (
              <button
                key={r.label}
                type="button"
                onClick={() => setRefreshSeconds(r.sec)}
                style={{
                  flex: 1,
                  padding: '7px 0',
                  fontSize: 12,
                  borderRadius: 'var(--radius-sm)',
                  background: refreshSeconds === r.sec ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                  border: `1px solid ${refreshSeconds === r.sec ? 'var(--accent-emerald)' : 'var(--glass-border-subtle)'}`,
                  color: refreshSeconds === r.sec ? 'var(--accent-emerald)' : 'var(--text-muted)',
                  fontWeight: refreshSeconds === r.sec ? 600 : 400,
                }}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          <button type="button" onClick={handleSave} className="btn-primary">
            Apply Temporal Range
          </button>
        </div>
      </div>
    </div>
  );
};
