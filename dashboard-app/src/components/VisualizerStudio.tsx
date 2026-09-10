import React, { useState } from 'react';
import type { AnalysisResponse, VisualizerType } from '../types/alert';
import { VISUALIZERS, VisualizerCanvas } from './VisualizerCanvas';

interface VisualizerStudioProps {
  data: AnalysisResponse;
}

export const VisualizerStudio: React.FC<VisualizerStudioProps> = ({ data }) => {
  const [activeVisualizer, setActiveVisualizer] = useState<VisualizerType>('outlier');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Studio header & visualizer selector */}
      <div className="glass" style={{ padding: 18 }}>
        <div style={{ marginBottom: 14 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Visualizer Studio</h2>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Switch between visualization engines to explore multidimensional DPI telemetry. Add any of these to the
            main dashboard from the “Custom Visualizers” panel there.
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8 }}>
          {VISUALIZERS.map((v) => {
            const isSelected = activeVisualizer === v.id;
            return (
              <div
                key={v.id}
                onClick={() => setActiveVisualizer(v.id)}
                className="glass-interactive"
                style={{
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-md)',
                  background: isSelected ? 'color-mix(in srgb, var(--accent-cyan) 14%, transparent)' : 'var(--bg-surface-hover)',
                  border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--glass-border-subtle)'}`,
                }}
              >
                <div style={{ fontSize: 12, fontWeight: isSelected ? 700 : 500, color: isSelected ? 'var(--accent-cyan)' : 'var(--text)', marginBottom: 4 }}>
                  {v.label}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-dim)', lineHeight: 1.3 }}>{v.description}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Stage */}
      <div className="glass" style={{ padding: 24, minHeight: 450 }}>
        <VisualizerCanvas type={activeVisualizer} data={data} />
      </div>
    </div>
  );
};
