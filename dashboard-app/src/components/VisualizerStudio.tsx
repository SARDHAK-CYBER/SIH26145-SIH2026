import React from 'react';
import type { AnalysisResponse } from '../types/alert';
import type { VizConfig } from '../lib/vizEngine';
import { VisualizationBuilder } from './VisualizationBuilder';

interface VisualizerStudioProps {
  data: AnalysisResponse;
  panelCount: number;
  onAddToDashboard: (config: VizConfig) => void;
}

export const VisualizerStudio: React.FC<VisualizerStudioProps> = ({ data, panelCount, onAddToDashboard }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {panelCount > 0 && (
        <div className="glass" style={{ padding: '10px 16px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)' }}>
          <span className="pulse-dot" />
          {panelCount} visualization{panelCount === 1 ? '' : 's'} saved to the main dashboard.
        </div>
      )}
      <VisualizationBuilder data={data} onAddToDashboard={onAddToDashboard} />
    </div>
  );
};
