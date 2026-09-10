import React from 'react';
import type { TemporalRange, Severity, ThreatClass } from '../types/alert';
import { ThemeToggle, type ThemeMode } from './ThemeToggle';

interface TopBarProps {
  temporalRange: TemporalRange;
  onOpenTemporalModal: () => void;
  activeFilters: {
    severity?: Severity;
    threatClass?: ThreatClass;
    protocol?: string;
    detectionMode?: string;
    searchQuery: string;
  };
  onUpdateFilter: (key: string, value: string | undefined) => void;
  onClearFilters: () => void;
  themeMode: ThemeMode;
  onThemeChange: (next: ThemeMode) => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  temporalRange,
  onOpenTemporalModal,
  activeFilters,
  onUpdateFilter,
  onClearFilters,
  themeMode,
  onThemeChange,
}) => {
  const hasActiveFilters =
    activeFilters.severity ||
    activeFilters.threatClass ||
    activeFilters.protocol ||
    activeFilters.detectionMode ||
    activeFilters.searchQuery;

  return (
    <header className="topbar-v2">
      {/* Global search */}
      <div className="topbar-search">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-dim)" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          placeholder="Search alerts, IPs, domains, MITRE techniques…"
          value={activeFilters.searchQuery}
          onChange={(e) => onUpdateFilter('searchQuery', e.target.value)}
        />
      </div>

      {/* Temporal + attribute filters */}
      <div className="topbar-filters">
        <div
          className={`filter-tag ${activeFilters.severity ? 'active' : ''}`}
          onClick={() => {
            const sevs: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
            const curIdx = activeFilters.severity ? sevs.indexOf(activeFilters.severity) : -1;
            const next = curIdx === -1 ? 'CRITICAL' : curIdx === sevs.length - 1 ? undefined : sevs[curIdx + 1];
            onUpdateFilter('severity', next);
          }}
        >
          <span>severity</span>
          {activeFilters.severity
            ? <span className="mono">: {activeFilters.severity}</span>
            : <span className="asterisk">*</span>}
        </div>

        <div
          className={`filter-tag ${activeFilters.threatClass ? 'active' : ''}`}
          onClick={() => {
            const classes: ThreatClass[] = [
              'VOLUMETRIC_DDOS',
              'C2_BEACONING',
              'DGA_DOMAIN',
              'ENCRYPTED_MALWARE',
              'RECONNAISSANCE',
              'DATA_EXFILTRATION',
              'ICS_UNAUTHORIZED_CONTROL_COMMAND',
            ];
            const curIdx = activeFilters.threatClass ? classes.indexOf(activeFilters.threatClass) : -1;
            const next = curIdx === -1 ? 'VOLUMETRIC_DDOS' : curIdx === classes.length - 1 ? undefined : classes[curIdx + 1];
            onUpdateFilter('threatClass', next);
          }}
        >
          <span>threat_class</span>
          {activeFilters.threatClass
            ? <span className="mono">: {activeFilters.threatClass}</span>
            : <span className="asterisk">*</span>}
        </div>

        <div
          className={`filter-tag ${activeFilters.protocol ? 'active' : ''}`}
          onClick={() => {
            const protos = ['TCP', 'UDP', 'ICMP'];
            const curIdx = activeFilters.protocol ? protos.indexOf(activeFilters.protocol) : -1;
            const next = curIdx === -1 ? 'TCP' : curIdx === protos.length - 1 ? undefined : protos[curIdx + 1];
            onUpdateFilter('protocol', next);
          }}
        >
          <span>protocol</span>
          {activeFilters.protocol
            ? <span className="mono">: {activeFilters.protocol}</span>
            : <span className="asterisk">*</span>}
        </div>

        <div
          className={`filter-tag ${activeFilters.detectionMode ? 'active' : ''}`}
          onClick={() => {
            const modes = ['rule', 'xgboost', 'isolation_forest'];
            const curIdx = activeFilters.detectionMode ? modes.indexOf(activeFilters.detectionMode) : -1;
            const next = curIdx === -1 ? 'xgboost' : curIdx === modes.length - 1 ? undefined : modes[curIdx + 1];
            onUpdateFilter('detectionMode', next);
          }}
        >
          <span>detection_mode</span>
          {activeFilters.detectionMode
            ? <span className="mono">: {activeFilters.detectionMode}</span>
            : <span className="asterisk">*</span>}
        </div>

        {/* Temporal range / filter */}
        <button
          onClick={onOpenTemporalModal}
          className="filter-tag"
          style={{ borderColor: 'var(--accent-cyan)', color: 'var(--accent-cyan)', cursor: 'pointer' }}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
            <line x1="16" y1="2" x2="16" y2="6" />
            <line x1="8" y1="2" x2="8" y2="6" />
            <line x1="3" y1="10" x2="21" y2="10" />
          </svg>
          <span style={{ fontWeight: 600 }}>{temporalRange.label}</span>
          <span className="mono" style={{ opacity: 0.75 }}>
            {temporalRange.startIso.slice(11, 19)}–{temporalRange.endIso.slice(11, 19)} UTC
          </span>
        </button>

        {hasActiveFilters && (
          <button
            onClick={onClearFilters}
            style={{
              background: 'color-mix(in srgb, var(--sev-critical) 14%, transparent)',
              border: '1px solid color-mix(in srgb, var(--sev-critical) 40%, transparent)',
              color: 'var(--sev-critical)',
              fontSize: 11,
              padding: '4px 10px',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Right cluster — Auto/Light/Dark */}
      <div className="topbar-actions">
        <ThemeToggle mode={themeMode} onChange={onThemeChange} />
      </div>
    </header>
  );
};
