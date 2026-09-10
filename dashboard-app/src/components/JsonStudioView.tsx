import React, { useState } from 'react';
import type { AnalysisResponse } from '../types/alert';

interface JsonStudioViewProps {
  data: AnalysisResponse;
  activeFilters: {
    severity?: string;
    threatClass?: string;
    protocol?: string;
    detectionMode?: string;
    searchQuery: string;
  };
}

export const JsonStudioView: React.FC<JsonStudioViewProps> = ({ data, activeFilters }) => {
  const [viewMode, setViewMode] = useState<'full' | 'query_dsl' | 'schema'>('full');
  const [isMinified, setIsMinified] = useState(false);
  const [copied, setCopied] = useState(false);
  const [searchInJson, setSearchInJson] = useState('');

  // Generated OpenSearch / Elasticsearch Query DSL
  const queryDsl = {
    query: {
      bool: {
        must: [
          activeFilters.searchQuery ? { multi_match: { query: activeFilters.searchQuery, fields: ['threat_class', 'evidence.*', 'mitre_attack.*'] } } : null,
          activeFilters.severity ? { term: { 'severity.keyword': activeFilters.severity } } : null,
          activeFilters.threatClass ? { term: { 'threat_class.keyword': activeFilters.threatClass } } : null,
          activeFilters.protocol ? { term: { 'flow_identifier.protocol.keyword': activeFilters.protocol } } : null,
          activeFilters.detectionMode ? { term: { 'detection_mode.keyword': activeFilters.detectionMode } } : null,
        ].filter(Boolean),
        filter: [
          {
            range: {
              '@timestamp': {
                gte: 'now-24h',
                lte: 'now',
              },
            },
          },
        ],
      },
    },
    sort: [{ '@timestamp': { order: 'desc' } }],
    size: 100,
  };

  const schemaSpec = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'StealthTapAlert',
    type: 'object',
    required: ['alert_id', 'timestamp', 'severity', 'confidence_score', 'threat_class', 'flow_identifier', 'mitre_attack'],
    properties: {
      alert_id: { type: 'string', format: 'uuid' },
      timestamp: { type: 'number', description: 'Unix timestamp float' },
      severity: { enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
      confidence_score: { type: 'number', minimum: 0, maximum: 100 },
      threat_class: { type: 'string' },
      flow_identifier: {
        type: 'object',
        required: ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol'],
        properties: {
          src_ip: { type: 'string', format: 'ipv4' },
          src_port: { type: 'integer' },
          dst_ip: { type: 'string', format: 'ipv4' },
          dst_port: { type: 'integer' },
          protocol: { enum: ['TCP', 'UDP', 'ICMP'] },
        },
      },
      mitre_attack: {
        type: 'object',
        required: ['tactic', 'technique_id', 'technique_name'],
        properties: {
          tactic: { type: 'string' },
          technique_id: { type: 'string' },
          technique_name: { type: 'string' },
        },
      },
      detection_mode: { enum: ['rule', 'xgboost', 'isolation_forest'] },
      model_scores: { type: 'object', additionalProperties: { type: 'number' } },
    },
  };

  const contentToDisplay =
    viewMode === 'full'
      ? data
      : viewMode === 'query_dsl'
      ? queryDsl
      : schemaSpec;

  const rawString = isMinified
    ? JSON.stringify(contentToDisplay)
    : JSON.stringify(contentToDisplay, null, 2);

  function handleCopy() {
    navigator.clipboard.writeText(rawString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownload() {
    const filename =
      viewMode === 'full'
        ? `stealthtap-export-${data.analysis_id}.json`
        : viewMode === 'query_dsl'
        ? 'opensearch-query-dsl.json'
        : 'stealthtap-alert-schema.json';

    const blob = new Blob([rawString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* JSON Studio Header & Controls */}
      <div className="glass" style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>StealthTap JSON Studio & Query DSL</h2>
              <span className="mono" style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: 'rgba(0, 229, 255, 0.15)', color: 'var(--accent-cyan)' }}>
                RFC 8259 VALIDATED
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 0' }}>
              Full payload inspection, OpenSearch DSL query generation, and schema export
            </p>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button onClick={handleCopy} className="btn-ghost" style={{ fontSize: 12 }}>
              {copied ? '✓ Copied' : 'Copy to Clipboard'}
            </button>
            <button onClick={handleDownload} className="btn-primary" style={{ fontSize: 12 }}>
              Export JSON File
            </button>
          </div>
        </div>

        {/* View Mode Toggle */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', gap: 6 }}>
            {[
              { id: 'full', label: 'Analysis Response Payload' },
              { id: 'query_dsl', label: 'OpenSearch Query DSL' },
              { id: 'schema', label: 'Alert Schema Definition' },
            ].map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => setViewMode(m.id as any)}
                style={{
                  fontSize: 12,
                  padding: '6px 12px',
                  borderRadius: 'var(--radius-sm)',
                  background: viewMode === m.id ? 'rgba(0, 229, 255, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                  border: `1px solid ${viewMode === m.id ? 'var(--accent-cyan)' : 'var(--glass-border-subtle)'}`,
                  color: viewMode === m.id ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  fontWeight: viewMode === m.id ? 600 : 400,
                }}
              >
                {m.label}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={isMinified}
                onChange={(e) => setIsMinified(e.target.checked)}
              />
              Minified JSON
            </label>
          </div>
        </div>
      </div>

      {/* JSON Viewer Window */}
      <div className="glass" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{
          padding: '10px 18px',
          background: 'rgba(0,0,0,0.4)',
          borderBottom: '1px solid var(--glass-border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
            {viewMode === 'full' ? 'ANALYSIS_PAYLOAD.json' : viewMode === 'query_dsl' ? 'OPENSEARCH_QUERY.json' : 'ALERT_SCHEMA.json'}
          </span>
          <span className="mono" style={{ fontSize: 11, color: 'var(--accent-cyan)' }}>
            {rawString.length.toLocaleString()} bytes • {rawString.split('\n').length} lines
          </span>
        </div>

        <pre
          className="mono"
          style={{
            margin: 0,
            padding: 20,
            fontSize: 12,
            lineHeight: 1.6,
            background: 'rgba(6, 8, 14, 0.85)',
            maxHeight: 600,
            overflow: 'auto',
            whiteSpace: isMinified ? 'pre-wrap' : 'pre',
            wordBreak: 'break-all',
            color: '#E2E8F0',
          }}
        >
          {rawString}
        </pre>
      </div>
    </div>
  );
};
