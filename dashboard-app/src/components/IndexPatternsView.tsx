import React, { useState, useEffect } from 'react';
import type { IndexPattern, IndexField } from '../types/alert';
import { fetchIndexPatterns } from '../api/client';

export const IndexPatternsView: React.FC = () => {
  const [patterns, setPatterns] = useState<IndexPattern[]>([]);
  const [selectedId, setSelectedId] = useState<string>('stealthtap-alerts-*');
  const [fieldSearch, setFieldSearch] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIndexPatterns()
      .then((data) => {
        setPatterns(data);
        if (data.length > 0) setSelectedId(data[0].id);
      })
      .catch(() => {
        // Fallback default patterns if API is offline
        setPatterns(DEFAULT_PATTERNS);
      })
      .finally(() => setLoading(false));
  }, []);

  const activePattern = patterns.find((p) => p.id === selectedId) || patterns[0] || DEFAULT_PATTERNS[0];

  const filteredFields = (activePattern?.fields || []).filter((f) => {
    const matchesSearch = f.name.toLowerCase().includes(fieldSearch.toLowerCase()) ||
                          f.sample.toLowerCase().includes(fieldSearch.toLowerCase());
    const matchesType = selectedType === 'all' || f.type === selectedType;
    return matchesSearch && matchesType;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Index Pattern Header & Switcher */}
      <div className="glass" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>OpenSearch Dashboards Index Patterns</h2>
              <span className="mono" style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: 'rgba(0, 229, 255, 0.15)', color: 'var(--accent-cyan)' }}>
                OPENDASHBOARD COMPATIBLE
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 0' }}>
              Index patterns tell OpenSearch Dashboards which indices contain the security telemetry you want to explore.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="mono" style={{ fontSize: 12, color: 'var(--text-dim)' }}>Time Field:</span>
            <span className="mono" style={{
              fontSize: 11,
              padding: '4px 10px',
              borderRadius: 6,
              background: 'rgba(0, 229, 255, 0.1)',
              color: 'var(--accent-cyan)',
              border: '1px solid rgba(0, 229, 255, 0.25)',
            }}>
              {activePattern?.timeFieldName || '@timestamp'}
            </span>
          </div>
        </div>

        {/* Index Pattern Chips */}
        <div style={{ display: 'flex', gap: 8, overflowX: 'auto', paddingBottom: 6 }}>
          {patterns.map((pat) => {
            const isSelected = selectedId === pat.id;
            return (
              <button
                key={pat.id}
                type="button"
                onClick={() => setSelectedId(pat.id)}
                className="mono"
                style={{
                  fontSize: 12,
                  padding: '7px 14px',
                  borderRadius: 'var(--radius-sm)',
                  background: isSelected ? 'rgba(0, 229, 255, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                  border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--glass-border-subtle)'}`,
                  color: isSelected ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  fontWeight: isSelected ? 600 : 400,
                  whiteSpace: 'nowrap',
                }}
              >
                {pat.title}
              </button>
            );
          })}
        </div>
      </div>

      {/* Pattern Description & Fields Directory */}
      <div className="glass" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 className="mono" style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'var(--accent-cyan)' }}>
              {activePattern?.title}
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 0' }}>
              {activePattern?.description}
            </p>
          </div>

          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {/* Type Filter */}
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              style={{
                padding: '6px 12px',
                fontSize: 12,
                borderRadius: 6,
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid var(--glass-border)',
                color: 'var(--text)',
                outline: 'none',
              }}
            >
              <option value="all">All Field Types</option>
              <option value="string">string</option>
              <option value="number">number</option>
              <option value="date">date</option>
              <option value="ip">ip</option>
              <option value="boolean">boolean</option>
            </select>

            {/* Field Search */}
            <input
              type="text"
              placeholder="Filter fields..."
              value={fieldSearch}
              onChange={(e) => setFieldSearch(e.target.value)}
              style={{
                padding: '6px 12px',
                fontSize: 12,
                borderRadius: 6,
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid var(--glass-border)',
                color: 'var(--text)',
                width: 200,
                outline: 'none',
              }}
            />
          </div>
        </div>

        {/* Fields Count Stat */}
        <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 12 }}>
          Showing {filteredFields.length} of {activePattern?.fields.length || 0} fields
        </div>

        {/* Field Dictionary Table */}
        <div style={{ overflowX: 'auto' }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Field Name</th>
                <th>Type</th>
                <th>Searchable</th>
                <th>Aggregatable</th>
                <th>Sample Value</th>
              </tr>
            </thead>
            <tbody>
              {filteredFields.map((field) => (
                <tr key={field.name}>
                  <td className="mono" style={{ color: 'var(--text)', fontWeight: 500 }}>
                    {field.name}
                  </td>
                  <td>
                    <span
                      className="mono"
                      style={{
                        fontSize: 10,
                        padding: '2px 7px',
                        borderRadius: 4,
                        background: getTypeBadgeBg(field.type),
                        color: getTypeBadgeColor(field.type),
                        fontWeight: 600,
                      }}
                    >
                      {field.type}
                    </span>
                  </td>
                  <td>
                    <span className="mono" style={{ color: field.searchable ? 'var(--accent-emerald)' : 'var(--text-dim)' }}>
                      {field.searchable ? 'true' : 'false'}
                    </span>
                  </td>
                  <td>
                    <span className="mono" style={{ color: field.aggregatable ? 'var(--accent-emerald)' : 'var(--text-dim)' }}>
                      {field.aggregatable ? 'true' : 'false'}
                    </span>
                  </td>
                  <td className="mono" style={{ color: 'var(--text-muted)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {field.sample}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

function getTypeBadgeBg(type: string): string {
  switch (type) {
    case 'string': return 'rgba(56, 189, 248, 0.15)';
    case 'number': return 'rgba(245, 158, 11, 0.15)';
    case 'date': return 'rgba(139, 92, 246, 0.15)';
    case 'ip': return 'rgba(0, 229, 255, 0.15)';
    case 'boolean': return 'rgba(16, 185, 129, 0.15)';
    default: return 'rgba(255, 255, 255, 0.1)';
  }
}

function getTypeBadgeColor(type: string): string {
  switch (type) {
    case 'string': return '#38BDF8';
    case 'number': return '#F59E0B';
    case 'date': return '#A78BFA';
    case 'ip': return '#00E5FF';
    case 'boolean': return '#10B981';
    default: return '#E2E8F0';
  }
}

const DEFAULT_PATTERNS: IndexPattern[] = [
  {
    id: 'stealthtap-alerts-*',
    title: 'stealthtap-alerts-*',
    timeFieldName: '@timestamp',
    description: 'Consolidated security incidents and threat detections across all 9 engines and ML models.',
    fields: [
      { name: '@timestamp', type: 'date', searchable: true, aggregatable: true, sample: '2026-09-09T10:45:00.000Z' },
      { name: 'alert_id', type: 'string', searchable: true, aggregatable: true, sample: 'a3b8c9d1-0f4e-4b72-a6f9' },
      { name: 'severity', type: 'string', searchable: true, aggregatable: true, sample: 'CRITICAL' },
      { name: 'threat_class', type: 'string', searchable: true, aggregatable: true, sample: 'VOLUMETRIC_DDOS' },
      { name: 'confidence_score', type: 'number', searchable: true, aggregatable: true, sample: '96.5' },
      { name: 'detection_mode', type: 'string', searchable: true, aggregatable: true, sample: 'xgboost' },
      { name: 'flow_identifier.src_ip', type: 'ip', searchable: true, aggregatable: true, sample: '192.168.1.105' },
      { name: 'flow_identifier.src_port', type: 'number', searchable: true, aggregatable: true, sample: '49210' },
      { name: 'flow_identifier.dst_ip', type: 'ip', searchable: true, aggregatable: true, sample: '10.0.0.50' },
      { name: 'flow_identifier.dst_port', type: 'number', searchable: true, aggregatable: true, sample: '80' },
      { name: 'flow_identifier.protocol', type: 'string', searchable: true, aggregatable: true, sample: 'TCP' },
      { name: 'mitre_attack.tactic', type: 'string', searchable: true, aggregatable: true, sample: 'Impact' },
      { name: 'mitre_attack.technique_id', type: 'string', searchable: true, aggregatable: true, sample: 'T1498' },
    ],
  },
  {
    id: 'zeek-conn-*',
    title: 'zeek-conn-*',
    timeFieldName: 'ts',
    description: 'Network flow metadata: session duration, transmitted bytes, states, and flags.',
    fields: [
      { name: 'ts', type: 'date', searchable: true, aggregatable: true, sample: '1788868800.0' },
      { name: 'uid', type: 'string', searchable: true, aggregatable: true, sample: 'Cabc123def456' },
      { name: 'id.orig_h', type: 'ip', searchable: true, aggregatable: true, sample: '192.168.1.100' },
      { name: 'id.orig_p', type: 'number', searchable: true, aggregatable: true, sample: '51234' },
      { name: 'id.resp_h', type: 'ip', searchable: true, aggregatable: true, sample: '93.184.216.34' },
      { name: 'id.resp_p', type: 'number', searchable: true, aggregatable: true, sample: '443' },
      { name: 'proto', type: 'string', searchable: true, aggregatable: true, sample: 'tcp' },
      { name: 'duration', type: 'number', searchable: true, aggregatable: true, sample: '1.24' },
      { name: 'orig_bytes', type: 'number', searchable: true, aggregatable: true, sample: '1420' },
      { name: 'resp_bytes', type: 'number', searchable: true, aggregatable: true, sample: '58400' },
    ],
  },
];
