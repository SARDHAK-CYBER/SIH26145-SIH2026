import React, { useState } from 'react';
import type { Alert } from '../types/alert';

interface AlertDetailDrawerProps {
  alert: Alert | null;
  onClose: () => void;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({ alert, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!alert) return null;
  const currentAlert: Alert = alert;

  function handleCopyJson() {
    navigator.clipboard.writeText(JSON.stringify(currentAlert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownloadJson() {
    const blob = new Blob([JSON.stringify(currentAlert, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alert-${currentAlert.alert_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="glass-drawer-backdrop" onClick={onClose}>
      <div className="glass-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Drawer Header */}
        <div style={{
          padding: '20px 24px',
          borderBottom: '1px solid var(--glass-border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(0,0,0,0.25)',
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
              <span className={`sev-badge sev-${alert.severity}`}>{alert.severity}</span>
              <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--text)' }}>
                {alert.threat_class}
              </h2>
            </div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              Alert ID: {alert.alert_id} • {new Date(alert.timestamp * 1000).toUTCString()}
            </div>
          </div>
          <button onClick={onClose} className="btn-ghost" style={{ padding: '6px 12px', fontSize: 14 }}>
            ✕
          </button>
        </div>

        {/* Drawer Content */}
        <div style={{ padding: '24px', overflowY: 'auto', flex: 1 }}>
          {/* Quick Metrics Banner */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: 12,
            marginBottom: 24,
          }}>
            <div className="glass" style={{ padding: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                Confidence Score
              </div>
              <div className="mono" style={{
                fontSize: 22,
                fontWeight: 700,
                color: alert.confidence_score > 90 ? 'var(--accent-cyan)' : 'var(--accent-amber)',
              }}>
                {alert.confidence_score.toFixed(1)}%
              </div>
            </div>

            <div className="glass" style={{ padding: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                Detection Mode
              </div>
              <div className="mono" style={{ fontSize: 16, fontWeight: 600, color: 'var(--text)', textTransform: 'uppercase' }}>
                {alert.detection_mode}
              </div>
            </div>

            <div className="glass" style={{ padding: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', textTransform: 'uppercase', marginBottom: 4 }}>
                MITRE Technique
              </div>
              <div className="mono" style={{ fontSize: 16, fontWeight: 600, color: 'var(--accent-violet)' }}>
                {alert.mitre_attack.technique_id}
              </div>
            </div>
          </div>

          {/* Section: Network Flow Identifier */}
          <div style={{ marginBottom: 24 }}>
            <h3 style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 10 }}>
              Network Flow 5-Tuple
            </h3>
            <div className="glass" style={{ padding: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', alignItems: 'center', gap: 16 }}>
                <div>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>SOURCE ENDPOINT</div>
                  <div className="mono" style={{ fontSize: 14, fontWeight: 600, color: 'var(--accent-cyan)' }}>
                    {alert.flow_identifier.src_ip}
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Port: {alert.flow_identifier.src_port}
                  </div>
                </div>

                <div style={{ textAlign: 'center', color: 'var(--text-dim)' }}>
                  <div className="mono" style={{
                    fontSize: 10,
                    padding: '2px 8px',
                    borderRadius: 4,
                    background: 'rgba(255,255,255,0.08)',
                    marginBottom: 4,
                  }}>
                    {alert.flow_identifier.protocol}
                  </div>
                  <div>&rarr;</div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>DESTINATION ENDPOINT</div>
                  <div className="mono" style={{ fontSize: 14, fontWeight: 600, color: 'var(--accent-pink)' }}>
                    {alert.flow_identifier.dst_ip}
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Port: {alert.flow_identifier.dst_port}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Section: MITRE ATT&CK Context */}
          <div style={{ marginBottom: 24 }}>
            <h3 style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 10 }}>
              MITRE ATT&CK Mapping
            </h3>
            <div className="glass" style={{ padding: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>Tactic:</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>{alert.mitre_attack.tactic}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>Technique ID:</span>
                <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent-violet)' }}>
                  {alert.mitre_attack.technique_id}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>Technique Name:</span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{alert.mitre_attack.technique_name}</span>
              </div>
            </div>
          </div>

          {/* Section: AI Model Scores & Evidence */}
          {alert.model_scores && (
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 10 }}>
                Hybrid AI Inference Telemetry
              </h3>
              <div className="glass" style={{ padding: 16 }}>
                {Object.entries(alert.model_scores).map(([model, score]) => (
                  <div key={model} style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                      <span className="mono" style={{ textTransform: 'uppercase' }}>{model} score:</span>
                      <span className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>
                        {Number(score).toFixed(4)}
                      </span>
                    </div>
                    <div style={{ height: 6, background: 'rgba(255,255,255,0.1)', borderRadius: 999, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        width: `${Math.min(100, Math.max(0, (Number(score) > 0 ? Number(score) : (Number(score) + 1) / 2) * 100))}%`,
                        background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-violet))',
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section: Raw Forensics & Evidence */}
          <div style={{ marginBottom: 24 }}>
            <h3 style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 10 }}>
              Evidence & Forensic Artifacts
            </h3>
            <div className="glass" style={{ padding: 16 }}>
              <pre className="mono" style={{
                fontSize: 11,
                lineHeight: 1.5,
                background: 'rgba(0,0,0,0.3)',
                padding: 12,
                borderRadius: 8,
                overflowX: 'auto',
                color: 'var(--text-muted)',
              }}>
                {JSON.stringify(alert.evidence, null, 2)}
              </pre>
              {alert.forensics && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-dim)', marginBottom: 4 }}>RAW SEGMENT SHA-256</div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--text-dim)', wordBreak: 'break-all' }}>
                    {String(alert.forensics.raw_segment_hash_sha256 || 'None recorded')}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Section: Complete Alert JSON */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <h3 style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', margin: 0 }}>
                Complete Alert JSON
              </h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={handleCopyJson} className="btn-ghost" style={{ fontSize: 11, padding: '4px 8px' }}>
                  {copied ? '✓ Copied' : 'Copy JSON'}
                </button>
                <button onClick={handleDownloadJson} className="btn-ghost" style={{ fontSize: 11, padding: '4px 8px' }}>
                  Export File
                </button>
              </div>
            </div>
            <pre className="mono" style={{
              fontSize: 11,
              lineHeight: 1.5,
              background: 'rgba(0,0,0,0.4)',
              padding: 16,
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--glass-border-subtle)',
              overflowX: 'auto',
              color: '#38BDF8',
            }}>
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
