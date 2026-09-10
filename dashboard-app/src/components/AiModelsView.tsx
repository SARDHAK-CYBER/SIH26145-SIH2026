import React, { useState, useEffect } from 'react';
import type { PipelineStatus, PipelineEngine } from '../types/alert';
import { fetchPipelineStatus, fetchModelsManifest, scoreFlow } from '../api/client';

interface ManifestEntry {
  family: string;
  feature_schema_version?: string;
  model_version?: string;
  training_data?: { source_file?: string; row_count?: number };
  xgboost_metrics?: Record<string, number>;
  isolation_forest_metrics?: Record<string, number>;
  artifacts?: string[];
}

export const AiModelsView: React.FC = () => {
  const [pipeline, setPipeline] = useState<PipelineStatus | null>(null);
  const [manifest, setManifest] = useState<ManifestEntry[]>([]);
  const [testDomain, setTestDomain] = useState('x9a8b7q6w5e4r3t2y1.biz');
  const [scoreResult, setScoreResult] = useState<any>(null);
  const [scoring, setScoring] = useState(false);
  const [scoreErr, setScoreErr] = useState<string | null>(null);

  useEffect(() => {
    fetchPipelineStatus().then(setPipeline).catch(() => {});
    fetchModelsManifest().then((m) => setManifest(Array.isArray(m) ? (m as ManifestEntry[]) : [])).catch(() => {});
  }, []);

  async function handleScoreSandbox() {
    setScoring(true);
    setScoreErr(null);
    try {
      // Real inference against the backend's /score/dns endpoint.
      const res = await scoreFlow('dns', { dns_query: testDomain.toLowerCase() });
      setScoreResult({ source: 'backend', domain: testDomain, ...res });
    } catch (e) {
      // Deterministic client-side preview if the API is offline.
      const len = testDomain.replace(/^https?:\/\//, '').split('.')[0]?.length ?? testDomain.length;
      const highEntropy = len > 14;
      setScoreResult({
        source: 'client-preview (API offline)',
        domain: testDomain,
        feature_schema_version: '1.0.0',
        model_scores: { xgboost: highEntropy ? 0.984 : 0.042, isolation_forest: highEntropy ? 0.62 : 0.18 },
        detection_mode: 'xgboost',
        verdict: highEntropy ? 'DGA_DOMAIN' : 'BENIGN',
      });
      setScoreErr(e instanceof Error ? e.message : 'scoring failed');
    } finally {
      setScoring(false);
    }
  }

  const defaultEngines: PipelineEngine[] = [
    { id: 'ENG-01', name: 'Volumetric DDoS + Slowloris', threat_class: 'VOLUMETRIC_DDOS', algorithm: 'Redis CMS time-bucket rate + source-IP HyperLogLog entropy', protocol: 'TCP/UDP', status: 'active' },
    { id: 'ENG-02', name: 'C2 Beaconing', threat_class: 'C2_BEACONING', algorithm: 'Inter-arrival coefficient-of-variation', protocol: 'TCP/DNS', status: 'active' },
    { id: 'ENG-03', name: 'DGA + DNS Tunnelling', threat_class: 'DGA_DOMAIN', algorithm: 'Trained dns XGBoost (262 features) + lexical heuristic; mDNS/LLMNR filtered', protocol: 'DNS', status: 'active' },
    { id: 'ENG-04', name: 'Encrypted Malware (JA4)', threat_class: 'ENCRYPTED_MALWARE', algorithm: 'Real JA4 from ClientHello vs FoxIO threat intel', protocol: 'TLS', status: 'active' },
    { id: 'ENG-05', name: 'Reconnaissance', threat_class: 'RECONNAISSANCE', algorithm: 'Distinct-destination fan-out, memory-bounded', protocol: 'TCP/UDP/ICMP', status: 'active' },
    { id: 'ENG-06', name: 'Data Exfiltration', threat_class: 'DATA_EXFILTRATION', algorithm: 'Per-flow + accumulated outbound:inbound byte ratio', protocol: 'TCP/UDP', status: 'active' },
    { id: 'ENG-07', name: 'OT Industrial Anomaly', threat_class: 'ICS_UNAUTHORIZED_CONTROL_COMMAND', algorithm: 'Dangerous Modbus / DNP3 / EtherNet-IP CIP command codes', protocol: 'Modbus · DNP3 · CIP', status: 'active' },
    { id: 'ENG-08', name: 'YARA File Scanner', threat_class: 'MALICIOUS_FILE_DETECTED', algorithm: '~401 rules on Zeek-extracted cleartext files', protocol: 'HTTP/FTP/SMB', status: 'active' },
    { id: 'ENG-09', name: 'HTTP C2 / Exfil', threat_class: 'DATA_EXFILTRATION', algorithm: 'Library-default UA + URI entropy + large POST bodies', protocol: 'HTTP', status: 'active' },
    { id: 'ENG-10', name: 'Suricata Signatures', threat_class: 'NETWORK_INTRUSION_ATTEMPT', algorithm: '20,829 Emerging Threats Open rules (eve.json bridge)', protocol: 'All', status: 'active' },
    { id: 'ENG-11', name: 'Kerberoasting', threat_class: 'NETWORK_INTRUSION_ATTEMPT', algorithm: 'TGS request + RC4 (rc4-hmac) cipher for a service account', protocol: 'Kerberos', status: 'active' },
    { id: 'ENG-12', name: 'SMB Lateral Movement', threat_class: 'NETWORK_INTRUSION_ATTEMPT', algorithm: 'MITRE BZAR notice parsing, technique IDs from BZAR output', protocol: 'SMB/DCE-RPC', status: 'active' },
    { id: 'ENG-13', name: 'Credential Brute Force', threat_class: 'NETWORK_INTRUSION_ATTEMPT', algorithm: 'Connection attempts per (src, dst, auth-port) over a wide window', protocol: 'FTP/SSH/RDP/…', status: 'active' },
  ];

  const engines = pipeline?.engines?.length ? pipeline.engines : defaultEngines;
  const dns = manifest.find((m) => m.family === 'dns');
  const pct = (v?: number) => (v == null ? '—' : `${(v * 100).toFixed(2)}%`);
  const num = (v?: number) => (v == null ? '—' : v.toFixed(4));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div className="glass" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>StealthTap AI Model Server &amp; 13 Engines</h2>
              <span className="mono" style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: 'rgba(139,92,246,.2)', color: 'var(--accent-violet)' }}>
                ONNX RUNTIME
              </span>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 0' }}>
              Hybrid XGBoost + Isolation Forest per protocol family, sharing one feature-extraction module with the training code — zero train/serve skew.
            </p>
          </div>
          <span className="mono" style={{
            fontSize: 11, padding: '4px 10px', borderRadius: 6,
            background: 'rgba(16,185,129,.15)', color: 'var(--accent-emerald)', border: '1px solid rgba(16,185,129,.3)',
          }}>
            ● Feature Schema v{dns?.feature_schema_version ?? '1.0.0'}
          </span>
        </div>

        {/* Real per-family cards from MANIFEST.json */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 12, marginTop: 16 }}>
          {manifest.length === 0 && (
            <div className="glass" style={{ padding: 14, color: 'var(--text-dim)', fontSize: 12 }}>
              No <span className="mono">models/MANIFEST.json</span> loaded — start the API with trained models in <span className="mono">models/</span>.
            </div>
          )}
          {manifest.map((m) => (
            <div key={m.family} className="glass" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase' }}>{m.family}</span>
                <span className="mono" style={{ fontSize: 10, color: 'var(--text-dim)' }}>{(m.training_data?.row_count ?? 0).toLocaleString()} rows</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 8, fontSize: 11 }}>
                <Metric label="Precision" value={pct(m.xgboost_metrics?.precision)} />
                <Metric label="Recall" value={pct(m.xgboost_metrics?.recall)} />
                <Metric label="F1" value={pct(m.xgboost_metrics?.f1)} />
                <Metric label="ROC-AUC" value={num(m.xgboost_metrics?.roc_auc)} />
              </div>
              <div style={{ fontSize: 9.5, color: 'var(--text-faint)', marginTop: 6 }}>
                XGBoost · Isolation Forest F1 {num(m.isolation_forest_metrics?.f1)} (advisory)
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 13 engines */}
      <div className="glass" style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px' }}>All 13 Detection Engines — architecture &amp; status</h3>
        <div style={{ overflowX: 'auto' }}>
          <table className="glass-table">
            <thead>
              <tr>
                <th>Engine</th><th>Detection scope</th><th>Threat class</th><th>Protocol</th><th>Core algorithm</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {engines.map((eng) => (
                <tr key={eng.id}>
                  <td className="mono" style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{eng.id}</td>
                  <td style={{ fontWeight: 500, color: 'var(--text)' }}>{eng.name}</td>
                  <td className="mono" style={{ color: 'var(--text-muted)' }}>{eng.threat_class}</td>
                  <td className="mono" style={{ color: 'var(--accent-violet)' }}>{eng.protocol}</td>
                  <td style={{ color: 'var(--text-dim)', fontSize: 11 }}>{eng.algorithm}</td>
                  <td>
                    <span className="mono" style={{
                      fontSize: 10, padding: '2px 8px', borderRadius: 4,
                      background: 'rgba(16,185,129,.15)', color: 'var(--accent-emerald)', border: '1px solid rgba(16,185,129,.3)',
                    }}>● {(eng.status || 'active').toUpperCase()}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Real inference sandbox */}
      <div className="glass" style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 8px' }}>Interactive AI inference sandbox</h3>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '0 0 16px' }}>
          Score a domain against the real hybrid <span className="mono">dns</span> model (<span className="mono">POST /score/dns</span>). Falls back to a deterministic client-side preview if the API is offline.
        </p>
        <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
          <input type="text" className="mono" value={testDomain} onChange={(e) => setTestDomain(e.target.value)}
            placeholder="e.g. kqx3vwzptlmnbrx9.com or www.google.com"
            style={{ flex: 1, padding: '10px 14px', fontSize: 13, borderRadius: 'var(--radius-sm)', background: 'rgba(0,0,0,.3)', border: '1px solid var(--glass-border)', color: 'var(--text)', outline: 'none' }} />
          <button type="button" onClick={handleScoreSandbox} className="btn-primary" disabled={scoring}>
            {scoring ? 'Scoring…' : 'Run Hybrid Score'}
          </button>
        </div>
        {scoreErr && <div style={{ fontSize: 11, color: 'var(--sev-medium)', marginBottom: 10 }}>API: {scoreErr}</div>}
        {scoreResult && (
          <div className="glass" style={{ padding: 18, background: 'rgba(0,0,0,.25)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>source: {scoreResult.source}</span>
              {scoreResult.fired != null && (
                <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: scoreResult.fired ? 'var(--sev-critical)' : 'var(--accent-emerald)' }}>
                  {scoreResult.fired ? 'ALERT FIRED' : 'below threshold'}
                </span>
              )}
            </div>
            <pre className="mono" style={{ fontSize: 11, padding: 12, borderRadius: 6, background: 'rgba(0,0,0,.4)', color: '#34D399', margin: 0, overflowX: 'auto' }}>
              {JSON.stringify(scoreResult, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: 'var(--text-faint)', textTransform: 'uppercase' }}>{label}</div>
      <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>{value}</div>
    </div>
  );
}
