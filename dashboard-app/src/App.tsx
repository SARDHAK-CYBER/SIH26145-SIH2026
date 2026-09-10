import { useState, useEffect, useMemo } from 'react';
import { TopBar } from './components/TopBar';
import { Sidebar } from './components/Sidebar';
import type { ThemeMode } from './components/ThemeToggle';
import { MainDashboard } from './components/MainDashboard';
import { DiscoverView } from './components/DiscoverView';
import { VisualizerStudio } from './components/VisualizerStudio';
import { IndexPatternsView } from './components/IndexPatternsView';
import { AiModelsView } from './components/AiModelsView';
import { JsonStudioView } from './components/JsonStudioView';
import { UploadPanel } from './components/UploadPanel';
import { LiveCaptureView } from './components/LiveCaptureView';
import { AlertDetailDrawer } from './components/AlertDetailDrawer';
import { TemporalPickerModal } from './components/TemporalPickerModal';
import { analyzePcap, fetchSampleAnalysis, fetchPipelineStatus, ApiError } from './api/client';
import type {
  AnalysisResponse,
  ActiveNavTab,
  TemporalRange,
  Alert,
  Severity,
  ThreatClass,
  PipelineStatus,
} from './types/alert';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveNavTab>('dashboard');
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isTemporalModalOpen, setIsTemporalModalOpen] = useState(false);
  const [pipeline, setPipeline] = useState<PipelineStatus | null>(null);

  // Auto / Light / Dark theme — persisted, applied to <html data-theme>
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem('stealthtap-theme');
      if (saved === 'light' || saved === 'dark' || saved === 'auto') return saved;
    } catch { /* storage blocked */ }
    return 'auto';
  });

  useEffect(() => {
    const root = document.documentElement;
    if (themeMode === 'auto') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', themeMode);
    try { localStorage.setItem('stealthtap-theme', themeMode); } catch { /* ignore */ }
  }, [themeMode]);

  // Temporal Range state
  const [temporalRange, setTemporalRange] = useState<TemporalRange>(() => {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    return {
      label: 'Last 1 Hour',
      startIso: oneHourAgo.toISOString(),
      endIso: now.toISOString(),
      isCustom: false,
      refreshSeconds: 10,
    };
  });

  // Palo Alto Filter Tags & Search Query
  const [activeFilters, setActiveFilters] = useState<{
    severity?: Severity;
    threatClass?: ThreatClass;
    protocol?: string;
    detectionMode?: string;
    searchQuery: string;
  }>({
    searchQuery: '',
  });

  // Load sample ground-truth analysis on mount so the user sees a complete SOC immediately
  useEffect(() => {
    fetchSampleAnalysis()
      .then(setResult)
      .catch(() => {
        // Safe fallback data if backend is offline
        setResult(FALLBACK_SAMPLE_DATA);
      });
    fetchPipelineStatus().then(setPipeline).catch(() => {});
  }, []);

  void pipeline; // reserved for future engine-health surfacing

  // Filter alerts based on active filter tags & search query
  const filteredResult = useMemo(() => {
    if (!result) return null;

    const filteredAlerts = result.alerts.filter((a) => {
      if (activeFilters.severity && a.severity !== activeFilters.severity) return false;
      if (activeFilters.threatClass && a.threat_class !== activeFilters.threatClass) return false;
      if (activeFilters.protocol && a.flow_identifier.protocol !== activeFilters.protocol) return false;
      if (activeFilters.detectionMode && a.detection_mode !== activeFilters.detectionMode) return false;
      if (activeFilters.searchQuery) {
        const q = activeFilters.searchQuery.toLowerCase();
        const matchesClass = a.threat_class.toLowerCase().includes(q);
        const matchesSrc = a.flow_identifier.src_ip.includes(q);
        const matchesDst = a.flow_identifier.dst_ip.includes(q);
        const matchesMitre = a.mitre_attack.technique_name.toLowerCase().includes(q) ||
                             a.mitre_attack.technique_id.toLowerCase().includes(q);
        if (!matchesClass && !matchesSrc && !matchesDst && !matchesMitre) return false;
      }
      return true;
    });

    const severityCounts: Partial<Record<Severity, number>> = {};
    const threatClassCounts: Partial<Record<ThreatClass, number>> = {};
    const detectionModeCounts: Partial<Record<'rule' | 'xgboost' | 'isolation_forest', number>> = {};

    filteredAlerts.forEach((a) => {
      severityCounts[a.severity] = (severityCounts[a.severity] || 0) + 1;
      threatClassCounts[a.threat_class] = (threatClassCounts[a.threat_class] || 0) + 1;
      detectionModeCounts[a.detection_mode] = (detectionModeCounts[a.detection_mode] || 0) + 1;
    });

    return {
      ...result,
      alert_count: filteredAlerts.length,
      severity_counts: severityCounts,
      threat_class_counts: threatClassCounts,
      detection_mode_counts: detectionModeCounts,
      alerts: filteredAlerts,
    };
  }, [result, activeFilters]);

  async function handleAnalyze(file: File) {
    setIsAnalyzing(true);
    setError(null);
    try {
      const data = await analyzePcap(file);
      setResult(data);
      setActiveTab('dashboard');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  }

  async function handleLoadSample() {
    setIsAnalyzing(true);
    setError(null);
    try {
      const data = await fetchSampleAnalysis();
      setResult(data);
      setActiveTab('dashboard');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load sample data');
    } finally {
      setIsAnalyzing(false);
    }
  }

  function handleUpdateFilter(key: string, value: string | undefined) {
    setActiveFilters((prev) => ({ ...prev, [key]: value }));
  }

  function handleClearFilters() {
    setActiveFilters({ searchQuery: '' });
  }

  return (
    <>
      {/* Animated Liquid Backdrop Orbs */}
      <div className="backdrop">
        <div className="orb orb-1" />
        <div className="orb orb-2" />
        <div className="orb orb-3" />
      </div>

      <div className="app-shell">
        {/* Left slide taskbar — brand mark + navigation */}
        <Sidebar
          activeTab={activeTab}
          onTabChange={setActiveTab}
          alertCount={filteredResult?.alert_count || 0}
        />

        <div className="main-col">
          {/* Top taskbar — search, temporal filter, theme */}
          <TopBar
            temporalRange={temporalRange}
            onOpenTemporalModal={() => setIsTemporalModalOpen(true)}
            activeFilters={activeFilters}
            onUpdateFilter={handleUpdateFilter}
            onClearFilters={handleClearFilters}
            themeMode={themeMode}
            onThemeChange={setThemeMode}
          />

          <div className="view-area">
            {error && (
              <div className="glass" style={{
                marginBottom: 20,
                padding: '14px 18px',
                border: '1px solid color-mix(in srgb, var(--sev-critical) 40%, transparent)',
                background: 'color-mix(in srgb, var(--sev-critical) 12%, transparent)',
                color: 'var(--sev-critical)',
                fontSize: 13,
                borderRadius: 'var(--radius-md)',
              }}>
                {error}
              </div>
            )}

            {/* View Routing */}
            {activeTab === 'dashboard' && filteredResult && (
              <MainDashboard
                data={filteredResult}
                onSelectAlert={setSelectedAlert}
                onFilterByThreat={(tc) => handleUpdateFilter('threatClass', tc)}
              />
            )}

            {activeTab === 'discover' && filteredResult && (
              <DiscoverView data={filteredResult} onSelectAlert={setSelectedAlert} />
            )}

            {activeTab === 'visualizers' && filteredResult && (
              <VisualizerStudio data={filteredResult} />
            )}

            {activeTab === 'index_patterns' && <IndexPatternsView />}

            {activeTab === 'ai_models' && <AiModelsView />}

            {activeTab === 'json_studio' && filteredResult && (
              <JsonStudioView data={filteredResult} activeFilters={activeFilters} />
            )}

            {activeTab === 'upload' && (
              <UploadPanel
                onAnalyze={handleAnalyze}
                onLoadSample={handleLoadSample}
                isAnalyzing={isAnalyzing}
              />
            )}

            {activeTab === 'live_capture' && <LiveCaptureView />}
          </div>
        </div>
      </div>

      {/* Forensic Inspection Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />

      {/* Temporal Selection Modal */}
      {isTemporalModalOpen && (
        <TemporalPickerModal
          currentRange={temporalRange}
          onApply={setTemporalRange}
          onClose={() => setIsTemporalModalOpen(false)}
        />
      )}
    </>
  );
}

const FALLBACK_SAMPLE_DATA: AnalysisResponse = {
  analysis_id: "sim-fallback-capture-01",
  filename: "simulated_attack_traffic.pcap",
  parser_used: "zeek",
  packet_summary: {
    conn_flows: 1284,
    dns_queries: 462,
    tls_sessions: 198,
    modbus_records: 74,
    http_requests: 215,
    files_yara_scanned: 8,
  },
  timing: { parse_seconds: 0.38, detection_seconds: 0.12 },
  models_active: ["dns", "flow"],
  yara_active: true,
  alert_count: 10,
  severity_counts: { CRITICAL: 3, HIGH: 4, MEDIUM: 2, LOW: 1 },
  threat_class_counts: {
    VOLUMETRIC_DDOS: 2,
    C2_BEACONING: 1,
    DGA_DOMAIN: 2,
    ENCRYPTED_MALWARE: 1,
    RECONNAISSANCE: 1,
    DATA_EXFILTRATION: 1,
    ICS_UNAUTHORIZED_CONTROL_COMMAND: 1,
    DNS_TUNNELING: 1,
  },
  detection_mode_counts: { rule: 7, xgboost: 2, isolation_forest: 1 },
  alerts: [
    {
      alert_id: "alt-ddos-1",
      timestamp: Date.now() / 1000 - 300,
      severity: "CRITICAL",
      confidence_score: 98.5,
      threat_class: "VOLUMETRIC_DDOS",
      flow_identifier: { src_ip: "198.51.100.42", src_port: 54122, dst_ip: "10.0.0.10", dst_port: 80, protocol: "TCP" },
      mitre_attack: { tactic: "Impact", technique_id: "T1498.001", technique_name: "Direct Network Flood" },
      evidence: { syn_flood_pps: 3200, bloom_filter_saturation: 0.94 },
      forensics: { raw_segment_hash_sha256: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a" },
      detection_mode: "rule",
      model_scores: { xgboost: 0.985, isolation_forest: -0.32 },
    },
    {
      alert_id: "alt-dga-2",
      timestamp: Date.now() / 1000 - 240,
      severity: "HIGH",
      confidence_score: 96.2,
      threat_class: "DGA_DOMAIN",
      flow_identifier: { src_ip: "10.0.0.105", src_port: 59124, dst_ip: "1.1.1.1", dst_port: 53, protocol: "UDP" },
      mitre_attack: { tactic: "Command and Control", technique_id: "T1568.002", technique_name: "Domain Generation Algorithms" },
      evidence: { domain: "vx79kmq10zlk8a.biz", entropy: 4.62 },
      forensics: { raw_segment_hash_sha256: "8a3241bbaef400329487cdef6543210987654321fedcba0987654321abcdef01" },
      detection_mode: "xgboost",
      model_scores: { xgboost: 0.962, isolation_forest: -0.28 },
    },
    {
      alert_id: "alt-ot-3",
      timestamp: Date.now() / 1000 - 180,
      severity: "CRITICAL",
      confidence_score: 99.0,
      threat_class: "ICS_UNAUTHORIZED_CONTROL_COMMAND",
      flow_identifier: { src_ip: "172.16.20.88", src_port: 40221, dst_ip: "172.16.20.10", dst_port: 502, protocol: "TCP" },
      mitre_attack: { tactic: "Impair Process Control", technique_id: "T0855", technique_name: "Unauthorized Command Message" },
      evidence: { modbus_func: "WRITE_MULTIPLE_REGISTERS", register_address: 40012 },
      forensics: { raw_segment_hash_sha256: "c8e1923847291a0f9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a" },
      detection_mode: "rule",
    },
    {
      alert_id: "alt-c2-4",
      timestamp: Date.now() / 1000 - 120,
      severity: "HIGH",
      confidence_score: 91.4,
      threat_class: "C2_BEACONING",
      flow_identifier: { src_ip: "10.0.0.112", src_port: 49811, dst_ip: "198.51.100.80", dst_port: 443, protocol: "TCP" },
      mitre_attack: { tactic: "Command and Control", technique_id: "T1071.001", technique_name: "Web Protocols" },
      evidence: { fft_peak_freq_hz: 0.033, periodicity_sec: 30.2, beacons: 40 },
      forensics: { raw_segment_hash_sha256: "9f112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" },
      detection_mode: "rule",
    },
    {
      alert_id: "alt-exfil-5",
      timestamp: Date.now() / 1000 - 60,
      severity: "HIGH",
      confidence_score: 94.0,
      threat_class: "DATA_EXFILTRATION",
      flow_identifier: { src_ip: "10.0.0.105", src_port: 52109, dst_ip: "203.0.113.88", dst_port: 443, protocol: "TCP" },
      mitre_attack: { tactic: "Exfiltration", technique_id: "T1048.003", technique_name: "Exfiltration Over Alternative Protocol" },
      evidence: { orig_bytes: 14200000, resp_bytes: 1010, byte_ratio: 14059.4 },
      forensics: { raw_segment_hash_sha256: "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b" },
      detection_mode: "rule",
    },
  ],
};

