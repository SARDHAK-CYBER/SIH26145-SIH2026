import { useState, useEffect, useMemo } from 'react';
import { TopBar } from './components/TopBar';
import { Sidebar, icon, type NavItem } from './components/Sidebar';
import type { ThemeMode } from './components/ThemeToggle';
import { MainDashboard } from './components/MainDashboard';
import { DiscoverView } from './components/DiscoverView';
import { VisualizerStudio } from './components/VisualizerStudio';
import { IndexPatternsView } from './components/IndexPatternsView';
import { AiModelsView } from './components/AiModelsView';
import { JsonStudioView } from './components/JsonStudioView';
import { UploadPanel } from './components/UploadPanel';
import { AlertDetailDrawer } from './components/AlertDetailDrawer';
import { TemporalPickerModal } from './components/TemporalPickerModal';
import { PacketInspector, type PacketSource } from './components/PacketInspector';
import { analyzePcap, analyzePcapJob, fetchPipelineStatus, pcapInspector, ApiError } from './api/client';
import type {
  AnalysisResponse,
  ActiveNavTab,
  TemporalRange,
  Alert,
  Severity,
  ThreatClass,
  PipelineStatus,
  Workspace,
} from './types/alert';
import type { VizConfig } from './lib/vizEngine';

const PANELS_KEY = 'stealthtap-dash-panels-v2';
const BIG_UPLOAD = 25 * 1024 * 1024;   // above this, submit-and-poll instead of one long request

function loadPanels(): VizConfig[] {
  try {
    const raw = localStorage.getItem(PANELS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

interface Props {
  workspace: Workspace;
  onWorkspaceChange: (w: Workspace) => void;
  themeMode: ThemeMode;
  onThemeChange: (m: ThemeMode) => void;
}

export function PcapWorkspace({ workspace, onWorkspaceChange, themeMode, onThemeChange }: Props) {
  // A fresh visit lands on the upload screen: no bundled/synthetic data is ever shown as if it were a result.
  const [activeTab, setActiveTab] = useState<ActiveNavTab>('upload');
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isTemporalModalOpen, setIsTemporalModalOpen] = useState(false);
  const [pipeline, setPipeline] = useState<PipelineStatus | null>(null);

  const [customPanels, setCustomPanels] = useState<VizConfig[]>(loadPanels);
  useEffect(() => {
    try { localStorage.setItem(PANELS_KEY, JSON.stringify(customPanels)); } catch { /* ignore */ }
  }, [customPanels]);
  const addPanel = (config: VizConfig) => setCustomPanels((p) => [...p, config]);
  const removePanel = (id: string) => setCustomPanels((p) => p.filter((c) => c.id !== id));

  const [temporalRange, setTemporalRange] = useState<TemporalRange>(() => {
    const now = new Date();
    return { label: 'Last 1 Hour', startIso: new Date(now.getTime() - 3600_000).toISOString(), endIso: now.toISOString(), isCustom: false, refreshSeconds: 10 };
  });

  const [activeFilters, setActiveFilters] = useState<{
    severity?: Severity; threatClass?: ThreatClass; protocol?: string; detectionMode?: string; searchQuery: string;
  }>({ searchQuery: '' });

  useEffect(() => { fetchPipelineStatus().then(setPipeline).catch(() => {}); }, []);
  void pipeline;

  const filteredResult = useMemo(() => {
    if (!result) return null;
    const filteredAlerts = result.alerts.filter((a) => {
      if (activeFilters.severity && a.severity !== activeFilters.severity) return false;
      if (activeFilters.threatClass && a.threat_class !== activeFilters.threatClass) return false;
      if (activeFilters.protocol && a.flow_identifier.protocol !== activeFilters.protocol) return false;
      if (activeFilters.detectionMode && a.detection_mode !== activeFilters.detectionMode) return false;
      if (activeFilters.searchQuery) {
        const q = activeFilters.searchQuery.toLowerCase();
        const hit = a.threat_class.toLowerCase().includes(q) || a.flow_identifier.src_ip.includes(q) || a.flow_identifier.dst_ip.includes(q)
          || a.mitre_attack.technique_name.toLowerCase().includes(q) || a.mitre_attack.technique_id.toLowerCase().includes(q);
        if (!hit) return false;
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
    return { ...result, alert_count: filteredAlerts.length, severity_counts: severityCounts, threat_class_counts: threatClassCounts,
      detection_mode_counts: detectionModeCounts, alerts: filteredAlerts };
  }, [result, activeFilters]);

  async function handleAnalyze(file: File) {
    setIsAnalyzing(true); setError(null); setProgress(null);
    try {
      const data = file.size > BIG_UPLOAD
        ? await analyzePcapJob(file, (s) => setProgress(`analysing… ${Math.round(s)} s`))
        : await analyzePcap(file);
      setResult(data);
      setActiveTab('dashboard');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Analysis failed');
    } finally {
      setIsAnalyzing(false); setProgress(null);
    }
  }

  const packetSource = useMemo<PacketSource | null>(() => {
    if (!result?.analysis_id) return null;
    const id = result.analysis_id;
    return {
      mode: 'pcap',
      list: async (cursor, limit, filter) => {
        const r = await pcapInspector.page(id, cursor, limit, filter);
        return { rows: r.rows, next: r.next, total: r.total, firstTs: r.first_ts };
      },
      detail: (n) => pcapInspector.detail(id, n),
      exportUrl: (f) => pcapInspector.exportUrl(id, f),
    };
  }, [result?.analysis_id]);

  const tabs: NavItem[] = [
    { id: 'upload', label: 'Upload capture', icon: icon(<><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" /></>) },
    { id: 'dashboard', label: 'Dashboard', icon: icon(<><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></>), badge: filteredResult?.alert_count || undefined },
    { id: 'packets', label: 'Packets', icon: icon(<><path d="M21 8 12 3 3 8v8l9 5 9-5z" /><path d="M3 8l9 5 9-5M12 13v8" /></>) },
    { id: 'discover', label: 'Discover', icon: icon(<><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></>) },
    { id: 'visualizers', label: 'Visualizer Studio', icon: icon(<><circle cx="12" cy="12" r="9" /><path d="M12 3v9l6 3" /></>) },
    { id: 'json_studio', label: 'JSON Studio', icon: icon(<><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></>) },
    { id: 'ai_models', label: 'AI Models & Engines', icon: icon(<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />), badge: '13' },
    { id: 'index_patterns', label: 'Index Patterns', icon: icon(<path d="M4 6h16M4 12h16M4 18h16" />) },
  ];

  const needsResult = !filteredResult && !['upload', 'ai_models', 'index_patterns'].includes(activeTab);

  return (
    <>
      <div className="app-shell">
        <Sidebar workspace={workspace} onWorkspaceChange={onWorkspaceChange} tabs={tabs} activeTab={activeTab}
          onTabChange={(t) => setActiveTab(t as ActiveNavTab)} />
        <div className="main-col">
          <TopBar
            temporalRange={temporalRange}
            onOpenTemporalModal={() => setIsTemporalModalOpen(true)}
            activeFilters={activeFilters}
            onUpdateFilter={(k, v) => setActiveFilters((prev) => ({ ...prev, [k]: v }))}
            onClearFilters={() => setActiveFilters({ searchQuery: '' })}
            themeMode={themeMode}
            onThemeChange={onThemeChange}
          />
          <div className="view-area">
            {error && (
              <div className="glass" style={{
                marginBottom: 20, padding: '14px 18px', fontSize: 13, borderRadius: 'var(--radius-md)',
                border: '1px solid color-mix(in srgb, var(--sev-critical) 40%, transparent)',
                background: 'color-mix(in srgb, var(--sev-critical) 12%, transparent)', color: 'var(--sev-critical)',
              }}>{error}</div>
            )}
            {progress && <div className="glass mono" style={{ marginBottom: 16, padding: '10px 16px', fontSize: 12 }}>{progress}</div>}

            {needsResult && (
              <div className="glass" style={{ padding: 28, textAlign: 'center' }}>
                <div style={{ fontSize: 15, fontWeight: 700 }}>No capture analysed yet</div>
                <div style={{ fontSize: 12.5, color: 'var(--text-muted)', margin: '6px 0 14px' }}>Upload a .pcap to see its alerts, flows and packets. Nothing here is pre-loaded or simulated.</div>
                <button className="btn-primary" onClick={() => setActiveTab('upload')}>Upload a capture</button>
              </div>
            )}

            {activeTab === 'dashboard' && filteredResult && (
              <MainDashboard data={filteredResult} onSelectAlert={setSelectedAlert}
                onFilterByThreat={(tc) => setActiveFilters((p) => ({ ...p, threatClass: tc }))}
                panels={customPanels} onRemovePanel={removePanel} onCreateVisualization={() => setActiveTab('visualizers')} />
            )}
            {activeTab === 'packets' && result && (
              packetSource && result.inspectable !== false
                ? <PacketInspector source={packetSource} presetFilter="" />
                : <div className="glass" style={{ padding: 24, fontSize: 13, color: 'var(--text-muted)' }}>
                    This capture cannot be paged packet-by-packet (only classic .pcap files are indexed — pcapng is analysed but not inspectable).
                  </div>
            )}
            {activeTab === 'discover' && filteredResult && <DiscoverView data={filteredResult} onSelectAlert={setSelectedAlert} />}
            {activeTab === 'visualizers' && filteredResult && <VisualizerStudio data={filteredResult} panelCount={customPanels.length} onAddToDashboard={addPanel} />}
            {activeTab === 'index_patterns' && <IndexPatternsView />}
            {activeTab === 'ai_models' && <AiModelsView />}
            {activeTab === 'json_studio' && filteredResult && <JsonStudioView data={filteredResult} activeFilters={activeFilters} />}
            {activeTab === 'upload' && <UploadPanel onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />}
          </div>
        </div>
      </div>

      <AlertDetailDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      {isTemporalModalOpen && (
        <TemporalPickerModal currentRange={temporalRange} onApply={setTemporalRange} onClose={() => setIsTemporalModalOpen(false)} />
      )}
    </>
  );
}
