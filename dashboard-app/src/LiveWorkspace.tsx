import { useMemo, useState } from 'react';
import { Sidebar, icon, type NavItem } from './components/Sidebar';
import { ThemeToggle, type ThemeMode } from './components/ThemeToggle';
import { AlertDetailDrawer } from './components/AlertDetailDrawer';
import { PacketInspector, type PacketSource } from './components/PacketInspector';
import { LiveOverview } from './components/live/LiveOverview';
import { LiveAlerts } from './components/live/LiveAlerts';
import { HostsView } from './components/live/HostsView';
import { FlowsView } from './components/live/FlowsView';
import { CaptureControl } from './components/live/CaptureControl';
import { useLiveData } from './hooks/useLiveData';
import { live } from './api/client';
import type { Alert, LiveTab, Workspace } from './types/alert';
import { fmtMbps, fmtPps } from './lib/format';

interface Props {
  workspace: Workspace;
  onWorkspaceChange: (w: Workspace) => void;
  themeMode: ThemeMode;
  onThemeChange: (m: ThemeMode) => void;
}

const TITLES: Record<LiveTab, string> = {
  overview: 'Live network overview', alerts: 'Live alerts', hosts: 'Hosts on the wire',
  flows: 'Active flows', packets: 'Packet inspector', capture: 'Capture control',
};

export function LiveWorkspace({ workspace, onWorkspaceChange, themeMode, onThemeChange }: Props) {
  const [tab, setTab] = useState<LiveTab>('overview');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [pktFilter, setPktFilter] = useState('');
  const d = useLiveData(tab);
  const { status } = d;
  const running = status.running;
  const tp = status.throughput ?? {};

  const source = useMemo<PacketSource>(() => ({
    mode: 'live',
    list: async (_c, limit, filter) => ({ rows: await live.packets(0, limit, filter) }),
    detail: (id) => live.packet(id),
    exportUrl: (f) => live.exportUrl(f),
  }), []);

  const tabs: NavItem[] = [
    { id: 'overview', label: 'Overview', icon: icon(<><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></>) },
    { id: 'alerts', label: 'Alerts', icon: icon(<><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></>), badge: status.alerts ? status.alerts : undefined },
    { id: 'hosts', label: 'Hosts', icon: icon(<><rect x="2" y="3" width="20" height="8" rx="2" /><rect x="2" y="13" width="20" height="8" rx="2" /><line x1="6" y1="7" x2="6.01" y2="7" /><line x1="6" y1="17" x2="6.01" y2="17" /></>), badge: status.capture?.hosts || undefined },
    { id: 'flows', label: 'Flows', icon: icon(<path d="M3 12h4l3-8 4 16 3-8h4" />) },
    { id: 'packets', label: 'Packets', icon: icon(<><path d="M21 8 12 3 3 8v8l9 5 9-5z" /><path d="M3 8l9 5 9-5M12 13v8" /></>) },
    { id: 'capture', label: 'Capture', icon: icon(<><path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0" /><line x1="12" y1="20" x2="12.01" y2="20" /></>) },
  ];

  const openPackets = (filter: string) => { setPktFilter(filter); setTab('packets'); };

  return (
    <div className="app-shell">
      <Sidebar workspace={workspace} onWorkspaceChange={onWorkspaceChange} tabs={tabs} activeTab={tab}
        onTabChange={(t) => setTab(t as LiveTab)} liveBadge={running ? 'live' : 'idle'} />
      <div className="main-col">
        <header className="topbar-v2">
          <div>
            <div style={{ fontSize: 15, fontWeight: 700 }}>{TITLES[tab]}</div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              {running
                ? `${status.source === 'pcap-replay' ? 'replaying' : 'capturing on'} ${status.source === 'pcap-replay' ? 'capture file' : status.interface}`
                : status.finished ? 'replay finished' : 'idle'}
            </div>
          </div>
          <div className="topbar-actions">
            {running && (
              <span className="mono live-pill">
                <span className="pulse-dot" /> {fmtMbps(tp.mbps)} · {fmtPps(tp.pps)}
              </span>
            )}
            {!d.reachable && <span className="mono live-pill warn">sensor offline</span>}
            <ThemeToggle mode={themeMode} onChange={onThemeChange} />
          </div>
        </header>

        <div className="view-area">
          {tab === 'overview' && (
            <LiveOverview status={status} series={d.series} summary={d.summary} hosts={d.hosts} protocols={d.protocols} alerts={d.alerts}
              onSelectAlert={setSelectedAlert} onOpenHost={(ip) => openPackets(ip)} onGoto={(t) => setTab(t)} />
          )}
          {tab === 'alerts' && (
            <LiveAlerts alerts={d.alerts} running={running} onSelect={setSelectedAlert}
              onOpenPackets={(a) => openPackets(`${a.flow_identifier.src_ip} ${a.flow_identifier.dst_ip}`)} />
          )}
          {tab === 'hosts' && <HostsView hosts={d.hosts} running={running} onOpenHost={(ip) => openPackets(ip)} />}
          {tab === 'flows' && <FlowsView flows={d.flows} onOpenFlow={openPackets} />}
          {tab === 'packets' && (
            <PacketInspector source={source} active={running || !!status.finished} presetFilter={pktFilter}
              emptyHint="No packets captured yet — start a capture, then packets stream in here." />
          )}
          {tab === 'capture' && (
            <CaptureControl status={status} reachable={d.reachable} onChanged={d.refreshStatus}
              onStarted={() => { d.resetAlerts(); setTab('overview'); }} />
          )}
        </div>
      </div>
      <AlertDetailDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </div>
  );
}
