import { useEffect, useState } from 'react';
import type { ThemeMode } from './components/ThemeToggle';
import { LiveWorkspace } from './LiveWorkspace';
import { PcapWorkspace } from './PcapWorkspace';
import type { Workspace } from './types/alert';

function workspaceFromHash(): Workspace {
  return window.location.hash.startsWith('#/pcap') ? 'pcap' : 'live';
}

/** Two separate dashboards -- live network monitoring and uploaded-PCAP analysis -- each at its own
 *  address (#/live, #/pcap) with its own navigation, sharing only the theme. */
export default function App() {
  const [workspace, setWorkspace] = useState<Workspace>(workspaceFromHash);

  useEffect(() => {
    const on = () => setWorkspace(workspaceFromHash());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);

  function changeWorkspace(w: Workspace) {
    window.location.hash = `#/${w}`;
    setWorkspace(w);
  }

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

  const common = { workspace, onWorkspaceChange: changeWorkspace, themeMode, onThemeChange: setThemeMode };

  return (
    <>
      <div className="backdrop">
        <div className="orb orb-1" />
        <div className="orb orb-2" />
        <div className="orb orb-3" />
      </div>
      {workspace === 'live' ? <LiveWorkspace {...common} /> : <PcapWorkspace {...common} />}
    </>
  );
}
