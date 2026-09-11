import React from 'react';
import type { ActiveNavTab } from '../types/alert';
import { Logo } from './Logo';

interface SidebarProps {
  activeTab: ActiveNavTab;
  onTabChange: (tab: ActiveNavTab) => void;
  alertCount: number;
}

const icon = (path: React.ReactNode) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {path}
  </svg>
);

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onTabChange, alertCount }) => {
  const tabs: Array<{ id: ActiveNavTab; label: string; icon: React.ReactNode; badge?: string | number }> = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: icon(<>
        <rect x="3" y="3" width="7" height="9" rx="1" />
        <rect x="14" y="3" width="7" height="5" rx="1" />
        <rect x="14" y="12" width="7" height="9" rx="1" />
        <rect x="3" y="16" width="7" height="5" rx="1" />
      </>),
      badge: alertCount > 0 ? alertCount : undefined,
    },
    {
      id: 'discover',
      label: 'Discover',
      icon: icon(<>
        <circle cx="11" cy="11" r="7" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </>),
    },
    {
      id: 'visualizers',
      label: 'Visualizer Studio',
      icon: icon(<>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 3v9l6 3" />
      </>),
      badge: '10',
    },
    {
      id: 'index_patterns',
      label: 'Index Patterns',
      icon: icon(<path d="M4 6h16M4 12h16M4 18h16" />),
    },
    {
      id: 'ai_models',
      label: 'AI Models & Engines',
      icon: icon(<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />),
      badge: '13',
    },
    {
      id: 'json_studio',
      label: 'JSON Studio',
      icon: icon(<>
        <polyline points="16 18 22 12 16 6" />
        <polyline points="8 6 2 12 8 18" />
      </>),
    },
    {
      id: 'upload',
      label: 'PCAP Ingest',
      icon: icon(<>
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
        <polyline points="17 8 12 3 7 8" />
        <line x1="12" y1="3" x2="12" y2="15" />
      </>),
    },
    {
      id: 'live_capture',
      label: 'Live Capture',
      icon: icon(<>
        <path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0" />
        <line x1="12" y1="20" x2="12.01" y2="20" />
      </>),
      badge: 'Kernel',
    },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <Logo size={30} />
      </div>

      <nav className="sidebar-nav">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              className={`sidebar-nav-btn ${isActive ? 'active' : ''}`}
              onClick={() => onTabChange(tab.id)}
              aria-current={isActive ? 'page' : undefined}
            >
              <span className="sb-icon">{tab.icon}</span>
              <span>{tab.label}</span>
              {tab.badge !== undefined && <span className="sb-badge">{tab.badge}</span>}
            </button>
          );
        })}
      </nav>

      <div className="sidebar-foot">
        StealthTap · Passive AI-DPI<br />NTRO · PS 26145
      </div>
    </aside>
  );
};
