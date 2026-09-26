import React from 'react';
import type { Workspace } from '../types/alert';
import { Logo } from './Logo';

export interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  badge?: string | number;
}

interface SidebarProps {
  workspace: Workspace;
  onWorkspaceChange: (w: Workspace) => void;
  tabs: NavItem[];
  activeTab: string;
  onTabChange: (tab: string) => void;
  liveBadge?: 'live' | 'idle';
}

export const icon = (path: React.ReactNode) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {path}
  </svg>
);

export const Sidebar: React.FC<SidebarProps> = ({ workspace, onWorkspaceChange, tabs, activeTab, onTabChange, liveBadge }) => (
  <aside className="sidebar">
    <div className="sidebar-logo">
      <Logo size={30} />
    </div>

    <div className="ws-switch" role="tablist" aria-label="Workspace">
      <button role="tab" aria-selected={workspace === 'live'} className={workspace === 'live' ? 'on' : ''} onClick={() => onWorkspaceChange('live')}>
        <span className={liveBadge === 'live' ? 'pulse-dot' : 'ws-dot'} /> Live network
      </button>
      <button role="tab" aria-selected={workspace === 'pcap'} className={workspace === 'pcap' ? 'on' : ''} onClick={() => onWorkspaceChange('pcap')}>
        PCAP analysis
      </button>
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
