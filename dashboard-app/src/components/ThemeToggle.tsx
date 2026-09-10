import React from 'react';

export type ThemeMode = 'auto' | 'light' | 'dark';

interface ThemeToggleProps {
  mode: ThemeMode;
  onChange: (next: ThemeMode) => void;
}

const NEXT: Record<ThemeMode, ThemeMode> = {
  auto: 'light',
  light: 'dark',
  dark: 'auto',
};

const ICON: Record<ThemeMode, React.ReactNode> = {
  auto: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 3v18" />
      <path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none" />
    </svg>
  ),
  light: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  ),
  dark: (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
    </svg>
  ),
};

const LABEL: Record<ThemeMode, string> = {
  auto: 'Auto',
  light: 'Light',
  dark: 'Dark',
};

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ mode, onChange }) => (
  <button
    type="button"
    className="theme-toggle"
    onClick={() => onChange(NEXT[mode])}
    title={`Theme: ${LABEL[mode]} — click for ${LABEL[NEXT[mode]]}`}
    aria-label={`Theme: ${LABEL[mode]}. Activate to switch to ${LABEL[NEXT[mode]]}.`}
  >
    {ICON[mode]}
    <span>{LABEL[mode]}</span>
  </button>
);
