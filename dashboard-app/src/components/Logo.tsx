import React from 'react';

interface LogoProps {
  /** Height of the mark in px. Wordmark scales with it. */
  size?: number;
  /** Hide the "STEALTH TAP" wordmark, show only the ST badge. */
  markOnly?: boolean;
}

/**
 * Optional real logo asset.
 *
 * Drop your file at  dashboard-app/src/assets/logo.png  (or .svg / .jpg / .webp)
 * and it is picked up automatically — no code change needed. Until then the
 * inline SVG recreation below is used.
 */
const assetMatches = import.meta.glob('../assets/logo.{png,svg,jpg,jpeg,webp}', {
  eager: true,
  query: '?url',
  import: 'default',
}) as Record<string, string>;
const LOGO_URL: string | undefined = Object.values(assetMatches)[0];

export const Logo: React.FC<LogoProps> = ({ size = 30, markOnly = false }) => {
  if (LOGO_URL) {
    return (
      <img
        src={LOGO_URL}
        alt="StealthTap"
        style={{ height: size * 1.4, width: 'auto', display: 'block', objectFit: 'contain' }}
      />
    );
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, color: 'var(--text)', lineHeight: 1 }}>
      <svg width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <defs>
          <linearGradient id="st-badge" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
            <stop stopColor="#FF9B3F" />
            <stop offset="1" stopColor="#F5821F" />
          </linearGradient>
        </defs>
        <rect x="1.5" y="1.5" width="45" height="45" rx="12" fill="url(#st-badge)" />
        <rect x="1.5" y="1.5" width="45" height="45" rx="12" stroke="#ffffff" strokeOpacity="0.25" strokeWidth="1.5" />
        <path
          d="M20.5 15.2c-3.9 0-6.7 1.9-6.7 5 0 2.8 2.1 4 5.6 4.7 2.6.5 3.4 1 3.4 2 0 1.1-1.2 1.8-3.2 1.8-2.2 0-3.7-.8-4.7-2.2l-2.6 2.4c1.6 2.2 4.2 3.4 7.2 3.4 4.2 0 7-2 7-5.2 0-3-2.2-4.1-5.7-4.8-2.5-.5-3.3-.9-3.3-1.9 0-1 1-1.7 2.9-1.7 1.8 0 3.2.7 4.1 1.9l2.6-2.4c-1.5-1.9-3.9-2.9-6.8-2.9Z"
          fill="#ffffff"
        />
        <path d="M27.4 15.6v3.4h4.6v13.2h3.8V19h4.6v-3.4H27.4Z" fill="#ffffff" />
      </svg>
      {!markOnly && (
        <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          <span style={{ fontSize: size * 0.42, fontWeight: 700, letterSpacing: '0.14em', color: 'var(--text)' }}>
            STEALTH
          </span>
          <span className="mono" style={{ fontSize: size * 0.34, fontWeight: 600, letterSpacing: '0.34em', color: 'var(--accent-brand, #F5821F)' }}>
            TAP
          </span>
        </span>
      )}
    </span>
  );
};
