import { useEffect, useState } from 'react';
import { AUTH_EVENT, getApiKey, setApiKey } from '../lib/auth';

/** Asks for the API key when the server answers 401; stores it and reloads so every panel refetches. */
export function AuthGate() {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState('');
  const [bad, setBad] = useState(false);

  useEffect(() => {
    const on = () => { setBad(getApiKey() !== ''); setOpen(true); };
    window.addEventListener(AUTH_EVENT, on);
    return () => window.removeEventListener(AUTH_EVENT, on);
  }, []);

  if (!open) return null;
  return (
    <div role="dialog" aria-modal="true" aria-label="API key required"
      style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'grid', placeItems: 'center', background: 'rgba(0,0,0,.55)' }}>
      <form className="glass" style={{ padding: 24, width: 'min(420px, 92vw)', display: 'grid', gap: 12 }}
        onSubmit={(e) => { e.preventDefault(); setApiKey(value.trim()); window.location.reload(); }}>
        <div style={{ fontSize: 16, fontWeight: 700 }}>API key required</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
          {bad ? 'That key was rejected. ' : ''}Enter the STEALTHTAP_API_KEY configured on the server. It is stored only in this browser.
        </div>
        <input className="pk-input mono" type="password" autoFocus autoComplete="off" placeholder="API key"
          value={value} onChange={(e) => setValue(e.target.value)} />
        <button className="btn-ghost" type="submit" disabled={value.trim().length === 0}>Sign in</button>
      </form>
    </div>
  );
}
