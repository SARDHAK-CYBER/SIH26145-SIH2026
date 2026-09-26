import { useEffect, useState } from 'react';
import { AUTH_EVENT, getApiKey, setApiKey } from '../lib/auth';
import { auth } from '../api/client';

/** Asks for credentials when the server answers 401: a named-user login (username + password -> signed token) or, for
 *  automation and first-time setup, the shared API key. Whatever is accepted is kept only in this browser. */
export function AuthGate() {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<'user' | 'key'>('user');
  const [user, setUser] = useState('');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const on = () => { setError(getApiKey() !== '' ? 'Your session is not accepted (expired, revoked or wrong credentials).' : null); setOpen(true); };
    window.addEventListener(AUTH_EVENT, on);
    return () => window.removeEventListener(AUTH_EVENT, on);
  }, []);

  if (!open) return null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      if (mode === 'user') {
        const r = await auth.login(user.trim(), secret);
        setApiKey(r.token);
      } else {
        setApiKey(secret.trim());
      }
      window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'sign-in failed');
      setBusy(false);
    }
  }

  const ready = secret.trim().length > 0 && (mode === 'key' || user.trim().length > 0);
  return (
    <div role="dialog" aria-modal="true" aria-label="Sign in"
      style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'grid', placeItems: 'center', background: 'rgba(0,0,0,.55)' }}>
      <form className="glass" style={{ padding: 24, width: 'min(420px, 92vw)', display: 'grid', gap: 12 }} onSubmit={submit}>
        <div style={{ fontSize: 16, fontWeight: 700 }}>Sign in</div>
        {error && <div role="alert" style={{ fontSize: 12, color: 'var(--sev-critical)', lineHeight: 1.5 }}>{error}</div>}
        {mode === 'user' && (
          <input className="pk-input" autoFocus autoComplete="username" placeholder="Username" value={user} onChange={(e) => setUser(e.target.value)} />
        )}
        <input className="pk-input mono" type="password" autoComplete={mode === 'user' ? 'current-password' : 'off'}
          placeholder={mode === 'user' ? 'Password' : 'API key'} value={secret} onChange={(e) => setSecret(e.target.value)} />
        <button className="btn-ghost" type="submit" disabled={!ready || busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <button type="button" className="btn-ghost" style={{ fontSize: 11, opacity: 0.8 }}
          onClick={() => { setMode(mode === 'user' ? 'key' : 'user'); setSecret(''); setError(null); }}>
          {mode === 'user' ? 'Use an API key instead' : 'Use a username and password'}
        </button>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
          The credential is stored only in this browser. A user session ends after 8 hours or when an administrator removes the account.
        </div>
      </form>
    </div>
  );
}
