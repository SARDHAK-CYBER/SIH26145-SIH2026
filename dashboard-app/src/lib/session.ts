import { useEffect, useState } from 'react';
import { auth } from '../api/client';

export type Role = 'viewer' | 'analyst' | 'sensor' | 'admin' | 'unknown';
export interface Session { role: Role; user: string | null; mfa: boolean; ready: boolean }

let cached: Session | null = null;
let inflight: Promise<Session> | null = null;

function load(): Promise<Session> {
  if (cached) return Promise.resolve(cached);
  inflight ??= auth.me()
    .then((m) => ({ role: (m.role ?? 'unknown') as Role, user: m.user, mfa: !!m.mfa, ready: true }))
    // no credential / auth disabled / server unreachable: do not hide anything (the server still enforces every rule)
    .catch(() => ({ role: 'unknown' as Role, user: null, mfa: false, ready: true }))
    .then((s) => (cached = s));
  return inflight;
}

/** What the signed-in user's role may do. Purely a convenience: the API returns 403 for anything not allowed. */
export function can(role: Role, action: 'upload' | 'capture'): boolean {
  if (role === 'unknown' || role === 'admin') return true;
  if (action === 'upload') return role === 'analyst';
  return false;   // starting/stopping capture, replay and discovery are admin-only
}

export function useSession(): Session {
  const [s, setS] = useState<Session>(cached ?? { role: 'unknown', user: null, mfa: false, ready: false });
  useEffect(() => { let dead = false; load().then((v) => { if (!dead) setS(v); }); return () => { dead = true; }; }, []);
  return s;
}
