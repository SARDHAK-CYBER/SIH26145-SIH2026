/** API-key handling. The key lives in this browser's localStorage and is attached to every request to the API / sensor. */
const KEY = 'stealthtap-api-key';
export const AUTH_EVENT = 'stealthtap-auth-required';

export function getApiKey(): string {
  try { return localStorage.getItem(KEY) ?? ''; } catch { return ''; }
}
export function setApiKey(k: string): void {
  try { if (k) localStorage.setItem(KEY, k); else localStorage.removeItem(KEY); } catch { /* storage blocked */ }
}
/** EventSource / <a download> cannot send headers, so those URLs carry the key as ?api_key= (the server accepts it there only). */
export function withKey(url: string): string {
  const k = getApiKey();
  if (!k) return url;
  return url + (url.includes('?') ? '&' : '?') + 'api_key=' + encodeURIComponent(k);
}

let installed = false;
/** Wrap window.fetch once: add X-API-Key to requests aimed at the API/sensor, and ask for a key when one answers 401. */
export function installAuthFetch(isApiUrl: (url: string) => boolean): void {
  if (installed) return;
  installed = true;
  const orig = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const key = getApiKey();
    if (key && isApiUrl(url)) {
      const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
      if (!headers.has('X-API-Key')) headers.set('X-API-Key', key);
      init = { ...init, headers };
    }
    const resp = await orig(input, init);
    if (resp.status === 401 && isApiUrl(url)) window.dispatchEvent(new Event(AUTH_EVENT));
    return resp;
  };
}
