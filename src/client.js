// @ts-check
// Client side: sign and send requests the guard will accept. Give this (or the
// Python / curl versions in examples/) to the client's partners.
import { toBuffer } from './crypto.js';
import { getProvider } from './providers.js';

/**
 * Build the signature headers for a request.
 * @param {{ provider?: string, secret: string, keyId?: string, url: string, method?: string, body?: any,
 *   contentType?: string, timestamp?: number, nonce?: string, bindPath?: boolean }} o
 * @returns {Record<string, string>}
 */
export function signRequest(o) {
  const p = getProvider(o.provider ?? 'generic');
  const u = new URL(o.url);
  /** @type {any} */
  const opts = {
    secret: o.secret, keyId: o.keyId, body: toBuffer(o.body), method: o.method ?? 'POST',
    path: o.bindPath === false ? '' : u.pathname + u.search, url: o.url,
    contentType: o.contentType ?? 'application/json',
  };
  if (o.timestamp !== undefined) opts.timestamp = o.timestamp;
  if (o.nonce !== undefined) opts.nonce = o.nonce;
  return p.sign(opts);
}

/**
 * Sign and send. Returns status, headers, parsed body and latency.
 * @param {Parameters<typeof signRequest>[0] & { headers?: Record<string, string>, timeoutMs?: number }} o
 */
export async function sendSigned(o) {
  const body = toBuffer(o.body);
  const contentType = o.contentType ?? 'application/json';
  const headers = { 'content-type': contentType, ...signRequest({ ...o, body, contentType }), ...(o.headers ?? {}) };
  const t0 = performance.now();
  const r = await fetch(o.url, {
    method: o.method ?? 'POST',
    headers,
    body: ['GET', 'HEAD'].includes((o.method ?? 'POST').toUpperCase()) ? undefined : body,
    signal: AbortSignal.timeout(o.timeoutMs ?? 15_000),
  });
  const text = await r.text();
  let parsed = text;
  try { parsed = JSON.parse(text); } catch { /* keep text */ }
  return { status: r.status, headers: Object.fromEntries(r.headers), body: parsed, ms: Math.round(performance.now() - t0), sentHeaders: headers };
}
