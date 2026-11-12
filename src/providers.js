// @ts-check
// Signature schemes. Each provider has verify(ctx) and sign(opts).
// verify never throws on bad input: it returns { ok: false, reason }.
import { randomUUID } from 'node:crypto';
import { hmacParts, randomNonce, safeEqual, sha256Hex, toBuffer } from './crypto.js';

/**
 * @typedef {{ id: string, client?: string, secret?: string, hash?: string, expiresAt?: number | null, limit?: { points: number, duration: number } | null }} GuardKey
 * @typedef {{ req: any, rawBody: Buffer, keys: GuardKey[], now: number, toleranceSec: number, bindPath?: boolean, publicBaseUrl?: string | null }} VerifyContext
 * @typedef {{ ok: true, key: GuardKey, timestamp?: number | null, nonce?: string | null } | { ok: false, reason: string }} VerifyResult
 */

const MAX_CANDIDATES = 5; // stops "v1=a,v1=b,... x1000" CPU abuse
const TS_RE = /^\d{1,12}$/;

/** @param {any} req @param {string} name */
export function getHeader(req, name) {
  const v = req.headers?.[name.toLowerCase()];
  if (Array.isArray(v)) return v[0];
  return typeof v === 'string' ? v : undefined;
}

/** @param {string} reason @returns {{ ok: false, reason: string }} */
const fail = (reason) => ({ ok: false, reason });
const nowSec = () => Math.floor(Date.now() / 1000);

/** @param {number} ts @param {number} now @param {number} toleranceSec */
export function checkTimestamp(ts, now, toleranceSec) {
  if (!Number.isFinite(ts)) return 'malformed_signature';
  if (Math.abs(now - ts) > toleranceSec) return 'stale_timestamp';
  return null;
}

/** "t=1,v1=abc,v1=def" -> Map { t: ['1'], v1: ['abc','def'] } */
export function parseKv(/** @type {string} */ header) {
  /** @type {Map<string, string[]>} */
  const map = new Map();
  for (const part of header.split(',')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!map.has(k)) map.set(k, []);
    map.get(k)?.push(v);
  }
  return map;
}

/**
 * Try every key (secret rotation). Compares against all candidates without
 * early exit. Keys past expiresAt are reported as key_expired.
 * @param {GuardKey[]} keys
 * @param {number} now seconds
 * @param {(key: GuardKey) => string | null} expectedFor
 * @param {string[]} candidates
 * @returns {{ ok: true, key: GuardKey, signature: string } | { ok: false, reason: string }}
 */
function matchKey(keys, now, expectedFor, candidates) {
  let expiredMatch = false;
  for (const key of keys) {
    const expected = expectedFor(key);
    if (!expected) continue;
    let hit = false;
    for (const c of candidates) if (safeEqual(expected, c)) hit = true;
    if (!hit) continue;
    if (key.expiresAt && key.expiresAt <= now * 1000) {
      expiredMatch = true;
      continue;
    }
    return { ok: true, key, signature: expected };
  }
  return fail(expiredMatch ? 'key_expired' : 'bad_signature');
}

/** Requests path as the client sent it: path + query. */
const requestPath = (/** @type {any} */ req) => req.originalUrl ?? req.url ?? '/';

// ---------------------------------------------------------------------------
// generic: hmac-guard's own scheme for your clients / partners.
// Signs version, timestamp, nonce, method, path and body hash, so a captured
// request cannot be replayed, re-timed, or pointed at another endpoint.
// ---------------------------------------------------------------------------
const generic = {
  name: 'generic',
  timestamped: true,
  description: 'hmac-guard scheme: HMAC-SHA256 over timestamp, nonce, method, path and body hash (X-Guard-* headers)',
  /** @param {{ timestamp: number | string, nonce: string, method: string, path: string, body: Buffer }} p */
  canonical({ timestamp, nonce, method, path, body }) {
    return `v1\n${timestamp}\n${nonce}\n${method.toUpperCase()}\n${path}\n${sha256Hex(body)}`;
  },
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    const { req } = ctx;
    const sig = getHeader(req, 'x-guard-signature');
    const ts = getHeader(req, 'x-guard-timestamp');
    const nonce = getHeader(req, 'x-guard-nonce');
    const kid = getHeader(req, 'x-guard-key-id');
    if (!sig || !ts || !nonce) return fail('missing_signature');
    if (!TS_RE.test(ts) || !/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return fail('malformed_signature');
    const candidates = (parseKv(sig).get('v1') ?? []).map((s) => s.toLowerCase());
    if (!candidates.length || candidates.length > MAX_CANDIDATES) return fail('malformed_signature');
    const tsErr = checkTimestamp(Number(ts), ctx.now, ctx.toleranceSec);
    if (tsErr) return fail(tsErr);
    let keys = ctx.keys;
    if (kid) {
      keys = keys.filter((k) => k.id === kid);
      if (!keys.length) return fail('unknown_key');
    }
    const canonical = generic.canonical({
      timestamp: ts, nonce, method: req.method ?? 'POST',
      path: ctx.bindPath === false ? '' : requestPath(req), body: ctx.rawBody,
    });
    const m = matchKey(keys, ctx.now, (k) => (k.secret ? hmacParts('sha256', k.secret, [canonical]) : null), candidates);
    if (!m.ok) return m;
    return { ok: true, key: m.key, timestamp: Number(ts), nonce: `${m.key.id}:${nonce}` };
  },
  /** @param {any} o */
  sign({ secret, keyId, body, method = 'POST', path = '/', timestamp = nowSec(), nonce = randomNonce() }) {
    const canonical = generic.canonical({ timestamp, nonce, method, path, body: toBuffer(body) });
    /** @type {Record<string, string>} */
    const headers = {
      'X-Guard-Timestamp': String(timestamp),
      'X-Guard-Nonce': nonce,
      'X-Guard-Signature': 'v1=' + hmacParts('sha256', secret, [canonical]),
    };
    if (keyId) headers['X-Guard-Key-Id'] = keyId;
    return headers;
  },
};

// ---------------------------------------------------------------------------
// Stripe: Stripe-Signature: t=<ts>,v1=<hex>  over "<t>.<body>"
// ---------------------------------------------------------------------------
const stripe = {
  name: 'stripe',
  timestamped: true,
  description: 'Stripe webhooks (Stripe-Signature, whsec_ secret)',
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    const h = getHeader(ctx.req, 'stripe-signature');
    if (!h) return fail('missing_signature');
    const kv = parseKv(h);
    const t = kv.get('t')?.[0];
    const v1 = (kv.get('v1') ?? []).map((s) => s.toLowerCase());
    if (!t || !TS_RE.test(t) || !v1.length || v1.length > MAX_CANDIDATES) return fail('malformed_signature');
    const tsErr = checkTimestamp(Number(t), ctx.now, ctx.toleranceSec);
    if (tsErr) return fail(tsErr);
    const m = matchKey(ctx.keys, ctx.now, (k) => (k.secret ? hmacParts('sha256', k.secret, [`${t}.`, ctx.rawBody]) : null), v1);
    if (!m.ok) return m;
    return { ok: true, key: m.key, timestamp: Number(t), nonce: `sig:${m.signature}` };
  },
  /** @param {any} o */
  sign({ secret, body, timestamp = nowSec() }) {
    return { 'Stripe-Signature': `t=${timestamp},v1=${hmacParts('sha256', secret, [`${timestamp}.`, toBuffer(body)])}` };
  },
};

// ---------------------------------------------------------------------------
// GitHub: X-Hub-Signature-256: sha256=<hex> over body. No timestamp, so the
// signature itself is the replay nonce (kept for replayTtlSec).
// ---------------------------------------------------------------------------
const github = {
  name: 'github',
  timestamped: false,
  description: 'GitHub webhooks (X-Hub-Signature-256)',
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    const h = getHeader(ctx.req, 'x-hub-signature-256');
    if (!h) return fail('missing_signature');
    if (!/^sha256=[0-9a-fA-F]{64}$/.test(h)) return fail('malformed_signature');
    const m = matchKey(ctx.keys, ctx.now, (k) => (k.secret ? hmacParts('sha256', k.secret, [ctx.rawBody]) : null), [h.slice(7).toLowerCase()]);
    if (!m.ok) return m;
    return { ok: true, key: m.key, timestamp: null, nonce: `sig:${m.signature}` };
  },
  /** @param {any} o */
  sign({ secret, body }) {
    return {
      'X-Hub-Signature-256': 'sha256=' + hmacParts('sha256', secret, [toBuffer(body)]),
      'X-GitHub-Delivery': randomUUID(),
      'X-GitHub-Event': 'ping',
    };
  },
};

// ---------------------------------------------------------------------------
// Shopify: X-Shopify-Hmac-Sha256: base64 HMAC-SHA256 over body.
// ---------------------------------------------------------------------------
const shopify = {
  name: 'shopify',
  timestamped: false,
  description: 'Shopify webhooks (X-Shopify-Hmac-Sha256, base64)',
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    const h = getHeader(ctx.req, 'x-shopify-hmac-sha256');
    if (!h) return fail('missing_signature');
    if (!/^[A-Za-z0-9+/]{43}=$/.test(h)) return fail('malformed_signature');
    const m = matchKey(ctx.keys, ctx.now, (k) => (k.secret ? hmacParts('sha256', k.secret, [ctx.rawBody], 'base64') : null), [h]);
    if (!m.ok) return m;
    return { ok: true, key: m.key, timestamp: null, nonce: `sig:${m.signature}` };
  },
  /** @param {any} o */
  sign({ secret, body }) {
    return {
      'X-Shopify-Hmac-Sha256': hmacParts('sha256', secret, [toBuffer(body)], 'base64'),
      'X-Shopify-Webhook-Id': randomUUID(),
      'X-Shopify-Topic': 'orders/create',
    };
  },
};

// ---------------------------------------------------------------------------
// Slack: X-Slack-Signature: v0=<hex> over "v0:<ts>:<body>"
// ---------------------------------------------------------------------------
const slack = {
  name: 'slack',
  timestamped: true,
  description: 'Slack Events API / slash commands / interactivity (X-Slack-Signature)',
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    const ts = getHeader(ctx.req, 'x-slack-request-timestamp');
    const sig = getHeader(ctx.req, 'x-slack-signature');
    if (!ts || !sig) return fail('missing_signature');
    if (!TS_RE.test(ts) || !/^v0=[0-9a-fA-F]{64}$/.test(sig)) return fail('malformed_signature');
    const tsErr = checkTimestamp(Number(ts), ctx.now, ctx.toleranceSec);
    if (tsErr) return fail(tsErr);
    const m = matchKey(ctx.keys, ctx.now, (k) => (k.secret ? 'v0=' + hmacParts('sha256', k.secret, [`v0:${ts}:`, ctx.rawBody]) : null), [sig.toLowerCase()]);
    if (!m.ok) return m;
    return { ok: true, key: m.key, timestamp: Number(ts), nonce: `sig:${m.signature}` };
  },
  /** @param {any} o */
  sign({ secret, body, timestamp = nowSec() }) {
    return {
      'X-Slack-Request-Timestamp': String(timestamp),
      'X-Slack-Signature': 'v0=' + hmacParts('sha256', secret, [`v0:${timestamp}:`, toBuffer(body)]),
    };
  },
};

// ---------------------------------------------------------------------------
// Standard Webhooks (Svix, Resend, Clerk, Liveblocks, ...):
// webhook-id / webhook-timestamp / webhook-signature: "v1,<base64> v1,<base64>"
// over "<id>.<ts>.<body>", secret "whsec_<base64>".
// ---------------------------------------------------------------------------
/** @param {string} secret */
const whsecKey = (secret) => (secret.startsWith('whsec_') ? Buffer.from(secret.slice(6), 'base64') : Buffer.from(secret, 'utf8'));

const standard = {
  name: 'standard',
  timestamped: true,
  description: 'Standard Webhooks / Svix / Resend / Clerk (webhook-id, webhook-timestamp, webhook-signature)',
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    const { req } = ctx;
    const id = getHeader(req, 'webhook-id') ?? getHeader(req, 'svix-id');
    const ts = getHeader(req, 'webhook-timestamp') ?? getHeader(req, 'svix-timestamp');
    const sig = getHeader(req, 'webhook-signature') ?? getHeader(req, 'svix-signature');
    if (!id || !ts || !sig) return fail('missing_signature');
    if (!TS_RE.test(ts) || id.length > 256) return fail('malformed_signature');
    const candidates = sig.split(' ').map((s) => s.trim()).filter((s) => s.startsWith('v1,')).map((s) => s.slice(3));
    if (!candidates.length || candidates.length > MAX_CANDIDATES) return fail('malformed_signature');
    const tsErr = checkTimestamp(Number(ts), ctx.now, ctx.toleranceSec);
    if (tsErr) return fail(tsErr);
    const m = matchKey(ctx.keys, ctx.now, (k) => (k.secret ? hmacParts('sha256', whsecKey(k.secret), [`${id}.${ts}.`, ctx.rawBody], 'base64') : null), candidates);
    if (!m.ok) return m;
    return { ok: true, key: m.key, timestamp: Number(ts), nonce: `id:${id}` };
  },
  /** @param {any} o */
  sign({ secret, body, timestamp = nowSec(), id = 'msg_' + randomNonce(12) }) {
    return {
      'webhook-id': id,
      'webhook-timestamp': String(timestamp),
      'webhook-signature': 'v1,' + hmacParts('sha256', whsecKey(secret), [`${id}.${timestamp}.`, toBuffer(body)], 'base64'),
    };
  },
};

// ---------------------------------------------------------------------------
// Twilio (SMS, WhatsApp, Voice): X-Twilio-Signature: base64 HMAC-SHA1 over
// full URL + sorted form params. JSON bodies are covered by ?bodySHA256=.
// ---------------------------------------------------------------------------
/** @param {string} url @param {Buffer} body @param {string} contentType */
function twilioData(url, body, contentType) {
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const params = [...new URLSearchParams(body.toString('utf8'))];
    params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
    return url + params.map(([k, v]) => k + v).join('');
  }
  return url;
}

const twilio = {
  name: 'twilio',
  timestamped: false,
  description: 'Twilio SMS / WhatsApp / Voice webhooks (X-Twilio-Signature). Set publicBaseUrl behind a proxy.',
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    const { req } = ctx;
    const sig = getHeader(req, 'x-twilio-signature');
    if (!sig) return fail('missing_signature');
    if (!/^[A-Za-z0-9+/]{27}=$/.test(sig)) return fail('malformed_signature');
    const base = ctx.publicBaseUrl
      ? ctx.publicBaseUrl.replace(/\/$/, '')
      : `${req.protocol ?? 'http'}://${getHeader(req, 'host') ?? 'localhost'}`;
    const url = base + requestPath(req);
    const ct = getHeader(req, 'content-type') ?? '';
    if (!ct.includes('application/x-www-form-urlencoded')) {
      // JSON bodies are only protected when Twilio adds bodySHA256 to the URL.
      const bodyHash = new URL(url).searchParams.get('bodySHA256');
      if (!bodyHash) return fail('malformed_signature');
      if (!safeEqual(bodyHash.toLowerCase(), sha256Hex(ctx.rawBody))) return fail('bad_signature');
    }
    const data = twilioData(url, ctx.rawBody, ct);
    const m = matchKey(ctx.keys, ctx.now, (k) => (k.secret ? hmacParts('sha1', k.secret, [data], 'base64') : null), [sig]);
    if (!m.ok) return m;
    return { ok: true, key: m.key, timestamp: null, nonce: `sig:${m.signature}` };
  },
  /** @param {any} o */
  sign({ secret, body, url, contentType = 'application/x-www-form-urlencoded' }) {
    return { 'X-Twilio-Signature': hmacParts('sha1', secret, [twilioData(url, toBuffer(body), contentType)], 'base64') };
  },
};

// ---------------------------------------------------------------------------
// API key: X-API-Key or Authorization: Bearer. Keys stored as sha256 hashes.
// No replay protection by design - use HMAC schemes for webhooks.
// ---------------------------------------------------------------------------
const apikey = {
  name: 'apikey',
  timestamped: false,
  description: 'Static API key (X-API-Key or Authorization: Bearer), stored hashed',
  /** @param {VerifyContext} ctx @returns {VerifyResult} */
  verify(ctx) {
    let presented = getHeader(ctx.req, 'x-api-key');
    const auth = getHeader(ctx.req, 'authorization');
    if (!presented && auth && /^Bearer /i.test(auth)) presented = auth.slice(7).trim();
    if (!presented) return fail('missing_api_key');
    if (presented.length > 256) return fail('malformed_signature');
    const digest = sha256Hex(presented);
    const m = matchKey(ctx.keys, ctx.now, (k) => (k.hash ? k.hash.replace(/^sha256:/, '').toLowerCase() : k.secret ? sha256Hex(k.secret) : null), [digest]);
    if (!m.ok) return m.reason === 'bad_signature' ? fail('bad_api_key') : m;
    return { ok: true, key: m.key, timestamp: null, nonce: null };
  },
  /** @param {any} o */
  sign({ secret }) {
    return { 'X-API-Key': secret };
  },
};

export const providers = { generic, stripe, github, shopify, slack, standard, twilio, apikey };
const aliases = { svix: 'standard', 'standard-webhooks': 'standard', resend: 'standard', clerk: 'standard', whatsapp: 'twilio', 'api-key': 'apikey', hmac: 'generic' };

/** @param {string} name */
export function getProvider(name) {
  const key = String(name ?? '').toLowerCase();
  // @ts-ignore - index by string
  const p = providers[key] ?? providers[aliases[key]];
  if (!p) throw new Error(`Unknown provider "${name}". Use one of: ${Object.keys(providers).join(', ')} (aliases: ${Object.keys(aliases).join(', ')})`);
  return p;
}

export const providerNames = () => Object.keys(providers);
