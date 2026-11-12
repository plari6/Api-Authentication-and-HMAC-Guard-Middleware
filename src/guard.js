// @ts-check
// The guard middleware. Checks run cheapest first, so a flood is dropped
// before the body is read or any HMAC is computed:
//
//   1. IP deny/allow list            403 ip_denied
//   2. IP banned for failed auth     429 ip_banned
//   3. Per-IP rate limit             429 rate_limited_ip
//   4. Global rate limit             503 rate_limited_global
//   5. Method / content type / size  405 / 415 / 413
//   6. Read raw body (limit+timeout) 413 body_too_large / 408 body_timeout
//   7. Signature + timestamp         401 (counts toward the IP ban)
//   8. Replay (nonce seen before)    409 replay
//   9. Per-client rate limit         429 rate_limited_client
//  10. Parse body, attach req.guard, next()
import { BlockList, isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { Audit } from './audit.js';
import { sha256Hex } from './crypto.js';
import { DEFAULT_LIMITS, consume, createLimiter, isBlocked } from './limiters.js';
import { MemoryNonceStore, RedisNonceStore } from './nonce-store.js';
import { getProvider } from './providers.js';

/** reason -> [HTTP status, public message] */
export const REASONS = {
  ip_denied: [403, 'Requests from this IP address are not allowed.'],
  ip_banned: [429, 'Too many failed authentication attempts. Try again later.'],
  rate_limited_ip: [429, 'Too many requests from this IP address.'],
  rate_limited_global: [503, 'Service is busy. Retry later.'],
  rate_limited_client: [429, 'Client rate limit exceeded.'],
  method_not_allowed: [405, 'Method not allowed.'],
  unsupported_media_type: [415, 'Unsupported content type.'],
  body_too_large: [413, 'Request body is too large.'],
  body_timeout: [408, 'Request body was not received in time.'],
  missing_signature: [401, 'Missing signature headers.'],
  malformed_signature: [401, 'Malformed signature headers.'],
  unknown_key: [401, 'Unknown key id.'],
  key_expired: [401, 'This key has expired. Use the current key.'],
  stale_timestamp: [401, 'Timestamp is outside the allowed window. Check the sender clock.'],
  bad_signature: [401, 'Signature does not match.'],
  missing_api_key: [401, 'Missing API key.'],
  bad_api_key: [401, 'Invalid API key.'],
  replay: [409, 'This request was already received (replay).'],
  invalid_body: [400, 'Body could not be parsed.'],
  not_found: [404, 'Not found.'],
  replay_store_unavailable: [503, 'Replay protection store unavailable.'],
  guard_error: [500, 'Internal error.'],
};

export const AUTH_FAILURES = new Set([
  'missing_signature', 'malformed_signature', 'unknown_key', 'key_expired',
  'stale_timestamp', 'bad_signature', 'missing_api_key', 'bad_api_key',
]);

/** "::ffff:1.2.3.4" -> "1.2.3.4" */
export function normalizeIp(/** @type {string | undefined} */ ip) {
  if (!ip) return '';
  if (ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4) return ip.slice(7);
  return ip;
}

/** @param {string[] | null | undefined} entries IPs or CIDRs, v4 or v6 */
export function buildIpList(entries) {
  if (!entries || !entries.length) return null;
  const list = new BlockList();
  for (const raw of entries) {
    const [addr, bits] = String(raw).trim().split('/');
    const fam = isIP(addr);
    if (!fam) throw new Error(`Invalid IP or CIDR: "${raw}"`);
    const type = fam === 6 ? 'ipv6' : 'ipv4';
    if (bits !== undefined) {
      const n = Number(bits);
      if (!Number.isInteger(n) || n < 0 || n > (fam === 6 ? 128 : 32)) throw new Error(`Invalid CIDR prefix: "${raw}"`);
      list.addSubnet(addr, n, type);
    } else list.addAddress(addr, type);
  }
  return list;
}

/** @param {BlockList} list @param {string} ip */
export function ipIn(list, ip) {
  const fam = isIP(ip);
  return fam ? list.check(ip, fam === 6 ? 'ipv6' : 'ipv4') : false;
}

/**
 * State shared by every route of one gateway (limiters, replay store, audit).
 * @param {{ limits?: any, redis?: any, nonceStore?: any, audit?: Audit, ipAllow?: string[], ipDeny?: string[], exposeReasons?: boolean }} [opts]
 */
export function createShared({ limits = DEFAULT_LIMITS, redis = null, nonceStore, audit, ipAllow, ipDeny, exposeReasons = true } = {}) {
  return {
    limits,
    limiters: {
      ip: createLimiter(limits.ip, { redis, keyPrefix: 'hg_ip' }),
      global: createLimiter(limits.global, { redis, keyPrefix: 'hg_global' }),
      failedAuth: createLimiter(limits.failedAuth, { redis, keyPrefix: 'hg_fail' }),
    },
    /** @type {Map<string, any>} */
    clientLimiters: new Map(),
    nonceStore: nonceStore ?? (redis ? new RedisNonceStore(redis) : new MemoryNonceStore()),
    audit: audit ?? new Audit(),
    allow: buildIpList(ipAllow),
    deny: buildIpList(ipDeny),
    exposeReasons,
    redis,
  };
}

/**
 * Steps 1-4: cheap checks that need nothing but the IP.
 * @param {ReturnType<typeof createShared>} shared
 * @param {string} ip
 * @returns {Promise<{ reason: string, retryAfterSec?: number } | null>}
 */
export async function preGate(shared, ip) {
  if (shared.deny && ipIn(shared.deny, ip)) return { reason: 'ip_denied' };
  if (shared.allow && !ipIn(shared.allow, ip)) return { reason: 'ip_denied' };
  const { failedAuth, ip: ipLimiter, global } = shared.limiters;
  if (failedAuth) {
    const b = await isBlocked(failedAuth, ip);
    if (b.blocked) return { reason: 'ip_banned', retryAfterSec: b.retryAfterSec };
  }
  if (ipLimiter) {
    const r = await consume(ipLimiter, ip);
    if (!r.ok) return { reason: 'rate_limited_ip', retryAfterSec: r.retryAfterSec };
  }
  if (global) {
    const r = await consume(global, 'global');
    if (!r.ok) return { reason: 'rate_limited_global', retryAfterSec: r.retryAfterSec };
  }
  return null;
}

/**
 * Read the raw body with a byte limit and a timeout (slow-body attacks).
 * @param {any} req @param {number} limit @param {number} timeoutMs
 * @returns {Promise<Buffer>}
 */
export function readRawBody(req, limit, timeoutMs) {
  if (Buffer.isBuffer(req.rawBody)) {
    if (req.rawBody.length > limit) return Promise.reject(Object.assign(new Error('too large'), { reason: 'body_too_large' }));
    return Promise.resolve(req.rawBody);
  }
  if (req.readableEnded || req._body) {
    return Promise.reject(new Error('The request body was already consumed by another body parser. Mount hmac-guard before express.json(), or use express.json({ verify: captureRawBody }).'));
  }
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */ const chunks = [];
    let size = 0;
    let done = false;
    const finish = (/** @type {any} */ err, /** @type {any} */ val = undefined) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('aborted', onAbort);
      if (err) reject(err);
      else resolve(val);
    };
    const onData = (/** @type {Buffer} */ c) => {
      size += c.length;
      if (size > limit) return finish(Object.assign(new Error('too large'), { reason: 'body_too_large' }));
      chunks.push(c);
    };
    const onEnd = () => finish(null, Buffer.concat(chunks, size));
    const onAbort = () => finish(Object.assign(new Error('aborted'), { reason: 'body_timeout' }));
    const timer = setTimeout(() => finish(Object.assign(new Error('timeout'), { reason: 'body_timeout' })), timeoutMs);
    req.on('error', (/** @type {Error} */ e) => finish(e)); // stays attached: no unhandled 'error' later
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('aborted', onAbort);
  });
}

/** For apps that must run express.json() first: express.json({ verify: captureRawBody }) */
export function captureRawBody(/** @type {any} */ req, /** @type {any} */ _res, /** @type {Buffer} */ buf) {
  req.rawBody = Buffer.from(buf);
}

/** @param {Buffer} raw @param {string} ct */
function parseBody(raw, ct) {
  if (!raw.length) return undefined;
  if (ct === 'application/json' || ct.endsWith('+json')) return JSON.parse(raw.toString('utf8'));
  if (ct === 'application/x-www-form-urlencoded') return Object.fromEntries(new URLSearchParams(raw.toString('utf8')));
  if (ct.startsWith('text/')) return raw.toString('utf8');
  return raw;
}

/** @param {any[]} keys */
function normalizeKeys(keys) {
  return keys.map((k, i) => {
    if (typeof k === 'string') return { id: `key${i + 1}`, secret: k };
    const expiresAt = k.expiresAt ? (typeof k.expiresAt === 'number' ? k.expiresAt : Date.parse(k.expiresAt)) : null;
    if (k.expiresAt && !Number.isFinite(expiresAt)) throw new Error(`Key "${k.id}": invalid expiresAt "${k.expiresAt}"`);
    return { id: String(k.id ?? `key${i + 1}`), client: k.client, secret: k.secret, hash: k.hash, expiresAt, limit: k.limit ?? null };
  });
}

/**
 * Create the guard middleware for one route.
 *
 * @param {{
 *   name?: string, provider?: string, secret?: string, keys?: any[],
 *   methods?: string[], contentTypes?: string[] | null, maxBodyBytes?: number, bodyTimeoutMs?: number,
 *   toleranceSec?: number, replayTtlSec?: number, bindPath?: boolean, publicBaseUrl?: string | null,
 *   ipAllow?: string[], ipDeny?: string[], limits?: any, redis?: any, nonceStore?: any, audit?: Audit,
 *   exposeReasons?: boolean, parseBody?: boolean,
 *   onReject?: (info: { reason: string, status: number, ip: string, route: string, client?: string }, req: any) => void,
 *   onAllow?: (guard: any, req: any) => void,
 * }} route
 * @param {ReturnType<typeof createShared>} [shared]
 */
export function createGuard(route, shared) {
  const provider = getProvider(route.provider ?? 'generic');
  const name = route.name ?? provider.name;
  const keys = normalizeKeys(route.keys ?? (route.secret ? [{ id: 'default', secret: route.secret }] : []));
  if (!keys.length) throw new Error(`Route "${name}": at least one key (secret) is required.`);
  for (const k of keys) {
    if (!k.secret && !(provider.name === 'apikey' && k.hash)) throw new Error(`Route "${name}": key "${k.id}" has no secret.`);
  }

  // Library use: a single route gets its own shared state.
  const sh = shared ?? createShared({
    limits: { ...DEFAULT_LIMITS, ...(route.limits ?? {}) },
    redis: route.redis, nonceStore: route.nonceStore, audit: route.audit, exposeReasons: route.exposeReasons,
  });
  const methods = (route.methods ?? ['POST']).map((m) => m.toUpperCase());
  const contentTypes = route.contentTypes?.length ? route.contentTypes.map((c) => c.toLowerCase()) : null;
  const maxBodyBytes = route.maxBodyBytes ?? 1_048_576;
  const bodyTimeoutMs = route.bodyTimeoutMs ?? 10_000;
  const toleranceSec = route.toleranceSec ?? 300;
  const replayTtlSec = route.replayTtlSec ?? 86_400;
  const routeAllow = buildIpList(route.ipAllow);
  const routeDeny = buildIpList(route.ipDeny);
  const clientLimitDefault = route.limits?.client ?? sh.limits.client;
  const shouldParse = route.parseBody !== false;

  /** @param {any} key */
  function clientLimiter(key) {
    const cfg = key.limit ?? clientLimitDefault;
    if (!cfg) return null;
    const id = `${name}|${cfg.points}|${cfg.duration ?? 1}|${cfg.blockDuration ?? 0}`;
    let l = sh.clientLimiters.get(id);
    if (!l) {
      l = createLimiter(cfg, { redis: sh.redis, keyPrefix: `hg_client_${sha256Hex(id).slice(0, 10)}` });
      sh.clientLimiters.set(id, l);
    }
    return l;
  }

  return async function hmacGuard(/** @type {any} */ req, /** @type {any} */ res, /** @type {any} */ next) {
    const t0 = performance.now();
    const ip = normalizeIp(req.ip ?? req.socket?.remoteAddress);
    const base = { route: name, ip, method: req.method, path: req.originalUrl ?? req.url, requestId: req.id };
    const ms = () => Math.round((performance.now() - t0) * 10) / 10;

    /** @param {string} reason @param {{ retryAfterSec?: number, client?: string, drain?: boolean, error?: string }} [extra] */
    const reject = (reason, extra = {}) => {
      // @ts-ignore
      const [status, message] = REASONS[reason] ?? [400, reason];
      if (extra.retryAfterSec) res.setHeader('Retry-After', String(extra.retryAfterSec));
      if (extra.drain) {
        const declared = Number(req.headers['content-length']);
        // Small overflow: drain so the client can read the 413. Huge: just close.
        if (Number.isFinite(declared) && declared > maxBodyBytes * 8) res.setHeader('Connection', 'close');
      }
      sh.audit.record({ ...base, outcome: 'rejected', reason, status, client: extra.client, ms: ms() });
      try { route.onReject?.({ reason, status, ip, route: name, client: extra.client }, req); } catch { /* hook errors never break the guard */ }
      res.status(status).json(sh.exposeReasons ? { error: reason, message } : { error: status >= 500 ? 'unavailable' : 'rejected' });
      if (extra.drain) req.resume?.();
    };

    try {
      const gate = await preGate(sh, ip);
      if (gate) return reject(gate.reason, gate);
      if ((routeDeny && ipIn(routeDeny, ip)) || (routeAllow && !ipIn(routeAllow, ip))) return reject('ip_denied');
      if (!methods.includes(req.method)) {
        res.setHeader('Allow', methods.join(', '));
        return reject('method_not_allowed');
      }
      const ct = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
      if (contentTypes && !contentTypes.includes(ct)) return reject('unsupported_media_type');
      if (Number(req.headers['content-length']) > maxBodyBytes) return reject('body_too_large', { drain: true });

      /** @type {Buffer} */
      let rawBody;
      try {
        rawBody = await readRawBody(req, maxBodyBytes, bodyTimeoutMs);
      } catch (e) {
        if (/** @type {any} */ (e).reason) return reject(/** @type {any} */ (e).reason, { drain: true });
        throw e;
      }

      const result = provider.verify({
        req, rawBody, keys, now: Math.floor(Date.now() / 1000), toleranceSec,
        bindPath: route.bindPath !== false, publicBaseUrl: route.publicBaseUrl ?? null,
      });
      if (!result.ok) {
        if (sh.limiters.failedAuth && AUTH_FAILURES.has(result.reason)) await consume(sh.limiters.failedAuth, ip);
        return reject(result.reason);
      }

      const key = result.key;
      const client = key.client ?? key.id;
      if (result.nonce) {
        const ttlSec = provider.timestamped ? toleranceSec * 2 + 60 : replayTtlSec;
        let fresh;
        try {
          fresh = await sh.nonceStore.checkAndSet(`${name}:${sha256Hex(result.nonce).slice(0, 40)}`, ttlSec * 1000);
        } catch (e) {
          return reject('replay_store_unavailable', { client, error: /** @type {Error} */ (e).message });
        }
        if (!fresh) return reject('replay', { client });
      }

      const cl = clientLimiter(key);
      if (cl) {
        const r = await consume(cl, client);
        if (!r.ok) return reject('rate_limited_client', { client, retryAfterSec: r.retryAfterSec });
      }

      req.rawBody = rawBody;
      if (shouldParse) {
        try {
          req.body = parseBody(rawBody, ct);
        } catch {
          return reject('invalid_body', { client });
        }
      }
      req.guard = {
        route: name, provider: provider.name, client, keyId: key.id,
        timestamp: result.timestamp ?? null, verifiedAt: new Date().toISOString(),
      };
      sh.audit.record({ ...base, outcome: 'allowed', status: null, client, keyId: key.id, ms: ms() });
      try { route.onAllow?.(req.guard, req); } catch { /* ignore hook errors */ }
      return next();
    } catch (err) {
      console.error(`[hmac-guard] ${name}: ${/** @type {Error} */ (err).stack ?? err}`);
      if (!res.headersSent) return reject('guard_error');
    }
  };
}

/**
 * Convenience for existing Express apps:
 *   app.post('/webhooks/stripe', hmacGuard({ provider: 'stripe', secret: process.env.STRIPE_WEBHOOK_SECRET }), handler)
 * @param {Parameters<typeof createGuard>[0]} options
 */
export const hmacGuard = (options) => createGuard(options);
