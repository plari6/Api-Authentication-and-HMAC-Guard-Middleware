// @ts-check
// Webhook gateway: one public endpoint per route, guarded, then forwarded to
// the private upstream (n8n, Make, Zapier, your API) or acknowledged.
import { randomUUID } from 'node:crypto';
import { appendFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname } from 'node:path';
import express from 'express';
import { Audit } from './audit.js';
import { REASONS, createGuard, createShared, normalizeIp, preGate } from './guard.js';
import { providers } from './providers.js';

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'host', 'content-length', 'expect',
]);
const sleep = (/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms));

export class Forwarder {
  /** @param {{ deadLetterFile?: string | null, logger?: Console }} [opts] */
  constructor({ deadLetterFile = null, logger = console } = {}) {
    this.deadLetterFile = deadLetterFile;
    this.logger = logger;
    /** @type {Set<Promise<void>>} */
    this.pending = new Set();
    this.stats = { delivered: 0, retried: 0, deadLettered: 0 };
  }

  /** Snapshot of what to send; the request object may be gone in async mode. @param {any} route @param {any} req */
  snapshot(route, req) {
    /** @type {Record<string, string>} */
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (HOP_BY_HOP.has(k) || k.startsWith('x-guard-') || v === undefined) continue;
      headers[k] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    const ip = normalizeIp(req.ip ?? req.socket?.remoteAddress);
    headers['x-forwarded-for'] = headers['x-forwarded-for'] ? `${headers['x-forwarded-for']}, ${ip}` : ip;
    // Set by the gateway only (incoming x-guard-* headers were stripped above).
    headers['x-guard-verified'] = 'true';
    headers['x-guard-route'] = route.name;
    headers['x-guard-client'] = req.guard?.client ?? '';
    headers['x-guard-request-id'] = req.id;
    for (const [k, v] of Object.entries(route.forward.headers ?? {})) headers[k.toLowerCase()] = String(v);
    const body = req.rawBody ?? Buffer.alloc(0);
    if (route.forward.secret) {
      // Defense in depth: the upstream can verify the call came from this gateway.
      const u = new URL(route.forward.url);
      const signed = providers.generic.sign({ secret: route.forward.secret, keyId: 'gateway', body, method: req.method, path: u.pathname + u.search });
      for (const [k, v] of Object.entries(signed)) headers[k.toLowerCase()] = v;
    }
    return { id: req.id, route: route.name, url: route.forward.url, method: req.method, headers, body };
  }

  /** @param {ReturnType<Forwarder['snapshot']>} job @param {number} timeoutMs */
  send(job, timeoutMs) {
    const hasBody = !['GET', 'HEAD'].includes(job.method);
    return fetch(job.url, {
      method: job.method,
      headers: job.headers,
      body: hasBody ? job.body : undefined,
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'manual',
    });
  }

  /** Wait for the upstream and pass its answer back. @param {any} route @param {any} req @param {any} res */
  async forwardSync(route, req, res) {
    const job = this.snapshot(route, req);
    try {
      const r = await this.send(job, route.forward.timeoutMs);
      const buf = Buffer.from(await r.arrayBuffer());
      this.stats.delivered++;
      const ct = r.headers.get('content-type');
      if (ct) res.setHeader('Content-Type', ct);
      res.status(r.status).send(buf);
    } catch (e) {
      const timeout = /** @type {Error} */ (e).name === 'TimeoutError';
      this.logger.error(`[hmac-guard] ${route.name}: upstream ${timeout ? 'timeout' : 'error'}: ${/** @type {Error} */ (e).message}`);
      res.status(timeout ? 504 : 502).json({ error: timeout ? 'upstream_timeout' : 'upstream_unreachable', requestId: req.id });
    }
  }

  /** Answer 202 at once (webhook senders want <1 s), deliver in the background with retries. @param {any} route @param {any} req @param {any} res */
  forwardAsync(route, req, res) {
    const job = this.snapshot(route, req);
    res.status(202).json({ accepted: true, requestId: req.id });
    const p = this.deliverWithRetry(route, job).finally(() => this.pending.delete(p));
    this.pending.add(p);
  }

  /** @param {any} route @param {ReturnType<Forwarder['snapshot']>} job */
  async deliverWithRetry(route, job) {
    const retries = route.forward.retries ?? 4;
    let last = '';
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (attempt > 0) {
        this.stats.retried++;
        const backoff = Math.min(30_000, (route.forward.retryBaseMs ?? 1000) * 2 ** (attempt - 1));
        await sleep(backoff * (0.8 + Math.random() * 0.4));
      }
      try {
        const r = await this.send(job, route.forward.timeoutMs);
        await r.arrayBuffer().catch(() => null);
        if (r.ok) { this.stats.delivered++; return; }
        last = `HTTP ${r.status}`;
        if (r.status < 500 && r.status !== 429 && r.status !== 408) break; // upstream rejected it: retrying won't help
      } catch (e) {
        last = /** @type {Error} */ (e).message;
      }
    }
    await this.deadLetter(job, last);
  }

  /** @param {ReturnType<Forwarder['snapshot']>} job @param {string} error */
  async deadLetter(job, error) {
    this.stats.deadLettered++;
    this.logger.error(`[hmac-guard] ${job.route}: delivery failed (${error}), request ${job.id} saved to dead-letter file`);
    if (!this.deadLetterFile) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(), requestId: job.id, route: job.route, url: job.url, method: job.method,
      error, headers: job.headers, bodyBase64: job.body.toString('base64'),
    });
    try {
      await mkdir(dirname(this.deadLetterFile), { recursive: true });
      await appendFile(this.deadLetterFile, line + '\n');
    } catch (e) {
      this.logger.error(`[hmac-guard] could not write dead-letter file: ${/** @type {Error} */ (e).message}`);
    }
  }

  /** Wait for background deliveries (bounded). */
  async drain(timeoutMs = 10_000) {
    if (!this.pending.size) return;
    await Promise.race([Promise.allSettled([...this.pending]), sleep(timeoutMs)]);
  }
}

/**
 * Build the Express app from a normalized config (see config.js).
 * @param {any} config
 * @param {{ logger?: Console, redisClient?: any, audit?: Audit }} [opts]
 */
export async function createGateway(config, { logger = console, redisClient, audit } = {}) {
  let redis = redisClient ?? null;
  let ownRedis = false;
  if (!redis && config.redis?.url) {
    let Redis;
    try {
      // @ts-ignore - optional dependency
      Redis = (await import('ioredis')).default;
    } catch {
      throw new Error('redis.url is set but the ioredis package is not installed. Run: npm i ioredis');
    }
    redis = new Redis(config.redis.url, { enableOfflineQueue: false, maxRetriesPerRequest: 1 });
    redis.on('error', (/** @type {Error} */ e) => logger.error(`[hmac-guard] redis: ${e.message}`));
    ownRedis = true;
  }

  const aud = audit ?? new Audit({ file: config.audit?.file, logToConsole: config.audit?.console });
  const shared = createShared({
    limits: config.limits, redis, audit: aud,
    ipAllow: config.ipAllow, ipDeny: config.ipDeny, exposeReasons: config.exposeReasons,
  });
  const forwarder = new Forwarder({ deadLetterFile: config.deadLetterFile, logger });

  const app = express();
  app.disable('x-powered-by');
  app.disable('etag');
  app.set('trust proxy', config.server.trustProxy);
  app.use((req, res, next) => {
    const incoming = req.headers['x-request-id'];
    // @ts-ignore
    req.id = typeof incoming === 'string' && /^[\w.-]{1,64}$/.test(incoming) ? incoming : randomUUID();
    // @ts-ignore
    res.setHeader('X-Request-Id', req.id);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, routes: config.routes.length, uptimeSec: Math.round(process.uptime()), forward: forwarder.stats, pendingDeliveries: forwarder.pending.size });
  });

  app.get('/metrics', (req, res) => {
    const token = config.server.metricsToken;
    if (token && req.headers.authorization !== `Bearer ${token}`) return void res.status(401).json({ error: 'unauthorized' });
    res.type('text/plain; version=0.0.4').send(aud.prometheus() + [
      '# TYPE hmac_guard_forward_total counter',
      `hmac_guard_forward_total{result="delivered"} ${forwarder.stats.delivered}`,
      `hmac_guard_forward_total{result="retried"} ${forwarder.stats.retried}`,
      `hmac_guard_forward_total{result="dead_lettered"} ${forwarder.stats.deadLettered}`,
    ].join('\n') + '\n');
  });

  for (const route of config.routes) {
    app.all(route.path, createGuard(route, shared), (req, res) => {
      if (!route.forward) {
        // @ts-ignore
        return void res.status(200).json({ ok: true, route: route.name, client: req.guard.client, requestId: req.id });
      }
      if (route.forward.mode === 'async') return forwarder.forwardAsync(route, req, res);
      return forwarder.forwardSync(route, req, res);
    });
  }

  // Unknown paths (scanners) still pay the IP rate limit.
  app.use(async (req, res) => {
    const ip = normalizeIp(req.ip ?? req.socket.remoteAddress);
    const gate = await preGate(shared, ip).catch(() => null);
    const reason = gate?.reason ?? 'not_found';
    // @ts-ignore
    const [status, message] = REASONS[reason];
    if (gate?.retryAfterSec) res.setHeader('Retry-After', String(gate.retryAfterSec));
    aud.record({ route: '-', outcome: 'rejected', reason, status, ip, method: req.method, path: req.originalUrl });
    res.status(status).json({ error: reason, message });
  });

  app.use((/** @type {any} */ err, /** @type {any} */ _req, /** @type {any} */ res, /** @type {any} */ _next) => {
    logger.error(`[hmac-guard] ${err.stack ?? err}`);
    if (!res.headersSent) res.status(500).json({ error: 'internal_error' });
  });

  async function close() {
    await forwarder.drain();
    await aud.close();
    shared.nonceStore.close?.();
    if (ownRedis) await redis.quit().catch(() => null);
  }

  return { app, shared, forwarder, audit: aud, close };
}

/**
 * Start the gateway with hardened server timeouts (slowloris protection).
 * @param {any} config
 * @param {{ logger?: Console, redisClient?: any, audit?: Audit, port?: number, host?: string }} [opts]
 */
export async function startGateway(config, opts = {}) {
  const gw = await createGateway(config, opts);
  const server = createServer(gw.app);
  server.headersTimeout = config.server.headersTimeoutMs;
  server.requestTimeout = config.server.requestTimeoutMs;
  server.keepAliveTimeout = config.server.keepAliveTimeoutMs;
  server.maxHeadersCount = 100;
  const port = opts.port ?? config.server.port;
  const host = opts.host ?? config.server.host;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(null));
  });
  const addr = /** @type {import('node:net').AddressInfo} */ (server.address());
  const shownHost = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host;
  const url = `http://${shownHost}:${addr.port}`;
  return {
    ...gw,
    server,
    url,
    port: addr.port,
    async close() {
      await new Promise((r) => { server.close(() => r(null)); server.closeAllConnections?.(); });
      await gw.close();
    },
  };
}
