// @ts-check
import { readFile } from 'node:fs/promises';
import { DEFAULT_LIMITS } from './limiters.js';
import { buildIpList } from './guard.js';
import { getProvider } from './providers.js';

export const DEFAULT_CONFIG = {
  server: {
    host: '0.0.0.0',
    port: 8080,
    /** Express "trust proxy": false, a hop count (1 behind one proxy), or a list of proxy IPs/CIDRs. */
    trustProxy: /** @type {any} */ (false),
    /** If set, /metrics needs "Authorization: Bearer <token>". */
    metricsToken: /** @type {string | null} */ (null),
    headersTimeoutMs: 10_000,
    requestTimeoutMs: 15_000,
    keepAliveTimeoutMs: 5_000,
  },
  limits: DEFAULT_LIMITS,
  defaults: {
    methods: ['POST'],
    contentTypes: /** @type {string[] | null} */ (null),
    toleranceSec: 300,
    maxBodyBytes: 1_048_576,
    bodyTimeoutMs: 10_000,
    replayTtlSec: 86_400,
    bindPath: true,
    publicBaseUrl: /** @type {string | null} */ (null),
  },
  ipAllow: /** @type {string[]} */ ([]),
  ipDeny: /** @type {string[]} */ ([]),
  redis: { url: /** @type {string | null} */ (null) },
  audit: { file: /** @type {string | null} */ ('logs/audit.jsonl'), console: true },
  deadLetterFile: 'logs/dead-letter.jsonl',
  exposeReasons: true,
  routes: /** @type {any[]} */ ([]),
};

/**
 * Replace "env:NAME" strings with environment values, recursively.
 * "env:NAME?" is optional (becomes null when unset).
 * @param {any} value @param {Record<string, string | undefined>} env @param {string} [path]
 * @returns {any}
 */
export function resolveEnv(value, env, path = '') {
  if (typeof value === 'string') {
    const m = /^env:([A-Za-z_][A-Za-z0-9_]*)(\?)?$/.exec(value);
    if (!m) return value;
    const v = env[m[1]];
    if (v === undefined || v === '') {
      if (m[2]) return null;
      throw new Error(`Missing environment variable ${m[1]} (used at ${path || 'root'})`);
    }
    return v;
  }
  if (Array.isArray(value)) return value.map((v, i) => resolveEnv(v, env, `${path}[${i}]`));
  if (value && typeof value === 'object') {
    /** @type {Record<string, any>} */ const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveEnv(v, env, path ? `${path}.${k}` : k);
    return out;
  }
  return value;
}

/** Merge defaults into the raw config and into each route. @param {any} raw */
export function normalizeConfig(raw) {
  const d = DEFAULT_CONFIG;
  const limits = { ...d.limits, ...(raw.limits ?? {}) };
  const defaults = { ...d.defaults, ...(raw.defaults ?? {}) };
  const cfg = {
    server: { ...d.server, ...(raw.server ?? {}) },
    limits,
    defaults,
    ipAllow: raw.ipAllow ?? d.ipAllow,
    ipDeny: raw.ipDeny ?? d.ipDeny,
    redis: { ...d.redis, ...(raw.redis ?? {}) },
    audit: { ...d.audit, ...(raw.audit ?? {}) },
    deadLetterFile: raw.deadLetterFile === undefined ? d.deadLetterFile : raw.deadLetterFile,
    exposeReasons: raw.exposeReasons ?? d.exposeReasons,
    routes: (raw.routes ?? []).map((/** @type {any} */ r, /** @type {number} */ i) => {
      const forward = r.forward && r.forward.url
        ? { mode: 'sync', timeoutMs: 10_000, retries: 4, secret: null, ...r.forward }
        : null;
      const declaredKeys = r.keys ?? (r.secret !== undefined ? [{ id: 'default', secret: r.secret }] : []);
      const keys = declaredKeys.filter((/** @type {any} */ k) => k && (k.secret || k.hash));
      return {
        ...defaults,
        ...r,
        name: r.name ?? `route${i + 1}`,
        provider: r.provider ?? 'generic',
        limits: r.limits ?? {},
        keys,
        forward,
        // Every key came from an unset optional env var (env:NAME?): route is switched off.
        disabled: r.disabled === true || (declaredKeys.length > 0 && keys.length === 0),
      };
    }),
  };
  return cfg;
}

/** @param {ReturnType<typeof normalizeConfig>} cfg */
export function validateConfig(cfg) {
  /** @type {string[]} */ const errors = [];
  /** @type {string[]} */ const warnings = [];
  for (const r of cfg.routes.filter((/** @type {any} */ r) => r.disabled)) warnings.push(`route "${r.name}" (${r.path}) is disabled: its secret env variable is not set`);
  if (!cfg.routes.some((/** @type {any} */ r) => !r.disabled)) errors.push('No active routes. Add a route to "routes" and set its secret.');
  const port = Number(cfg.server.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) errors.push(`server.port must be 0-65535 (got ${cfg.server.port})`);
  for (const [label, list] of [['ipAllow', cfg.ipAllow], ['ipDeny', cfg.ipDeny]]) {
    try { buildIpList(/** @type {string[]} */ (list)); } catch (e) { errors.push(`${label}: ${/** @type {Error} */ (e).message}`); }
  }
  if (cfg.server.trustProxy === true) warnings.push('server.trustProxy=true trusts any X-Forwarded-For value, so attackers can fake their IP and dodge IP limits. Use a hop count (e.g. 1) or the proxy IPs.');

  const paths = new Set();
  const names = new Set();
  for (const r of cfg.routes.filter((/** @type {any} */ r) => !r.disabled)) {
    const where = `route "${r.name}"`;
    if (names.has(r.name)) errors.push(`${where}: duplicate route name`);
    names.add(r.name);
    if (typeof r.path !== 'string' || !r.path.startsWith('/')) errors.push(`${where}: path must start with "/"`);
    else if (paths.has(r.path)) errors.push(`${where}: duplicate path ${r.path}`);
    paths.add(r.path);
    let provider = null;
    try { provider = getProvider(r.provider); } catch (e) { errors.push(`${where}: ${/** @type {Error} */ (e).message}`); }
    if (!r.keys.length) errors.push(`${where}: no usable keys (each key needs "secret", or "hash" for apikey routes). Check the env variables it references.`);
    const ids = new Set();
    for (const k of r.keys) {
      if (ids.has(k.id)) errors.push(`${where}: duplicate key id "${k.id}"`);
      ids.add(k.id);
      if (k.hash && provider?.name !== 'apikey') errors.push(`${where}: key "${k.id}" uses "hash", which only works for provider apikey`);
      if (k.hash && !/^sha256:[0-9a-f]{64}$/i.test(k.hash)) errors.push(`${where}: key "${k.id}" hash must look like sha256:<64 hex>`);
      if (k.secret && /paste|replace|changeme|example/i.test(k.secret)) warnings.push(`${where}: key "${k.id}" still has a placeholder secret`);
      else if (k.secret && provider?.name === 'generic' && k.secret.length < 32) warnings.push(`${where}: key "${k.id}" secret is short (<32 chars). Generate one with: hmac-guard keygen`);
      if (k.expiresAt && !Number.isFinite(Date.parse(k.expiresAt))) errors.push(`${where}: key "${k.id}" expiresAt is not a date`);
    }
    try { buildIpList(r.ipAllow); buildIpList(r.ipDeny); } catch (e) { errors.push(`${where}: ${/** @type {Error} */ (e).message}`); }
    if (r.forward) {
      try {
        const u = new URL(r.forward.url);
        if (!/^https?:$/.test(u.protocol)) throw new Error('not http(s)');
      } catch { errors.push(`${where}: forward.url is not a valid http(s) URL`); }
      if (!['sync', 'async'].includes(r.forward.mode)) errors.push(`${where}: forward.mode must be "sync" or "async"`);
    }
    if (provider && !provider.timestamped && provider.name !== 'apikey') {
      warnings.push(`${where}: ${provider.name} signatures carry no timestamp; replays are blocked for replayTtlSec=${r.replayTtlSec}s via the signature itself.`);
    }
    if (provider?.name === 'twilio' && !r.publicBaseUrl) warnings.push(`${where}: set publicBaseUrl (e.g. https://hooks.example.com) so Twilio URLs match behind a proxy.`);
  }
  return { errors, warnings };
}

/**
 * @param {string} file
 * @param {{ env?: Record<string, string | undefined> }} [opts]
 */
export async function loadConfig(file, { env = process.env } = {}) {
  let text;
  try { text = await readFile(file, 'utf8'); } catch {
    throw new Error(`Config file not found: ${file}. Create one with: hmac-guard init`);
  }
  let raw;
  try { raw = JSON.parse(text); } catch (e) {
    throw new Error(`Config file ${file} is not valid JSON: ${/** @type {Error} */ (e).message}`);
  }
  return buildConfig(raw, { env });
}

/** @param {any} raw @param {{ env?: Record<string, string | undefined> }} [opts] */
export function buildConfig(raw, { env = process.env } = {}) {
  const cfg = normalizeConfig(resolveEnv(raw, env));
  const { errors, warnings } = validateConfig(cfg);
  if (errors.length) {
    const err = new Error(`Invalid config:\n  - ${errors.join('\n  - ')}`);
    /** @type {any} */ (err).errors = errors;
    throw err;
  }
  return { config: { ...cfg, routes: cfg.routes.filter((/** @type {any} */ r) => !r.disabled) }, warnings };
}
