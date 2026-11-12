// @ts-check
import { RateLimiterMemory, RateLimiterRedis } from 'rate-limiter-flexible';

/**
 * @typedef {{ points: number, duration?: number, blockDuration?: number }} LimitConfig
 */

/** Defaults tuned for webhook traffic: generous for real senders, tight for floods. */
export const DEFAULT_LIMITS = {
  /** Every request, before any body read or crypto: per source IP. */
  ip: { points: 30, duration: 1, blockDuration: 10 },
  /** Whole gateway: protects the upstream (n8n, CRM, your API) from collapse. */
  global: { points: 1000, duration: 1 },
  /** Failed signatures per IP: brute force / spam ban. */
  failedAuth: { points: 10, duration: 600, blockDuration: 900 },
  /** Verified requests per client (key's client id), per route. */
  client: { points: 600, duration: 60 },
};

/**
 * @param {LimitConfig | null | undefined} cfg
 * @param {{ redis?: any, keyPrefix?: string }} [opts]
 */
export function createLimiter(cfg, { redis, keyPrefix = 'hg' } = {}) {
  if (!cfg || !cfg.points) return null;
  const base = {
    points: cfg.points,
    duration: cfg.duration ?? 1,
    blockDuration: cfg.blockDuration ?? 0,
    keyPrefix,
  };
  if (redis) {
    return new RateLimiterRedis({
      ...base,
      storeClient: redis,
      // Once a key is over the limit, answer from memory: a flood never reaches Redis.
      inMemoryBlockOnConsumed: cfg.points + 1,
      inMemoryBlockDuration: Math.max(1, base.blockDuration || base.duration),
      // Redis down -> keep limiting per process instead of failing open.
      insuranceLimiter: new RateLimiterMemory(base),
    });
  }
  return new RateLimiterMemory(base);
}

/**
 * Consume points; never throws for "limit reached".
 * @param {any} limiter
 * @param {string} key
 * @returns {Promise<{ ok: true } | { ok: false, retryAfterSec: number }>}
 */
export async function consume(limiter, key, points = 1) {
  try {
    await limiter.consume(key, points);
    return { ok: true };
  } catch (res) {
    if (res instanceof Error) throw res;
    const ms = /** @type {any} */ (res)?.msBeforeNext ?? 1000;
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil(ms / 1000)) };
  }
}

/**
 * Is this key currently over its limit (e.g. banned after failed auth)?
 * @param {any} limiter
 * @param {string} key
 */
export async function isBlocked(limiter, key) {
  const res = await limiter.get(key);
  if (res && res.consumedPoints > limiter.points) {
    return { blocked: true, retryAfterSec: Math.max(1, Math.ceil(res.msBeforeNext / 1000)) };
  }
  return { blocked: false, retryAfterSec: 0 };
}
