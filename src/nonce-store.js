// @ts-check
// Replay protection stores. checkAndSet(key, ttlMs) returns true the first
// time a key is seen inside its TTL, false for a replay. Nonces are only
// stored after a valid signature, so an attacker without the secret cannot
// fill the store.

export class MemoryNonceStore {
  /** @param {{ maxEntries?: number, sweepMs?: number }} [opts] */
  constructor({ maxEntries = 200_000, sweepMs = 60_000 } = {}) {
    /** @type {Map<string, number>} key -> expiry (ms) */
    this.map = new Map();
    this.maxEntries = maxEntries;
    this.timer = setInterval(() => this.sweep(), sweepMs);
    this.timer.unref?.();
  }

  /** @param {string} key @param {number} ttlMs */
  async checkAndSet(key, ttlMs) {
    const now = Date.now();
    const exp = this.map.get(key);
    if (exp !== undefined && exp > now) return false;
    if (this.map.size >= this.maxEntries) this.evict(now);
    this.map.set(key, now + ttlMs);
    return true;
  }

  sweep(now = Date.now()) {
    for (const [k, exp] of this.map) if (exp <= now) this.map.delete(k);
  }

  /** Drop expired entries; if still full, drop the oldest 10%. */
  evict(/** @type {number} */ now) {
    this.sweep(now);
    if (this.map.size < this.maxEntries) return;
    let drop = Math.ceil(this.maxEntries / 10);
    for (const k of this.map.keys()) {
      this.map.delete(k);
      if (--drop <= 0) break;
    }
  }

  get size() {
    return this.map.size;
  }

  close() {
    clearInterval(this.timer);
  }
}

/** Shared store for several gateway instances (ioredis client). */
export class RedisNonceStore {
  /** @param {any} client ioredis instance @param {string} [prefix] */
  constructor(client, prefix = 'hg:nonce:') {
    this.client = client;
    this.prefix = prefix;
  }

  /** @param {string} key @param {number} ttlMs */
  async checkAndSet(key, ttlMs) {
    const r = await this.client.set(this.prefix + key, '1', 'PX', Math.max(1, Math.round(ttlMs)), 'NX');
    return r === 'OK';
  }

  close() {}
}
