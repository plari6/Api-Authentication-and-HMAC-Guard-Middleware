// @ts-check
import { createReadStream, createWriteStream, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createInterface } from 'node:readline';

const FLOOD_REASONS = new Set(['rate_limited_ip', 'rate_limited_global', 'rate_limited_client', 'ip_banned', 'ip_denied', 'not_found']);
const FLOOD_WINDOW_MS = 10_000;

/**
 * @typedef {{ ts?: string, route?: string, outcome: 'allowed' | 'rejected', reason?: string, status?: number | null,
 *   ip?: string, client?: string, keyId?: string, method?: string, path?: string, ms?: number, requestId?: string, suppressed?: number, count?: number, summary?: boolean }} AuditEvent
 */

/**
 * Security audit log (JSONL) + in-memory counters for /metrics.
 * During a flood, repeated rate-limit rejections from the same IP are written
 * once per 10 s with a "suppressed" count, so an attack cannot fill the disk.
 */
export class Audit {
  /** @param {{ file?: string | null, logToConsole?: boolean, sink?: (e: AuditEvent) => void }} [opts] */
  constructor({ file = null, logToConsole = false, sink } = {}) {
    /** @type {Map<string, number>} */
    this.counters = new Map();
    /** @type {Map<string, { at: number, suppressed: number, route?: string, status?: number | null }>} */
    this.floodSeen = new Map();
    this.startedAt = Date.now();
    this.logToConsole = logToConsole;
    this.sink = sink;
    this.file = file;
    /** @type {import('node:fs').WriteStream | null} */
    this.stream = null;
    if (file) {
      mkdirSync(dirname(file), { recursive: true });
      this.stream = createWriteStream(file, { flags: 'a' });
      this.stream.on('error', (e) => console.error(`[hmac-guard] audit log error: ${e.message}`));
    }
    // Write suppressed-flood totals even if the attacker goes quiet.
    this.flushTimer = setInterval(() => this.flushSuppressed(), FLOOD_WINDOW_MS);
    this.flushTimer.unref?.();
  }

  /** One line per IP+reason with the number of rejections not written individually. */
  flushSuppressed(force = false) {
    const now = Date.now();
    for (const [fk, seen] of this.floodSeen) {
      const expired = force || now - seen.at >= FLOOD_WINDOW_MS;
      if (seen.suppressed) {
        const [ip, reason] = fk.split('\u0000');
        /** @type {AuditEvent} */
        const e = { ts: new Date().toISOString(), route: seen.route, outcome: 'rejected', reason, status: seen.status, ip, count: seen.suppressed, summary: true };
        this.stream?.write(JSON.stringify(e) + '\n');
        this.sink?.(e);
        if (this.logToConsole) console.log(formatEvent(e));
        seen.suppressed = 0;
      }
      if (expired) this.floodSeen.delete(fk);
    }
  }

  /** @param {AuditEvent} evt */
  record(evt) {
    const e = { ts: new Date().toISOString(), ...evt };
    const ck = `${e.route ?? '-'}\u0000${e.outcome}\u0000${e.reason ?? ''}`;
    this.counters.set(ck, (this.counters.get(ck) ?? 0) + 1);

    if (e.reason && FLOOD_REASONS.has(e.reason)) {
      const fk = `${e.ip}\u0000${e.reason}`;
      const seen = this.floodSeen.get(fk);
      const now = Date.now();
      if (seen && now - seen.at < FLOOD_WINDOW_MS) {
        seen.suppressed++;
        return;
      }
      if (seen?.suppressed) e.suppressed = seen.suppressed;
      if (this.floodSeen.size > 50_000) this.flushSuppressed(true);
      this.floodSeen.set(fk, { at: now, suppressed: 0, route: e.route, status: e.status });
    }

    this.stream?.write(JSON.stringify(e) + '\n');
    this.sink?.(e);
    if (this.logToConsole) console.log(formatEvent(e));
  }

  snapshot() {
    return [...this.counters].map(([k, count]) => {
      const [route, outcome, reason] = k.split('\u0000');
      return { route, outcome, reason: reason || null, count };
    });
  }

  /** Prometheus text exposition. */
  prometheus() {
    const esc = (/** @type {string} */ s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
    const lines = [
      '# HELP hmac_guard_requests_total Requests seen by hmac-guard, by route, outcome and reason.',
      '# TYPE hmac_guard_requests_total counter',
    ];
    for (const s of this.snapshot()) {
      lines.push(`hmac_guard_requests_total{route="${esc(s.route)}",outcome="${s.outcome}",reason="${esc(s.reason ?? '')}"} ${s.count}`);
    }
    lines.push('# HELP hmac_guard_uptime_seconds Seconds since the guard started.', '# TYPE hmac_guard_uptime_seconds gauge');
    lines.push(`hmac_guard_uptime_seconds ${Math.round((Date.now() - this.startedAt) / 1000)}`);
    return lines.join('\n') + '\n';
  }

  /** @returns {Promise<void>} */
  close() {
    clearInterval(this.flushTimer);
    this.flushSuppressed(true);
    return new Promise((resolve) => {
      if (!this.stream) return resolve();
      this.stream.end(() => resolve());
    });
  }
}

/** @param {AuditEvent} e */
export function formatEvent(e) {
  const time = (e.ts ?? '').slice(11, 19);
  const who = e.client ? ` client=${e.client}` : '';
  if (e.summary) return `${time} BLOCK  ${e.route} ${e.ip} ${e.status} ${e.reason} x${e.count} (flood summary)`;
  const sup = e.suppressed ? ` (+${e.suppressed} suppressed)` : '';
  if (e.outcome === 'allowed') return `${time} ALLOW  ${e.route} ${e.ip}${who} ${e.ms ?? 0}ms`;
  return `${time} BLOCK  ${e.route} ${e.ip} ${e.status} ${e.reason}${who}${sup}`;
}

/**
 * Summarize an audit JSONL file (streamed, any size).
 * @param {string} file
 * @param {{ sinceMs?: number }} [opts]
 */
export async function summarizeAuditFile(file, { sinceMs = 0 } = {}) {
  if (!existsSync(file)) throw new Error(`Audit file not found: ${file}`);
  /** @type {Record<string, number>} */ const byReason = {};
  /** @type {Record<string, { allowed: number, rejected: number }>} */ const byRoute = {};
  /** @type {Map<string, number>} */ const ips = new Map();
  /** @type {Map<string, number>} */ const clients = new Map();
  let total = 0, allowed = 0, rejected = 0, bad = 0;
  let first = null, last = null;
  const rl = createInterface({ input: createReadStream(file, 'utf8'), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let e;
    try { e = JSON.parse(line); } catch { bad++; continue; }
    const t = Date.parse(e.ts);
    if (sinceMs && t < sinceMs) continue;
    const weight = e.summary ? (e.count ?? 0) : 1 + (e.suppressed ?? 0);
    total += weight;
    first ??= e.ts;
    last = e.ts;
    const r = (byRoute[e.route ?? '-'] ??= { allowed: 0, rejected: 0 });
    if (e.outcome === 'allowed') {
      allowed += weight; r.allowed += weight;
      if (e.client) clients.set(e.client, (clients.get(e.client) ?? 0) + weight);
    } else {
      rejected += weight; r.rejected += weight;
      byReason[e.reason] = (byReason[e.reason] ?? 0) + weight;
      if (e.ip) ips.set(e.ip, (ips.get(e.ip) ?? 0) + weight);
    }
  }
  const top = (/** @type {Map<string, number>} */ m) => [...m].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, n]) => ({ key: k, count: n }));
  return { file, total, allowed, rejected, malformedLines: bad, first, last, byReason, byRoute, topBlockedIps: top(ips), topClients: top(clients) };
}
