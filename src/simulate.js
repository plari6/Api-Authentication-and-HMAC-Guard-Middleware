// @ts-check
// Attack simulator: fires the attacks the guard is meant to stop at a live
// endpoint and reports what got through. Use it as a sales demo, as an
// acceptance test after deploying, or in CI against staging.
import { randomBytes } from 'node:crypto';
import { generateWhsec, randomNonce } from './crypto.js';
import { getProvider } from './providers.js';

/**
 * @typedef {{ status: number, reason?: string, ms: number }} Hit
 * @typedef {{ name: string, attack: string, expected: string, got: string, pass: boolean, detail?: string }} ScenarioResult
 */

/** Process-wide, so consecutive suites never reuse a banned fake IP. */
let spoofSeq = Math.floor(Math.random() * 1000);

/**
 * @param {{
 *   target: string, provider?: string, secret: string, keyId?: string,
 *   maxBodyBytes?: number, brute?: number, flood?: number, spoofIps?: boolean, skipFlood?: boolean,
 *   bindPath?: boolean, timeoutMs?: number, onResult?: (r: ScenarioResult) => void,
 * }} opts
 * @returns {Promise<{ target: string, provider: string, results: ScenarioResult[], passed: number, failed: number }>}
 */
export async function runAttackSuite(opts) {
  const {
    target, secret, keyId, maxBodyBytes = 1_048_576, brute = 15, flood = 80,
    spoofIps = false, skipFlood = false, bindPath = true, timeoutMs = 10_000, onResult,
  } = opts;
  const provider = getProvider(opts.provider ?? 'generic');
  const isForm = provider.name === 'twilio';
  const contentType = isForm ? 'application/x-www-form-urlencoded' : 'application/json';
  const u = new URL(target);
  const path = u.pathname + u.search;

  /** A fresh source IP per scenario (needs trustProxy on the target - lab use only). */
  const nextIp = () => {
    if (!spoofIps) return undefined;
    const n = spoofSeq++;
    return `198.18.${Math.floor(n / 250) % 250}.${(n % 250) + 1}`;
  };

  const makeBody = () => isForm
    ? Buffer.from(new URLSearchParams({ From: '+15550001111', Body: 'attack test', MessageSid: 'SM' + randomNonce(16) }).toString())
    : Buffer.from(JSON.stringify({ event: 'hmac_guard.attack_test', id: randomNonce(8), at: new Date().toISOString() }));

  /** @param {Buffer} body @param {Record<string, any>} [extra] @param {string} [withSecret] */
  const sign = (body, extra = {}, withSecret = secret) =>
    provider.sign({ secret: withSecret, keyId, body, method: 'POST', path: bindPath ? path : '', url: target, contentType, ...extra });

  /** @param {Buffer} body @param {Record<string, string>} headers @param {string | undefined} ip @returns {Promise<Hit>} */
  async function post(body, headers, ip) {
    /** @type {Record<string, string>} */
    const h = { 'content-type': contentType, ...headers };
    if (ip) h['x-forwarded-for'] = ip;
    const t0 = performance.now();
    try {
      const r = await fetch(target, { method: 'POST', headers: h, body, signal: AbortSignal.timeout(timeoutMs) });
      const text = await r.text();
      let reason;
      try { reason = JSON.parse(text)?.error; } catch { /* not json */ }
      return { status: r.status, reason, ms: Math.round(performance.now() - t0) };
    } catch (e) {
      const err = /** @type {any} */ (e);
      return { status: 0, reason: err.cause?.code ?? err.name, ms: Math.round(performance.now() - t0) };
    }
  }

  const fmt = (/** @type {Hit} */ h) => (h.status ? `${h.status}${h.reason ? ' ' + h.reason : ''}` : `network error (${h.reason})`);
  /** @type {ScenarioResult[]} */
  const results = [];
  /** @param {ScenarioResult} r */
  const push = (r) => { results.push(r); onResult?.(r); };

  /**
   * One request, compare status (and reason when the server exposes it).
   * @param {string} name @param {string} attack @param {number[]} statuses @param {string[]} reasons @param {() => Promise<Hit>} fn
   */
  async function single(name, attack, statuses, reasons, fn) {
    const hit = await fn();
    const statusOk = statuses.includes(hit.status) || (statuses.includes(200) && hit.status >= 200 && hit.status < 300);
    const reasonOk = !hit.reason || !reasons.length || reasons.includes(hit.reason);
    const expected = statuses.includes(200) ? '2xx' : `${statuses.join('/')} ${reasons.join('|')}`.trim();
    push({ name, attack, expected, got: fmt(hit), pass: statusOk && reasonOk });
    return hit;
  }

  const wrongSecret = provider.name === 'standard' ? generateWhsec() : secret + 'x';

  await single('valid_request', 'Correctly signed request (must be let through)', [200], [], async () => {
    const b = makeBody();
    return post(b, sign(b), nextIp());
  });

  await single('no_signature', 'Unsigned spam request', [401], ['missing_signature', 'missing_api_key'], async () =>
    post(makeBody(), {}, nextIp()));

  await single('wrong_secret', 'Attacker guesses / uses a wrong secret', [401], ['bad_signature', 'bad_api_key', 'unknown_key'], async () => {
    const b = makeBody();
    return post(b, sign(b, {}, wrongSecret), nextIp());
  });

  if (provider.name !== 'apikey') {
    await single('tampered_body', 'Valid signature, body changed in transit (e.g. amount edited)', [401], ['bad_signature'], async () => {
      const b = makeBody();
      const h = sign(b);
      const tampered = isForm
        ? Buffer.from(b.toString().replace('attack+test', 'refund+all'))
        : Buffer.from(b.toString().replace('attack_test', 'refund_all'));
      return post(tampered, h, nextIp());
    });
  }

  if (provider.timestamped) {
    await single('stale_timestamp', 'Captured request re-sent 1 hour later', [401], ['stale_timestamp'], async () => {
      const b = makeBody();
      return post(b, sign(b, { timestamp: Math.floor(Date.now() / 1000) - 3600 }), nextIp());
    });
    await single('future_timestamp', 'Pre-signed request with a future timestamp', [401], ['stale_timestamp'], async () => {
      const b = makeBody();
      return post(b, sign(b, { timestamp: Math.floor(Date.now() / 1000) + 3600 }), nextIp());
    });
  }

  if (provider.name !== 'apikey') {
    const b = makeBody();
    const h = sign(b);
    const ip = nextIp();
    const first = await post(b, h, ip);
    const second = await post(b, h, ip);
    push({
      name: 'replay_attack',
      attack: 'Exact copy of a valid request sent again (replay)',
      expected: '2xx then 409 replay',
      got: `${fmt(first)} then ${fmt(second)}`,
      pass: first.status >= 200 && first.status < 300 && second.status === 409,
    });
  }

  if (provider.name === 'generic' && bindPath) {
    await single('path_swap', 'Signature made for another endpoint, sent here', [401], ['bad_signature'], async () => {
      const b = makeBody();
      return post(b, provider.sign({ secret, keyId, body: b, method: 'POST', path: path + '-admin' }), nextIp());
    });
  }

  await single('oversized_body', `Body larger than the limit (${maxBodyBytes + 1024} bytes)`, [413], ['body_too_large'], async () => {
    const pad = isForm
      ? Buffer.from(new URLSearchParams({ Body: 'A'.repeat(maxBodyBytes + 1024) }).toString())
      : Buffer.from(JSON.stringify({ pad: randomBytes(Math.ceil((maxBodyBytes + 1024) / 2)).toString('hex') }));
    return post(pad, sign(pad), nextIp());
  });

  if (!skipFlood) {
    // Brute force: bad signatures from one IP until it gets banned.
    {
      const ip = nextIp();
      /** @type {Hit[]} */ const hits = [];
      for (let i = 0; i < brute; i++) {
        const b = makeBody();
        const h = await post(b, sign(b, {}, wrongSecret), ip);
        hits.push(h);
        if (h.status === 429) break;
      }
      const banned = hits.findIndex((h) => h.status === 429);
      push({
        name: 'brute_force',
        attack: `Up to ${brute} wrong signatures from one IP`,
        expected: '429 ip_banned',
        got: banned >= 0 ? `banned after ${banned} attempts (${fmt(hits[banned])})` : `not banned (${hits.length} x ${fmt(hits[hits.length - 1])})`,
        pass: banned >= 0,
      });
    }
    // Flood: many unsigned requests at once from one IP.
    {
      const ip = nextIp();
      const t0 = performance.now();
      const hits = await Promise.all(Array.from({ length: flood }, () => post(makeBody(), {}, ip)));
      const limited = hits.filter((h) => h.status === 429).length;
      const errors = hits.filter((h) => h.status === 0).length;
      push({
        name: 'flood',
        attack: `${flood} concurrent requests from one IP (DDoS / spam burst)`,
        expected: 'most get 429',
        got: `${limited}/${flood} rate limited${errors ? `, ${errors} network errors` : ''} in ${Math.round(performance.now() - t0)} ms`,
        pass: limited > 0 && limited >= flood / 2,
      });
    }
  }

  const passed = results.filter((r) => r.pass).length;
  return { target, provider: provider.name, results, passed, failed: results.length - passed };
}
