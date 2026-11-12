import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { Audit, summarizeAuditFile } from '../src/audit.js';
import { buildConfig, resolveEnv } from '../src/config.js';
import { MemoryNonceStore } from '../src/nonce-store.js';
import { providers } from '../src/providers.js';
import { startGateway } from '../src/server.js';
import { runAttackSuite } from '../src/simulate.js';
import { startMockUpstream } from '../src/demo.js';
import { post, sleep } from './helpers.js';

const SECRET = 'hgs_' + 'g'.repeat(43);
const quiet = { log() {}, error() {} };

describe('config', () => {
  it('resolves env:NAME and env:NAME?', () => {
    assert.deepEqual(resolveEnv({ a: 'env:A', b: ['env:B?'], c: 'plain' }, { A: '1' }), { a: '1', b: [null], c: 'plain' });
    assert.throws(() => resolveEnv({ k: { s: 'env:MISSING' } }, {}), /MISSING \(used at k\.s\)/);
  });

  it('reports every config error at once', () => {
    assert.throws(() => buildConfig({
      routes: [
        { name: 'a', path: 'no-slash', provider: 'nope', keys: [] },
        { name: 'b', path: '/b', provider: 'generic', keys: [{ id: 'x', secret: SECRET }], forward: { url: 'ftp://x', mode: 'later' } },
      ],
      ipDeny: ['not-an-ip'],
    }, { env: {} }), (e) => {
      const msg = e.message;
      return ['path must start', 'Unknown provider', 'no usable keys', 'forward.url', 'forward.mode', 'ipDeny'].every((s) => msg.includes(s));
    });
  });

  it('applies defaults to routes and warns on weak setups', () => {
    const { config, warnings } = buildConfig({
      server: { trustProxy: true },
      routes: [{ path: '/h', keys: [{ id: 'k', secret: 'short' }] }, { path: '/t', provider: 'twilio', secret: 'tok' }],
    }, { env: {} });
    assert.equal(config.routes[0].provider, 'generic');
    assert.equal(config.routes[0].maxBodyBytes, 1_048_576);
    assert.ok(warnings.some((w) => w.includes('trustProxy=true')));
    assert.ok(warnings.some((w) => w.includes('secret is short')));
    assert.ok(warnings.some((w) => w.includes('publicBaseUrl')));
  });
});

describe('gateway', () => {
  let gw, upstream, dir;
  before(async () => {
    dir = await mkdtemp(join(tmpdir(), 'hmac-guard-'));
    upstream = await startMockUpstream();
    const { config } = buildConfig({
      server: { host: '127.0.0.1', port: 0, trustProxy: true, metricsToken: 'm-token' },
      limits: { ip: { points: 100, duration: 1 }, failedAuth: { points: 50, duration: 60 } },
      audit: { file: join(dir, 'audit.jsonl'), console: false },
      deadLetterFile: join(dir, 'dead.jsonl'),
      routes: [
        { name: 'sync', path: '/hooks/sync', keys: [{ id: 'k', client: 'acme', secret: SECRET }],
          forward: { url: `${upstream.url}/in/sync`, mode: 'sync', secret: 'internal-secret' } },
        { name: 'async', path: '/hooks/async', keys: [{ id: 'k', client: 'acme', secret: SECRET }],
          forward: { url: `${upstream.url}/in/async`, mode: 'async' } },
        { name: 'dead', path: '/hooks/dead', keys: [{ id: 'k', secret: SECRET }],
          forward: { url: 'http://127.0.0.1:9/unreachable', mode: 'async', retries: 1, retryBaseMs: 10, timeoutMs: 500 } },
        { name: 'ack', path: '/hooks/ack', provider: 'shopify', secret: 'shp' },
      ],
    }, { env: {} });
    gw = await startGateway(config, { logger: quiet });
  });
  after(async () => {
    await gw.close();
    await upstream.close();
    await rm(dir, { recursive: true, force: true });
  });

  const send = (path, body, extraHeaders = {}) =>
    post(gw.url + path, { body, headers: { ...providers.generic.sign({ secret: SECRET, keyId: 'k', body, path }), ...extraHeaders } });

  it('sync forward returns the upstream answer; spoofed x-guard headers are stripped; upstream call is re-signed', async () => {
    const before = upstream.received.length;
    const r = await send('/hooks/sync', '{"lead":"x"}', { 'X-Guard-Client': 'evil', 'X-Custom': 'kept' });
    assert.equal(r.status, 200);
    assert.equal(r.body.handledBy, 'mock-upstream');
    const got = upstream.received[before];
    assert.equal(got.path, '/in/sync');
    assert.equal(got.body, '{"lead":"x"}');
    assert.equal(got.headers['x-guard-client'], 'acme');
    assert.equal(got.headers['x-guard-verified'], 'true');
    assert.equal(got.headers['x-custom'], 'kept');
    // upstream can verify the gateway's own signature
    const check = providers.generic.verify({
      req: { method: 'POST', originalUrl: '/in/sync', headers: got.headers }, rawBody: Buffer.from(got.body),
      keys: [{ id: 'gateway', secret: 'internal-secret' }], now: Math.floor(Date.now() / 1000), toleranceSec: 300,
    });
    assert.equal(check.ok, true);
  });

  it('async forward answers 202 at once and delivers in the background', async () => {
    const before = upstream.received.length;
    const r = await send('/hooks/async', '{"n":1}');
    assert.equal(r.status, 202);
    assert.equal(r.body.accepted, true);
    for (let i = 0; i < 50 && upstream.received.length === before; i++) await sleep(20);
    assert.equal(upstream.received.at(-1).path, '/in/async');
  });

  it('failed deliveries go to the dead-letter file with the body', async () => {
    const r = await send('/hooks/dead', '{"keep":"me"}');
    assert.equal(r.status, 202);
    await gw.forwarder.drain(5000);
    const line = JSON.parse((await readFile(join(dir, 'dead.jsonl'), 'utf8')).trim().split('\n').at(-1));
    assert.equal(Buffer.from(line.bodyBase64, 'base64').toString(), '{"keep":"me"}');
    assert.equal(line.route, 'dead');
  });

  it('ack-only route, healthz, metrics auth, 404', async () => {
    const body = '{"id":1}';
    const shop = await post(gw.url + '/hooks/ack', { body, headers: providers.shopify.sign({ secret: 'shp', body }) });
    assert.equal(shop.status, 200);
    assert.equal(shop.body.ok, true);
    assert.equal((await fetch(gw.url + '/healthz').then((r) => r.json())).ok, true);
    assert.equal((await fetch(gw.url + '/metrics')).status, 401);
    const m = await fetch(gw.url + '/metrics', { headers: { authorization: 'Bearer m-token' } }).then((r) => r.text());
    assert.match(m, /hmac_guard_requests_total\{route="sync",outcome="allowed",reason=""\} \d+/);
    const nf = await fetch(gw.url + '/wp-login.php');
    assert.equal(nf.status, 404);
  });

  it('audit file can be summarized', async () => {
    await post(gw.url + '/hooks/sync', { body: '{}', ip: '192.0.2.99' }); // unsigned -> blocked
    await gw.audit.close();
    gw.audit.stream = null; // further events stay in memory only
    const s = await summarizeAuditFile(join(dir, 'audit.jsonl'));
    assert.ok(s.allowed >= 3);
    assert.ok(s.byReason.missing_signature >= 1);
    assert.equal(s.topBlockedIps.some((x) => x.key === '192.0.2.99'), true);
    assert.equal(s.topClients[0].key, 'acme');
  });
});

describe('attack suite against a gateway', () => {
  it('generic route: every scenario passes', async () => {
    const { config } = buildConfig({
      server: { host: '127.0.0.1', port: 0, trustProxy: true },
      limits: { ip: { points: 20, duration: 1, blockDuration: 5 }, failedAuth: { points: 4, duration: 60, blockDuration: 60 } },
      defaults: { maxBodyBytes: 4096 },
      audit: { file: null, console: false },
      routes: [{ path: '/hooks/p', keys: [{ id: 'k', secret: SECRET }] }],
    }, { env: {} });
    const gw = await startGateway(config, { logger: quiet });
    try {
      const suite = await runAttackSuite({ target: gw.url + '/hooks/p', secret: SECRET, keyId: 'k', maxBodyBytes: 4096, spoofIps: true, flood: 50, brute: 8 });
      assert.equal(suite.failed, 0, JSON.stringify(suite.results.filter((r) => !r.pass), null, 2));
      assert.ok(suite.results.length >= 11);
    } finally { await gw.close(); }
  });
});

describe('nonce store', () => {
  it('first sighting true, replay false, expires after ttl, evicts when full', async () => {
    const s = new MemoryNonceStore({ maxEntries: 10 });
    assert.equal(await s.checkAndSet('a', 50), true);
    assert.equal(await s.checkAndSet('a', 50), false);
    await sleep(70);
    assert.equal(await s.checkAndSet('a', 50), true);
    for (let i = 0; i < 25; i++) await s.checkAndSet('k' + i, 60_000);
    assert.ok(s.size <= 10);
    s.close();
  });
});

describe('audit flood suppression', () => {
  it('writes repeated rate-limit events once per window but counts them all', () => {
    const seen = [];
    const a = new Audit({ sink: (e) => seen.push(e) });
    for (let i = 0; i < 100; i++) a.record({ route: 'r', outcome: 'rejected', reason: 'rate_limited_ip', status: 429, ip: '1.1.1.1' });
    assert.equal(seen.length, 1);
    assert.equal(a.snapshot()[0].count, 100);
  });
});

describe('audit flood summary', () => {
  it('flushes suppressed counts on close so stats see the whole attack', async () => {
    const seen = [];
    const a = new Audit({ sink: (e) => seen.push(e) });
    for (let i = 0; i < 40; i++) a.record({ route: 'r', outcome: 'rejected', reason: 'rate_limited_ip', status: 429, ip: '9.9.9.9' });
    await a.close();
    assert.equal(seen.length, 2);
    assert.equal(seen[1].summary, true);
    assert.equal(seen[1].count, 39);
    assert.equal(seen[1].ip, '9.9.9.9');
  });
});
