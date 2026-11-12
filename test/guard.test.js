import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { after, before, describe, it } from 'node:test';
import express from 'express';
import { Audit } from '../src/audit.js';
import { hashApiKey } from '../src/crypto.js';
import { captureRawBody, createGuard, hmacGuard } from '../src/guard.js';
import { providers } from '../src/providers.js';
import { appWith, listen, post } from './helpers.js';

const SECRET = 'hgs_' + 'a'.repeat(43);
let ipN = 0;
const freshIp = () => `203.0.113.${(ipN++ % 250) + 1}`;
const signed = (path, body, extra = {}) => providers.generic.sign({ secret: SECRET, keyId: 'acme-1', body, path, ...extra });

describe('guard middleware (generic scheme)', () => {
  let srv;
  const events = [];
  before(async () => {
    const guard = createGuard({
      name: 'partner', provider: 'generic', keys: [{ id: 'acme-1', client: 'acme', secret: SECRET }],
      contentTypes: ['application/json'], maxBodyBytes: 2048, bodyTimeoutMs: 500,
      limits: { ip: { points: 50, duration: 1 }, failedAuth: { points: 3, duration: 60, blockDuration: 60 }, client: { points: 1000, duration: 60 } },
      audit: new Audit({ sink: (e) => events.push(e) }),
    });
    srv = await listen(appWith('/hooks/partner', guard));
  });
  after(() => srv.close());
  const url = () => `${srv.url}/hooks/partner`;

  it('lets a valid request through with parsed body and req.guard', async () => {
    const body = JSON.stringify({ order: 42 });
    const r = await post(url(), { body, headers: signed('/hooks/partner', body), ip: freshIp() });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.body, { order: 42 });
    assert.equal(r.body.guard.client, 'acme');
    assert.equal(r.body.guard.keyId, 'acme-1');
    assert.equal(r.body.raw, body.length);
    assert.ok(events.some((e) => e.outcome === 'allowed' && e.client === 'acme'));
  });

  it('blocks a replay with 409', async () => {
    const body = '{"a":1}';
    const h = signed('/hooks/partner', body);
    const ip = freshIp();
    assert.equal((await post(url(), { body, headers: h, ip })).status, 200);
    const again = await post(url(), { body, headers: h, ip });
    assert.equal(again.status, 409);
    assert.equal(again.body.error, 'replay');
  });

  it('401 for missing, bad and stale signatures', async () => {
    assert.equal((await post(url(), { body: '{}', ip: freshIp() })).body.error, 'missing_signature');
    const bad = signed('/hooks/partner', '{}');
    assert.equal((await post(url(), { body: '{"x":1}', headers: bad, ip: freshIp() })).body.error, 'bad_signature');
    const stale = signed('/hooks/partner', '{}', { timestamp: Math.floor(Date.now() / 1000) - 900 });
    const r = await post(url(), { body: '{}', headers: stale, ip: freshIp() });
    assert.equal(r.status, 401);
    assert.equal(r.body.error, 'stale_timestamp');
  });

  it('bans an IP after repeated failures, other IPs unaffected', async () => {
    const ip = freshIp();
    for (let i = 0; i < 3; i++) assert.equal((await post(url(), { body: '{}', ip })).status, 401);
    const fourth = await post(url(), { body: '{}', ip });
    assert.equal(fourth.status, 401); // the 4th failure crosses the limit
    const banned = await post(url(), { body: '{}', headers: signed('/hooks/partner', '{}'), ip });
    assert.equal(banned.status, 429);
    assert.equal(banned.body.error, 'ip_banned');
    assert.ok(Number(banned.headers.get('retry-after')) > 0);
    // a valid request from another IP still works
    assert.equal((await post(url(), { body: '{}', headers: signed('/hooks/partner', '{}'), ip: freshIp() })).status, 200);
  });

  it('413 for bodies over the limit (declared and chunked)', async () => {
    const big = JSON.stringify({ pad: 'x'.repeat(4096) });
    const r = await post(url(), { body: big, headers: signed('/hooks/partner', big), ip: freshIp() });
    assert.equal(r.status, 413);
    // chunked: no content-length, stream exceeds the limit
    const stream = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(big)); c.close(); } });
    const r2 = await fetch(url(), { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': freshIp() }, body: stream, duplex: 'half' });
    assert.equal(r2.status, 413);
  });

  it('415 for a wrong content type, 405 for a wrong method', async () => {
    const r = await post(url(), { body: 'x', headers: { 'content-type': 'text/plain' }, ip: freshIp() });
    assert.equal(r.status, 415);
    const g = await fetch(url(), { headers: { 'x-forwarded-for': freshIp() } });
    assert.equal(g.status, 405);
    assert.equal(g.headers.get('allow'), 'POST');
  });

  it('400 when a signed body is not valid JSON', async () => {
    const body = '{not json';
    const r = await post(url(), { body, headers: signed('/hooks/partner', body), ip: freshIp() });
    assert.equal(r.status, 400);
    assert.equal(r.body.error, 'invalid_body');
  });

  it('408 for a slow body (slowloris)', async () => {
    const { port } = new URL(srv.url);
    const status = await new Promise((resolve, reject) => {
      const s = connect(Number(port), '127.0.0.1', () => {
        s.write(`POST /hooks/partner HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\nX-Forwarded-For: ${freshIp()}\r\n\r\n{"a":`);
      });
      let data = '';
      s.on('data', (d) => { data += d; const m = /^HTTP\/1\.1 (\d+)/.exec(data); if (m) { resolve(Number(m[1])); s.destroy(); } });
      s.on('error', reject);
    });
    assert.equal(status, 408);
  });
});

describe('rate limits', () => {
  it('per-IP limit returns 429 before any crypto runs', async () => {
    const guard = createGuard({ provider: 'generic', secret: SECRET, limits: { ip: { points: 5, duration: 10 }, failedAuth: null } });
    const srv = await listen(appWith('/h', guard));
    try {
      const results = await Promise.all(Array.from({ length: 12 }, () => post(`${srv.url}/h`, { body: '{}', ip: '198.51.100.7' })));
      const limited = results.filter((r) => r.status === 429);
      assert.equal(limited.length, 7);
      assert.equal(limited[0].body.error, 'rate_limited_ip');
    } finally { await srv.close(); }
  });

  it('per-client limit applies to verified traffic, per-key override wins', async () => {
    const guard = createGuard({
      provider: 'generic',
      keys: [{ id: 'small', client: 'small-co', secret: SECRET, limit: { points: 2, duration: 60 } }, { id: 'big', client: 'big-co', secret: SECRET + 'b' }],
      limits: { ip: null, client: { points: 100, duration: 60 } },
    });
    const srv = await listen(appWith('/h', guard));
    try {
      const send = (secret, keyId) => { const b = '{}'; return post(`${srv.url}/h`, { body: b, headers: providers.generic.sign({ secret, keyId, body: b, path: '/h' }) }); };
      assert.equal((await send(SECRET, 'small')).status, 200);
      assert.equal((await send(SECRET, 'small')).status, 200);
      const third = await send(SECRET, 'small');
      assert.equal(third.status, 429);
      assert.equal(third.body.error, 'rate_limited_client');
      assert.equal((await send(SECRET + 'b', 'big')).status, 200);
    } finally { await srv.close(); }
  });

  it('global limit returns 503', async () => {
    const guard = createGuard({ provider: 'generic', secret: SECRET, limits: { ip: null, global: { points: 2, duration: 10 } } });
    const srv = await listen(appWith('/h', guard));
    try {
      const rs = [];
      for (let i = 0; i < 3; i++) rs.push(await post(`${srv.url}/h`, { body: '{}', ip: freshIp() }));
      assert.equal(rs[2].status, 503);
      assert.equal(rs[2].body.error, 'rate_limited_global');
    } finally { await srv.close(); }
  });
});

describe('IP lists', () => {
  it('route ipAllow (CIDR) and ipDeny', async () => {
    const guard = createGuard({ provider: 'generic', secret: SECRET, ipAllow: ['10.0.0.0/8', '2001:db8::/32'], ipDeny: ['10.6.6.6'] });
    const srv = await listen(appWith('/h', guard));
    try {
      const b = '{}';
      const h = () => providers.generic.sign({ secret: SECRET, body: b, path: '/h' });
      assert.equal((await post(`${srv.url}/h`, { body: b, headers: h(), ip: '10.1.2.3' })).status, 200);
      assert.equal((await post(`${srv.url}/h`, { body: b, headers: h(), ip: '2001:db8::1' })).status, 200);
      assert.equal((await post(`${srv.url}/h`, { body: b, headers: h(), ip: '8.8.8.8' })).body.error, 'ip_denied');
      assert.equal((await post(`${srv.url}/h`, { body: b, headers: h(), ip: '10.6.6.6' })).body.error, 'ip_denied');
    } finally { await srv.close(); }
  });
});

describe('library usage', () => {
  it('hmacGuard() with a Stripe secret in an existing app', async () => {
    const secret = 'whsec_lib_test';
    const app = express();
    app.post('/webhooks/stripe', hmacGuard({ provider: 'stripe', secret }), (req, res) => res.json({ type: req.body.type }));
    const srv = await listen(app);
    try {
      const body = JSON.stringify({ type: 'invoice.paid' });
      const r = await post(`${srv.url}/webhooks/stripe`, { body, headers: providers.stripe.sign({ secret, body }) });
      assert.equal(r.status, 200);
      assert.equal(r.body.type, 'invoice.paid');
    } finally { await srv.close(); }
  });

  it('works after express.json() when captureRawBody is used', async () => {
    const app = express();
    app.use(express.json({ verify: captureRawBody }));
    app.post('/h', hmacGuard({ provider: 'github', secret: 'gh' }), (req, res) => res.json(req.body));
    const srv = await listen(app);
    try {
      const body = '{"zen":"Keep it logically awesome."}';
      const r = await post(`${srv.url}/h`, { body, headers: providers.github.sign({ secret: 'gh', body }) });
      assert.equal(r.status, 200);
      assert.equal(r.body.zen, 'Keep it logically awesome.');
    } finally { await srv.close(); }
  });

  it('apikey provider with hashed key', async () => {
    const app = express();
    app.post('/api', hmacGuard({ provider: 'apikey', keys: [{ id: 'k', client: 'acme', hash: hashApiKey('hgk_123') }] }), (req, res) => res.json(req.guard));
    const srv = await listen(app);
    try {
      assert.equal((await post(`${srv.url}/api`, { body: '{}', headers: { authorization: 'Bearer hgk_123' } })).body.client, 'acme');
      assert.equal((await post(`${srv.url}/api`, { body: '{}', headers: { 'x-api-key': 'nope' } })).status, 401);
    } finally { await srv.close(); }
  });

  it('exposeReasons:false hides why a request failed', async () => {
    const app = express();
    app.post('/h', hmacGuard({ provider: 'generic', secret: SECRET, exposeReasons: false }), (req, res) => res.json({}));
    const srv = await listen(app);
    try {
      const r = await post(`${srv.url}/h`, { body: '{}' });
      assert.equal(r.status, 401);
      assert.deepEqual(r.body, { error: 'rejected' });
    } finally { await srv.close(); }
  });

  it('refuses to start without a secret', () => {
    assert.throws(() => createGuard({ provider: 'stripe' }), /at least one key/);
  });
});

describe('partner-side signer (examples/sign-request.mjs)', () => {
  it('headers built without hmac-guard code are accepted, incl. query string', async () => {
    const { sign } = await import('../examples/sign-request.mjs');
    const guard = createGuard({ provider: 'generic', keys: [{ id: 'p1', secret: SECRET }], limits: { ip: null } });
    const srv = await listen(appWith('/hooks/p', guard));
    try {
      const url = `${srv.url}/hooks/p?source=crm&v=2`;
      const body = JSON.stringify({ lead: 'Jane' });
      const r = await post(url, { body, headers: sign({ secret: SECRET, keyId: 'p1', url, body }) });
      assert.equal(r.status, 200, JSON.stringify(r.body));
    } finally { await srv.close(); }
  });
});

describe('RedisNonceStore', () => {
  it('uses SET NX PX and maps OK/null to fresh/replay', async () => {
    const { RedisNonceStore } = await import('../src/nonce-store.js');
    const data = new Map();
    const calls = [];
    const fake = { async set(k, v, px, ttl, nx) { calls.push([px, nx, ttl]); if (data.has(k)) return null; data.set(k, v); return 'OK'; } };
    const s = new RedisNonceStore(fake);
    assert.equal(await s.checkAndSet('n1', 1500), true);
    assert.equal(await s.checkAndSet('n1', 1500), false);
    assert.deepEqual(calls[0], ['PX', 'NX', 1500]);
  });
});
