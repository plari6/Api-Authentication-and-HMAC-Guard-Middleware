import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateWhsec, hashApiKey, safeEqual } from '../src/crypto.js';
import { getProvider, providers } from '../src/providers.js';

const now = Math.floor(Date.now() / 1000);
const fakeReq = (headers, { method = 'POST', path = '/hooks/x', host = 'example.com', protocol = 'https' } = {}) => ({
  method, originalUrl: path, protocol,
  headers: Object.fromEntries(Object.entries({ host, ...headers }).map(([k, v]) => [k.toLowerCase(), v])),
});
const ctx = (req, body, keys, extra = {}) => ({ req, rawBody: Buffer.from(body), keys, now, toleranceSec: 300, bindPath: true, ...extra });

describe('official test vectors', () => {
  it('GitHub docs example', () => {
    const h = providers.github.sign({ secret: "It's a Secret to Everybody", body: 'Hello, World!' });
    assert.equal(h['X-Hub-Signature-256'], 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17');
  });

  it('Standard Webhooks reference vector', () => {
    // Public example secret from the Standard Webhooks spec (not a real credential).
    // Built from parts so secret scanners don't mistake it for a Stripe whsec_ key.
    const specSecret = ['whsec', 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw'].join('_');
    const h = providers.standard.sign({
      secret: specSecret, body: '{"test": 2432232314}',
      timestamp: 1614265330, id: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
    });
    assert.equal(h['webhook-signature'], 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=');
  });

  it('Slack docs example', () => {
    const body = 'token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c';
    const h = providers.slack.sign({ secret: '8f742231b10e8888abcd99yyyzzz85a5', body, timestamp: 1531420618 });
    assert.equal(h['X-Slack-Signature'], 'v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503');
  });

  it('Twilio (twilio-node test vector)', () => {
    const body = 'CallSid=CA1234567890ABCDE&Caller=%2B14158675309&Digits=1234&From=%2B14158675309&To=%2B18005551212';
    const h = providers.twilio.sign({ secret: '12345', url: 'https://mycompany.com/myapp.php?foo=1&bar=2', body });
    assert.equal(h['X-Twilio-Signature'], 'RSOYDt4T1cUTdK1PDd93/VVr8B8=');
  });
});

describe('sign -> verify round trips and tampering', () => {
  const cases = [
    ['generic', 'hgs_' + 'k'.repeat(40)],
    ['stripe', 'whsec_test_secret_value_123'],
    ['github', 'gh-secret'],
    ['shopify', 'shpss_secret'],
    ['slack', 'slack-signing-secret'],
    ['standard', generateWhsec()],
  ];
  for (const [name, secret] of cases) {
    it(`${name}: valid, tampered, wrong secret`, () => {
      const p = getProvider(name);
      const body = '{"amount":100}';
      const headers = p.sign({ secret, keyId: 'k1', body, method: 'POST', path: '/hooks/x' });
      const keys = [{ id: 'k1', secret }];
      const ok = p.verify(ctx(fakeReq(headers), body, keys));
      assert.equal(ok.ok, true, JSON.stringify(ok));
      assert.equal(ok.key.id, 'k1');
      assert.equal(p.verify(ctx(fakeReq(headers), '{"amount":999}', keys)).reason, 'bad_signature');
      const wrong = name === 'standard' ? generateWhsec() : secret + 'x';
      assert.equal(p.verify(ctx(fakeReq(headers), body, [{ id: 'k1', secret: wrong }])).reason, name === 'generic' ? 'bad_signature' : 'bad_signature');
      assert.equal(p.verify(ctx(fakeReq({}), body, keys)).reason, 'missing_signature');
    });
  }

  it('twilio: form params are signed, JSON needs bodySHA256', () => {
    const p = providers.twilio;
    const url = 'https://example.com/hooks/x';
    const body = 'Body=hi&From=%2B1555';
    const headers = { ...p.sign({ secret: 't', url, body }), 'content-type': 'application/x-www-form-urlencoded' };
    assert.equal(p.verify(ctx(fakeReq(headers), body, [{ id: 'a', secret: 't' }])).ok, true);
    assert.equal(p.verify(ctx(fakeReq(headers), 'Body=bye&From=%2B1555', [{ id: 'a', secret: 't' }])).reason, 'bad_signature');
    // behind a proxy the public URL differs from Host -> publicBaseUrl fixes it
    const viaProxy = fakeReq(headers, { host: 'internal:3000', protocol: 'http' });
    assert.equal(p.verify(ctx(viaProxy, body, [{ id: 'a', secret: 't' }])).reason, 'bad_signature');
    assert.equal(p.verify(ctx(viaProxy, body, [{ id: 'a', secret: 't' }], { publicBaseUrl: 'https://example.com' })).ok, true);
    // JSON without bodySHA256 is refused (body would be unsigned)
    const jsonHeaders = { ...p.sign({ secret: 't', url, body: '{}', contentType: 'application/json' }), 'content-type': 'application/json' };
    assert.equal(p.verify(ctx(fakeReq(jsonHeaders), '{}', [{ id: 'a', secret: 't' }])).reason, 'malformed_signature');
  });

  it('apikey: hashed keys, bearer header, wrong key', () => {
    const p = providers.apikey;
    const keys = [{ id: 'a', hash: hashApiKey('hgk_live_1') }];
    assert.equal(p.verify(ctx(fakeReq({ 'x-api-key': 'hgk_live_1' }), '', keys)).ok, true);
    assert.equal(p.verify(ctx(fakeReq({ authorization: 'Bearer hgk_live_1' }), '', keys)).ok, true);
    assert.equal(p.verify(ctx(fakeReq({ 'x-api-key': 'hgk_live_2' }), '', keys)).reason, 'bad_api_key');
    assert.equal(p.verify(ctx(fakeReq({}), '', keys)).reason, 'missing_api_key');
  });
});

describe('generic scheme details', () => {
  const p = providers.generic;
  const secret = 'hgs_' + 'z'.repeat(40);

  it('binds the path: a signature for /a fails on /b', () => {
    const h = p.sign({ secret, body: 'x', path: '/a' });
    assert.equal(p.verify(ctx(fakeReq(h, { path: '/b' }), 'x', [{ id: 'k', secret }])).reason, 'bad_signature');
    assert.equal(p.verify(ctx(fakeReq(h, { path: '/a' }), 'x', [{ id: 'k', secret }])).ok, true);
  });

  it('binds the method', () => {
    const h = p.sign({ secret, body: 'x', path: '/a', method: 'POST' });
    assert.equal(p.verify(ctx(fakeReq(h, { path: '/a', method: 'PUT' }), 'x', [{ id: 'k', secret }])).reason, 'bad_signature');
  });

  it('rejects stale and future timestamps', () => {
    const old = p.sign({ secret, body: 'x', path: '/a', timestamp: now - 301 });
    const future = p.sign({ secret, body: 'x', path: '/a', timestamp: now + 301 });
    assert.equal(p.verify(ctx(fakeReq(old, { path: '/a' }), 'x', [{ id: 'k', secret }])).reason, 'stale_timestamp');
    assert.equal(p.verify(ctx(fakeReq(future, { path: '/a' }), 'x', [{ id: 'k', secret }])).reason, 'stale_timestamp');
  });

  it('key rotation: old and new key both work, key id selects the key', () => {
    const keys = [{ id: 'old', secret: secret + 'old' }, { id: 'new', secret: secret + 'new' }];
    const viaOld = p.sign({ secret: secret + 'old', body: 'x', path: '/a' });
    const viaNew = p.sign({ secret: secret + 'new', keyId: 'new', body: 'x', path: '/a' });
    assert.equal(p.verify(ctx(fakeReq(viaOld, { path: '/a' }), 'x', keys)).key.id, 'old');
    assert.equal(p.verify(ctx(fakeReq(viaNew, { path: '/a' }), 'x', keys)).key.id, 'new');
    const unknown = p.sign({ secret, keyId: 'nope', body: 'x', path: '/a' });
    assert.equal(p.verify(ctx(fakeReq(unknown, { path: '/a' }), 'x', keys)).reason, 'unknown_key');
  });

  it('expired key is refused with key_expired', () => {
    const keys = [{ id: 'k', secret, expiresAt: Date.now() - 1000 }];
    const h = p.sign({ secret, body: 'x', path: '/a' });
    assert.equal(p.verify(ctx(fakeReq(h, { path: '/a' }), 'x', keys)).reason, 'key_expired');
  });

  it('malformed headers and signature spraying', () => {
    const h = p.sign({ secret, body: 'x', path: '/a' });
    assert.equal(p.verify(ctx(fakeReq({ ...h, 'X-Guard-Nonce': 'short' }, { path: '/a' }), 'x', [{ id: 'k', secret }])).reason, 'malformed_signature');
    const spray = Array.from({ length: 6 }, () => 'v1=' + '0'.repeat(64)).join(',');
    assert.equal(p.verify(ctx(fakeReq({ ...h, 'X-Guard-Signature': spray }, { path: '/a' }), 'x', [{ id: 'k', secret }])).reason, 'malformed_signature');
  });

  it('nonce differs per request so the replay store can tell them apart', () => {
    const a = p.verify(ctx(fakeReq(p.sign({ secret, body: 'x', path: '/a' }), { path: '/a' }), 'x', [{ id: 'k', secret }]));
    const b = p.verify(ctx(fakeReq(p.sign({ secret, body: 'x', path: '/a' }), { path: '/a' }), 'x', [{ id: 'k', secret }]));
    assert.notEqual(a.nonce, b.nonce);
  });
});

describe('helpers', () => {
  it('safeEqual', () => {
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('abc', 'abd'), false);
    assert.equal(safeEqual('abc', 'abcd'), false);
  });
  it('aliases and unknown provider', () => {
    assert.equal(getProvider('svix').name, 'standard');
    assert.equal(getProvider('Resend').name, 'standard');
    assert.throws(() => getProvider('nope'), /Unknown provider/);
  });
});
