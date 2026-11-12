// Send a request signed for an hmac-guard "generic" route. Node 18+, no dependencies.
// Give this file to partners who call your client's API.
//
//   HMAC_KEY_ID=acme-202611-ab12 HMAC_SECRET=hgs_... node sign-request.mjs https://hooks.example.com/hooks/partner '{"event":"lead.created"}'
import { createHash, createHmac, randomBytes } from 'node:crypto';

export function sign({ secret, keyId, method = 'POST', url, body }) {
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(16).toString('hex');
  const u = new URL(url);
  const bodyHash = createHash('sha256').update(body).digest('hex');
  const canonical = ['v1', ts, nonce, method.toUpperCase(), u.pathname + u.search, bodyHash].join('\n');
  return {
    'X-Guard-Key-Id': keyId,
    'X-Guard-Timestamp': ts,
    'X-Guard-Nonce': nonce,
    'X-Guard-Signature': 'v1=' + createHmac('sha256', secret).update(canonical).digest('hex'),
  };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('sign-request.mjs')) {
  const [url, body = '{"event":"test"}'] = process.argv.slice(2);
  const headers = { 'content-type': 'application/json', ...sign({ secret: process.env.HMAC_SECRET, keyId: process.env.HMAC_KEY_ID, url, body }) };
  const r = await fetch(url, { method: 'POST', headers, body });
  console.log(r.status, await r.text());
  process.exitCode = r.ok ? 0 : 1;
}
