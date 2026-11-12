// @ts-check
// Self-contained demo: starts a mock upstream (stands in for n8n / a CRM), a
// gateway in front of it, and runs the attack suite against several routes.
import { createServer } from 'node:http';
import { buildConfig } from './config.js';
import { generateSecret, generateWhsec } from './crypto.js';
import { startGateway } from './server.js';
import { runAttackSuite } from './simulate.js';

/** Mock upstream that counts what actually reaches it. */
export async function startMockUpstream() {
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      received.push({ path: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, handledBy: 'mock-upstream' }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', () => r(null)));
  const addr = /** @type {import('node:net').AddressInfo} */ (server.address());
  return { url: `http://127.0.0.1:${addr.port}`, received, close: () => new Promise((r) => server.close(() => r(null))) };
}

export function demoSecrets() {
  return {
    generic: generateSecret(),
    stripe: 'whsec_' + generateSecret('', 24),
    github: generateSecret('', 24),
    slack: generateSecret('', 16).replace(/[^a-zA-Z0-9]/g, 'a'),
    standard: generateWhsec(),
    twilio: generateSecret('', 16),
  };
}

/** @param {ReturnType<typeof demoSecrets>} s @param {string} upstreamUrl */
export function demoConfig(s, upstreamUrl) {
  return buildConfig({
    // Lab only: trust X-Forwarded-For so each attack can come from its own fake IP.
    server: { host: '127.0.0.1', port: 0, trustProxy: true },
    limits: {
      ip: { points: 20, duration: 1, blockDuration: 5 },
      global: { points: 5000, duration: 1 },
      failedAuth: { points: 5, duration: 600, blockDuration: 900 },
      client: { points: 100, duration: 60 },
    },
    defaults: { maxBodyBytes: 65_536 },
    audit: { file: null, console: false },
    deadLetterFile: null,
    routes: [
      { name: 'partner-api', path: '/hooks/partner', provider: 'generic', contentTypes: ['application/json'],
        keys: [{ id: 'acme-demo', client: 'acme', secret: s.generic }],
        forward: { url: `${upstreamUrl}/webhook/partner`, mode: 'sync' } },
      { name: 'stripe', path: '/hooks/stripe', provider: 'stripe', keys: [{ id: 'stripe', secret: s.stripe }],
        forward: { url: `${upstreamUrl}/webhook/stripe`, mode: 'async' } },
      { name: 'github', path: '/hooks/github', provider: 'github', keys: [{ id: 'github', secret: s.github }] },
      { name: 'slack', path: '/hooks/slack', provider: 'slack', keys: [{ id: 'slack', secret: s.slack }] },
      { name: 'resend', path: '/hooks/resend', provider: 'standard', keys: [{ id: 'resend', secret: s.standard }] },
      { name: 'twilio', path: '/hooks/twilio', provider: 'twilio', keys: [{ id: 'twilio', secret: s.twilio }],
        contentTypes: ['application/x-www-form-urlencoded'] },
    ],
  }, { env: {} }).config;
}

/**
 * @param {{ providers?: string[], onSuite?: (suite: any) => void, onSuiteDone?: (suite: any) => void, onResult?: (r: any) => void }} [opts]
 */
export async function runDemo({ providers, onSuite, onSuiteDone, onResult } = {}) {
  const upstream = await startMockUpstream();
  const secrets = demoSecrets();
  const config = demoConfig(secrets, upstream.url);
  const gw = await startGateway(config, { logger: /** @type {any} */ ({ log() {}, error() {} }) });
  const plan = [
    { provider: 'generic', path: '/hooks/partner', secret: secrets.generic, keyId: 'acme-demo' },
    { provider: 'stripe', path: '/hooks/stripe', secret: secrets.stripe },
    { provider: 'github', path: '/hooks/github', secret: secrets.github },
    { provider: 'slack', path: '/hooks/slack', secret: secrets.slack },
    { provider: 'standard', path: '/hooks/resend', secret: secrets.standard },
    { provider: 'twilio', path: '/hooks/twilio', secret: secrets.twilio },
  ].filter((p) => !providers?.length || providers.includes(p.provider));
  const suites = [];
  try {
    for (const p of plan) {
      onSuite?.({ ...p, target: gw.url + p.path });
      const suite = await runAttackSuite({
        target: gw.url + p.path, provider: p.provider, secret: p.secret, keyId: p.keyId,
        maxBodyBytes: 65_536, spoofIps: true, flood: 60, brute: 10, onResult,
      });
      suites.push(suite);
      onSuiteDone?.(suite);
    }
    await gw.forwarder.drain(5000);
    return { suites, upstreamReceived: upstream.received.length, metrics: gw.audit.snapshot() };
  } finally {
    await gw.close();
    await upstream.close();
  }
}
