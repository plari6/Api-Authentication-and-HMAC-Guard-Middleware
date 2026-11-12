#!/usr/bin/env node
// @ts-check
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { appendFile, readFile } from 'node:fs/promises';
import { Command, Option } from 'commander';
import { summarizeAuditFile } from '../src/audit.js';
import { sendSigned, signRequest } from '../src/client.js';
import { loadConfig } from '../src/config.js';
import { generateKeyId, generateSecret, generateWhsec, hashApiKey, toBuffer } from '../src/crypto.js';
import { runDemo } from '../src/demo.js';
import { getProvider, providerNames, providers } from '../src/providers.js';
import { startGateway } from '../src/server.js';
import { runAttackSuite } from '../src/simulate.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

// ---- tiny output helpers (no chalk) --------------------------------------
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (/** @type {string} */ code) => (/** @type {string} */ s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = paint('32'), red = paint('31'), yellow = paint('33'), dim = paint('2'), bold = paint('1');

/** @param {string[]} headers @param {string[][]} rows */
function table(headers, rows) {
  const plain = (/** @type {string} */ s) => s.replace(/\x1b\[[0-9;]*m/g, '');
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => plain(r[i] ?? '').length)));
  const line = (/** @type {string[]} */ cells) => cells.map((c, i) => c + ' '.repeat(widths[i] - plain(c).length)).join('  ');
  console.log(bold(line(headers)));
  console.log(dim(widths.map((w) => '-'.repeat(w)).join('  ')));
  for (const r of rows) console.log(line(r));
}

function loadEnvFile(/** @type {string | undefined} */ file) {
  const f = file ?? '.env';
  if (existsSync(f)) {
    try { process.loadEnvFile(f); } catch (e) { console.error(yellow(`Could not read ${f}: ${/** @type {Error} */ (e).message}`)); }
  } else if (file) {
    console.error(yellow(`Env file not found: ${file}`));
  }
}

/** @param {{ body?: string, file?: string }} o */
async function readBody(o) {
  if (o.file) return readFile(o.file);
  return toBuffer(o.body ?? '');
}

/** "Name: value" list -> headers object */
function parseHeaders(/** @type {string[]} */ list = []) {
  /** @type {Record<string, string>} */ const out = {};
  for (const h of list) {
    const i = h.indexOf(':');
    if (i <= 0) throw new Error(`Bad header "${h}", expected "Name: value"`);
    out[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim();
  }
  return out;
}

const collect = (/** @type {string} */ v, /** @type {string[]} */ prev = []) => [...prev, v];
const providerOption = () => new Option('-p, --provider <name>', 'signature scheme').choices(providerNames()).default('generic');

/** @param {any} suite */
function printSuite(suite) {
  table(['', 'scenario', 'attack', 'expected', 'got'], suite.results.map((/** @type {any} */ r) => [
    r.pass ? green('PASS') : red('FAIL'), r.name, r.attack, r.expected, r.pass ? r.got : red(r.got),
  ]));
  const verdict = suite.failed ? red(`${suite.failed} attack(s) NOT blocked`) : green('all attacks blocked, valid traffic let through');
  console.log(`\n${bold(suite.provider)} ${suite.target}: ${suite.passed}/${suite.results.length} passed - ${verdict}\n`);
}

const program = new Command();
program
  .name('hmac-guard')
  .description('Protect public API webhooks against DDoS, replay attacks and unauthorized spam.')
  .version(pkg.version)
  .option('--env-file <path>', 'load environment variables from this file (default: ./.env if present)')
  .hook('preAction', (cmd) => loadEnvFile(cmd.opts().envFile));

// ---- demo ------------------------------------------------------------------
program.command('demo')
  .description('start a guarded gateway + mock upstream and attack it (no setup needed)')
  .option('--only <providers>', 'comma-separated providers, e.g. generic,stripe')
  .option('--json', 'print JSON instead of tables')
  .action(async (o) => {
    const only = o.only ? String(o.only).split(',').map((s) => s.trim()) : undefined;
    if (!o.json) console.log(bold('\nhmac-guard demo') + dim(' - gateway + mock upstream on localhost, fake attacker IPs\n'));
    const out = await runDemo({
      providers: only,
      onSuite: (s) => { if (!o.json) console.log(bold(`> ${s.provider}`) + dim(`  ${s.target}`)); },
      onSuiteDone: (s) => { if (!o.json) printSuite(s); },
    });
    if (o.json) return console.log(JSON.stringify(out, null, 2));
    const total = out.suites.reduce((n, s) => n + s.results.length, 0);
    const failed = out.suites.reduce((n, s) => n + s.failed, 0);
    console.log(bold('Summary: ') + (failed ? red(`${failed}/${total} scenarios failed`) : green(`${total}/${total} scenarios passed`)));
    console.log(dim(`Requests that reached the upstream: ${out.upstreamReceived} (only verified, unique ones)`));
    process.exitCode = failed ? 1 : 0;
  });

// ---- init ------------------------------------------------------------------
program.command('init')
  .description('write a starter guard.config.json and add generated secrets to .env')
  .option('-c, --config <path>', 'config file to create', 'guard.config.json')
  .option('--env <path>', 'env file to append secrets to', '.env')
  .option('--client <name>', 'first partner/client name', 'acme')
  .option('-f, --force', 'overwrite an existing config')
  .action(async (o) => {
    if (existsSync(o.config) && !o.force) throw new Error(`${o.config} already exists (use --force to overwrite)`);
    const kid = generateKeyId(o.client);
    const envVar = `${o.client.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_HMAC_SECRET`;
    const config = {
      server: { port: 8080, trustProxy: 1, metricsToken: 'env:METRICS_TOKEN?' },
      limits: {
        ip: { points: 30, duration: 1, blockDuration: 10 },
        global: { points: 1000, duration: 1 },
        failedAuth: { points: 10, duration: 600, blockDuration: 900 },
        client: { points: 600, duration: 60 },
      },
      defaults: { toleranceSec: 300, maxBodyBytes: 1048576, replayTtlSec: 86400 },
      redis: { url: 'env:REDIS_URL?' },
      audit: { file: 'logs/audit.jsonl', console: true },
      deadLetterFile: 'logs/dead-letter.jsonl',
      ipDeny: [],
      routes: [
        {
          name: 'partner-api', path: '/hooks/partner', provider: 'generic', contentTypes: ['application/json'],
          keys: [{ id: kid, client: o.client, secret: `env:${envVar}` }],
          forward: { url: 'env:PARTNER_UPSTREAM_URL?', mode: 'async', retries: 4 },
        },
        {
          name: 'stripe', path: '/hooks/stripe', provider: 'stripe',
          keys: [{ id: 'stripe-live', secret: 'env:STRIPE_WEBHOOK_SECRET?' }],
          forward: { url: 'env:STRIPE_UPSTREAM_URL?', mode: 'async' },
        },
        {
          name: 'github', path: '/hooks/github', provider: 'github',
          keys: [{ id: 'github', secret: 'env:GITHUB_WEBHOOK_SECRET?' }],
          forward: { url: 'env:GITHUB_UPSTREAM_URL?', mode: 'async' },
        },
      ],
    };
    writeFileSync(o.config, JSON.stringify(config, null, 2) + '\n');
    const existing = existsSync(o.env) ? readFileSync(o.env, 'utf8') : '';
    const lines = [];
    if (!new RegExp(`^${envVar}=`, 'm').test(existing)) lines.push(`${envVar}=${generateSecret()}`);
    if (!/^METRICS_TOKEN=/m.test(existing)) lines.push(`METRICS_TOKEN=${generateSecret('', 18)}`);
    for (const v of ['PARTNER_UPSTREAM_URL', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_UPSTREAM_URL', 'GITHUB_WEBHOOK_SECRET', 'GITHUB_UPSTREAM_URL', 'REDIS_URL']) {
      if (!new RegExp(`^${v}=`, 'm').test(existing)) lines.push(`${v}=`);
    }
    if (lines.length) await appendFile(o.env, (existing && !existing.endsWith('\n') ? '\n' : '') + `# added by hmac-guard init ${new Date().toISOString().slice(0, 10)}\n` + lines.join('\n') + '\n');
    console.log(green(`Created ${o.config}`) + ` and updated ${o.env}`);
    console.log(`\nPartner "${o.client}" key id: ${bold(kid)}  (secret is ${envVar} in ${o.env})`);
    console.log('Next:');
    console.log('  1. Fill the *_UPSTREAM_URL values (n8n/Make/your API) and provider secrets in .env');
    console.log('  2. hmac-guard check');
    console.log('  3. hmac-guard serve');
    console.log(`  4. hmac-guard attack http://localhost:8080/hooks/partner --key-id ${kid} --secret <secret>`);
  });

// ---- keygen ----------------------------------------------------------------
program.command('keygen')
  .description('generate a key id + secret for a client (or an API key and its hash)')
  .option('--client <name>', 'client / partner name', 'client')
  .addOption(new Option('-t, --type <type>', 'what to generate').choices(['hmac', 'whsec', 'apikey']).default('hmac'))
  .option('--expires <date>', 'optional expiry, e.g. 2027-01-01')
  .option('--json', 'print JSON')
  .action((o) => {
    const id = generateKeyId(o.client);
    const secret = o.type === 'whsec' ? generateWhsec() : o.type === 'apikey' ? generateSecret('hgk_') : generateSecret();
    /** @type {Record<string, any>} */
    const key = { id, client: o.client };
    if (o.type === 'apikey') key.hash = hashApiKey(secret); else key.secret = `env:${o.client.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_SECRET`;
    if (o.expires) key.expiresAt = o.expires;
    if (o.json) return console.log(JSON.stringify({ keyId: id, secret, configEntry: key }, null, 2));
    console.log(`${bold('Key id:')}  ${id}`);
    console.log(`${bold(o.type === 'apikey' ? 'API key:' : 'Secret:')}  ${secret}`);
    console.log(dim('\nGive the client the key id and secret over a secure channel (password manager / one-time link).'));
    console.log(dim('Add this to the route\'s "keys" in guard.config.json:'));
    console.log(JSON.stringify(key, null, 2));
    if (o.type !== 'apikey') console.log(dim(`and put the secret in .env as ${key.secret.slice(4)}=...`));
    else console.log(dim('Only the hash is stored server-side; the plain key cannot be recovered from it.'));
  });

// ---- sign ------------------------------------------------------------------
program.command('sign')
  .description('print the signature headers (or a curl command) for a request')
  .requiredOption('-u, --url <url>', 'full URL the request will be sent to')
  .requiredOption('-s, --secret <secret>', 'signing secret (or env:NAME)')
  .addOption(providerOption())
  .option('-k, --key-id <id>', 'key id (generic scheme)')
  .option('-d, --body <text>', 'request body', '')
  .option('-f, --file <path>', 'read the body from a file')
  .option('-X, --method <method>', 'HTTP method', 'POST')
  .option('--content-type <type>', 'content type', 'application/json')
  .option('--no-bind-path', 'do not sign the path (only if the route sets bindPath: false)')
  .option('--curl', 'print a ready curl command')
  .action(async (o) => {
    const secret = resolveSecret(o.secret);
    const body = await readBody(o);
    const headers = signRequest({ provider: o.provider, secret, keyId: o.keyId, url: o.url, method: o.method, body, contentType: o.contentType, bindPath: o.bindPath });
    if (!o.curl) {
      for (const [k, v] of Object.entries(headers)) console.log(`${k}: ${v}`);
      return;
    }
    const q = (/** @type {string} */ s) => `'${s.replace(/'/g, `'\\''`)}'`;
    const parts = [`curl -sS -X ${o.method} ${q(o.url)}`, `-H ${q('Content-Type: ' + o.contentType)}`];
    for (const [k, v] of Object.entries(headers)) parts.push(`-H ${q(`${k}: ${v}`)}`);
    parts.push(o.file ? `--data-binary @${q(o.file)}` : `--data-binary ${q(body.toString('utf8'))}`);
    console.log(parts.join(' \\\n  '));
    if (headers['X-Guard-Timestamp']) console.log(dim('\n# valid for the tolerance window (default 5 min) and only once (replay protection)'));
  });

// ---- verify ----------------------------------------------------------------
program.command('verify')
  .description('check a captured request offline (headers + body) against a secret')
  .requiredOption('-s, --secret <secret>', 'secret (or env:NAME); repeatable for rotation', collect)
  .addOption(providerOption())
  .option('-H, --header <header>', '"Name: value", repeatable', collect)
  .option('-d, --body <text>', 'body', '')
  .option('-f, --file <path>', 'read the body from a file')
  .option('-u, --url <url>', 'request URL (path is signed by generic, full URL by twilio)', 'http://localhost/')
  .option('-X, --method <method>', 'HTTP method', 'POST')
  .option('--tolerance <sec>', 'timestamp tolerance in seconds', '300')
  .option('--no-bind-path', 'path is not part of the signature')
  .action(async (o) => {
    const p = getProvider(o.provider);
    const u = new URL(o.url);
    const req = { method: o.method.toUpperCase(), headers: parseHeaders(o.header), originalUrl: u.pathname + u.search, protocol: u.protocol.slice(0, -1) };
    const keys = o.secret.map((/** @type {string} */ s, /** @type {number} */ i) => ({ id: `secret${i + 1}`, secret: resolveSecret(s) }));
    const r = p.verify({ req, rawBody: await readBody(o), keys, now: Math.floor(Date.now() / 1000), toleranceSec: Number(o.tolerance), bindPath: o.bindPath, publicBaseUrl: u.origin });
    if (r.ok) {
      console.log(green('VALID') + ` - matched ${r.key.id}` + (r.timestamp ? `, signed ${new Date(r.timestamp * 1000).toISOString()}` : ''));
    } else {
      console.log(red('INVALID') + ` - ${r.reason}`);
      process.exitCode = 1;
    }
  });

// ---- send ------------------------------------------------------------------
program.command('send')
  .description('sign and send a request (test a guarded endpoint as a partner would)')
  .argument('<url>', 'target URL')
  .requiredOption('-s, --secret <secret>', 'signing secret (or env:NAME)')
  .addOption(providerOption())
  .option('-k, --key-id <id>', 'key id (generic scheme)')
  .option('-d, --body <text>', 'request body', '{"event":"test"}')
  .option('-f, --file <path>', 'read the body from a file')
  .option('-X, --method <method>', 'HTTP method', 'POST')
  .option('--content-type <type>', 'content type', 'application/json')
  .option('-H, --header <header>', 'extra "Name: value" header, repeatable', collect)
  .option('--no-bind-path', 'do not sign the path')
  .action(async (url, o) => {
    const r = await sendSigned({
      url, provider: o.provider, secret: resolveSecret(o.secret), keyId: o.keyId, body: await readBody(o),
      method: o.method, contentType: o.contentType, headers: parseHeaders(o.header), bindPath: o.bindPath,
    });
    const color = r.status < 300 ? green : r.status < 500 ? yellow : red;
    console.log(`${color(String(r.status))} in ${r.ms} ms`);
    console.log(typeof r.body === 'string' ? r.body : JSON.stringify(r.body, null, 2));
    if (r.status >= 300) process.exitCode = 1;
  });

// ---- check -----------------------------------------------------------------
program.command('check')
  .description('validate the config and list the protected routes')
  .option('-c, --config <path>', 'config file', 'guard.config.json')
  .action(async (o) => {
    const { config, warnings } = await loadConfig(o.config);
    table(['route', 'path', 'provider', 'keys', 'forward', 'max body', 'tolerance'], config.routes.map((/** @type {any} */ r) => [
      r.name, r.path, r.provider, r.keys.map((/** @type {any} */ k) => k.id).join(', '),
      r.forward ? `${r.forward.mode} -> ${new URL(r.forward.url).host}` : dim('ack only'),
      `${Math.round(r.maxBodyBytes / 1024)} KB`, getProvider(r.provider).timestamped ? `${r.toleranceSec}s` : dim('n/a'),
    ]));
    const l = config.limits;
    console.log(dim(`\nlimits: ip ${l.ip?.points ?? '-'}/${l.ip?.duration ?? '-'}s, global ${l.global?.points ?? '-'}/${l.global?.duration ?? '-'}s, ban after ${l.failedAuth?.points ?? '-'} bad signatures for ${l.failedAuth?.blockDuration ?? '-'}s, client ${l.client?.points ?? '-'}/${l.client?.duration ?? '-'}s`));
    console.log(dim(`replay store: ${config.redis.url ? 'redis' : 'memory (single instance)'}, audit: ${config.audit.file ?? 'off'}`));
    for (const w of warnings) console.log(yellow('warning: ') + w);
    console.log(green('\nConfig OK'));
  });

// ---- serve -----------------------------------------------------------------
program.command('serve')
  .description('run the guarded webhook gateway')
  .option('-c, --config <path>', 'config file', 'guard.config.json')
  .option('--port <port>', 'override server.port')
  .option('--host <host>', 'override server.host')
  .action(async (o) => {
    const { config, warnings } = await loadConfig(o.config);
    for (const w of warnings) console.log(yellow('warning: ') + w);
    const gw = await startGateway(config, { port: o.port ? Number(o.port) : undefined, host: o.host });
    console.log(green(`hmac-guard ${pkg.version} listening on ${gw.url}`));
    for (const r of config.routes) console.log(`  ${r.path.padEnd(24)} ${r.provider.padEnd(9)} ${r.forward ? `-> ${r.forward.mode} ${new URL(r.forward.url).host}` : 'ack only'}`);
    console.log(dim('  /healthz, /metrics'));
    let closing = false;
    const stop = async (/** @type {string} */ sig) => {
      if (closing) return;
      closing = true;
      console.log(dim(`\n${sig}: finishing deliveries and shutting down...`));
      await gw.close();
      process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });

// ---- attack ----------------------------------------------------------------
program.command('attack')
  .description('fire replay / tamper / brute-force / flood attacks at an endpoint and report what got through')
  .argument('<url>', 'guarded endpoint, e.g. https://hooks.client.com/hooks/partner')
  .requiredOption('-s, --secret <secret>', 'the route secret (or env:NAME), used for the valid and replay cases')
  .addOption(providerOption())
  .option('-k, --key-id <id>', 'key id (generic scheme)')
  .option('--max-body <bytes>', 'route body limit, for the oversize test', '1048576')
  .option('--brute <n>', 'max bad-signature attempts', '15')
  .option('--flood <n>', 'concurrent flood requests', '80')
  .option('--skip-flood', 'skip brute-force and flood (they will ban your IP for a while)')
  .option('--spoof-ips', 'send each scenario from a fake X-Forwarded-For IP (only works if the target trusts it)')
  .option('--no-bind-path', 'route uses bindPath: false')
  .option('--json', 'print JSON')
  .action(async (url, o) => {
    if (!o.skipFlood && !o.spoofIps && !o.json) console.log(yellow('Note: brute-force/flood will rate-limit and ban YOUR IP on the target for the configured blockDuration.\n'));
    const suite = await runAttackSuite({
      target: url, provider: o.provider, secret: resolveSecret(o.secret), keyId: o.keyId, maxBodyBytes: Number(o.maxBody),
      brute: Number(o.brute), flood: Number(o.flood), skipFlood: o.skipFlood, spoofIps: o.spoofIps, bindPath: o.bindPath,
    });
    if (o.json) console.log(JSON.stringify(suite, null, 2)); else printSuite(suite);
    process.exitCode = suite.failed ? 1 : 0;
  });

// ---- stats -----------------------------------------------------------------
program.command('stats')
  .description('summarize the audit log: blocked attacks by reason, top attacker IPs, top clients')
  .option('--file <path>', 'audit JSONL file', 'logs/audit.jsonl')
  .option('--since <duration>', 'only the last 30m / 24h / 7d')
  .option('--json', 'print JSON')
  .action(async (o) => {
    let sinceMs = 0;
    if (o.since) {
      const m = /^(\d+)([mhd])$/.exec(o.since);
      if (!m) throw new Error('--since must look like 30m, 24h or 7d');
      sinceMs = Date.now() - Number(m[1]) * { m: 60e3, h: 3600e3, d: 86400e3 }[/** @type {'m'|'h'|'d'} */ (m[2])];
    }
    const s = await summarizeAuditFile(o.file, { sinceMs });
    if (o.json) return console.log(JSON.stringify(s, null, 2));
    console.log(bold(`Audit ${s.file}`) + dim(` ${s.first ?? ''} .. ${s.last ?? ''}`));
    const pct = s.total ? Math.round((s.rejected / s.total) * 1000) / 10 : 0;
    console.log(`requests ${s.total}, allowed ${green(String(s.allowed))}, blocked ${red(String(s.rejected))} (${pct}%)\n`);
    if (Object.keys(s.byReason).length) {
      table(['blocked because', 'count'], Object.entries(s.byReason).sort((a, b) => b[1] - a[1]).map(([k, v]) => [k, String(v)]));
      console.log();
    }
    table(['route', 'allowed', 'blocked'], Object.entries(s.byRoute).map(([k, v]) => [k, String(v.allowed), String(v.rejected)]));
    if (s.topBlockedIps.length) { console.log(); table(['top blocked IP', 'count'], s.topBlockedIps.map((x) => [x.key, String(x.count)])); }
    if (s.topClients.length) { console.log(); table(['top client', 'verified requests'], s.topClients.map((x) => [x.key, String(x.count)])); }
  });

// ---- providers -------------------------------------------------------------
program.command('providers')
  .description('list the supported signature schemes')
  .action(() => {
    table(['provider', 'timestamp', 'description'], Object.values(providers).map((p) => [p.name, p.timestamped ? 'yes' : dim('no'), p.description]));
  });

/** "env:NAME" -> value of NAME */
function resolveSecret(/** @type {string} */ s) {
  const m = /^env:([A-Za-z_][A-Za-z0-9_]*)$/.exec(s);
  if (!m) return s;
  const v = process.env[m[1]];
  if (!v) throw new Error(`Environment variable ${m[1]} is not set`);
  return v;
}

program.parseAsync(process.argv).catch((err) => {
  console.error(red('Error: ') + (err?.message ?? err));
  process.exit(1);
});

