import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/hmac-guard.js', import.meta.url));
const cli = (args, opts = {}) => run(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: '1' }, ...opts });

describe('CLI', () => {
  let dir;
  before(async () => { dir = await mkdtemp(join(tmpdir(), 'hmac-guard-cli-')); });
  after(() => rm(dir, { recursive: true, force: true }));

  it('keygen --json gives an id, secret and config entry', async () => {
    const { stdout } = await cli(['keygen', '--client', 'Acme Corp', '--json']);
    const out = JSON.parse(stdout);
    assert.match(out.keyId, /^acme-corp-\d{6}-[0-9a-f]{4}$/);
    assert.match(out.secret, /^hgs_[A-Za-z0-9_-]{43}$/);
    assert.equal(out.configEntry.secret, 'env:ACME_CORP_SECRET');
  });

  it('sign output verifies; a changed body does not', async () => {
    const args = ['--provider', 'stripe', '--secret', 'whsec_cli', '--body', '{"a":1}'];
    const { stdout } = await cli(['sign', '--url', 'http://x/h', ...args]);
    const header = stdout.trim();
    assert.match(header, /^Stripe-Signature: t=\d+,v1=[0-9a-f]{64}$/);
    const ok = await cli(['verify', ...args, '-H', header]);
    assert.match(ok.stdout, /VALID/);
    await assert.rejects(cli(['verify', '--provider', 'stripe', '--secret', 'whsec_cli', '--body', '{"a":2}', '-H', header]), (e) => /INVALID - bad_signature/.test(e.stdout));
  });

  it('init writes a config that passes check', async () => {
    const config = join(dir, 'guard.config.json');
    const env = join(dir, '.env');
    await cli(['init', '--config', config, '--env', env, '--client', 'globex']);
    const envText = await readFile(env, 'utf8');
    assert.match(envText, /^GLOBEX_HMAC_SECRET=hgs_/m);
    const { stdout } = await cli(['--env-file', env, 'check', '--config', config]);
    assert.match(stdout, /partner-api/);
    assert.match(stdout, /Config OK/);
    await assert.rejects(cli(['init', '--config', config, '--env', env]), /already exists/);
  });

  it('demo --only generic passes and exits 0', async () => {
    const { stdout } = await cli(['demo', '--only', 'generic', '--json'], { timeout: 60_000 });
    const out = JSON.parse(stdout);
    assert.equal(out.suites[0].failed, 0);
  });
});
