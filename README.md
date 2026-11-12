# hmac-guard: API Authentication & HMAC Guard Middleware

Protects public API and webhook endpoints against **DDoS-style floods, replay attacks and unauthorized spam**.
Use it as Express middleware in an existing app, or run it as a stand-alone **webhook gateway** in front of n8n, Make, Zapier or any internal API.

**Stack:** JavaScript (Node.js ESM) with Express 5, `node:crypto` and `rate-limiter-flexible`. It is middleware plus a CLI, with no build step and three runtime dependencies (plus optional `ioredis`).

```
Internet ──► hmac-guard ──(verified, unique, rate-limited)──► n8n / Make / CRM / your API
             │
             ├─ 1  IP deny / allow list (CIDR, v4+v6)          403
             ├─ 2  IP banned after repeated bad signatures     429
             ├─ 3  per-IP rate limit (before any body read)    429
             ├─ 4  global rate limit (protects the upstream)   503
             ├─ 5  method / content type / declared size       405 / 415 / 413
             ├─ 6  raw body read with byte limit + timeout     413 / 408
             ├─ 7  HMAC signature + timestamp window           401
             ├─ 8  replay check (nonce / signature seen)       409
             └─ 9  per-client rate limit                       429
```

The checks run in order of cost. A flood is dropped before the body is read or any HMAC is computed. Replay nonces are stored only after a valid signature, so an attacker without the secret cannot fill the store.

## What it stops

| Attack | Defense | Result |
|---|---|---|
| Unsigned spam / bots hitting a public webhook URL | Signature required | `401 missing_signature` |
| Forged requests, guessed secrets | HMAC-SHA256, constant-time compare | `401 bad_signature` |
| Body edited in transit (amount, email, status) | Signature covers the raw bytes | `401 bad_signature` |
| Captured request re-sent later | Timestamp window (default 300 s) | `401 stale_timestamp` |
| Captured request re-sent immediately | Nonce / signature replay store | `409 replay` |
| Signature reused on another endpoint | Path and method are signed (generic scheme) | `401 bad_signature` |
| Brute force on the secret | IP banned after N failures | `429 ip_banned` |
| Request floods / spam bursts | Per-IP, global and per-client limits | `429` / `503` + `Retry-After` |
| Huge or endless bodies, slowloris | Byte limit, body timeout, server header/request timeouts | `413` / `408` |
| Leaked key | Key rotation with `expiresAt`, per-key limits | `401 key_expired` |

## Quick start

```bash
npm install
node bin/hmac-guard.js demo          # gateway + mock upstream + 57 attack scenarios, no setup
```

Real setup:

```bash
node bin/hmac-guard.js init --client acme   # guard.config.json + generated secrets in .env
# edit .env: upstream URLs (n8n...), provider secrets (Stripe, GitHub...)
node bin/hmac-guard.js check                # validate config, list routes and limits
node bin/hmac-guard.js serve                # run the gateway
node bin/hmac-guard.js attack http://localhost:8080/hooks/partner --key-id <id> --secret <secret>
node bin/hmac-guard.js stats --since 24h    # what was blocked, top attacker IPs, top clients
```

Install globally with `npm link` to type `hmac-guard ...` instead of `node bin/hmac-guard.js ...`.

## CLI

| Command | What it does |
|---|---|
| `demo [--only generic,stripe]` | Starts a gateway and a mock upstream, attacks every provider route, and prints PASS/FAIL tables. |
| `init [--client name]` | Writes a starter `guard.config.json` and appends generated secrets to `.env` (it never overwrites existing values). |
| `keygen --client acme [--type hmac\|whsec\|apikey] [--expires 2027-01-01]` | Creates a key id and secret for a partner. For API keys it prints the hash to store. |
| `sign -u URL -s SECRET [-p provider] [-k keyId] [-d body] [--curl]` | Prints signature headers or a ready `curl` command. |
| `verify -s SECRET -H "Name: value" ... -d body` | Checks a captured request offline and says why it fails. |
| `send URL -s SECRET -k keyId -d body` | Signs and sends a request the way a partner would. |
| `check [-c config]` | Validates the config and lists routes, limits and warnings. |
| `serve [-c config] [--port]` | Runs the gateway. It shuts down cleanly on SIGTERM and finishes background deliveries first. |
| `attack URL -s SECRET [-k id] [--skip-flood] [--spoof-ips] [--json]` | Runs the attack suite against a live endpoint. It exits 1 if anything got through, so you can use it in CI. |
| `stats [--file] [--since 24h] [--json]` | Summarizes the audit log. |
| `providers` | Lists the signature schemes. |

`--secret env:NAME` reads the secret from the environment, so it stays out of shell history.

## Providers

| `provider` | Used by | Timestamp | Replay key |
|---|---|---|---|
| `generic` | Your own partners and clients (spec below) | yes | key id + nonce |
| `stripe` | Stripe | yes | signature |
| `slack` | Slack Events, slash commands, interactivity | yes | signature |
| `standard` (`svix`, `resend`, `clerk`) | Standard Webhooks: Svix, Resend, Clerk and others | yes | `webhook-id` |
| `github` | GitHub | no | signature (kept `replayTtlSec`) |
| `shopify` | Shopify | no | signature |
| `twilio` (`whatsapp`) | Twilio SMS / WhatsApp / Voice | no | signature |
| `apikey` | Internal callers (`X-API-Key` or `Bearer`), keys stored as SHA-256 hashes | no | none |

The Stripe, GitHub, Slack, Standard Webhooks and Twilio implementations are tested against the providers' published reference signatures (`test/providers.test.js`).

## Generic scheme (give this to partners)

```
X-Guard-Key-Id:    acme-202611-ab12
X-Guard-Timestamp: 1762950000                 (unix seconds)
X-Guard-Nonce:     32 random hex chars, new for every request
X-Guard-Signature: v1=<hex HMAC-SHA256(secret, canonical)>

canonical = "v1\n" + timestamp + "\n" + nonce + "\n" + METHOD + "\n" + path_and_query + "\n" + sha256_hex(raw_body)
```

Ready-made clients: [examples/sign-request.mjs](examples/sign-request.mjs) (Node, no dependencies) and [examples/sign-request.py](examples/sign-request.py) (Python standard library). For curl, run `hmac-guard sign --curl`.

## Configuration

See [examples/guard.config.example.json](examples/guard.config.example.json). Any string can be `env:NAME`, which is required, or `env:NAME?`, which is optional. A route whose secrets are all unset is **disabled with a warning**, so you can enable a provider by filling in `.env`.

| Key | Default | Notes |
|---|---|---|
| `server.trustProxy` | `false` | Set this to `1` behind one proxy, or to the proxy IPs. **Never** use `true` in production, because then anyone can fake `X-Forwarded-For`. |
| `server.metricsToken` | none | Bearer token for `/metrics` (Prometheus). |
| `limits.ip` | 30 / 1 s, block 10 s | Applies to every request, before any work. |
| `limits.global` | 1000 / 1 s | Caps the load sent to the upstream. |
| `limits.failedAuth` | 10 / 10 min, ban 15 min | Brute-force and spam ban. |
| `limits.client` | 600 / 60 s | Applies per client, per route. A key's own `limit` overrides it. |
| `defaults.toleranceSec` | 300 | Timestamp window. |
| `defaults.maxBodyBytes` | 1 MiB | |
| `defaults.replayTtlSec` | 86400 | Replay memory for providers without timestamps. |
| route `forward` | none | `{ url, mode: "sync"\|"async", retries, timeoutMs, secret, headers }` |
| route `bindPath` | `true` | Signs the path (generic scheme). Set it to `false` if a proxy rewrites paths. |
| route `publicBaseUrl` | none | The public `https://` origin. Twilio needs it behind a proxy. |
| route `ipAllow` / `ipDeny` | none | CIDR lists per route, for example a provider's published IP ranges. |
| `exposeReasons` | `true` | Set it to `false` to answer only `{"error":"rejected"}`. |

### Forwarding

- **`async`** answers `202` straight away, so webhook senders never time out. It then delivers in the background with exponential backoff (on network errors, 5xx, 408 and 429). Requests that still fail are written to `deadLetterFile` with the full body.
- **`sync`** waits for the upstream and passes its status and body back. Use it for Twilio replies or any API that returns data.
- The upstream receives `X-Guard-Verified`, `X-Guard-Client`, `X-Guard-Route` and `X-Guard-Request-Id`. Any `X-Guard-*` headers sent by the caller are stripped, so they cannot be spoofed. With `forward.secret` set, the gateway also signs the forwarded call with the generic scheme, so the upstream can check that it came from the gateway.

## Library use

```js
import express from 'express';
import { hmacGuard } from 'hmac-guard';

const app = express();
app.post('/webhooks/stripe', hmacGuard({ provider: 'stripe', secret: process.env.STRIPE_WEBHOOK_SECRET }),
  (req, res) => { /* req.body verified + parsed, req.guard.client */ res.json({ ok: true }); });
app.use(express.json()); // other routes
```

Mount guarded routes **before** `express.json()`. If you can't, use `express.json({ verify: captureRawBody })`. The full example is in [examples/express-app.js](examples/express-app.js).

Exports: `hmacGuard`, `createGuard`, `createShared`, `captureRawBody`, `providers`, `signRequest`, `sendSigned`, `MemoryNonceStore`, `RedisNonceStore`, `Audit`, `startGateway`, `runAttackSuite`, `loadConfig`, `generateSecret`, `hashApiKey`.

## Deploy

```bash
docker build -t hmac-guard .
docker run -p 8080:8080 --env-file .env -v $PWD/config:/app/config:ro -v $PWD/logs:/app/logs hmac-guard
# several replicas with shared limits + replay store:
docker compose up -d --scale guard=2
```

- Put it behind TLS (Caddy, nginx, a cloud load balancer) and set `trustProxy` to match.
- With more than one instance, set `REDIS_URL`. Rate limits and replay nonces are then shared. Floods are still answered from memory once a key is over its limit, and if Redis goes down each instance falls back to a local limiter instead of failing open.
- `GET /healthz` is for liveness. `GET /metrics` exposes Prometheus counters by route, outcome and reason, plus forward stats.
- The audit log is JSONL. During a flood, repeated rate-limit rejections are written as one summary line per IP every 10 s, so an attack cannot fill the disk.

## Limits (be honest with clients)

- This stops **application-layer** abuse: request floods, spam, brute force and replays. Volumetric network DDoS (saturated bandwidth, SYN floods) has to be absorbed upstream by a CDN or WAF such as Cloudflare or AWS Shield. hmac-guard is the layer behind that.
- GitHub, Shopify and Twilio signatures carry no timestamp. A replay of the exact same request is blocked for `replayTtlSec`, after which it would be accepted again.
- Twilio JSON callbacks are only protected when Twilio adds `bodySHA256`. Form posts, which are the default, are fully signed.
- `apikey` routes have no replay protection by design. Use HMAC for anything that changes state.
- The memory stores are per process. Use Redis for multiple instances.

## Tests

```bash
npm test     # 56 tests: provider reference vectors, every guard branch, gateway forwarding, dead letters, CLI, full attack suite
npm run demo # 57 attack scenarios across 6 providers
```

## License

MIT
