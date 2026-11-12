// Library mode: protect routes inside an existing Express app.
//   STRIPE_WEBHOOK_SECRET=whsec_... PARTNER_SECRET=hgs_... node examples/express-app.js
// In your own project: import { hmacGuard } from 'hmac-guard';
import express from 'express';
import { hmacGuard, MemoryNonceStore } from '../src/index.js';

const app = express();
app.set('trust proxy', 1); // one reverse proxy (nginx, Caddy, a load balancer) in front

// Mount guarded routes BEFORE express.json(): the guard must see the raw bytes.
app.post('/webhooks/stripe',
  hmacGuard({ provider: 'stripe', secret: process.env.STRIPE_WEBHOOK_SECRET ?? 'whsec_dev' }),
  (req, res) => {
    // req.body is parsed JSON, verified; req.guard = { client, keyId, timestamp, ... }
    console.log('stripe event', req.body.type);
    res.json({ received: true });
  });

// Your own partner API with key rotation and per-client limits.
app.post('/api/partner/leads',
  hmacGuard({
    provider: 'generic',
    keys: [
      { id: 'acme-202611', client: 'acme', secret: process.env.PARTNER_SECRET ?? 'hgs_dev_secret_change_me_0000000000000' },
      // old key keeps working until it expires: zero-downtime rotation
      { id: 'acme-202605', client: 'acme', secret: process.env.PARTNER_SECRET_OLD ?? 'old', expiresAt: '2026-12-31' },
    ],
    contentTypes: ['application/json'],
    maxBodyBytes: 256 * 1024,
    limits: { client: { points: 120, duration: 60 } },
    nonceStore: new MemoryNonceStore(),
    onReject: ({ reason, ip }) => { if (reason === 'ip_banned') console.warn('banned', ip); },
  }),
  (req, res) => res.status(201).json({ ok: true, client: req.guard.client }));

// Everything else can use the normal JSON parser.
app.use(express.json());
app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(3000, () => console.log('listening on http://localhost:3000'));
