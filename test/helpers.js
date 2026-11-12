import { createServer } from 'node:http';
import express from 'express';

/** Start an Express app on a random port. */
export async function listen(app) {
  const server = createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    close: () => new Promise((r) => { server.close(r); server.closeAllConnections(); }),
  };
}

/** App with one guarded POST route that echoes what the guard attached. */
export function appWith(path, guard, { trustProxy = true } = {}) {
  const app = express();
  app.set('trust proxy', trustProxy);
  app.all(path, guard, (req, res) => res.json({ ok: true, guard: req.guard, body: req.body, raw: req.rawBody?.length }));
  return app;
}

export async function post(url, { body = '', headers = {}, ip } = {}) {
  const h = { 'content-type': 'application/json', ...headers };
  if (ip) h['x-forwarded-for'] = ip;
  const r = await fetch(url, { method: 'POST', headers: h, body });
  const text = await r.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, body: json, headers: r.headers };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
