// @ts-check
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * HMAC over several parts without joining them into one string first,
 * so binary bodies are signed byte for byte.
 * @param {string} algorithm e.g. 'sha256'
 * @param {string | Buffer} key
 * @param {Array<string | Buffer>} parts
 * @param {'hex' | 'base64'} [encoding]
 */
export function hmacParts(algorithm, key, parts, encoding = 'hex') {
  const h = createHmac(algorithm, key);
  for (const part of parts) h.update(part);
  return h.digest(encoding);
}

/** @param {string | Buffer} data */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Constant-time string comparison. Different lengths still burn one
 * comparison so the timing does not reveal where they differ.
 * @param {string} a
 * @param {string} b
 */
export function safeEqual(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) {
    timingSafeEqual(ba, ba);
    return false;
  }
  return timingSafeEqual(ba, bb);
}

export const randomNonce = (bytes = 16) => randomBytes(bytes).toString('hex');

/** 256-bit random secret, URL-safe. */
export const generateSecret = (prefix = 'hgs_', bytes = 32) => prefix + randomBytes(bytes).toString('base64url');

/** Secret in the Standard Webhooks / Svix format: whsec_<base64>. */
export const generateWhsec = (bytes = 24) => 'whsec_' + randomBytes(bytes).toString('base64');

/** API keys are stored hashed in config; only the client ever sees the plain key. */
export const hashApiKey = (/** @type {string} */ key) => 'sha256:' + sha256Hex(key);

/** @param {string} client */
export function generateKeyId(client = 'client') {
  const slug = String(client).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'client';
  const d = new Date();
  const ym = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
  return `${slug}-${ym}-${randomBytes(2).toString('hex')}`;
}

/** @param {unknown} body */
export function toBuffer(body) {
  if (body === undefined || body === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (body instanceof Uint8Array) return Buffer.from(body);
  return Buffer.from(JSON.stringify(body), 'utf8');
}
