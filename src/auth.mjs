// Auth: OAuth2 client-credentials (client_id/client_secret) -> short-lived HS256 JWT.
// No external deps: node:crypto only. Rotating any client secret in
// LARK_MCP_CLIENTS re-derives the JWT key, which revokes all issued tokens.
import crypto from 'node:crypto';

/** @typedef {{id: string, secret: string}} Client */

/**
 * Parse "id1:secret1,id2:secret2" into clients. Secrets may contain any
 * char except ':' ',' newline.
 * @param {string} spec
 * @returns {Client[]}
 */
export function parseClients(spec) {
  if (!spec?.trim()) return [];
  return spec.split(',').map((pair) => {
    const i = pair.indexOf(':');
    if (i <= 0 || i === pair.length - 1) {
      throw new Error(`bad client entry (want id:secret): ${JSON.stringify(pair.trim())}`);
    }
    return { id: pair.slice(0, i).trim(), secret: pair.slice(i + 1).trim() };
  });
}

/** Timing-safe string compare; length leak is acceptable (hash-style ids). */
export function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/** Derive the JWT signing key from all client secrets. */
export function deriveJwtKey(/** @type {Client[]} */ clients) {
  return crypto.createHash('sha256').update(clients.map((c) => c.secret).join('\n')).digest();
}

const b64u = (data) => Buffer.from(/** @type {any} */ (data)).toString('base64url');

/**
 * Sign an HS256 JWT.
 * @param {{sub: string, iss: string, exp: number}} claims
 * @param {Buffer} key
 */
export function signJwt(claims, key) {
  const header = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64u(JSON.stringify(claims));
  const sig = crypto.createHmac('sha256', key).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${sig}`;
}

/**
 * Verify an HS256 JWT; returns claims or null. Checks signature, alg, exp, iss.
 * @param {string} token
 * @param {Buffer} key
 * @param {string} issuer
 * @returns {{sub: string, exp: number} | null}
 */
export function verifyJwt(token, key, issuer) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, sig] = parts;
  let h;
  try {
    h = JSON.parse(Buffer.from(header, 'base64url').toString());
  } catch {
    return null;
  }
  if (h.alg !== 'HS256') return null;
  const expected = crypto.createHmac('sha256', key).update(`${header}.${payload}`).digest();
  const got = Buffer.from(sig, 'base64url');
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null;
  let p;
  try {
    p = JSON.parse(Buffer.from(payload, 'base64url').toString());
  } catch {
    return null;
  }
  if (p.iss !== issuer || typeof p.exp !== 'number' || p.exp <= Date.now() / 1000) return null;
  return p;
}

/**
 * Tiny in-memory per-IP failure lockout (public-internet hygiene).
 * @param {number} maxFails lock after this many failures
 * @param {number} lockMs lock duration
 */
export function makeFailureTracker(maxFails, lockMs) {
  /** @type {Map<string, {n: number, until: number}>} */
  const ips = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, st] of ips) if (st.until < now && st.n === 0) ips.delete(ip);
  }, 10 * 60_000);
  timer.unref?.();
  return {
    /** @returns {boolean} true if locked out */
    isLocked(/** @type {string} */ ip) {
      const st = ips.get(ip);
      if (!st) return false;
      if (st.until > Date.now()) return true;
      if (st.until !== 0 && st.until <= Date.now() && st.n === 0) ips.delete(ip);
      return false;
    },
    fail(/** @type {string} */ ip) {
      const st = ips.get(ip) ?? { n: 0, until: 0 };
      st.n += 1;
      if (st.n >= maxFails) {
        st.until = Date.now() + lockMs;
        st.n = 0;
      }
      ips.set(ip, st);
    },
    reset(/** @type {string} */ ip) {
      ips.delete(ip);
    },
  };
}
