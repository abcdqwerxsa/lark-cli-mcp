// Minimal OAuth 2.1 Authorization Server: authorization_code + PKCE (S256),
// refresh_token, and client_credentials. No user database — the consent screen
// asks for the client's own secret, so only someone who already holds the
// credential can complete a browser sign-in.
import crypto from 'node:crypto';
import { safeEqual, signJwt, verifyJwt } from './auth.mjs';
/** The one Google Connected Apps redirect URI registered for this MCP app. */
export const GOOGLE_REDIRECT_URIS = new Set([
  'https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-d9d9d6165bd340bea77cc9ac',
]);
/** @deprecated kept for callers that need a regex; prefer GOOGLE_REDIRECT_URIS. */
export const GOOGLE_REDIRECT_RE =
  /^https:\/\/oauth-redirect(?:-sandbox|-test)?\.googleusercontent\.com\/[ra]\/.+$/;
const redirectAllowed = (/** @type {string} */ uri) =>
  GOOGLE_REDIRECT_URIS.has(uri) || GOOGLE_REDIRECT_RE.test(uri);

/** @typedef {{id: string, secret: string}} Client */

/**
 * @param {{clients: Client[], jwtKey: Buffer, issuer: string, tokenTtl: number, refreshTtl: number, publicUrl: string}} cfg
 */
export function createOAuth(cfg) {
  const clientMap = new Map(cfg.clients.map((c) => [c.id, c.secret]));
  /** @type {Map<string, {clientId: string, redirectUri: string, codeChallenge: string, scope: string, exp: number}>} */
  const codes = new Map();
  /** @type {Set<string>} refresh token ids that were rotated (replay guard) */
  const usedRefresh = new Set();
  let seq = 0;
  const now = () => Math.floor(Date.now() / 1000);
  const rnd = () => crypto.randomBytes(32).toString('base64url');

  const verifyPkce = (challenge, verifier) =>
    /^[A-Za-z0-9_-]{43,128}$/.test(verifier) &&
    crypto.createHash('sha256').update(verifier).digest('base64url') === challenge;

  // Shared validation for /oauth/authorize and the consent form (hidden fields are client-controlled).
  const validate = (clientId, redirectUri, challenge, method) => {
    if (!clientMap.has(clientId)) return 'invalid_client';
    if (!redirectAllowed(redirectUri)) return 'invalid_request: redirect_uri is not allowlisted';
    if (method && method !== 'S256') return 'invalid_request: code_challenge_method must be S256';
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) return 'invalid_request: bad code_challenge';
    return null;
  };

  const issue = (sub, scope) => {
    const t = now();
    const refresh = `${sub}.${rnd()}`;
    return {
      access_token: signJwt({ iss: cfg.issuer, sub, iat: t, exp: t + cfg.tokenTtl, scope }, cfg.jwtKey),
      token_type: 'Bearer',
      expires_in: cfg.tokenTtl,
      refresh_token: signJwt({ iss: cfg.issuer, sub, jti: refresh, iat: t, exp: t + cfg.refreshTtl, scope, typ: 'refresh' }, cfg.jwtKey),
      scope,
    };
  };

  return {
    /** GET /oauth/authorize — consent screen; verifies client, redirect_uri, PKCE. */
    authorize(/** @type {URL} */ url) {
      const p = url.searchParams;
      const clientId = p.get('client_id') ?? '';
      const redirectUri = p.get('redirect_uri') ?? '';
      const challenge = p.get('code_challenge') ?? '';
      const method = p.get('code_challenge_method') ?? '';
      const scope = p.get('scope') ?? 'mcp';
      const state = p.get('state') ?? '';
      const err = (error, desc) => ({ error, error_description: desc });
      if (p.get('response_type') !== 'code') return err('unsupported_response_type', 'only "code" is supported');
      const invalid = validate(clientId, redirectUri, challenge, method);
      if (invalid) {
        const [error, error_description] = invalid.split(': ');
        return err(error, error_description);
      }
      return { clientId, redirectUri, codeChallenge: challenge, scope, state };
    },

    /** Validate the consent form and mint a one-time code (60s). */
    consent(/** @type {Record<string, string>} */ f) {
      const expected = clientMap.get(f.client_id);
      if (!expected || !f.secret || !safeEqual(f.secret, expected)) {
        console.log(`consent REJECT client=${f.client_id} reason=${expected ? 'bad secret' : 'unknown client'} secret_len=${(f.secret ?? '').length}`);
        return null;
      }
      if (validate(f.client_id, f.redirect_uri, f.code_challenge, '')) {
        console.log(`consent REJECT client=${f.client_id} reason=${validate(f.client_id, f.redirect_uri, f.code_challenge, '')} redirect_uri=${f.redirect_uri}`);
        return null;
      }
      const code = rnd();
      codes.set(code, {
        clientId: f.client_id,
        redirectUri: f.redirect_uri,
        codeChallenge: f.code_challenge,
        scope: f.scope,
        exp: now() + 60,
      });
      const to = new URL(f.redirect_uri);
      to.searchParams.set('code', code);
      to.searchParams.set('state', f.state);
      return to.toString();
    },

    /** POST /oauth/token */
    token(/** @type {Record<string, string>} */ f) {
      const bad = (error, error_description, status = 400) => ({ status, body: { error, error_description } });
      // client auth: Basic or form
      let id = '';
      let secret = '';
      if (f._basic) {
        const dec = Buffer.from(f._basic, 'base64').toString('utf8').split(':');
        id = decodeURIComponent(dec[0] ?? '');
        secret = decodeURIComponent(dec.slice(1).join(':'));
      }
      id ||= f.client_id ?? '';
      secret ||= f.client_secret ?? '';
      if (id && clientMap.has(id) && secret && safeEqual(secret, clientMap.get(id))) {
        /* authenticated */
      } else {
        return bad('invalid_client', 'unknown client or bad secret', 401);
      }
      const grant = f.grant_type ?? '';
      if (grant === 'client_credentials') return { status: 200, body: issue(id, f.scope ?? 'mcp') };
      if (grant === 'refresh_token') {
        const claims = verifyJwt(f.refresh_token ?? '', cfg.jwtKey, cfg.issuer);
        if (!claims || claims.typ !== 'refresh' || claims.sub !== id) return bad('invalid_grant', 'bad refresh token');
        if (usedRefresh.has(claims.jti)) return bad('invalid_grant', 'refresh token already used');
        usedRefresh.add(claims.jti);
        return { status: 200, body: issue(id, claims.scope ?? 'mcp') };
      }
      if (grant === 'authorization_code') {
        const rec = codes.get(f.code ?? '');
        if (!rec || rec.exp < now() || rec.clientId !== id) return bad('invalid_grant', 'unknown, expired or foreign code');
        if (rec.redirectUri !== (f.redirect_uri ?? '')) return bad('invalid_grant', 'redirect_uri mismatch');
        if (!verifyPkce(rec.codeChallenge, f.code_verifier ?? '')) return bad('invalid_grant', 'PKCE verification failed');
        codes.delete(f.code);
        return { status: 200, body: issue(id, rec.scope) };
      }
      return bad('unsupported_grant_type', 'supported: authorization_code, refresh_token, client_credentials');
    },
  };
}

/**
 * Mount the authorization-server routes on an Express app.
 * @param {import('express').Express} app
 * @param {ReturnType<typeof createOAuth>} oauth
 */
export function mountOAuth(app, oauth) {
  app.get('/oauth/authorize', (req, res) => {
    const auth = oauth.authorize(new URL(req.url, 'http://x'));
    if (auth.error) return res.status(400).json(auth);
    // Consent page: the only "user" is whoever holds the client secret.
    res.type('html').send(`<!doctype html><meta charset=utf-8><title>lark-mcp sign in</title>
<form method=post action=/oauth/consent>
<input type=hidden name=client_id value="${auth.clientId}">
<input type=hidden name=redirect_uri value="${auth.redirectUri}">
<input type=hidden name=code_challenge value="${auth.codeChallenge}">
<input type=hidden name=scope value="${auth.scope}">
<input type=hidden name=state value="${auth.state}">
<h2>Allow "${auth.clientId}" to use lark-mcp?</h2>
<p>This signs the MCP client in as the Feishu user configured on this server.</p>
<label>Client secret <input type=password name=secret autocomplete=current-password autofocus></label>
<button>Allow</button>
</form>`);
  });

  app.post('/oauth/consent', (req, res) => {
    const target = oauth.consent(req.body ?? {});
    if (!target) {
      res.status(403).type('text/plain').send('wrong client secret or redirect_uri not allowlisted');
      return;
    }
    res.redirect(302, target);
  });

  // Body parsing is already app-wide (index.mjs: express.urlencoded).
  app.post('/oauth/token', (req, res) => {
    const result = oauth.token({ ...req.body, _basic: req.headers.authorization?.startsWith('Basic ') ? req.headers.authorization.slice(6) : '' });
    res.status(result.status).json(result.body);
  });
}
