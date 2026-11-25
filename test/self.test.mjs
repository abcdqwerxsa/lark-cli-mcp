// Self-checks for the non-trivial logic: JWT, client parsing, clipping, envelope unwrap.
import assert from 'node:assert/strict';

import crypto from "node:crypto";
import { test } from "node:test";
import { deriveJwtKey, makeFailureTracker, parseClients, safeEqual, signJwt, verifyJwt } from '../src/auth.mjs';
import { buildApiArgs, clip, scopeJq, toToolResult } from '../src/lark.mjs';

const key = crypto.createHash('sha256').update('s3cret').digest();

test('parseClients', () => {
  const cs = parseClients(' a:b ,x:y:z ');
  assert.deepEqual(cs.map((c) => c.id), ['a', 'x']);
  assert.equal(cs[1].secret, 'y:z');
  assert.deepEqual(parseClients(''), []);
  assert.deepEqual(parseClients(undefined), []);
  assert.throws(() => parseClients('noseparator'));
});

test('jwt roundtrip + tamper + expiry', () => {
  const now = Math.floor(Date.now() / 1000);
  const tok = signJwt({ iss: 'lark-mcp', sub: 'c1', exp: now + 60 }, key);
  assert.equal(verifyJwt(tok, key, 'lark-mcp')?.sub, 'c1');
  // tampered payload
  const [h, , s] = tok.split('.');
  const evil = signJwt({ iss: 'lark-mcp', sub: 'other', exp: now + 60 }, key);
  assert.equal(verifyJwt(`${h}.${evil.split('.')[1]}.${s}`, key, 'lark-mcp'), null);
  // wrong issuer
  assert.equal(verifyJwt(signJwt({ iss: 'x', sub: 'c1', exp: now + 60 }, key), key, 'lark-mcp'), null);
  // expired
  assert.equal(verifyJwt(signJwt({ iss: 'lark-mcp', sub: 'c1', exp: now - 1 }, key), key, 'lark-mcp'), null);
  // wrong key
  assert.equal(verifyJwt(tok, crypto.createHash('sha256').update('other').digest(), 'lark-mcp'), null);
});

test('safeEqual + deriveJwtKey depends on secrets', () => {
  assert.ok(safeEqual('abc', 'abc'));
  assert.ok(!safeEqual('abc', 'abd'));
  assert.ok(!safeEqual('abc', 'abcd'));
  assert.notDeepEqual(deriveJwtKey([{ id: 'a', secret: '1' }]), deriveJwtKey([{ id: 'a', secret: '2' }]));
});

test('failure tracker locks and recovers', () => {
  const t = makeFailureTracker(3, 50);
  t.fail('ip'); t.fail('ip');
  assert.equal(t.isLocked('ip'), false);
  t.fail('ip'); // 3rd failure -> locked
  assert.equal(t.isLocked('ip'), true);
  assert.equal(t.isLocked('other'), false);
  t.reset('other');
  // lock expires (50ms)
  return new Promise((r) => setTimeout(() => {
    assert.equal(t.isLocked('ip'), false);
    r();
  }, 60));
});

test('clip truncates on utf8 boundary-ish and reports size', () => {
  const c = clip('x'.repeat(10), 4);
  assert.equal(c.truncated, true);
  assert.ok(c.text.startsWith('xxxx'));
  assert.ok(c.text.includes('[truncated'));
  assert.equal(clip('ab', 4).truncated, false);
});

test('buildApiArgs maps flags', () => {
  assert.deepEqual(
    buildApiArgs({ method: 'get', path: 'im/v1/messages' }),
    ['api', 'GET', 'im/v1/messages'],
  );
  assert.deepEqual(buildApiArgs({ method: 'POST', path: 'im/v1/messages', as: 'bot' }), ['api', 'POST', 'im/v1/messages', '--as', 'bot']);
  assert.deepEqual(
    buildApiArgs({ method: 'POST', path: '/open-apis/im/v1/messages', params: { a: 1 }, data: { b: 2 }, jq: '.items', page_all: true, page_limit: 5 }),
    ['api', 'POST', '/open-apis/im/v1/messages', '--params', '{"a":1}', '--data', '{"b":2}', '--jq', '.data | (.items)', '--page-all', '--page-limit', '5'],
  );
});

test('scopeJq evaluates user expressions in the .data context', () => {
  // natural LLM forms get scoped
  assert.equal(scopeJq('.name'), '.data | (.name)');
  assert.equal(scopeJq('{name, open_id}'), '.data | ({name, open_id})');
  assert.equal(scopeJq('.items[] | {id, name}'), '.data | (.items[] | {id, name})');
  assert.equal(scopeJq('.[0].id'), '.data[0].id');
  assert.equal(scopeJq('.'), '.data');
  // envelope-aware expressions are left alone
  assert.equal(scopeJq('.data.name'), '.data.name');
  assert.equal(scopeJq('.meta.pagination.next_token'), '.meta.pagination.next_token');
  assert.equal(scopeJq('.ok'), '.ok');
});

test('toToolResult unwraps success envelope (object, array+pagination)', () => {
  const ok = toToolResult({ code: 0, stdout: JSON.stringify({ ok: true, data: { a: 1 } }), stderr: '', timedOut: false }, 65536);
  assert.equal(ok.isError, undefined);
  assert.equal(JSON.parse(ok.content[0].text).a, 1);

  const pag = toToolResult({ code: 0, stdout: JSON.stringify({ ok: true, data: [1, 2], meta: { pagination: { complete: false, pages: 1, items: 2, next_token: 't' } } }), stderr: '', timedOut: false }, 65536);
  const parsed = JSON.parse(pag.content[0].text);
  assert.deepEqual(parsed.data, [1, 2]);
  assert.equal(parsed._pagination.next_token, 't');

  // success envelope whose data exceeds max -> truncated
  const big = toToolResult({ code: 0, stdout: JSON.stringify({ ok: true, data: { s: 'y'.repeat(1000) } }), stderr: '', timedOut: false }, 100);
  assert.ok(big.content[0].text.includes('[truncated'));
});

test('toToolResult: --jq output (bare value / stream) with exit 0 is success', () => {
  const bare = toToolResult({ code: 0, stdout: '"\\u848b\\u90f4\\u946b"', stderr: '', timedOut: false }, 65536);
  assert.equal(bare.isError, undefined);
  assert.equal(JSON.parse(bare.content[0].text), '蒋郴鑫');
  const stream = toToolResult({ code: 0, stdout: '{"a":1}\n{"a":2}\n', stderr: '', timedOut: false }, 65536);
  assert.equal(stream.isError, undefined);
  assert.equal(stream.content[0].text, '{"a":1}\n{"a":2}');
  // an error envelope on stderr still wins when exit code is non-zero
  const err = toToolResult({ code: 3, stdout: '', stderr: JSON.stringify({ ok: false, error: { message: 'x' } }), timedOut: false }, 65536);
  assert.equal(err.isError, true);
});

test('toToolResult maps error envelope and raw failures', () => {
  const err = toToolResult({ code: 3, stdout: '', stderr: JSON.stringify({ ok: false, error: { message: 'need login', hint: 'auth login' } }), timedOut: false }, 65536);
  assert.equal(err.isError, true);
  const parsed = JSON.parse(err.content[0].text);
  assert.equal(parsed.message, 'need login');

  const raw = toToolResult({ code: 127, stdout: '', stderr: 'Error: spawn lark-cli ENOENT', timedOut: false }, 65536);
  assert.equal(raw.isError, true);
  assert.ok(raw.content[0].text.includes('ENOENT'));

  const t = toToolResult({ code: 1, stdout: '', stderr: '', timedOut: true }, 65536);
  assert.equal(t.isError, true);
  assert.ok(t.content[0].text.includes('timed out'));
});


import { createOAuth, mountOAuth, GOOGLE_REDIRECT_RE, GOOGLE_REDIRECT_URIS } from '../src/oauth.mjs';
import express from 'express';

const oauthCfg = () => ({
  clients: [{ id: 'gemini', secret: 'gs3cret' }],
  jwtKey: crypto.createHash('sha256').update('k').digest(),
  issuer: 'lark-mcp',
  tokenTtl: 60,
  refreshTtl: 3600,
  publicUrl: 'https://mcp.example.test',
});
const VERIFIER = crypto.randomBytes(32).toString('base64url'); // 43 chars
const CHALLENGE = crypto.createHash('sha256').update(VERIFIER).digest('base64url');
const G_URI = 'https://oauth-redirect.googleusercontent.com/r/abc123';
const basic = (id, s) => ({ _basic: Buffer.from(`${id}:${s}`).toString('base64') });

test('redirect allowlist matches Google variants only', () => {
  const mine = 'https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-d9d9d6165bd340bea77cc9ac';
  assert.ok(GOOGLE_REDIRECT_URIS.has(mine), 'the registered app redirect URI is allowlisted exactly');
  const o0 = createOAuth(oauthCfg());
  assert.equal(o0.authorize(new URL(`http://x/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: 'gemini', redirect_uri: mine, code_challenge: CHALLENGE, code_challenge_method: 'S256' })}`)).error, undefined);
  for (const u of [
    'https://oauth-redirect.googleusercontent.com/r/abc',
    'https://oauth-redirect.googleusercontent.com/a/abc',
    'https://oauth-redirect-sandbox.googleusercontent.com/r/abc',
    'https://oauth-redirect-test.googleusercontent.com/a/abc',
  ]) assert.ok(GOOGLE_REDIRECT_RE.test(u), u);
  for (const u of [
    'http://oauth-redirect.googleusercontent.com/r/abc', // not https
    'https://oauth-redirect.googleusercontent.com/x/abc', // wrong prefix
    'https://evil.example/r/abc',
    'https://oauth-redirect.googleusercontent.com.evil.example/r/abc',
  ]) assert.ok(!GOOGLE_REDIRECT_RE.test(u), u);
});

test('authorize validates response_type, client, redirect_uri, PKCE', () => {
  const o = createOAuth(oauthCfg());
  const q = (over = {}) => {
    const p = new URLSearchParams({
      response_type: 'code',
      client_id: 'gemini',
      redirect_uri: G_URI,
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
      state: 'st',
      ...over,
    });
    return o.authorize(new URL(`http://x/oauth/authorize?${p}`));
  };
  assert.equal(q().clientId, 'gemini');
  assert.equal(q({ response_type: 'token' }).error, 'unsupported_response_type');
  assert.equal(q({ client_id: 'nope' }).error, 'invalid_client');
  assert.ok(q({ redirect_uri: 'https://evil.example/r/x' }).error.startsWith('invalid_request'));
  assert.ok(q({ code_challenge_method: 'plain' }).error.startsWith('invalid_request'));
  assert.ok(q({ code_challenge: 'short' }).error.startsWith('invalid_request'));
});

test('full authorization_code + PKCE roundtrip, replay and mismatch rejected', () => {
  const o = createOAuth(oauthCfg());
  const auth = o.authorize(
    new URL(
      `http://x/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: 'gemini',
        redirect_uri: G_URI,
        code_challenge: CHALLENGE,
        code_challenge_method: 'S256',
        state: 'xyz',
      })}`,
    ),
  );
  assert.ok(!auth.error);
  // consent form (hidden fields are client-controlled: must be re-validated)
  assert.equal(o.consent({ client_id: 'gemini', secret: 'wrong', redirect_uri: G_URI, code_challenge: CHALLENGE, scope: 'mcp', state: 'xyz' }), null);
  assert.equal(o.consent({ client_id: 'gemini', secret: 'gs3cret', redirect_uri: 'https://evil.example/r/x', code_challenge: CHALLENGE, scope: 'mcp', state: 'xyz' }), null);
  const redirect = o.consent({ client_id: 'gemini', secret: 'gs3cret', redirect_uri: G_URI, code_challenge: CHALLENGE, scope: 'mcp', state: 'xyz' });
  const u = new URL(redirect);
  assert.equal(u.origin + u.pathname, G_URI);
  assert.equal(u.searchParams.get('state'), 'xyz');
  const code = u.searchParams.get('code');
  const exchange = (over = {}) =>
    o.token({ ...basic('gemini', 'gs3cret'), grant_type: 'authorization_code', code, redirect_uri: G_URI, code_verifier: VERIFIER, ...over });
  // wrong verifier / wrong redirect / foreign client
  assert.equal(exchange({ code_verifier: crypto.randomBytes(32).toString('base64url') }).body.error, 'invalid_grant');
  assert.equal(exchange({ redirect_uri: 'https://oauth-redirect.googleusercontent.com/a/other' }).body.error, 'invalid_grant');
  assert.equal(o.token({ client_id: 'other', client_secret: 'x', grant_type: 'authorization_code', code, redirect_uri: G_URI, code_verifier: VERIFIER }).status, 401);
  // good exchange
  const ok = exchange();
  assert.equal(ok.status, 200);
  assert.ok(ok.body.access_token && ok.body.refresh_token && ok.body.token_type === 'Bearer');
  const claims = verifyJwt(ok.body.access_token, oauthCfg().jwtKey, 'lark-mcp');
  assert.equal(claims.sub, 'gemini');
  assert.equal(claims.scope, 'mcp');
  // code is single-use
  assert.equal(exchange().body.error, 'invalid_grant');
  // refresh works once; replay of the same refresh token is rejected
  const r1 = o.token({ ...basic('gemini', 'gs3cret'), grant_type: 'refresh_token', refresh_token: ok.body.refresh_token });
  assert.equal(r1.status, 200);
  assert.ok(verifyJwt(r1.body.access_token, oauthCfg().jwtKey, 'lark-mcp'));
  assert.equal(o.token({ ...basic('gemini', 'gs3cret'), grant_type: 'refresh_token', refresh_token: ok.body.refresh_token }).body.error, 'invalid_grant');
  // refresh token cannot be used as an access token
  assert.equal(verifyJwt(ok.body.refresh_token, oauthCfg().jwtKey, 'lark-mcp')?.typ, 'refresh');
});

test('client_credentials still works and bad clients are 401', () => {
  const o = createOAuth(oauthCfg());
  assert.equal(o.token({ ...basic('gemini', 'gs3cret'), grant_type: 'client_credentials' }).status, 200);
  assert.equal(o.token({ client_id: 'gemini', client_secret: 'nope', grant_type: 'client_credentials' }).status, 401);
  assert.equal(o.token({ ...basic('gemini', 'gs3cret'), grant_type: 'password' }).body.error, 'unsupported_grant_type');
});

test('consent page hidden fields carry the exact authorize params (regression: undefined code_challenge)', async () => {
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  mountOAuth(app, createOAuth(oauthCfg()));
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  try {
    const q = new URLSearchParams({
      response_type: 'code', client_id: 'gemini', redirect_uri: G_URI,
      code_challenge: CHALLENGE, code_challenge_method: 'S256', state: 'xyz', scope: 'mcp',
    });
    const html = await (await fetch(`http://127.0.0.1:${server.address().port}/oauth/authorize?${q}`)).text();
    const field = (n) => html.match(new RegExp(`name=${n} value="([^"]*)"`))?.[1];
    assert.equal(field('code_challenge'), CHALLENGE);
    assert.equal(field('state'), 'xyz');
    assert.equal(field('scope'), 'mcp');
    assert.equal(field('redirect_uri'), G_URI);
    assert.equal(field('client_id'), 'gemini');
    // and the real form post succeeds end-to-end through HTTP
    const post = await fetch(`http://127.0.0.1:${server.address().port}/oauth/consent`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'gemini', secret: 'gs3cret', redirect_uri: G_URI, code_challenge: CHALLENGE, scope: 'mcp', state: 'xyz' }),
    });
    assert.equal(post.status, 302);
    assert.ok(post.headers.get('location')?.startsWith(G_URI));
  } finally {
    server.close();
  }
});
