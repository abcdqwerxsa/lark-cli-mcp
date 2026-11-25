// lark-mcp: MCP server wrapping the official lark-cli (@larksuite/cli).
// Public-internet deployment: OAuth2 client-credentials (client_id/client_secret)
// -> short-lived Bearer JWT, RFC 9728/8414 discovery, Host validation,
// per-IP failure lockout. Streamable HTTP, stateless (no server-side sessions).
import express from 'express';
import { z } from 'zod';
import {
  createMcpExpressApp,
  getOAuthProtectedResourceMetadataUrl,
  hostHeaderValidation,
  mcpAuthMetadataRouter,
  requireBearerAuth,
} from '@modelcontextprotocol/express';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { McpServer, OAuthError, OAuthErrorCode } from '@modelcontextprotocol/server';
import { deriveJwtKey, makeFailureTracker, parseClients, verifyJwt } from './auth.mjs';
import { larkApiTool, larkAuthStatusTool } from './lark.mjs';
import { createOAuth, mountOAuth } from './oauth.mjs';

const env = process.env;
const ISSUER = 'lark-mcp';
const clients = parseClients(env.LARK_MCP_CLIENTS ?? '');
if (clients.length === 0) {
  console.error('LARK_MCP_CLIENTS is required: "client-id:client-secret[,id2:secret2]"');
  process.exit(1);
}
const clientMap = new Map(clients.map((c) => [c.id, c.secret]));
const jwtKey = deriveJwtKey(clients);
const tokenTtl = Number(env.LARK_MCP_TOKEN_TTL) || 3600;
const publicUrl = env.LARK_MCP_PUBLIC_URL; // e.g. https://lark-mcp.example.com (behind TLS proxy)
// The OAuth "resource" is the MCP endpoint itself (RFC 9728 path-specific metadata),
// so clients that bind tokens to the resource see https://<host>/mcp, not the host root.
const mcpUrl = publicUrl ? `${publicUrl.replace(/\/$/, '')}/mcp` : undefined;
const host = env.HOST ?? '127.0.0.1';
const port = Number(env.PORT) || 3333;
const failures = makeFailureTracker(Number(env.LARK_MCP_MAX_FAILS) || 10, 15 * 60_000);
const oauth = createOAuth({
  clients,
  jwtKey,
  issuer: ISSUER,
  tokenTtl,
  refreshTtl: Number(env.LARK_MCP_REFRESH_TTL) || 30 * 86400,
  publicUrl,
});

const allowedHosts = publicUrl
  ? [new URL(publicUrl).hostname, 'localhost', '127.0.0.1', '[::1]']
  : undefined;
// Host validation is mounted manually below so /healthz (kubelet probes hit the
// pod IP, whose Host is not allowlisted) can sit in front of it.
const app = createMcpExpressApp({ host, jsonLimit: '8mb' });
if (allowedHosts) app.set('trust proxy', 1); // real client IP from X-Forwarded-For behind the TLS proxy
// Access log (traefik has none): method, path, status, client, UA — enough to see
// whether an OAuth client like Gemini actually reaches us, and with what.
app.use((req, res, next) => {
  res.on('finish', () => {
    if (req.path !== '/healthz') {
      console.log(
        `${req.method} ${req.originalUrl} ${res.statusCode} ip=${req.ip} ua=${(req.headers['user-agent'] ?? '-').slice(0, 60)}`,
      );
    }
  });
  next();
});
app.get('/healthz', (_req, res) => res.type('text/plain').send('ok'));
if (allowedHosts) app.use(hostHeaderValidation(allowedHosts));
app.use(express.urlencoded({ extended: false })); // OAuth token endpoint form bodies

// --- OAuth discovery (RFC 9728 protected resource + RFC 8414 AS metadata) ---
if (publicUrl) {
  app.use(
    mcpAuthMetadataRouter({
      resourceServerUrl: new URL(mcpUrl),
      oauthMetadata: {
        issuer: publicUrl,
        authorization_endpoint: `${publicUrl}/oauth/authorize`,
        token_endpoint: `${publicUrl}/oauth/token`,
        grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        scopes_supported: ['mcp'],
      },
    }),
  );
  // Root-path RFC 9728 as well: some clients probe /.well-known/oauth-protected-resource
  // before the path-specific one. Same AS, resource still bound to /mcp.
  app.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.json({ resource: mcpUrl, authorization_servers: [publicUrl], bearer_methods_supported: ['header'] });
  });
}

// --- /oauth/authorize, /oauth/consent, /oauth/token (see oauth.mjs) ---
// Lockout wrapper first: it counts failed token exchanges, then delegates.
app.post('/oauth/token', (req, res, next) => {
  const ip = req.ip ?? '?';
  if (failures.isLocked(ip)) {
    res.status(429).json({ error: 'slow_down' });
    return;
  }
  res.on('finish', () => {
    if (res.statusCode === 401) failures.fail(ip);
    else if (res.statusCode === 200) failures.reset(ip);
  });
  next();
});
mountOAuth(app, oauth);

// --- /mcp: MCP Streamable HTTP (stateless) behind Bearer auth ---
const bearerAuth = requireBearerAuth({
  verifier: {
    verifyAccessToken: async (token) => {
      const claims = verifyJwt(token, jwtKey, ISSUER);
      if (!claims) throw new OAuthError(OAuthErrorCode.InvalidToken, 'unknown, tampered or expired token');
      return { token, clientId: claims.sub, scopes: ['mcp'], expiresAt: claims.exp };
    },
  },
  ...(mcpUrl ? { resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(mcpUrl)) } : {}),
});

app.post('/mcp', (req, res, next) => {
  const ip = req.ip ?? '?';
  if (failures.isLocked(ip)) {
    res.status(429).json({ error: 'slow_down' });
    return;
  }
  res.on('finish', () => {
    if (res.statusCode === 401) failures.fail(ip);
    else if (res.statusCode < 400) failures.reset(ip);
  });
  bearerAuth(req, res, next);
}, async (req, res) => {
  // Stateless pattern from the SDK: fresh server+transport per request, no session id.
  const server = new McpServer({ name: 'lark-mcp', version: '0.1.0' });
  server.registerTool(
    'lark_api',
    {
      title: 'Feishu Open API',
      description: [
        'Call any Feishu/Lark Open API through the official lark-cli (identity: the user logged in on the server).',
        'path: API path, e.g. "im/v1/messages" (the /open-apis prefix is optional).',
        'method: GET|POST|PUT|PATCH|DELETE; params: query object; data: body object.',
        'as: "user" (act as the logged-in human; needs the matching user scope) or "bot" (the app bot; must be a member of the chat). Defaults to user when logged in.',
        'jq: filter the response to only the fields you need (strongly recommended to save tokens).',
        'page_all: auto-paginate a list endpoint; page_limit: max pages (default 10).',
      ].join('\n'),
      inputSchema: z.object({
        method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
        path: z.string().min(1),
        as: z.enum(['user', 'bot']).optional(),
        params: z.record(z.string(), z.unknown()).optional(),
        data: z.record(z.string(), z.unknown()).optional(),
        jq: z.string().optional(),
        page_all: z.boolean().optional(),
        page_limit: z.number().int().min(0).max(1000).optional(),
      }),
    },
    (input) => larkApiTool(input),
  );
  server.registerTool(
    'lark_auth_status',
    {
      title: 'Feishu login status',
      description:
        'Report the server-side lark-cli auth state (logged-in user, token validity). Use to check whether a re-login is needed.',
    },
    () => larkAuthStatusTool(),
  );
  const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
// Statelessness: no GET SSE stream and no session DELETE; both are 405.
app.get('/mcp', (_req, res) => res.status(405).end());
app.delete('/mcp', (_req, res) => res.status(405).end());

app.listen(port, host, () => {
  console.log(`lark-mcp listening on http://${host}:${port} (${clients.length} client(s))`);
});
