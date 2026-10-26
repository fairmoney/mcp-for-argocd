import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import express from 'express';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { logger } from '../logging/logging.js';
import { createServer } from './server.js';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { tokenRegistryFromEnv } from './tokenRegistry.js';
import { resolveAuthMode, loadOidcConfig } from '../auth/config.js';
import {
  createAuthDispatcher,
  createPassthroughMiddleware,
  resolveAllowArgocdToken
} from '../auth/argocdTokenPassthrough.js';
import { createOidcMcpHandler } from './oidcMcpHandler.js';
import { discoverOidc, SSONotConfiguredError } from '../auth/oidcDiscovery.js';
import type { OidcProviderMetadata } from '../auth/types.js';
import { createTokenStore } from '../auth/tokenStoreFactory.js';
import { OAuthProxyProvider } from '../auth/oauthProxyProvider.js';
import { makeSessionTokenProvider } from '../auth/sessionTokenProvider.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { HttpSessionManager } from './httpSessionManager.js';
import {
  applyListenerSecurity,
  resolveListenerSecurity,
  type ListenerSecurityOptions
} from './security.js';

// Load the base-URL -> token registry once at startup from the JSON file at
// ARGOCD_TOKEN_REGISTRY_PATH. Shared across all connections; read-only after
// construction.
const tokenRegistry = tokenRegistryFromEnv();

export const connectStdioTransport = () => {
  const server = createServer({
    argocdBaseUrl: process.env.ARGOCD_BASE_URL || '',
    argocdApiToken: process.env.ARGOCD_API_TOKEN || '',
    tokenRegistry
  });

  logger.info('Connecting to stdio transport');
  server.connect(new StdioServerTransport());
};

export type TransportOptions = ListenerSecurityOptions;

// Liveness probe, registered before the security middleware: a kubelet probe
// addresses the pod IP and carries no bearer token. Reports only that we are up.
const registerHealthz = (app: express.Express) => {
  app.get('/healthz', (_, res) => {
    res.status(200).json({ status: 'ok' });
  });
};

// Log the address actually bound, so an operator can see whether the listener is
// loopback-only or exposed. Both handlers hang off events rather than
// app.listen()'s callback, which Express invokes even when the bind fails, with
// server.address() still null.
const listen = (app: express.Express, bindAddress: string, port: number, label: string) => {
  const server = app.listen(port, bindAddress);
  server.on('listening', () => {
    const { address, port: boundPort } = server.address() as AddressInfo;
    logger.info(`${label} listening on ${address}:${boundPort}`);
  });
  server.on('error', (err: NodeJS.ErrnoException) => {
    logger.error(`${label} could not bind ${bindAddress}:${port}: ${err.code ?? err.message}`);
    process.exit(1);
  });
  return server;
};

export const connectSSETransport = (options: TransportOptions) => {
  const security = resolveListenerSecurity(options);
  const { port } = options;
  const app = express();
  registerHealthz(app);
  applyListenerSecurity(app, security);
  const transports: { [sessionId: string]: SSEServerTransport } = {};

  app.get('/sse', async (req, res) => {
    // Same credential requirement as the http transport. Without it the handler
    // built an McpServer with empty credentials and held it until the socket
    // closed, one per connection.
    const credentials = resolveCredentials(req, res);
    if (!credentials) return;
    const server = createServer({ ...credentials, tokenRegistry });

    const transport = new SSEServerTransport('/messages', res);
    transports[transport.sessionId] = transport;
    res.on('close', () => {
      delete transports[transport.sessionId];
      // Release the per-connection McpServer too; dropping only the transport
      // reference would leak the server (and its tools/HTTP client) per session.
      void server.close();
    });
    await server.connect(transport);
  });

  app.post('/messages', async (req, res) => {
    const sessionId = req.query.sessionId as string;
    const transport = transports[sessionId];
    if (transport) {
      await transport.handlePostMessage(req, res);
    } else {
      res.status(400).send(`No transport found for sessionId: ${sessionId}`);
    }
  });

  return listen(app, security.bindAddress, port, 'SSE transport');
};

// Resolve the session-level ArgoCD credentials from headers or env.
//
// The API token is only ever accepted here (x-argocd-api-token header or
// ARGOCD_API_TOKEN env var) — never as a tool-call argument — so the secret
// stays in the transport layer and out of prompts/model context.
//
// The token is normally MANDATORY and the connection is rejected when it is
// missing. The exception is when a token registry (ARGOCD_TOKEN_REGISTRY_PATH)
// is configured: the per-call base URL can then resolve its token from the
// registry, so a tokenless connection is allowed.
//
// The base URL is optional at this level: when it is absent, callers may supply
// it per call via the argocdBaseUrl tool argument.
//
// These are outbound credentials only. Inbound authorization is the listener's
// job (MCP_AUTH_TOKEN in token mode, the OIDC login or a verified ArgoCD token
// in oidc mode; see security.ts and the oidc branch of connectHttpTransport).
const resolveCredentials = (
  req: express.Request,
  res: express.Response
): { argocdBaseUrl: string; argocdApiToken: string } | null => {
  const argocdBaseUrl =
    (req.headers['x-argocd-base-url'] as string) || process.env.ARGOCD_BASE_URL || '';
  const argocdApiToken =
    (req.headers['x-argocd-api-token'] as string) || process.env.ARGOCD_API_TOKEN || '';
  if (!argocdApiToken && tokenRegistry.getSize() === 0) {
    res
      .status(400)
      .send(
        'x-argocd-api-token must be provided in the request header (or the ARGOCD_API_TOKEN env var), ' +
          'or a token registry must be configured via ARGOCD_TOKEN_REGISTRY_PATH.'
      );
    return null;
  }
  return { argocdBaseUrl, argocdApiToken };
};

// Number of reverse-proxy hops in front of this server. Behind a Kubernetes
// ingress the X-Forwarded-For header is present; Express must be told to trust
// it or express-rate-limit (used by the OAuth router) throws
// ERR_ERL_UNEXPECTED_X_FORWARDED_FOR. Default 1 (single ingress); set
// TRUST_PROXY_HOPS higher for stacked proxies (e.g. ALB + nginx = 2), or 0 to
// disable trust for direct exposure. Fails closed on a malformed value.
export const resolveTrustProxy = (env: NodeJS.ProcessEnv = process.env): number => {
  const raw = (env.TRUST_PROXY_HOPS ?? '').trim();
  if (!raw) return 1;
  const hops = Number(raw);
  if (!Number.isInteger(hops) || hops < 0) {
    throw new Error(
      `Invalid TRUST_PROXY_HOPS "${env.TRUST_PROXY_HOPS}": expected a non-negative integer`
    );
  }
  return hops;
};

// Parse an optional positive-integer env var (fail closed on garbage), returning
// undefined when unset so HttpSessionManager falls back to its own default.
const resolvePositiveInt = (raw: string | undefined, name: string): number | undefined => {
  const trimmed = (raw ?? '').trim();
  if (!trimmed) return undefined;
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`Invalid ${name} "${raw}": expected a positive integer`);
  }
  return n;
};

// Build the session-manager knobs from the environment. MAX_SESSIONS caps how
// many concurrent MCP sessions (each pinning an McpServer) may live at once;
// SESSION_IDLE_TIMEOUT_SEC reaps sessions whose client vanished without a clean
// close so their heap is reclaimed.
export const resolveHttpSessionOptions = (env: NodeJS.ProcessEnv = process.env) => {
  const idleSec = resolvePositiveInt(env.SESSION_IDLE_TIMEOUT_SEC, 'SESSION_IDLE_TIMEOUT_SEC');
  return {
    maxSessions: resolvePositiveInt(env.MAX_SESSIONS, 'MAX_SESSIONS'),
    idleTimeoutMs: idleSec ? idleSec * 1000 : undefined
  };
};

export const connectHttpTransport = async (options: TransportOptions & { stateless?: boolean }) => {
  const { port, stateless = false } = options;
  const authMode = resolveAuthMode();

  // ArgoCD token passthrough (MCP_ALLOW_ARGOCD_TOKEN) sits beside the OIDC
  // login; off means the OIDC bearer is the only way in. Resolved before the
  // mode check so that setting it in token mode refuses to start, as the docs
  // say, rather than being ignored.
  const allowArgocdToken = resolveAllowArgocdToken();

  // oidc mode authenticates every /mcp request itself (the OIDC bearer or a
  // verified ArgoCD token), so the listener may bind past loopback without
  // MCP_AUTH_TOKEN; a second bearer scheme on the same header would only be
  // ambiguous, so that variable is refused here. The public hostname is always
  // an accepted Host, which keeps Host validation on behind the ingress.
  const oidcConfig = authMode === 'oidc' ? loadOidcConfig() : undefined;
  if (oidcConfig && options.authToken !== undefined) {
    throw new Error(
      'MCP_AUTH_TOKEN cannot be combined with AUTH_MODE=oidc: the OIDC login (and ' +
        'MCP_ALLOW_ARGOCD_TOKEN) already authenticate every request.'
    );
  }
  const security = resolveListenerSecurity(
    oidcConfig
      ? {
          ...options,
          authenticatedByApp: true,
          allowedHostHeaders: [
            ...(options.allowedHostHeaders ?? []),
            new URL(oidcConfig.publicUrl).host
          ]
        }
      : options
  );

  const app = express();
  // Trust the ingress/proxy chain so forwarded client IPs are honored and the
  // OAuth router's rate limiter can key on the real client rather than throwing.
  app.set('trust proxy', resolveTrustProxy());
  registerHealthz(app);
  applyListenerSecurity(app, security);
  // After the security middleware, so malformed JSON returns 401/403 rather than
  // the body parser's 400, which would tell a caller it passed the credential check.
  app.use(express.json());

  // Tracks live stateful sessions, reaps idle ones, and caps concurrency so an
  // abandoned or abusive client cannot grow the heap without bound. Unused in
  // stateless mode (transports are per-request and closed on response end).
  const sessions = new HttpSessionManager(resolveHttpSessionOptions());

  if (oidcConfig) {
    const config = oidcConfig;
    logger.info(
      { clientMode: config.mode, clientId: config.clientId },
      'OIDC client mode resolved'
    );
    if (allowArgocdToken) {
      logger.info('ArgoCD token passthrough enabled (x-argocd-api-token)');
    }
    const store = createTokenStore(config);

    // Resolve OIDC discovery ONCE at startup and fail closed. Starting the
    // server against an ArgoCD instance that has no SSO configured would leave
    // every /mcp request unauthenticatable, so we refuse to start instead.
    let meta: OidcProviderMetadata;
    try {
      meta = await discoverOidc(config.argocdBaseUrl);
    } catch (err) {
      if (err instanceof SSONotConfiguredError) {
        logger.error(
          { argocdBaseUrl: config.argocdBaseUrl },
          'ArgoCD SSO is not configured; cannot start in oidc mode'
        );
      } else {
        logger.error(
          { error: err instanceof Error ? err.message : String(err) },
          'Failed to discover ArgoCD OIDC configuration at startup'
        );
      }
      process.exit(1);
    }

    // Reuse the one resolved metadata everywhere: the provider gets it via a
    // resolved-promise discover(), and sessions read the same local. No
    // per-session rediscovery.
    const provider = new OAuthProxyProvider({
      config,
      store,
      discover: async () => meta
    });

    // OAuth 2.1 metadata + endpoints (/.well-known/*, /authorize, /token, /register).
    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: new URL(config.publicUrl),
        baseUrl: new URL(config.publicUrl)
      })
    );

    // The Dex redirect lands here (registered as the static client redirectURI).
    app.get(config.callbackPath, async (req, res) => {
      const code = req.query.code as string | undefined;
      const state = req.query.state as string | undefined;
      if (!code || !state) {
        res.status(400).send('Missing code or state');
        return;
      }
      try {
        const redirect = await provider.handleUpstreamCallback(code, state);
        res.redirect(redirect);
      } catch (error) {
        logger.error(
          { error: error instanceof Error ? error.message : String(error) },
          'OAuth callback failed'
        );
        res.status(400).send('Authentication failed');
      }
    });

    // One dispatcher decides per request: a forwarded ArgoCD token goes to
    // the passthrough middleware, everything else to the SDK's bearer check.
    const authenticate = createAuthDispatcher({
      allowArgocdToken,
      passthrough: createPassthroughMiddleware({
        allowArgocdToken,
        argocdBaseUrl: config.argocdBaseUrl,
        stateless
      }),
      bearerAuth: requireBearerAuth({ verifier: provider })
    });

    app.post(
      '/mcp',
      authenticate,
      createOidcMcpHandler({
        sessions,
        stateless,
        argocdBaseUrl: config.argocdBaseUrl,
        oidcProviderFor: (opaque) => makeSessionTokenProvider(store, meta, config, opaque),
        createTransport: (opts) => new StreamableHTTPServerTransport(opts),
        createServer
      })
    );

    app.get('/mcp', (_req, res) => {
      res.status(405).send('Method Not Allowed');
    });
    app.delete('/mcp', (_req, res) => {
      res.status(405).send('Method Not Allowed');
    });

    logger.info(
      { argocdBaseUrl: config.argocdBaseUrl, tokenStore: config.tokenStore },
      'Http Stream transport starting (oidc auth mode)'
    );
    return listen(app, security.bindAddress, port, 'Http Stream transport (oidc auth mode)');
  }

  // ---- token mode (existing behavior) ----
  app.post('/mcp', async (req, res) => {
    const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    const existing =
      !stateless && sessionIdFromHeader ? sessions.get(sessionIdFromHeader) : undefined;
    if (existing) {
      transport = existing as StreamableHTTPServerTransport;
    } else if (stateless || (!sessionIdFromHeader && isInitializeRequest(req.body))) {
      const credentials = resolveCredentials(req, res);
      if (!credentials) return;

      if (!stateless && !sessions.hasCapacity()) {
        res.status(503).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Server at session capacity; try again later.' },
          id: req.body?.id ?? null
        });
        return;
      }

      transport = new StreamableHTTPServerTransport(
        stateless
          ? { sessionIdGenerator: undefined }
          : {
              sessionIdGenerator: () => randomUUID(),
              onsessioninitialized: (newSessionId) => {
                sessions.add(newSessionId, transport, server);
              }
            }
      );

      if (!stateless) {
        transport.onclose = () => {
          if (transport.sessionId) sessions.forget(transport.sessionId);
        };
      }

      const server = createServer({ ...credentials, tokenRegistry });
      // Stateless: close per-request transport + server when the response ends.
      if (stateless) {
        res.on('close', () => {
          void transport.close();
          void server.close();
        });
      }
      await server.connect(transport);
    } else {
      const errorMsg = sessionIdFromHeader
        ? `Invalid or expired session ID: ${sessionIdFromHeader}`
        : 'Bad Request: Not an initialization request and no valid session ID provided.';
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: errorMsg },
        id: req.body?.id !== undefined ? req.body.id : null
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  });

  const handleSessionRequest = async (req: express.Request, res: express.Response) => {
    if (stateless) {
      res.status(405).send('Method Not Allowed in stateless mode');
      return;
    }
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const transport = sessionId ? sessions.get(sessionId) : undefined;
    if (!transport) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await (transport as StreamableHTTPServerTransport).handleRequest(req, res);
  };

  app.get('/mcp', handleSessionRequest);
  app.delete('/mcp', handleSessionRequest);

  return listen(
    app,
    security.bindAddress,
    port,
    `Http Stream transport${stateless ? ' (stateless mode)' : ''}`
  );
};
