import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import express from 'express';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { logger } from '../logging/logging.js';
import { createServer } from './server.js';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { tokenRegistryFromEnv } from './tokenRegistry.js';
import { resolveAuthMode, loadOidcConfig } from '../auth/config.js';
import { discoverOidc, SSONotConfiguredError } from '../auth/oidcDiscovery.js';
import type { OidcProviderMetadata } from '../auth/types.js';
import { createTokenStore } from '../auth/tokenStoreFactory.js';
import { OAuthProxyProvider } from '../auth/oauthProxyProvider.js';
import { makeSessionTokenProvider } from '../auth/sessionTokenProvider.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';

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

export const connectSSETransport = (port: number) => {
  const app = express();
  const transports: { [sessionId: string]: SSEServerTransport } = {};

  app.get('/sse', async (req, res) => {
    const server = createServer({
      argocdBaseUrl: (req.headers['x-argocd-base-url'] as string) || '',
      argocdApiToken: (req.headers['x-argocd-api-token'] as string) || '',
      tokenRegistry
    });

    const transport = new SSEServerTransport('/messages', res);
    transports[transport.sessionId] = transport;
    res.on('close', () => {
      delete transports[transport.sessionId];
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

  logger.info(`Connecting to SSE transport on port: ${port}`);
  app.listen(port);
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

export const connectHttpTransport = async (port: number, stateless = false) => {
  const app = express();
  // Trust the ingress/proxy chain so forwarded client IPs are honored and the
  // OAuth router's rate limiter can key on the real client rather than throwing.
  app.set('trust proxy', resolveTrustProxy());
  app.use(express.json());

  app.get('/healthz', (_, res) => {
    res.status(200).json({ status: 'ok' });
  });

  const httpTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

  if (resolveAuthMode() === 'oidc') {
    const config = loadOidcConfig();
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

    const bearerAuth = requireBearerAuth({ verifier: provider });

    app.post('/mcp', bearerAuth, async (req, res) => {
      try {
        const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;

        if (!stateless && sessionIdFromHeader && httpTransports[sessionIdFromHeader]) {
          transport = httpTransports[sessionIdFromHeader];
        } else if (stateless || (!sessionIdFromHeader && isInitializeRequest(req.body))) {
          const opaque = req.auth!.token; // set by requireBearerAuth
          const tokenSource = makeSessionTokenProvider(store, meta, config, opaque);

          transport = new StreamableHTTPServerTransport(
            stateless
              ? { sessionIdGenerator: undefined }
              : {
                  sessionIdGenerator: () => randomUUID(),
                  onsessioninitialized: (id) => {
                    httpTransports[id] = transport;
                  }
                }
          );
          if (!stateless) {
            transport.onclose = () => {
              if (transport.sessionId) delete httpTransports[transport.sessionId];
            };
          }

          const server = createServer({
            argocdBaseUrl: config.argocdBaseUrl,
            argocdApiToken: '',
            pinBaseUrl: true,
            tokenSource
          });
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
      } catch (error) {
        logger.error(
          { error: error instanceof Error ? error.message : String(error) },
          'oidc /mcp request handler failed'
        );
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal error' },
            id: req.body?.id ?? null
          });
        }
      }
    });

    app.get('/mcp', (_req, res) => {
      res.status(405).send('Method Not Allowed');
    });
    app.delete('/mcp', (_req, res) => {
      res.status(405).send('Method Not Allowed');
    });

    logger.info(
      { port, argocdBaseUrl: config.argocdBaseUrl, tokenStore: config.tokenStore },
      `Connecting to Http Stream transport on port: ${port} (oidc auth mode)`
    );
    app.listen(port);
    return;
  }

  // ---- token mode (existing behavior, unchanged) ----
  app.post('/mcp', async (req, res) => {
    const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    if (!stateless && sessionIdFromHeader && httpTransports[sessionIdFromHeader]) {
      transport = httpTransports[sessionIdFromHeader];
    } else if (stateless || (!sessionIdFromHeader && isInitializeRequest(req.body))) {
      const credentials = resolveCredentials(req, res);
      if (!credentials) return;

      transport = new StreamableHTTPServerTransport(
        stateless
          ? { sessionIdGenerator: undefined }
          : {
              sessionIdGenerator: () => randomUUID(),
              onsessioninitialized: (newSessionId) => {
                httpTransports[newSessionId] = transport;
              }
            }
      );

      if (!stateless) {
        transport.onclose = () => {
          if (transport.sessionId) delete httpTransports[transport.sessionId];
        };
      }

      const server = createServer({ ...credentials, tokenRegistry });
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
    if (!sessionId || !httpTransports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await httpTransports[sessionId].handleRequest(req, res);
  };

  app.get('/mcp', handleSessionRequest);
  app.delete('/mcp', handleSessionRequest);

  logger.info(
    `Connecting to Http Stream transport on port: ${port}${stateless ? ' (stateless mode)' : ''}`
  );
  app.listen(port);
};
