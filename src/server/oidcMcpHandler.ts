import type { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { BearerTokenProvider, TokenSource } from '../argocd/http.js';
import { logger } from '../logging/logging.js';
import type { ClosableServer, HttpSessionManager } from './httpSessionManager.js';
import { resolveSessionCredentials, resolveSessionOwner } from './sessionCredentials.js';

// Just enough of StreamableHTTPServerTransport / McpServer for the handler,
// kept structural so the handler is unit-testable with fakes.
export interface McpTransportLike extends Transport {
  handleRequest(req: Request, res: Response, parsedBody?: unknown): Promise<void>;
}
export interface McpServerLike extends ClosableServer {
  connect(transport: Transport): Promise<void>;
}
export interface TransportOptions {
  sessionIdGenerator: (() => string) | undefined;
  onsessioninitialized?: (sessionId: string) => void;
}
export interface SessionServerInfo {
  argocdBaseUrl: string;
  argocdApiToken: string;
  pinBaseUrl: true;
  tokenSource: TokenSource;
  principal?: string;
}

export interface OidcMcpHandlerDeps {
  sessions: HttpSessionManager;
  stateless: boolean;
  argocdBaseUrl: string;
  // Builds the refreshable ArgoCD token source for an OIDC login's opaque token.
  oidcProviderFor: (opaqueToken: string) => BearerTokenProvider;
  createTransport: (opts: TransportOptions) => McpTransportLike;
  createServer: (info: SessionServerInfo) => McpServerLike;
  newSessionId?: () => string;
}

const jsonRpcError = (res: Response, status: number, message: string, id: unknown) => {
  res.status(status).json({ jsonrpc: '2.0', error: { code: -32000, message }, id: id ?? null });
};

// The oidc-mode POST /mcp handler. It runs behind requireBearerAuth, so
// req.auth is always a verified OIDC login or machine key. Each HTTP session
// is bound to the owner that opened it and is built with that owner's ArgoCD
// credentials; a request for someone else's session id is told there is no
// such session.
export const createOidcMcpHandler = (deps: OidcMcpHandlerDeps) => {
  const { sessions, stateless } = deps;
  const newSessionId = deps.newSessionId ?? randomUUID;

  return async (req: Request, res: Response): Promise<void> => {
    try {
      const auth = req.auth!;
      const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
      const owner = resolveSessionOwner(auth);

      const existing =
        !stateless && sessionIdFromHeader ? sessions.get(sessionIdFromHeader, owner) : undefined;
      if (existing) {
        await (existing as McpTransportLike).handleRequest(req, res, req.body);
        return;
      }

      if (!(stateless || (!sessionIdFromHeader && isInitializeRequest(req.body)))) {
        jsonRpcError(
          res,
          400,
          sessionIdFromHeader
            ? `Invalid or expired session ID: ${sessionIdFromHeader}`
            : 'Bad Request: Not an initialization request and no valid session ID provided.',
          req.body?.id
        );
        return;
      }
      if (!stateless && !sessions.hasCapacity()) {
        jsonRpcError(res, 503, 'Server at session capacity; try again later.', req.body?.id);
        return;
      }

      const creds = resolveSessionCredentials(auth, deps.oidcProviderFor);
      // The client address is the one signal that a token is in use from
      // somewhere other than its expected path.
      const logSessionStart = (fields: Record<string, unknown>) => {
        if (creds.principal) {
          logger.info(
            { principal: creds.principal, clientAddress: req.ip, ...fields },
            'Token session started'
          );
        }
      };

      const server = deps.createServer({
        argocdBaseUrl: deps.argocdBaseUrl,
        argocdApiToken: '',
        pinBaseUrl: true,
        tokenSource: creds.tokenSource,
        principal: creds.principal
      });

      let transport: McpTransportLike;
      if (stateless) {
        transport = deps.createTransport({ sessionIdGenerator: undefined });
        logSessionStart({ stateless: true });
      } else {
        transport = deps.createTransport({
          sessionIdGenerator: newSessionId,
          onsessioninitialized: (id) => {
            sessions.add(id, transport, server, creds.owner);
            logSessionStart({ sessionId: id });
          }
        });
        transport.onclose = () => {
          if (transport.sessionId) sessions.forget(transport.sessionId);
        };
      }

      // Stateless: nothing tracks this transport/server, so close both when
      // the response ends or the client disconnects — otherwise each request
      // leaks a full McpServer until GC.
      if (stateless) {
        res.on('close', () => {
          void transport.close();
          void server.close();
        });
      }
      await server.connect(transport);
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
  };
};
