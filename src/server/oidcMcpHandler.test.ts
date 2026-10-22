import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Request, Response } from 'express';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { BearerTokenProvider } from '../argocd/http.js';
import { logger } from '../logging/logging.js';
import { HttpSessionManager } from './httpSessionManager.js';
import {
  createOidcMcpHandler,
  type McpTransportLike,
  type OidcMcpHandlerDeps,
  type SessionServerInfo,
  type TransportOptions
} from './oidcMcpHandler.js';

// Drives the oidc /mcp handler with fakes for the SDK transport and the MCP
// server. These are the cases a unit test on the pieces cannot see: which
// owner a session is stored under, whose credentials a server is built with,
// and what a request for someone else's session gets back.

const INIT = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-03-26',
    capabilities: {},
    clientInfo: { name: 't', version: '0' }
  }
};
const CALL = {
  jsonrpc: '2.0',
  id: 2,
  method: 'tools/call',
  params: { name: 'list_applications', arguments: {} }
};

const machineAuth = (name: string): AuthInfo => ({
  token: `amk_${name}`,
  clientId: `apikey:${name}`,
  scopes: [],
  expiresAt: 9e9,
  extra: { kind: 'apikey', principal: `apikey:${name}`, argocdToken: `argocd-token-${name}` }
});
const oidcAuth = (sessionId: string): AuthInfo => ({
  token: `opaque-${sessionId}`,
  clientId: 'client-shared',
  scopes: [],
  expiresAt: 9e9,
  extra: { argocdToken: 'upstream', argocdBaseUrl: 'https://argocd', sessionId }
});

const provider: BearerTokenProvider = { current: async () => 'live', refresh: async () => 'live' };

// A fake transport that behaves like the SDK's for our purposes: on an
// initialize request it mints the session id through the generator and fires
// onsessioninitialized, exactly when the SDK would.
const makeHarness = (opts: { stateless?: boolean; maxSessions?: number } = {}) => {
  const sessions = new HttpSessionManager({ disableTimer: true, maxSessions: opts.maxSessions });
  const transports: {
    opts: TransportOptions;
    handled: unknown[];
    closed: boolean;
    t: McpTransportLike;
  }[] = [];
  const servers: SessionServerInfo[] = [];
  const serversClosed: number[] = [];
  let ids = 0;
  const deps: OidcMcpHandlerDeps = {
    sessions,
    stateless: opts.stateless ?? false,
    argocdBaseUrl: 'https://argocd.internal',
    oidcProviderFor: () => provider,
    newSessionId: () => `sid-${++ids}`,
    createTransport: (topts) => {
      const entry = {
        opts: topts,
        handled: [] as unknown[],
        closed: false,
        t: {
          sessionId: undefined as string | undefined,
          start: async () => {},
          send: async () => {},
          close: async () => {
            entry.closed = true;
          },
          handleRequest: async (_req: Request, _res: Response, body?: unknown) => {
            entry.handled.push(body);
            if (
              topts.sessionIdGenerator &&
              (body as { method?: string })?.method === 'initialize'
            ) {
              entry.t.sessionId = topts.sessionIdGenerator();
              topts.onsessioninitialized?.(entry.t.sessionId);
            }
          }
        } as McpTransportLike
      };
      transports.push(entry);
      return entry.t;
    },
    createServer: (info) => {
      const index = servers.push(info) - 1;
      return {
        connect: async () => {},
        close: () => {
          serversClosed.push(index);
        }
      };
    }
  };
  return {
    deps,
    sessions,
    transports,
    servers,
    serversClosed,
    handler: createOidcMcpHandler(deps)
  };
};

const makeReq = (auth: AuthInfo, body: unknown, sessionId?: string) =>
  ({
    auth,
    body,
    ip: '10.0.0.9',
    headers: sessionId ? { 'mcp-session-id': sessionId } : {}
  }) as unknown as Request;

const makeRes = () => {
  const out = {
    status: 200 as number,
    json: undefined as unknown,
    closeHandlers: [] as (() => void)[]
  };
  const res = {
    headersSent: false,
    status(code: number) {
      out.status = code;
      return res;
    },
    json(payload: unknown) {
      out.json = payload;
      return res;
    },
    on(event: string, cb: () => void) {
      if (event === 'close') out.closeHandlers.push(cb);
    }
  };
  return { res: res as unknown as Response, out };
};

const captureInfo = async (fn: () => Promise<void>) => {
  const lines: Record<string, unknown>[] = [];
  const original = logger.info;
  logger.info = ((fields: Record<string, unknown>) => {
    lines.push(fields);
  }) as typeof logger.info;
  try {
    await fn();
  } finally {
    logger.info = original;
  }
  return lines;
};

test('machine initialize: server built with the key token and principal, session owned by the key', async () => {
  const h = makeHarness();
  const { res, out } = makeRes();

  const lines = await captureInfo(() => h.handler(makeReq(machineAuth('bot'), INIT), res));

  assert.equal(out.status, 200);
  assert.equal(h.servers.length, 1);
  assert.deepEqual(h.servers[0], {
    argocdBaseUrl: 'https://argocd.internal',
    argocdApiToken: '',
    pinBaseUrl: true,
    tokenSource: 'argocd-token-bot',
    principal: 'apikey:bot'
  });
  assert.equal(h.sessions.get('sid-1', 'apikey:bot'), h.transports[0].t, 'stored under the key');
  const start = lines.find((l) => l.principal === 'apikey:bot');
  assert.ok(start, 'machine session start is logged');
  assert.equal(start.sessionId, 'sid-1');
  assert.equal(start.clientAddress, '10.0.0.9');
});

test('the owner that opened a session reuses it without a new server', async () => {
  const h = makeHarness();
  await h.handler(makeReq(machineAuth('bot'), INIT), makeRes().res);
  const { res, out } = makeRes();

  await h.handler(makeReq(machineAuth('bot'), CALL, 'sid-1'), res);

  assert.equal(out.status, 200);
  assert.equal(h.servers.length, 1, 'no second server');
  assert.deepEqual(h.transports[0].handled, [INIT, CALL]);
});

test('another principal presenting the session id is told there is no such session', async () => {
  const h = makeHarness();
  await h.handler(makeReq(machineAuth('bot'), INIT), makeRes().res);

  for (const intruder of [machineAuth('other'), oidcAuth('login-1')]) {
    const { res, out } = makeRes();
    await h.handler(makeReq(intruder, CALL, 'sid-1'), res);
    assert.equal(out.status, 400);
    assert.match(
      (out.json as { error: { message: string } }).error.message,
      /Invalid or expired session ID/
    );
  }
  assert.deepEqual(h.transports[0].handled, [INIT], 'the session never saw the intruders');
  assert.equal(h.servers.length, 1);
});

test('OIDC initialize: server built with the refreshable provider, no principal, owned by the login', async () => {
  const h = makeHarness();
  const { res } = makeRes();

  const lines = await captureInfo(() => h.handler(makeReq(oidcAuth('login-7'), INIT), res));

  assert.equal(h.servers[0].tokenSource, provider);
  assert.equal(h.servers[0].principal, undefined);
  assert.equal(h.sessions.get('sid-1', 'oidc:login-7'), h.transports[0].t);
  assert.equal(
    h.sessions.get('sid-1', 'client:client-shared'),
    undefined,
    'not owned by the shared client'
  );
  assert.equal(
    lines.some((l) => 'principal' in l),
    false,
    'nothing logged about a person'
  );
});

test('stateless: no session is kept, every request builds its own server, machine start is logged', async () => {
  const h = makeHarness({ stateless: true });
  const { res, out } = makeRes();

  const lines = await captureInfo(() => h.handler(makeReq(machineAuth('bot'), CALL), res));

  assert.equal(h.transports[0].opts.sessionIdGenerator, undefined);
  assert.equal(h.sessions.size, 0);
  assert.equal(h.servers[0].principal, 'apikey:bot');
  assert.equal(
    out.closeHandlers.length,
    1,
    'transport and server are released when the response closes'
  );
  const start = lines.find((l) => l.principal === 'apikey:bot');
  assert.ok(start);
  assert.equal(start.stateless, true);
  assert.equal(start.clientAddress, '10.0.0.9');
});

test('a non-initialize request without a session id is a 400', async () => {
  const h = makeHarness();
  const { res, out } = makeRes();

  await h.handler(makeReq(machineAuth('bot'), CALL), res);

  assert.equal(out.status, 400);
  assert.equal(h.servers.length, 0);
});

test('at capacity, a new session is refused with 503', async () => {
  const h = makeHarness({ maxSessions: 1 });
  await h.handler(makeReq(machineAuth('bot'), INIT), makeRes().res);
  const { res, out } = makeRes();

  await h.handler(makeReq(machineAuth('other'), INIT), res);

  assert.equal(out.status, 503);
  assert.equal(h.servers.length, 1);
});

test('stateless: closing the response releases the transport and the server', async () => {
  const h = makeHarness({ stateless: true });
  const { res, out } = makeRes();
  await h.handler(makeReq(machineAuth('bot'), CALL), res);
  assert.equal(h.transports[0].closed, false);
  assert.deepEqual(h.serversClosed, []);

  out.closeHandlers[0]();

  assert.equal(h.transports[0].closed, true, 'transport closed with the response');
  assert.deepEqual(h.serversClosed, [0], 'server closed with the response');
});

test('a stateful session is forgotten when its transport closes', async () => {
  const h = makeHarness();
  await h.handler(makeReq(machineAuth('bot'), INIT), makeRes().res);
  assert.equal(h.sessions.size, 1);

  h.transports[0].t.onclose?.();

  assert.equal(h.sessions.size, 0, 'the slot is freed');
  assert.equal(h.sessions.get('sid-1', 'apikey:bot'), undefined);
});
