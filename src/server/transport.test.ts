import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo, Server } from 'node:net';
import { connectHttpTransport, connectSSETransport } from './transport.js';

// These boot the real transports. The security tests build their own Express app,
// so they pin what applyListenerSecurity does but not that each transport calls
// it, and protection here is positional: a route registered above the call is
// exempt from every check.

const INBOUND_TOKEN = 'inbound-secret';

const withEnv = async (env: Record<string, string | undefined>, fn: () => Promise<void>) => {
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
};

// --- the guarantees that live in the wiring, not in a unit --------------------

test('http transport: token mode with MCP_ALLOW_ARGOCD_TOKEN set refuses to start', async () => {
  await withEnv({ AUTH_MODE: 'token', MCP_ALLOW_ARGOCD_TOKEN: 'true', ARGOCD_API_TOKEN: 'x' }, () =>
    assert.rejects(connectHttpTransport({ port: 0 }), /AUTH_MODE=oidc/)
  );
});

test('http transport: token mode refuses a non-loopback bind without inbound auth', async () => {
  await withEnv({ AUTH_MODE: 'token', MCP_ALLOW_ARGOCD_TOKEN: undefined }, () =>
    assert.rejects(
      connectHttpTransport({ port: 0, bindAddress: '0.0.0.0' }),
      /Refusing to bind to 0\.0\.0\.0 without inbound authentication/
    )
  );
});

// --- upstream's listener tests, against this fork's transports -------------------

const freePort = async (): Promise<number> => {
  const probe = net.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
};

// Boot a transport on a loopback port with an inbound token configured, with the
// ArgoCD credentials absent so a request that gets past the security layer stops at
// the credential check rather than reaching out to a cluster. The http transport
// is async in this fork (oidc discovery), so the connector's result is awaited.
const startTransport = async (
  connect: (options: { port: number; authToken: string }) => Server | Promise<Server>
): Promise<{ port: number; close: () => Promise<void> }> => {
  const port = await freePort();
  const previousToken = process.env.ARGOCD_API_TOKEN;
  const previousMode = process.env.AUTH_MODE;
  delete process.env.ARGOCD_API_TOKEN;
  delete process.env.AUTH_MODE;
  const server = await connect({ port, authToken: INBOUND_TOKEN });
  await new Promise((resolve) => server.once('listening', resolve));
  return {
    port,
    close: async () => {
      if (previousToken !== undefined) process.env.ARGOCD_API_TOKEN = previousToken;
      if (previousMode !== undefined) process.env.AUTH_MODE = previousMode;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };
};

const request = (
  port: number,
  options: { method?: string; path?: string; headers?: Record<string, string>; body?: string } = {}
): Promise<{ status: number; body: string }> =>
  new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: options.path ?? '/mcp',
        method: options.method ?? 'POST',
        headers: options.headers ?? {}
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      }
    );
    req.on('error', reject);
    req.end(options.body);
  });

const initialize = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'transport-test', version: '1.0.0' }
  }
});

const authorized = (port: number) => ({
  host: `localhost:${port}`,
  authorization: `Bearer ${INBOUND_TOKEN}`,
  'content-type': 'application/json'
});

test('the http transport requires the inbound token on /mcp', async () => {
  const { port, close } = await startTransport(connectHttpTransport);
  try {
    for (const method of ['POST', 'GET', 'DELETE']) {
      const res = await request(port, {
        method,
        headers: { host: `localhost:${port}`, 'content-type': 'application/json' },
        body: method === 'POST' ? initialize : undefined
      });
      assert.equal(res.status, 401, `${method} /mcp without a token is rejected`);
    }
  } finally {
    await close();
  }
});

test('the http transport rejects a forged Host and a cross-origin request on /mcp', async () => {
  const { port, close } = await startTransport(connectHttpTransport);
  try {
    const forgedHost = await request(port, {
      headers: { ...authorized(port), host: 'evil.example' },
      body: initialize
    });
    assert.equal(forgedHost.status, 403);
    assert.match(forgedHost.body, /Invalid Host/);

    const crossOrigin = await request(port, {
      headers: { ...authorized(port), origin: 'https://evil.example' },
      body: initialize
    });
    assert.equal(crossOrigin.status, 403);
    assert.match(crossOrigin.body, /Invalid Origin/);
  } finally {
    await close();
  }
});

test('an authorized request reaches the http transport itself', async () => {
  const { port, close } = await startTransport(connectHttpTransport);
  try {
    // Stopping at the ArgoCD credential check is how we know the request cleared
    // every listener protection and entered the transport's own handler.
    const res = await request(port, { headers: authorized(port), body: initialize });
    assert.equal(res.status, 400);
    assert.match(res.body, /x-argocd-api-token/);
  } finally {
    await close();
  }
});

test('the sse transport requires the inbound token on /sse and /messages', async () => {
  const { port, close } = await startTransport(connectSSETransport);
  try {
    const sse = await request(port, {
      method: 'GET',
      path: '/sse',
      headers: { host: `localhost:${port}` }
    });
    assert.equal(sse.status, 401);

    const messages = await request(port, {
      path: '/messages?sessionId=made-up',
      headers: { host: `localhost:${port}`, 'content-type': 'application/json' },
      body: '{}'
    });
    assert.equal(messages.status, 401);
  } finally {
    await close();
  }
});

test('the sse transport requires ArgoCD credentials before allocating a server', async () => {
  const { port, close } = await startTransport(connectSSETransport);
  try {
    // Previously this handler built an McpServer with empty credentials and held it
    // until the socket closed, so a caller could allocate one per connection.
    const res = await request(port, {
      method: 'GET',
      path: '/sse',
      headers: authorized(port)
    });
    assert.equal(res.status, 400);
    assert.match(res.body, /x-argocd-api-token/);
  } finally {
    await close();
  }
});

test('/healthz stays reachable without a token on both transports', async () => {
  for (const connect of [connectHttpTransport, connectSSETransport]) {
    const { port, close } = await startTransport(connect);
    try {
      // A kubelet probe addresses the pod IP, so it fails Host validation and
      // carries no bearer token. The exemption is held only by registration order,
      // which is exactly why it needs a test.
      const res = await request(port, {
        method: 'GET',
        path: '/healthz',
        headers: { host: '10.1.2.3:8080' }
      });
      assert.equal(res.status, 200);
      assert.match(res.body, /"status":"ok"/);
    } finally {
      await close();
    }
  }
});

// node:http always supplies a Host header, so this goes onto the socket directly,
// as HTTP/1.0: Node's parser answers a Host-less HTTP/1.1 request with 400 before
// Express sees it, which would pass a "not 2xx" assertion for the wrong reason.
const rawRequest = (port: number, payload: string): Promise<string> =>
  new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => socket.write(payload));
    let response = '';
    socket.on('data', (chunk) => (response += chunk));
    socket.on('end', () => resolve(response.split('\r\n')[0]));
    socket.on('error', reject);
  });

test('an absent or empty Host header is rejected, not treated as an allowed name', async () => {
  const { port, close } = await startTransport(connectHttpTransport);
  try {
    // A valid token, so what is being measured is the Host check rather than the
    // credential in front of it.
    const authorization = `Authorization: Bearer ${INBOUND_TOKEN}`;
    const absent = await rawRequest(port, `GET /mcp HTTP/1.0\r\n${authorization}\r\n\r\n`);
    assert.match(absent, /^HTTP\/1\.1 403/);

    const empty = await rawRequest(port, `GET /mcp HTTP/1.0\r\nHost:\r\n${authorization}\r\n\r\n`);
    assert.match(empty, /^HTTP\/1\.1 403/);
  } finally {
    await close();
  }
});
