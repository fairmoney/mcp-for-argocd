import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runCmd, type Transports } from './cmd.js';

// A stub set of transports that records what each one was handed. All are
// async, mirroring the real connectHttpTransport, whose top-level `await
// discoverOidc(...)` in oidc mode is what made a parseSync-based parser throw.
const stubTransports = () => {
  const calls: { name: string; options: unknown }[] = [];
  const transports: Transports = {
    connectStdioTransport: async () => {
      calls.push({ name: 'stdio', options: undefined });
    },
    connectSSETransport: async (options) => {
      calls.push({ name: 'sse', options });
    },
    connectHttpTransport: async (options) => {
      // Suspend on a real microtask, like the oidc discovery await, so a
      // synchronous parser would see a pending promise and throw.
      await Promise.resolve();
      calls.push({ name: 'http', options });
    }
  };
  return { calls, transports };
};

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

test('runCmd awaits an async http handler to completion, with the listener defaults', async () => {
  await withEnv({ MCP_BIND_ADDRESS: undefined, MCP_AUTH_TOKEN: undefined }, async () => {
    const { calls, transports } = stubTransports();
    await runCmd(['http', '--port', '4000'], transports);
    assert.deepEqual(calls, [
      {
        name: 'http',
        options: {
          port: 4000,
          bindAddress: '127.0.0.1',
          allowedHostHeaders: [],
          allowedOrigins: [],
          authToken: undefined,
          allowUnauthenticated: false,
          stateless: false
        }
      }
    ]);
  });
});

test('runCmd passes the stateless flag and the listener flags through to the http transport', async () => {
  await withEnv({ MCP_BIND_ADDRESS: '0.0.0.0', MCP_AUTH_TOKEN: 'inbound' }, async () => {
    const { calls, transports } = stubTransports();
    await runCmd(
      [
        'http',
        '--stateless',
        '--allowed-host-header',
        'mcp.example',
        '--allowed-origin',
        'https://ide.example',
        '--allow-unauthenticated'
      ],
      transports
    );
    assert.deepEqual(calls, [
      {
        name: 'http',
        options: {
          port: 3000,
          bindAddress: '0.0.0.0',
          allowedHostHeaders: ['mcp.example'],
          allowedOrigins: ['https://ide.example'],
          authToken: 'inbound',
          allowUnauthenticated: true,
          stateless: true
        }
      }
    ]);
  });
});

test('runCmd refuses an unknown flag instead of silently dropping it', async () => {
  const { transports } = stubTransports();
  await assert.rejects(runCmd(['http', '--allowed-host', 'x'], transports));
});

test('runCmd refuses port 0 and non-numeric ports', async () => {
  const { transports } = stubTransports();
  await assert.rejects(runCmd(['http', '--port', '0'], transports), /Invalid --port/);
  await assert.rejects(runCmd(['http', '--port', 'abc'], transports), /Invalid --port/);
});
