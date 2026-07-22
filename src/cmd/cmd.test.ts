import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runCmd } from './cmd.js';

// A stub set of transports that records which one ran. All are async, mirroring
// the real connectHttpTransport, whose top-level `await discoverOidc(...)` in
// oidc mode is what made a parseSync-based parser throw.
const stubTransports = () => {
  const calls: { name: string; args: unknown[] }[] = [];
  return {
    calls,
    transports: {
      connectStdioTransport: async () => {
        calls.push({ name: 'stdio', args: [] });
      },
      connectSSETransport: async (port: number) => {
        calls.push({ name: 'sse', args: [port] });
      },
      connectHttpTransport: async (port: number, stateless: boolean) => {
        // Suspend on a real microtask, like the oidc discovery await, so a
        // synchronous parser would see a pending promise and throw.
        await Promise.resolve();
        calls.push({ name: 'http', args: [port, stateless] });
      }
    }
  };
};

test('runCmd awaits an async http handler to completion', async () => {
  const { calls, transports } = stubTransports();
  await runCmd(['http', '--port', '0'], transports);
  assert.deepEqual(calls, [{ name: 'http', args: [0, false] }]);
});

test('runCmd passes the stateless flag through to the http transport', async () => {
  const { calls, transports } = stubTransports();
  await runCmd(['http', '--stateless'], transports);
  assert.deepEqual(calls, [{ name: 'http', args: [3000, true] }]);
});
