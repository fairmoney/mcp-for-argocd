import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import { HttpClient, type BearerTokenProvider } from './http.js';

// Install a mocked global fetch that records Authorization headers and returns
// queued responses in order. Returns a handle to inspect captured headers.
const installFetch = (responses: Array<{ status: number; body: unknown }>) => {
  const authHeaders: string[] = [];
  let i = 0;
  mock.method(globalThis, 'fetch', async (_url: unknown, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    authHeaders.push(headers['Authorization'] ?? headers['authorization'] ?? '');
    const r = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return new Response(JSON.stringify(r.body), { status: r.status });
  });
  return { authHeaders };
};

test('static string token is sent as a Bearer header', async (t) => {
  const { authHeaders } = installFetch([{ status: 200, body: { ok: true } }]);
  t.after(() => mock.restoreAll());
  const client = new HttpClient('https://argo.example.com', 'static-token');
  const res = await client.get<{ ok: boolean }>('/api/v1/applications');
  assert.equal(res.status, 200);
  assert.equal(authHeaders[0], 'Bearer static-token');
});

test('provider token is resolved per request via current()', async (t) => {
  const { authHeaders } = installFetch([{ status: 200, body: {} }]);
  t.after(() => mock.restoreAll());
  const provider: BearerTokenProvider = {
    current: async () => 'live-token',
    refresh: async () => 'unused'
  };
  const client = new HttpClient('https://argo.example.com', provider);
  await client.get('/api/v1/applications');
  assert.equal(authHeaders[0], 'Bearer live-token');
});

test('on 401 the client refreshes once and retries with the new token', async (t) => {
  const { authHeaders } = installFetch([
    { status: 401, body: { error: 'expired' } },
    { status: 200, body: { ok: true } }
  ]);
  t.after(() => mock.restoreAll());
  let current = 'old-token';
  const provider: BearerTokenProvider = {
    current: async () => current,
    refresh: async () => {
      current = 'new-token';
      return current;
    }
  };
  const client = new HttpClient('https://argo.example.com', provider);
  const res = await client.get('/api/v1/applications');
  assert.equal(res.status, 200);
  assert.deepEqual(authHeaders, ['Bearer old-token', 'Bearer new-token']);
});

test('a static-token 401 is not retried', async (t) => {
  const { authHeaders } = installFetch([{ status: 401, body: {} }]);
  t.after(() => mock.restoreAll());
  const client = new HttpClient('https://argo.example.com', 'static');
  const res = await client.get('/api/v1/applications');
  assert.equal(res.status, 401);
  assert.equal(authHeaders.length, 1);
});
