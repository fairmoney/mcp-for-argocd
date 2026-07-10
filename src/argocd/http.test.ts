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

test("a 401 whose refresh fails surfaces ArgoCD's rejection reason", async (t) => {
  // ArgoCD refuses the token (e.g. audience mismatch), then the refresh has no
  // session to fall back on. The thrown error must name ArgoCD's reason, not the
  // misleading downstream "No upstream refresh token" message.
  const { authHeaders } = installFetch([
    { status: 401, body: { error: 'invalid session: failed to verify the token' } }
  ]);
  t.after(() => mock.restoreAll());
  const provider: BearerTokenProvider = {
    current: async () => 'tok',
    refresh: async () => {
      throw new Error('No upstream refresh token available for this session');
    }
  };
  const client = new HttpClient('https://argo.example.com', provider);
  await assert.rejects(
    () => client.get('/api/v1/applications'),
    /ArgoCD rejected the bearer token \(401: invalid session: failed to verify the token\); token refresh failed: No upstream refresh token/
  );
  assert.equal(authHeaders.length, 1); // no retry attempted after a failed refresh
});
