import assert from 'node:assert/strict';
import { test, mock } from 'node:test';
import { HttpClient, type BearerTokenProvider } from './http.js';
import { ArgoCDClient } from './client.js';

// Install a mocked global fetch that records Authorization headers plus the
// request URL/method/body, and returns queued responses in order. Returns a
// handle to inspect the captured requests.
const installFetch = (responses: Array<{ status: number; body: unknown }>) => {
  const authHeaders: string[] = [];
  const requests: Array<{ url: URL; method: string; body?: string }> = [];
  let i = 0;
  mock.method(globalThis, 'fetch', async (url: unknown, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    authHeaders.push(headers['Authorization'] ?? headers['authorization'] ?? '');
    requests.push({
      url: new URL(String(url)),
      method: init?.method ?? 'GET',
      body: typeof init?.body === 'string' ? init.body : undefined
    });
    const r = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return new Response(JSON.stringify(r.body), { status: r.status });
  });
  return { authHeaders, requests };
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

// --- Resource-level escape hatches -------------------------------------------
//
// These exercise ArgoCDClient's wire format for the resource-level endpoints:
// the path, the resource-ref query params, and (for patch) the body encoding.
// ArgoCD's PatchResource endpoint takes the patch as a JSON-encoded *string*
// body (i.e. a quoted string on the wire), same as RunResourceAction's action.

const RESOURCE_REF = {
  uid: 'uid-1',
  group: 'apps',
  kind: 'Deployment',
  version: 'v1',
  namespace: 'prod',
  name: 'my-deploy'
};

test('patchResource POSTs the patch string to the resource endpoint with patchType', async (t) => {
  const { requests } = installFetch([{ status: 200, body: { manifest: '{}' } }]);
  t.after(() => mock.restoreAll());
  const client = new ArgoCDClient('https://argo.example.com', 'tok');
  const patch = '{"metadata":{"finalizers":null}}';
  await client.patchResource(
    'my-app',
    'argocd',
    RESOURCE_REF,
    patch,
    'application/merge-patch+json'
  );

  assert.equal(requests.length, 1);
  const { url, method, body } = requests[0];
  assert.equal(method, 'POST');
  assert.equal(url.pathname, '/api/v1/applications/my-app/resource');
  assert.equal(url.searchParams.get('appNamespace'), 'argocd');
  assert.equal(url.searchParams.get('namespace'), 'prod');
  assert.equal(url.searchParams.get('resourceName'), 'my-deploy');
  assert.equal(url.searchParams.get('group'), 'apps');
  assert.equal(url.searchParams.get('kind'), 'Deployment');
  assert.equal(url.searchParams.get('version'), 'v1');
  assert.equal(url.searchParams.get('patchType'), 'application/merge-patch+json');
  // The patch travels as a JSON-encoded string body (quoted on the wire).
  assert.equal(body, JSON.stringify(patch));
});

test('deleteResource DELETEs the resource endpoint with force/orphan flags', async (t) => {
  const { requests } = installFetch([{ status: 200, body: {} }]);
  t.after(() => mock.restoreAll());
  const client = new ArgoCDClient('https://argo.example.com', 'tok');
  await client.deleteResource('my-app', 'argocd', RESOURCE_REF, { force: true, orphan: false });

  assert.equal(requests.length, 1);
  const { url, method, body } = requests[0];
  assert.equal(method, 'DELETE');
  assert.equal(body, undefined);
  assert.equal(url.pathname, '/api/v1/applications/my-app/resource');
  assert.equal(url.searchParams.get('appNamespace'), 'argocd');
  assert.equal(url.searchParams.get('namespace'), 'prod');
  assert.equal(url.searchParams.get('resourceName'), 'my-deploy');
  assert.equal(url.searchParams.get('group'), 'apps');
  assert.equal(url.searchParams.get('kind'), 'Deployment');
  assert.equal(url.searchParams.get('version'), 'v1');
  assert.equal(url.searchParams.get('force'), 'true');
  assert.equal(url.searchParams.get('orphan'), 'false');
});

test('deleteResource omits force/orphan and appNamespace when not provided', async (t) => {
  const { requests } = installFetch([{ status: 200, body: {} }]);
  t.after(() => mock.restoreAll());
  const client = new ArgoCDClient('https://argo.example.com', 'tok');
  await client.deleteResource('my-app', undefined, RESOURCE_REF);

  const { url } = requests[0];
  assert.equal(url.searchParams.has('force'), false);
  assert.equal(url.searchParams.has('orphan'), false);
  assert.equal(url.searchParams.has('appNamespace'), false);
});

test('terminateOperation DELETEs the operation endpoint', async (t) => {
  const { requests } = installFetch([{ status: 200, body: {} }]);
  t.after(() => mock.restoreAll());
  const client = new ArgoCDClient('https://argo.example.com', 'tok');
  await client.terminateOperation('my-app', 'argocd');

  assert.equal(requests.length, 1);
  const { url, method } = requests[0];
  assert.equal(method, 'DELETE');
  assert.equal(url.pathname, '/api/v1/applications/my-app/operation');
  assert.equal(url.searchParams.get('appNamespace'), 'argocd');
});

test('terminateOperation omits appNamespace when not provided', async (t) => {
  const { requests } = installFetch([{ status: 200, body: {} }]);
  t.after(() => mock.restoreAll());
  const client = new ArgoCDClient('https://argo.example.com', 'tok');
  await client.terminateOperation('my-app');

  assert.equal(requests[0].url.searchParams.has('appNamespace'), false);
});
