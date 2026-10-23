import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import type { NextFunction, Request, Response } from 'express';
import { logger } from '../logging/logging.js';
import {
  classifyRequest,
  createPassthroughMiddleware,
  fingerprintOf,
  passthroughAuthOf,
  principalFor,
  resolveAllowArgocdToken,
  PASSTHROUGH_AUTH_TTL_SEC,
  PassthroughRejected,
  verifyArgocdToken
} from './argocdTokenPassthrough.js';

// --- flag ---------------------------------------------------------------------

test('resolveAllowArgocdToken is off unless exactly "true", and refused outside oidc mode', () => {
  assert.equal(resolveAllowArgocdToken({ AUTH_MODE: 'oidc' }), false);
  assert.equal(
    resolveAllowArgocdToken({ AUTH_MODE: 'oidc', MCP_ALLOW_ARGOCD_TOKEN: 'yes' }),
    false
  );
  assert.equal(
    resolveAllowArgocdToken({ AUTH_MODE: 'oidc', MCP_ALLOW_ARGOCD_TOKEN: ' TRUE ' }),
    true
  );
  assert.throws(
    () => resolveAllowArgocdToken({ MCP_ALLOW_ARGOCD_TOKEN: 'true' }),
    /AUTH_MODE=oidc/
  );
  assert.throws(
    () => resolveAllowArgocdToken({ AUTH_MODE: 'token', MCP_ALLOW_ARGOCD_TOKEN: 'true' }),
    /AUTH_MODE=oidc/
  );
});

// --- routing --------------------------------------------------------------------

test('classifyRequest: off or no token header means the OIDC path; both credentials is ambiguous', () => {
  assert.equal(classifyRequest({}, false), 'oidc');
  assert.equal(classifyRequest({ 'x-argocd-api-token': 'tok' }, false), 'oidc');
  assert.equal(classifyRequest({ authorization: 'Bearer opaque' }, true), 'oidc');
  assert.equal(classifyRequest({ 'x-argocd-api-token': '   ' }, true), 'oidc');
  assert.equal(classifyRequest({ 'x-argocd-api-token': 'tok' }, true), 'passthrough');
  assert.equal(
    classifyRequest({ 'x-argocd-api-token': 'tok', authorization: 'Bearer opaque' }, true),
    'ambiguous'
  );
});

// --- naming ---------------------------------------------------------------------

test('principalFor names a local account and fingerprints anything else', () => {
  const fp = 'a'.repeat(64);
  assert.equal(principalFor('devops-agent', fp), 'argocd:devops-agent');
  assert.equal(principalFor('someone@example.com', fp), 'argocd-token:aaaaaaaa');
  assert.equal(principalFor(undefined, fp), 'argocd-token:aaaaaaaa');
  assert.equal(principalFor('Mixed.Case', fp), 'argocd-token:aaaaaaaa');
});

test('fingerprintOf is the SHA-256 of the token', () => {
  assert.equal(fingerprintOf('tok'), createHash('sha256').update('tok').digest('hex'));
});

// --- verification against ArgoCD ------------------------------------------------

const fetchAnswering = (
  status: number,
  body?: unknown,
  calls: { url: string; auth?: string }[] = []
) =>
  (async (url: string | URL | globalThis.Request, init?: RequestInit) => {
    calls.push({
      url: String(url),
      auth: (init?.headers as Record<string, string>)?.Authorization
    });
    return new globalThis.Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' }
    });
  }) as typeof fetch;

test('verifyArgocdToken asks userinfo with the token and returns the username when logged in', async () => {
  const calls: { url: string; auth?: string }[] = [];
  const result = await verifyArgocdToken(
    'https://argocd.example.com/',
    'tok',
    fetchAnswering(200, { loggedIn: true, username: 'devops-agent' }, calls)
  );
  assert.deepEqual(result, { username: 'devops-agent' });
  assert.deepEqual(calls, [
    { url: 'https://argocd.example.com/api/v1/session/userinfo', auth: 'Bearer tok' }
  ]);
});

test('verifyArgocdToken: not logged in, 401 and 403 are a 401; other failures are a 503', async () => {
  const rejectsWith = async (fetchImpl: typeof fetch, status: 401 | 503) =>
    assert.rejects(verifyArgocdToken('https://argocd', 'sekrit-1', fetchImpl), (e: unknown) => {
      assert.ok(e instanceof PassthroughRejected);
      assert.equal(e.status, status);
      assert.doesNotMatch(e.message, /sekrit/);
      return true;
    });
  await rejectsWith(fetchAnswering(200, { loggedIn: false }), 401);
  await rejectsWith(fetchAnswering(401), 401);
  await rejectsWith(fetchAnswering(403), 401);
  await rejectsWith(fetchAnswering(500), 503);
  await rejectsWith(
    (async () => {
      throw new Error('connect ECONNREFUSED');
    }) as typeof fetch,
    503
  );
});

// --- middleware -----------------------------------------------------------------

const makeReq = (headers: Record<string, string>) =>
  ({ headers, auth: undefined }) as unknown as Request & { auth?: unknown };
const makeRes = () => {
  const out = { status: 200, json: undefined as unknown };
  const res = {
    status(code: number) {
      out.status = code;
      return res;
    },
    json(payload: unknown) {
      out.json = payload;
      return res;
    }
  };
  return { res: res as unknown as Response, out };
};
const run = async (
  headers: Record<string, string>,
  deps: Partial<Parameters<typeof createPassthroughMiddleware>[0]> & { verifyCalls?: string[] }
) => {
  const verifyCalls: string[] = deps.verifyCalls ?? [];
  const mw = createPassthroughMiddleware({
    allowArgocdToken: deps.allowArgocdToken ?? true,
    argocdBaseUrl: 'https://argocd',
    stateless: deps.stateless ?? false,
    verify:
      deps.verify ??
      (async (_base, token) => {
        verifyCalls.push(token);
        return { username: 'devops-agent' };
      })
  });
  const req = makeReq(headers);
  const { res, out } = makeRes();
  let nextCalled = false;
  await mw(req, res, (() => {
    nextCalled = true;
  }) as NextFunction);
  return { req, out, nextCalled, verifyCalls };
};

test('middleware: flag off, or no token header, passes through untouched', async () => {
  for (const [headers, allow] of [
    [{ 'x-argocd-api-token': 'tok' }, false],
    [{ authorization: 'Bearer opaque' }, true],
    [{}, true]
  ] as const) {
    const r = await run(headers, { allowArgocdToken: allow });
    assert.equal(r.nextCalled, true);
    assert.equal(r.req.auth, undefined);
    assert.deepEqual(r.verifyCalls, []);
  }
});

test('middleware: both credentials is a 400 and stops there', async () => {
  const r = await run({ 'x-argocd-api-token': 'tok', authorization: 'Bearer x' }, {});
  assert.equal(r.out.status, 400);
  assert.equal(r.nextCalled, false);
  assert.deepEqual(r.verifyCalls, []);
});

test('middleware: a session start verifies the token with ArgoCD and attaches the identity', async () => {
  const before = Math.floor(Date.now() / 1000);
  const r = await run({ 'x-argocd-api-token': ' tok ' }, {});

  assert.deepEqual(r.verifyCalls, ['tok']);
  assert.equal(r.nextCalled, true);
  const auth = passthroughAuthOf(r.req.auth as never);
  assert.deepEqual(auth, {
    kind: 'argocd-token',
    argocdToken: 'tok',
    fingerprint: fingerprintOf('tok'),
    principal: 'argocd:devops-agent'
  });
  const info = r.req.auth as { clientId: string; expiresAt: number };
  assert.equal(info.clientId, 'argocd:devops-agent');
  assert.ok(info.expiresAt >= before + PASSTHROUGH_AUTH_TTL_SEC - 1);
});

test('middleware: a session reuse attaches the identity without asking ArgoCD', async () => {
  const r = await run({ 'x-argocd-api-token': 'tok', 'mcp-session-id': 'sid-1' }, {});
  assert.deepEqual(r.verifyCalls, []);
  assert.equal(r.nextCalled, true);
  assert.equal(passthroughAuthOf(r.req.auth as never)?.fingerprint, fingerprintOf('tok'));
});

test('middleware: stateless verifies on every request, session id or not', async () => {
  const r = await run(
    { 'x-argocd-api-token': 'tok', 'mcp-session-id': 'sid-1' },
    { stateless: true }
  );
  assert.deepEqual(r.verifyCalls, ['tok']);
});

test('middleware: an SSO user token is named by fingerprint, never by email', async () => {
  const r = await run(
    { 'x-argocd-api-token': 'tok' },
    { verify: async () => ({ username: 'someone@example.com' }) }
  );
  assert.equal(
    passthroughAuthOf(r.req.auth as never)?.principal,
    `argocd-token:${fingerprintOf('tok').slice(0, 8)}`
  );
  assert.doesNotMatch(JSON.stringify(r.req.auth), /example\.com/);
});

test('middleware: ArgoCD rejecting the token is a 401, ArgoCD unavailable a 503, with a log line and no next', async () => {
  const warned: Record<string, unknown>[] = [];
  const original = logger.warn;
  logger.warn = ((fields: Record<string, unknown>) => {
    warned.push(fields);
  }) as typeof logger.warn;
  try {
    for (const [status, verify] of [
      [
        401,
        async () => {
          throw new PassthroughRejected(401, 'ArgoCD rejected the token');
        }
      ],
      [
        503,
        async () => {
          throw new PassthroughRejected(503, 'ArgoCD unreachable');
        }
      ]
    ] as const) {
      const r = await run({ 'x-argocd-api-token': 'sekrit-1' }, { verify });
      assert.equal(r.out.status, status);
      assert.equal(r.nextCalled, false);
      assert.equal(r.req.auth, undefined);
    }
  } finally {
    logger.warn = original;
  }
  assert.equal(warned.length, 2);
  assert.doesNotMatch(JSON.stringify(warned), /sekrit/);
});
