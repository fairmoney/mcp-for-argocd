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
  createAuthDispatcher,
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

test('principalFor names a local account by issuer and fingerprints anything else', () => {
  const fp = 'a'.repeat(64);
  assert.equal(principalFor('devops-agent', 'argocd', fp), 'argocd:devops-agent');
  // An SSO user with a bare handle is still a person: the issuer says so.
  assert.equal(principalFor('jdoe', 'https://argocd/api/dex', fp), 'argocd-token:aaaaaaaa');
  assert.equal(principalFor('someone@example.com', 'argocd', fp), 'argocd-token:aaaaaaaa');
  assert.equal(principalFor('devops-agent', undefined, fp), 'argocd-token:aaaaaaaa');
  // The name pattern is a last guard on what is logged, issuer or not.
  for (const odd of ['devops_agent', 'devops.agent', 'DevOps', '']) {
    assert.equal(principalFor(odd, 'argocd', fp), 'argocd-token:aaaaaaaa', odd);
  }
  assert.equal(principalFor(undefined, 'argocd', fp), 'argocd-token:aaaaaaaa');
});

test('fingerprintOf is the SHA-256 of the token', () => {
  assert.equal(fingerprintOf('tok'), createHash('sha256').update('tok').digest('hex'));
});

// --- verification against ArgoCD ------------------------------------------------

type FetchCall = { url: string; auth?: string; hasTimeout: boolean };
const fetchAnswering = (status: number, body?: unknown, calls: FetchCall[] = [], raw = false) =>
  (async (url: string | URL | globalThis.Request, init?: RequestInit) => {
    calls.push({
      url: String(url),
      auth: (init?.headers as Record<string, string>)?.Authorization,
      hasTimeout: init?.signal instanceof AbortSignal
    });
    const payload = body === undefined ? null : raw ? String(body) : JSON.stringify(body);
    return new globalThis.Response(payload, {
      status,
      headers: { 'content-type': raw ? 'text/html' : 'application/json' }
    });
  }) as typeof fetch;

test('verifyArgocdToken asks userinfo with the token, under a deadline, and returns who it is', async () => {
  const calls: FetchCall[] = [];
  const result = await verifyArgocdToken(
    'https://argocd.example.com/',
    'tok',
    fetchAnswering(200, { loggedIn: true, username: 'devops-agent', iss: 'argocd' }, calls)
  );
  assert.deepEqual(result, { username: 'devops-agent', iss: 'argocd' });
  assert.deepEqual(calls, [
    {
      url: 'https://argocd.example.com/api/v1/session/userinfo',
      auth: 'Bearer tok',
      hasTimeout: true
    }
  ]);
});

test('verifyArgocdToken: a non-JSON 2xx is a 503 and the body never enters the message', async () => {
  await assert.rejects(
    verifyArgocdToken(
      'https://argocd',
      'tok',
      fetchAnswering(200, '<html>login page SECRET-MARKER</html>', [], true)
    ),
    (e: unknown) => {
      assert.ok(e instanceof PassthroughRejected);
      assert.equal(e.status, 503);
      assert.doesNotMatch(e.message, /SECRET-MARKER|html/);
      return true;
    }
  );
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
  // What AbortSignal.timeout produces when ArgoCD accepts the connection and
  // never answers: the deadline is a 503, not a hang and not a pass.
  await rejectsWith(
    (async () => {
      throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
    }) as typeof fetch,
    503
  );
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
        return { username: 'devops-agent', iss: 'argocd' };
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
  assert.equal((r.req.auth as { clientId: string }).clientId, 'argocd:devops-agent');
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
    { verify: async () => ({ username: 'someone@example.com', iss: 'argocd' }) }
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

// --- dispatcher ----------------------------------------------------------------

test('dispatcher: the OIDC route gets the bearer check, token routes get the passthrough middleware', () => {
  const seen: string[] = [];
  const dispatch = createAuthDispatcher({
    allowArgocdToken: true,
    passthrough: () => {
      seen.push('passthrough');
    },
    bearerAuth: () => {
      seen.push('bearer');
    }
  });
  const next = (() => {}) as NextFunction;
  const res = makeRes().res;

  dispatch(makeReq({ authorization: 'Bearer opaque' }), res, next);
  dispatch(makeReq({}), res, next);
  dispatch(makeReq({ 'x-argocd-api-token': 'tok' }), res, next);
  dispatch(makeReq({ 'x-argocd-api-token': 'tok', authorization: 'Bearer x' }), res, next);

  assert.deepEqual(seen, ['bearer', 'bearer', 'passthrough', 'passthrough']);
});

test('dispatcher: with the flag off everything is the bearer check, token header or not', () => {
  const seen: string[] = [];
  const dispatch = createAuthDispatcher({
    allowArgocdToken: false,
    passthrough: () => {
      seen.push('passthrough');
    },
    bearerAuth: () => {
      seen.push('bearer');
    }
  });
  dispatch(makeReq({ 'x-argocd-api-token': 'tok' }), makeRes().res, (() => {}) as NextFunction);
  assert.deepEqual(seen, ['bearer']);
});

test('verifyArgocdToken: a silent ArgoCD is cut off by the deadline, not waited for', async () => {
  // This fetch answers only when the signal it was given aborts, so the test
  // passes only if the deadline really fires.
  const silentUntilAborted = ((_url: unknown, init?: RequestInit) =>
    new Promise<never>((_, reject) => {
      init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
    })) as typeof fetch;
  const outcome = await Promise.race([
    verifyArgocdToken('https://argocd', 'tok', silentUntilAborted, 20).then(
      () => 'resolved',
      (e: unknown) => (e instanceof PassthroughRejected ? `rejected ${e.status}` : 'other error')
    ),
    new Promise<string>((resolve) => setTimeout(() => resolve('no deadline fired'), 1000))
  ]);
  assert.equal(outcome, 'rejected 503');
});
