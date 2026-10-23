import assert from 'node:assert/strict';
import { test } from 'node:test';
import { connectHttpTransport } from './transport.js';

// The one guarantee that lives in the wiring rather than in a unit:
// MCP_ALLOW_ARGOCD_TOKEN must be resolved before the auth-mode branch, so a
// token-mode process with the flag set refuses to start instead of silently
// ignoring it. The transport throws before app.listen, so no port is opened.
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

test('http transport: token mode with MCP_ALLOW_ARGOCD_TOKEN set refuses to start', async () => {
  await withEnv({ AUTH_MODE: 'token', MCP_ALLOW_ARGOCD_TOKEN: 'true', ARGOCD_API_TOKEN: 'x' }, () =>
    assert.rejects(connectHttpTransport(0), /AUTH_MODE=oidc/)
  );
});
