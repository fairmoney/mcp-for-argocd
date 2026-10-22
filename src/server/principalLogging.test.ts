import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from './server.js';
import { TokenRegistry } from './tokenRegistry.js';
import { logger } from '../logging/logging.js';

// Machine sessions carry a principal, and every tool call they make is logged
// with it so a key's use can be traced. OIDC sessions carry none, so nothing
// new is logged about people. The tool call below fails before any network
// request (no token can be resolved for the overridden base URL), which keeps
// the test hermetic; the log line is about the call, not its result.

const DEFAULT_BASE_URL = 'https://argocd.internal.example.com';
const OTHER_BASE_URL = 'https://argocd.other.example.com';

type LogCall = { fields: Record<string, unknown>; message: string };

// Capture logger.info calls for the duration of fn, restoring it afterwards.
const captureInfo = async (fn: () => Promise<void>): Promise<LogCall[]> => {
  const calls: LogCall[] = [];
  const original = logger.info;
  logger.info = ((fields: Record<string, unknown>, message: string) => {
    calls.push({ fields, message });
  }) as typeof logger.info;
  try {
    await fn();
  } finally {
    logger.info = original;
  }
  return calls;
};

const callGetApplication = async (server: ReturnType<typeof createServer>) => {
  const registered = (
    server as unknown as {
      _registeredTools: Record<string, { handler: (...a: unknown[]) => Promise<unknown> }>;
    }
  )._registeredTools;
  return (await registered['get_application'].handler(
    { applicationName: 'demo', argocdBaseUrl: OTHER_BASE_URL },
    {}
  )) as { isError?: boolean };
};

test('a server with a principal logs every tool call with principal, tool and outcome', async () => {
  const server = createServer({
    argocdBaseUrl: DEFAULT_BASE_URL,
    argocdApiToken: '',
    tokenRegistry: new TokenRegistry(),
    principal: 'apikey:devops-agent'
  });

  const calls = await captureInfo(async () => {
    const result = await callGetApplication(server);
    assert.equal(result.isError, true, 'the call fails hermetically before any request');
  });

  const line = calls.find((c) => c.fields.tool === 'get_application');
  assert.ok(line, 'a log line for the tool call is emitted');
  assert.equal(line.fields.principal, 'apikey:devops-agent');
  assert.equal(line.fields.outcome, 'error');
  // Arguments and results stay out of the log line.
  assert.equal('applicationName' in line.fields, false);
  assert.equal('args' in line.fields, false);
});

test('a server without a principal logs nothing about its tool calls', async () => {
  const server = createServer({
    argocdBaseUrl: DEFAULT_BASE_URL,
    argocdApiToken: '',
    tokenRegistry: new TokenRegistry()
  });

  const calls = await captureInfo(async () => {
    await callGetApplication(server);
  });

  assert.equal(
    calls.filter((c) => c.fields.tool === 'get_application').length,
    0,
    'OIDC and token-mode sessions must not gain a per-call log line'
  );
});
