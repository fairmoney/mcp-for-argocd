import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from './server.js';
import { ArgoCDClient } from '../argocd/client.js';
import type { BearerTokenProvider } from '../argocd/http.js';

// In oidc mode the per-call argocdBaseUrl override must be ignored: a user's
// token is only ever sent to the configured ARGOCD_BASE_URL. resolveClient is
// private, so we reach it the same way server.test.ts does: cast the server
// instance and call it directly. This is hermetic (no network, no tool-handler
// indirection) and asserts the pinning behavior itself, not a side effect of a
// failed network call.
const DEFAULT_BASE_URL = 'https://argocd.internal.example.com';
const EVIL_BASE_URL = 'https://evil.example.com';

const getResolveClient = (server: ReturnType<typeof createServer>) =>
  (
    server as unknown as {
      resolveClient: (a: { argocdBaseUrl?: string }) => ArgoCDClient;
    }
  ).resolveClient.bind(server);

const baseUrlOf = (client: ArgoCDClient): string =>
  (client as unknown as { baseUrl: string }).baseUrl;

const tokenSourceOf = (client: ArgoCDClient): unknown =>
  (client as unknown as { client: { apiToken?: string; tokenSource?: unknown } }).client
    .tokenSource ?? (client as unknown as { client: { apiToken?: string } }).client.apiToken;

test('pinBaseUrl mode: per-call argocdBaseUrl override is ignored, default base URL is always used', () => {
  const server = createServer({
    argocdBaseUrl: DEFAULT_BASE_URL,
    argocdApiToken: '',
    pinBaseUrl: true,
    tokenSource: 'session-token'
  });
  const resolveClient = getResolveClient(server);

  const clientWithOverride = resolveClient({ argocdBaseUrl: EVIL_BASE_URL });
  const clientWithoutOverride = resolveClient({});

  assert.equal(
    baseUrlOf(clientWithOverride),
    DEFAULT_BASE_URL,
    'must target the configured default base URL, not the attacker-supplied override'
  );
  assert.notEqual(baseUrlOf(clientWithOverride), EVIL_BASE_URL);
  // Pinning also means the client is stable across calls regardless of the
  // (ignored) argument — same underlying client instance both times.
  assert.equal(clientWithOverride, clientWithoutOverride);
});

test('pinBaseUrl mode: the client is built with the provided tokenSource, not a static token', () => {
  const provider: BearerTokenProvider = {
    current: async () => 'live-token',
    refresh: async () => 'refreshed-token'
  };
  const server = createServer({
    argocdBaseUrl: DEFAULT_BASE_URL,
    argocdApiToken: '',
    pinBaseUrl: true,
    tokenSource: provider
  });
  const resolveClient = getResolveClient(server);

  const client = resolveClient({ argocdBaseUrl: EVIL_BASE_URL });

  assert.equal(tokenSourceOf(client), provider);
});

test('pinBaseUrl mode: without a configured default base URL, resolveClient throws rather than falling back', () => {
  const server = createServer({
    argocdBaseUrl: '',
    argocdApiToken: '',
    pinBaseUrl: true,
    tokenSource: 'session-token'
  });
  const resolveClient = getResolveClient(server);

  assert.throws(() => resolveClient({ argocdBaseUrl: EVIL_BASE_URL }), /ARGOCD_BASE_URL/);
});
