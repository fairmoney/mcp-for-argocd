import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { TokenStore } from './tokenStore.js';

const client = (id: string): OAuthClientInformationFull =>
  ({ client_id: id, redirect_uris: ['http://localhost/cb'] }) as OAuthClientInformationFull;

// Shared behavior every TokenStore implementation must satisfy. Called once per
// implementation from that implementation's *.test.ts file.
export const runTokenStoreContract = (name: string, makeStore: () => TokenStore): void => {
  test(`[${name}] client round-trips`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putClient(client('abc'));
    const got = await store.getClient('abc');
    assert.equal(got?.client_id, 'abc');
    assert.equal(await store.getClient('missing'), undefined);
  });

  test(`[${name}] pending auth is get-and-delete`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putPendingAuth(
      's1',
      {
        upstreamState: 's1',
        upstreamPkce: { codeVerifier: 'v', codeChallenge: 'c', codeChallengeMethod: 'S256' },
        clientRedirectUri: 'http://localhost/cb',
        clientCodeChallenge: 'cc',
        clientId: 'abc'
      },
      600
    );
    const first = await store.takePendingAuth('s1');
    assert.equal(first?.clientId, 'abc');
    const second = await store.takePendingAuth('s1');
    assert.equal(second, undefined); // consumed
  });

  test(`[${name}] access token round-trips and deletes`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putAccessToken('opaque1', {
      upstream: { accessToken: 'A', refreshToken: 'R', expiresAtMs: 1_000_000 },
      clientId: 'abc',
      sessionId: 'sess1'
    });
    const got = await store.getAccessToken('opaque1');
    assert.equal(got?.upstream.accessToken, 'A');
    await store.deleteAccessToken('opaque1');
    assert.equal(await store.getAccessToken('opaque1'), undefined);
  });

  test(`[${name}] refresh token round-trips and deletes`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putRefreshToken('r1', { clientId: 'abc', sessionId: 'sess1' });
    assert.equal((await store.getRefreshToken('r1'))?.sessionId, 'sess1');
    assert.equal((await store.getRefreshToken('r1'))?.clientId, 'abc');
    await store.deleteRefreshToken('r1');
    assert.equal(await store.getRefreshToken('r1'), undefined);
  });

  test(`[${name}] session record round-trips and deletes`, async (t) => {
    const store = makeStore();
    t.after(() => store.dispose());
    await store.putSession('sess1', { upstreamRefreshToken: 'UR', clientId: 'abc' });
    const got = await store.getSession('sess1');
    assert.equal(got?.upstreamRefreshToken, 'UR');
    assert.equal(got?.clientId, 'abc');
    await store.deleteSession('sess1');
    assert.equal(await store.getSession('sess1'), undefined);
  });
};
