import assert from 'node:assert/strict';
import { test } from 'node:test';
import { refreshUpstream, UpstreamTokenError } from './oauth.js';
import type { OidcProviderMetadata } from './types.js';

const META: OidcProviderMetadata = {
  issuer: 'https://argocd.example.com/api/dex',
  authorizationEndpoint: 'https://argocd.example.com/api/dex/auth',
  tokenEndpoint: 'https://argocd.example.com/api/dex/token'
};
const OPTS = { clientId: 'c', clientSecret: 's', refreshToken: 'R1' };

const answering = (status: number, body: string): typeof fetch =>
  (async () => new Response(body, { status })) as unknown as typeof fetch;

test('a rejected grant carries the status and the OAuth error code from Dex', async () => {
  await assert.rejects(
    () =>
      refreshUpstream(
        META,
        OPTS,
        answering(
          400,
          JSON.stringify({
            error: 'invalid_request',
            error_description: 'Refresh token is invalid'
          })
        )
      ),
    (error: unknown) => {
      assert.ok(error instanceof UpstreamTokenError);
      assert.equal(error.status, 400);
      assert.equal(error.oauthError, 'invalid_request');
      assert.equal(error.grantRejected, true);
      // The description stays out of the message, which can reach the client.
      assert.equal(error.message, 'Upstream token endpoint returned 400: invalid_request');
      assert.equal(error.description, 'Refresh token is invalid');
      return true;
    }
  );
});

test('a 5xx from Dex is not a rejected grant', async () => {
  await assert.rejects(
    () => refreshUpstream(META, OPTS, answering(503, 'upstream down')),
    (error: unknown) => {
      assert.ok(error instanceof UpstreamTokenError);
      assert.equal(error.status, 503);
      assert.equal(error.grantRejected, false);
      assert.equal(error.oauthError, undefined);
      assert.match(error.message, /^Upstream token endpoint returned 503$/);
      return true;
    }
  );
});

test('an over-long error description is cut short', async () => {
  await assert.rejects(
    () =>
      refreshUpstream(
        META,
        OPTS,
        answering(
          400,
          JSON.stringify({ error: 'invalid_grant', error_description: 'x'.repeat(1000) })
        )
      ),
    (error: unknown) => {
      assert.ok(error instanceof UpstreamTokenError);
      assert.ok(error.description!.length < 200, `description is ${error.description!.length}`);
      return true;
    }
  );
});

// A wrong or rotated client secret is our configuration fault: it must not be
// read as every user's login being dead.
test('401 invalid_client is not a rejected grant', async () => {
  await assert.rejects(
    () => refreshUpstream(META, OPTS, answering(401, JSON.stringify({ error: 'invalid_client' }))),
    (error: unknown) => {
      assert.ok(error instanceof UpstreamTokenError);
      assert.equal(error.grantRejected, false);
      return true;
    }
  );
});

test('a 400 without an OAuth error code is not a rejected grant', async () => {
  await assert.rejects(
    () => refreshUpstream(META, OPTS, answering(400, 'not json')),
    (error: unknown) => {
      assert.ok(error instanceof UpstreamTokenError);
      assert.equal(error.grantRejected, false);
      return true;
    }
  );
});
