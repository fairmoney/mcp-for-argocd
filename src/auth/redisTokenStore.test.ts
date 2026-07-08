import assert from 'node:assert/strict';
import { test } from 'node:test';
import RedisMock from 'ioredis-mock';
import { runTokenStoreContract } from './tokenStore.contract.js';
import { RedisTokenStore } from './redisTokenStore.js';
import { aesGcmCodec } from './encryption.js';

// Contract: run the shared suite against a fresh in-memory Redis each time.
runTokenStoreContract('redis', () => new RedisTokenStore(new RedisMock()));

// Contract with encryption enabled, to prove encode/decode is transparent.
runTokenStoreContract(
  'redis+aes',
  () => new RedisTokenStore(new RedisMock(), aesGcmCodec(Buffer.alloc(32, 7)))
);

test('[redis+aes] stored value is not plaintext in Redis', async (t) => {
  const redis = new RedisMock();
  const store = new RedisTokenStore(redis, aesGcmCodec(Buffer.alloc(32, 7)));
  t.after(() => store.dispose());
  await store.putAccessToken('opaqueX', {
    upstream: { accessToken: 'SUPER_SECRET_JWT' },
    clientId: 'abc',
    sessionId: 'sessX'
  });
  const raw = (await redis.get('argocd-mcp:access:opaqueX')) ?? '';
  assert.ok(!raw.includes('SUPER_SECRET_JWT'), 'raw Redis value must be encrypted');
  const got = await store.getAccessToken('opaqueX');
  assert.equal(got?.upstream.accessToken, 'SUPER_SECRET_JWT');
});
