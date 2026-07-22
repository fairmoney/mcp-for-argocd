import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runTokenStoreContract } from './tokenStore.contract.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';

runTokenStoreContract('memory', () => new InMemoryTokenStore());

// A controllable clock so eviction is deterministic and no real timer is needed.
const makeClock = (start = 0) => {
  let t = start;
  return { now: () => t, advanceSec: (s: number) => (t += s * 1000) };
};

test('[memory] idle sessions are evicted after their sliding TTL', async (t) => {
  const clock = makeClock();
  const store = new InMemoryTokenStore({ sessionTtlSec: 100, now: clock.now });
  t.after(() => store.dispose());

  await store.putSession('s1', { upstreamRefreshToken: 'UR', clientId: 'abc' });
  clock.advanceSec(101); // past the TTL, untouched
  assert.equal(await store.getSession('s1'), undefined, 'idle session should be evicted');
});

test('[memory] reading a session slides its TTL window', async (t) => {
  const clock = makeClock();
  const store = new InMemoryTokenStore({ sessionTtlSec: 100, now: clock.now });
  t.after(() => store.dispose());

  await store.putSession('s1', { upstreamRefreshToken: 'UR', clientId: 'abc' });
  // Keep it alive by reading before each deadline.
  for (let i = 0; i < 5; i++) {
    clock.advanceSec(90);
    assert.ok(await store.getSession('s1'), 'active session must survive');
  }
  // Once reads stop, it expires.
  clock.advanceSec(101);
  assert.equal(await store.getSession('s1'), undefined);
});

test('[memory] idle dynamic client registrations are evicted after their TTL', async (t) => {
  const clock = makeClock();
  const store = new InMemoryTokenStore({ clientTtlSec: 100, now: clock.now });
  t.after(() => store.dispose());

  await store.putClient({
    client_id: 'c1',
    redirect_uris: ['http://localhost/cb']
  } as Parameters<InMemoryTokenStore['putClient']>[0]);
  clock.advanceSec(101);
  assert.equal(await store.getClient('c1'), undefined, 'idle client should be evicted');
});
