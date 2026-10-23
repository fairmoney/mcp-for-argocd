import assert from 'node:assert/strict';
import { test } from 'node:test';
import { HttpSessionManager } from './httpSessionManager.js';

const makeClock = (start = 0) => {
  let t = start;
  return { now: () => t, advanceMs: (ms: number) => (t += ms) };
};

// A fake transport/server pair that records whether it was closed.
const makePair = () => {
  const state = { transportClosed: false, serverClosed: false };
  return {
    state,
    transport: {
      sessionId: 'x',
      close: () => {
        state.transportClosed = true;
      }
    },
    server: {
      close: () => {
        state.serverClosed = true;
      }
    }
  };
};

test('get() returns the transport and resets the idle clock', () => {
  const clock = makeClock();
  const mgr = new HttpSessionManager({ idleTimeoutMs: 1000, now: clock.now, disableTimer: true });
  const p = makePair();
  mgr.add('s1', p.transport, p.server);

  clock.advanceMs(900);
  assert.equal(mgr.get('s1'), p.transport); // touches lastActivity
  clock.advanceMs(900); // 900 < 1000 since last touch
  mgr.sweepIdle();
  assert.equal(mgr.size, 1, 'recently-used session must survive the sweep');
});

test('sweepIdle() closes transport and server of idle sessions', () => {
  const clock = makeClock();
  const mgr = new HttpSessionManager({ idleTimeoutMs: 1000, now: clock.now, disableTimer: true });
  const p = makePair();
  mgr.add('s1', p.transport, p.server);

  clock.advanceMs(1001);
  mgr.sweepIdle();
  assert.equal(mgr.size, 0);
  assert.equal(p.state.transportClosed, true);
  assert.equal(p.state.serverClosed, true);
});

test('hasCapacity() evicts the oldest idle session when full', () => {
  const clock = makeClock();
  const mgr = new HttpSessionManager({
    maxSessions: 1,
    idleTimeoutMs: 1000,
    now: clock.now,
    disableTimer: true
  });
  const first = makePair();
  mgr.add('s1', first.transport, first.server);

  clock.advanceMs(1001); // s1 now idle
  assert.equal(mgr.hasCapacity(), true, 'should make room by evicting idle s1');
  assert.equal(first.state.transportClosed, true);
  assert.equal(mgr.size, 0);
});

test('hasCapacity() refuses when every slot is actively in use', () => {
  const clock = makeClock();
  const mgr = new HttpSessionManager({
    maxSessions: 1,
    idleTimeoutMs: 1000,
    now: clock.now,
    disableTimer: true
  });
  const p = makePair();
  mgr.add('s1', p.transport, p.server);

  // Still within the idle window -> no eviction, no capacity.
  clock.advanceMs(500);
  assert.equal(mgr.hasCapacity(), false);
  assert.equal(p.state.transportClosed, false);
});

test('forget() drops the entry without closing (transport already closed itself)', () => {
  const mgr = new HttpSessionManager({ disableTimer: true });
  const p = makePair();
  mgr.add('s1', p.transport, p.server);
  mgr.forget('s1');
  assert.equal(mgr.size, 0);
  assert.equal(p.state.transportClosed, false, 'forget must not double-close');
});

test('dispose() closes all live sessions', () => {
  const mgr = new HttpSessionManager({ disableTimer: true });
  const a = makePair();
  const b = makePair();
  mgr.add('a', a.transport, a.server);
  mgr.add('b', b.transport, b.server);
  mgr.dispose();
  assert.equal(mgr.size, 0);
  assert.equal(a.state.serverClosed, true);
  assert.equal(b.state.serverClosed, true);
});

// --- Owner binding ------------------------------------------------------------
//
// A session id is only usable by the principal that opened it. Without this,
// any authenticated caller who learns a session's UUID could drive it.

test('get() returns the transport only to the owner that added the session', () => {
  const clock = makeClock();
  const mgr = new HttpSessionManager({ idleTimeoutMs: 1000, now: clock.now, disableTimer: true });
  const p = makePair();
  mgr.add('s1', p.transport, p.server, 'argocd:devops-agent');

  assert.equal(mgr.get('s1', 'argocd:devops-agent'), p.transport);
  assert.equal(mgr.get('s1', 'client-abc'), undefined, 'another principal must be refused');
  assert.equal(mgr.get('s1'), undefined, 'an ownerless lookup must not match an owned session');
});

test('a refused get() does not reset the idle clock', () => {
  const clock = makeClock();
  const mgr = new HttpSessionManager({ idleTimeoutMs: 1000, now: clock.now, disableTimer: true });
  const p = makePair();
  mgr.add('s1', p.transport, p.server, 'owner-a');

  clock.advanceMs(900);
  assert.equal(mgr.get('s1', 'owner-b'), undefined);
  clock.advanceMs(200); // 1100 since add; the refused lookup must not have touched it
  mgr.sweepIdle();
  assert.equal(mgr.size, 0, 'session must be reaped as idle');
});

test('ownerless sessions (token mode) keep working with ownerless lookups only', () => {
  const clock = makeClock();
  const mgr = new HttpSessionManager({ idleTimeoutMs: 1000, now: clock.now, disableTimer: true });
  const p = makePair();
  mgr.add('s1', p.transport, p.server);

  assert.equal(mgr.get('s1'), p.transport);
  assert.equal(mgr.get('s1', 'argocd:devops-agent'), undefined);
});
