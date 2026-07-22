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
