import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveTrustProxy } from './transport.js';

test('resolveTrustProxy defaults to 1 (single ingress hop) when unset', () => {
  assert.equal(resolveTrustProxy({}), 1);
});

test('resolveTrustProxy parses a positive hop count for stacked proxies', () => {
  assert.equal(resolveTrustProxy({ TRUST_PROXY_HOPS: '2' }), 2);
});

test('resolveTrustProxy allows 0 to disable proxy trust (direct exposure)', () => {
  assert.equal(resolveTrustProxy({ TRUST_PROXY_HOPS: '0' }), 0);
});

test('resolveTrustProxy trims surrounding whitespace', () => {
  assert.equal(resolveTrustProxy({ TRUST_PROXY_HOPS: '  3 ' }), 3);
});

test('resolveTrustProxy fails closed on a non-integer value', () => {
  assert.throws(() => resolveTrustProxy({ TRUST_PROXY_HOPS: 'yes' }), /TRUST_PROXY_HOPS/);
});

test('resolveTrustProxy fails closed on a negative value', () => {
  assert.throws(() => resolveTrustProxy({ TRUST_PROXY_HOPS: '-1' }), /TRUST_PROXY_HOPS/);
});
