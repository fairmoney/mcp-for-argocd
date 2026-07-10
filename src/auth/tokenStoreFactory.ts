import { Redis } from 'ioredis';
import type { OidcConfig } from './config.js';
import type { TokenStore } from './tokenStore.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';
import { RedisTokenStore } from './redisTokenStore.js';
import { aesGcmCodec, plainCodec } from './encryption.js';
import { logger } from '../logging/logging.js';

// Parse an optional positive-integer seconds env var. Returns undefined when
// unset/blank (the store then uses its own default); fails closed on garbage so
// a typo can't silently disable the memory bound.
const parseTtlSec = (raw: string | undefined, name: string): number | undefined => {
  const trimmed = (raw ?? '').trim();
  if (!trimmed) return undefined;
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`Invalid ${name} "${raw}": expected a positive integer number of seconds`);
  }
  return n;
};

// Build the TokenStore chosen by config. Redis enables multiple replicas (and
// bounds memory in Redis via native key TTLs); the optional encryption key
// protects tokens written to Redis at rest. The in-memory store keeps idle
// sessions/clients on a sliding TTL so a long-lived single replica does not
// grow without bound — tune via SESSION_IDLE_TTL_SEC / CLIENT_IDLE_TTL_SEC.
export const createTokenStore = (
  config: OidcConfig,
  env: NodeJS.ProcessEnv = process.env
): TokenStore => {
  if (config.tokenStore === 'redis') {
    if (!config.redisUrl) throw new Error('TOKEN_STORE=redis requires REDIS_URL');
    logger.info('Using Redis token store');
    const codec = config.encryptionKey ? aesGcmCodec(config.encryptionKey) : plainCodec;
    return new RedisTokenStore(new Redis(config.redisUrl), codec);
  }
  logger.info('Using in-memory token store (single replica only)');
  return new InMemoryTokenStore({
    sessionTtlSec: parseTtlSec(env.SESSION_IDLE_TTL_SEC, 'SESSION_IDLE_TTL_SEC'),
    clientTtlSec: parseTtlSec(env.CLIENT_IDLE_TTL_SEC, 'CLIENT_IDLE_TTL_SEC')
  });
};
