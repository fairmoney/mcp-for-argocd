import { Redis } from 'ioredis';
import type { OidcConfig } from './config.js';
import type { TokenStore } from './tokenStore.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';
import { RedisTokenStore } from './redisTokenStore.js';
import { aesGcmCodec, plainCodec } from './encryption.js';
import { logger } from '../logging/logging.js';

// Build the TokenStore chosen by config. Redis enables multiple replicas; the
// optional encryption key protects tokens written to Redis at rest.
export const createTokenStore = (config: OidcConfig): TokenStore => {
  if (config.tokenStore === 'redis') {
    if (!config.redisUrl) throw new Error('TOKEN_STORE=redis requires REDIS_URL');
    logger.info('Using Redis token store');
    const codec = config.encryptionKey ? aesGcmCodec(config.encryptionKey) : plainCodec;
    return new RedisTokenStore(new Redis(config.redisUrl), codec);
  }
  logger.info('Using in-memory token store (single replica only)');
  return new InMemoryTokenStore();
};
