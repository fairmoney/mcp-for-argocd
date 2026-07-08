import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type {
  TokenStore,
  PendingAuth,
  CompletedAuth,
  StoredToken,
  RefreshRecord
} from './tokenStore.js';
import { plainCodec, type ValueCodec } from './encryption.js';

// The subset of ioredis we use. Declared structurally so tests can pass
// ioredis-mock without a type dependency on the concrete client.
export interface RedisLike {
  get(key: string): Promise<string | null>;
  getdel(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  set(key: string, value: string, mode: 'EX', ttlSec: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  quit(): Promise<unknown>;
}

const NS = 'argocd-mcp';
const K = {
  client: (id: string) => `${NS}:client:${id}`,
  pending: (s: string) => `${NS}:pending:${s}`,
  code: (c: string) => `${NS}:code:${c}`,
  access: (o: string) => `${NS}:access:${o}`,
  refresh: (o: string) => `${NS}:refresh:${o}`
};

// Redis-backed TokenStore. Key TTL is native (SET ... EX), so no sweep is
// needed. Values are run through `codec` so tokens can be encrypted at rest.
// Sharing one Redis across replicas lets an OAuth callback be served by a
// different pod than the /authorize that created the pending state.
export class RedisTokenStore implements TokenStore {
  constructor(
    private redis: RedisLike,
    private codec: ValueCodec = plainCodec
  ) {}

  private async putJson(key: string, value: unknown, ttlSec?: number): Promise<void> {
    const payload = this.codec.encode(JSON.stringify(value));
    if (ttlSec && ttlSec > 0) {
      await this.redis.set(key, payload, 'EX', ttlSec);
    } else {
      await this.redis.set(key, payload);
    }
  }

  private async getJson<T>(key: string): Promise<T | undefined> {
    const raw = await this.redis.get(key);
    if (raw === null) return undefined;
    return JSON.parse(this.codec.decode(raw)) as T;
  }

  // Atomic get-and-delete via Redis GETDEL: the read and the delete are a single
  // command, so concurrent callers (e.g. two replicas racing on the same OAuth
  // callback) cannot both observe the value. This preserves the single-use
  // invariant that authorization codes and pending-auth state depend on.
  private async take<T>(key: string): Promise<T | undefined> {
    const raw = await this.redis.getdel(key);
    if (raw === null) return undefined;
    return JSON.parse(this.codec.decode(raw)) as T;
  }

  async putClient(client: OAuthClientInformationFull): Promise<void> {
    await this.putJson(K.client(client.client_id), client);
  }
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.getJson<OAuthClientInformationFull>(K.client(clientId));
  }

  async putPendingAuth(state: string, value: PendingAuth, ttlSec: number): Promise<void> {
    await this.putJson(K.pending(state), value, ttlSec);
  }
  async takePendingAuth(state: string): Promise<PendingAuth | undefined> {
    return this.take<PendingAuth>(K.pending(state));
  }

  async putAuthCode(code: string, value: CompletedAuth, ttlSec: number): Promise<void> {
    await this.putJson(K.code(code), value, ttlSec);
  }
  async takeAuthCode(code: string): Promise<CompletedAuth | undefined> {
    return this.take<CompletedAuth>(K.code(code));
  }

  async putAccessToken(opaque: string, value: StoredToken, ttlSec?: number): Promise<void> {
    await this.putJson(K.access(opaque), value, ttlSec);
  }
  async getAccessToken(opaque: string): Promise<StoredToken | undefined> {
    return this.getJson<StoredToken>(K.access(opaque));
  }
  async deleteAccessToken(opaque: string): Promise<void> {
    await this.redis.del(K.access(opaque));
  }

  async putRefreshToken(opaque: string, value: RefreshRecord): Promise<void> {
    await this.putJson(K.refresh(opaque), value);
  }
  async getRefreshToken(opaque: string): Promise<RefreshRecord | undefined> {
    return this.getJson<RefreshRecord>(K.refresh(opaque));
  }
  async deleteRefreshToken(opaque: string): Promise<void> {
    await this.redis.del(K.refresh(opaque));
  }

  dispose(): void {
    // Best-effort close; ignore errors during shutdown.
    void this.redis.quit().catch(() => undefined);
  }
}
