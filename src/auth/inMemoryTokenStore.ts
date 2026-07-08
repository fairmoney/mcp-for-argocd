import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type {
  TokenStore,
  PendingAuth,
  CompletedAuth,
  StoredToken,
  RefreshRecord,
  SessionRecord
} from './tokenStore.js';

interface Expiring<T> {
  value: T;
  expiresAtMs?: number;
}

// Single-process TokenStore. A periodic sweep evicts expired flow-state and
// access-token entries. Use only with a single replica; for multiple replicas
// use RedisTokenStore so state is shared across pods.
export class InMemoryTokenStore implements TokenStore {
  private clients = new Map<string, OAuthClientInformationFull>();
  private pending = new Map<string, Expiring<PendingAuth>>();
  private codes = new Map<string, Expiring<CompletedAuth>>();
  private access = new Map<string, Expiring<StoredToken>>();
  private refresh = new Map<string, Expiring<RefreshRecord>>();
  // Sessions live as long as the refresh chain; no TTL and no sweep.
  private sessions = new Map<string, SessionRecord>();
  private sweep: ReturnType<typeof setInterval>;

  constructor() {
    this.sweep = setInterval(() => this.evictExpired(), 60_000);
    if (this.sweep.unref) this.sweep.unref();
  }

  private nowMs(): number {
    return Date.now();
  }

  private fresh<T>(map: Map<string, Expiring<T>>, key: string): T | undefined {
    const entry = map.get(key);
    if (!entry) return undefined;
    if (entry.expiresAtMs && this.nowMs() > entry.expiresAtMs) {
      map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  private evictExpired(): void {
    const now = this.nowMs();
    for (const map of [this.pending, this.codes, this.access, this.refresh]) {
      for (const [key, entry] of map) {
        if (entry.expiresAtMs && now > entry.expiresAtMs) map.delete(key);
      }
    }
  }

  async putClient(client: OAuthClientInformationFull): Promise<void> {
    this.clients.set(client.client_id, client);
  }
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async putPendingAuth(state: string, value: PendingAuth, ttlSec: number): Promise<void> {
    this.pending.set(state, { value, expiresAtMs: this.nowMs() + ttlSec * 1000 });
  }
  async takePendingAuth(state: string): Promise<PendingAuth | undefined> {
    const v = this.fresh(this.pending, state);
    this.pending.delete(state);
    return v;
  }

  async putAuthCode(code: string, value: CompletedAuth, ttlSec: number): Promise<void> {
    this.codes.set(code, { value, expiresAtMs: this.nowMs() + ttlSec * 1000 });
  }
  async takeAuthCode(code: string): Promise<CompletedAuth | undefined> {
    const v = this.fresh(this.codes, code);
    this.codes.delete(code);
    return v;
  }

  async putAccessToken(opaque: string, value: StoredToken, ttlSec?: number): Promise<void> {
    this.access.set(opaque, {
      value,
      expiresAtMs: ttlSec ? this.nowMs() + ttlSec * 1000 : undefined
    });
  }
  async getAccessToken(opaque: string): Promise<StoredToken | undefined> {
    return this.fresh(this.access, opaque);
  }
  async deleteAccessToken(opaque: string): Promise<void> {
    this.access.delete(opaque);
  }

  async putRefreshToken(opaque: string, value: RefreshRecord): Promise<void> {
    this.refresh.set(opaque, { value });
  }
  async getRefreshToken(opaque: string): Promise<RefreshRecord | undefined> {
    return this.fresh(this.refresh, opaque);
  }
  async deleteRefreshToken(opaque: string): Promise<void> {
    this.refresh.delete(opaque);
  }

  async putSession(sessionId: string, value: SessionRecord): Promise<void> {
    this.sessions.set(sessionId, value);
  }
  async getSession(sessionId: string): Promise<SessionRecord | undefined> {
    return this.sessions.get(sessionId);
  }
  async deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  dispose(): void {
    clearInterval(this.sweep);
  }
}
