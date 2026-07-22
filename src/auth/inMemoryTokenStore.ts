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

// Long-lived state (sessions, dynamic client registrations) is kept on a
// SLIDING idle TTL rather than forever: any read refreshes the window, so an
// actively-used entry never expires, but one left untouched for the whole TTL
// is evicted. Defaults are generous (30 days) so a normal refresh chain always
// outlives them; override for tighter memory bounds. A session idle this long
// is almost certainly backed by an already-expired upstream refresh token, so
// dropping it frees heap with no functional loss (the user simply re-auths).
const DEFAULT_SESSION_TTL_SEC = 30 * 24 * 60 * 60;
const DEFAULT_CLIENT_TTL_SEC = 30 * 24 * 60 * 60;
const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

export interface InMemoryTokenStoreOptions {
  // Sliding idle TTL for login sessions, in seconds.
  sessionTtlSec?: number;
  // Sliding idle TTL for dynamic client registrations, in seconds.
  clientTtlSec?: number;
  // How often the background sweep runs, in milliseconds.
  sweepIntervalMs?: number;
  // Injectable clock (tests). Defaults to Date.now.
  now?: () => number;
}

// Single-process TokenStore. A periodic sweep evicts expired flow-state and
// access-token entries, and idle sessions/clients past their sliding TTL. Use
// only with a single replica; for multiple replicas use RedisTokenStore so
// state is shared across pods (and bounded by Redis, not the Node heap).
export class InMemoryTokenStore implements TokenStore {
  private clients = new Map<string, Expiring<OAuthClientInformationFull>>();
  private pending = new Map<string, Expiring<PendingAuth>>();
  private codes = new Map<string, Expiring<CompletedAuth>>();
  private access = new Map<string, Expiring<StoredToken>>();
  private refresh = new Map<string, Expiring<RefreshRecord>>();
  // Sessions live on a sliding idle TTL (see note above): read refreshes the
  // window, so the refresh chain keeps them alive; abandonment evicts them.
  private sessions = new Map<string, Expiring<SessionRecord>>();
  private sweep: ReturnType<typeof setInterval>;

  private readonly now: () => number;
  private readonly sessionTtlSec: number;
  private readonly clientTtlSec: number;

  constructor(opts: InMemoryTokenStoreOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.sessionTtlSec = opts.sessionTtlSec ?? DEFAULT_SESSION_TTL_SEC;
    this.clientTtlSec = opts.clientTtlSec ?? DEFAULT_CLIENT_TTL_SEC;
    const sweepMs = opts.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
    this.sweep = setInterval(() => this.evictExpired(), sweepMs);
    if (this.sweep.unref) this.sweep.unref();
  }

  private nowMs(): number {
    return this.now();
  }

  // Read an entry, evicting (and returning undefined) when past its deadline.
  // When slideTtlSec is given, a live read refreshes the sliding window.
  private fresh<T>(
    map: Map<string, Expiring<T>>,
    key: string,
    slideTtlSec?: number
  ): T | undefined {
    const entry = map.get(key);
    if (!entry) return undefined;
    if (entry.expiresAtMs && this.nowMs() > entry.expiresAtMs) {
      map.delete(key);
      return undefined;
    }
    if (slideTtlSec) entry.expiresAtMs = this.nowMs() + slideTtlSec * 1000;
    return entry.value;
  }

  private evictExpired(): void {
    const now = this.nowMs();
    for (const map of [
      this.pending,
      this.codes,
      this.access,
      this.refresh,
      this.sessions,
      this.clients
    ]) {
      for (const [key, entry] of map) {
        if (entry.expiresAtMs && now > entry.expiresAtMs) map.delete(key);
      }
    }
  }

  async putClient(client: OAuthClientInformationFull): Promise<void> {
    this.clients.set(client.client_id, {
      value: client,
      expiresAtMs: this.nowMs() + this.clientTtlSec * 1000
    });
  }
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.fresh(this.clients, clientId, this.clientTtlSec);
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
    this.sessions.set(sessionId, {
      value,
      expiresAtMs: this.nowMs() + this.sessionTtlSec * 1000
    });
  }
  async getSession(sessionId: string): Promise<SessionRecord | undefined> {
    return this.fresh(this.sessions, sessionId, this.sessionTtlSec);
  }
  async deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  dispose(): void {
    clearInterval(this.sweep);
  }
}
