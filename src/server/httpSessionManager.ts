import { logger } from '../logging/logging.js';

// Minimal shapes of the things a session owns. Kept structural (not tied to the
// concrete SDK classes) so this manager is unit-testable with fakes.
export interface ClosableTransport {
  sessionId?: string;
  close(): Promise<void> | void;
}
export interface ClosableServer {
  close(): Promise<void> | void;
}

interface SessionEntry {
  transport: ClosableTransport;
  server: ClosableServer;
  lastActivityMs: number;
}

// Defaults chosen to bound the heap on a long-running server without cutting off
// legitimately active clients. Each live session pins a whole McpServer (its
// tools, Zod schemas and HTTP client), so an unbounded, never-reaped session map
// is the dominant memory leak in stateful HTTP mode.
const DEFAULT_MAX_SESSIONS = 1000;
const DEFAULT_IDLE_TIMEOUT_MS = 60 * 60 * 1000; // 1h
const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

export interface HttpSessionManagerOptions {
  maxSessions?: number;
  idleTimeoutMs?: number;
  sweepIntervalMs?: number;
  now?: () => number;
  // When true, do not start the background timer (tests drive sweep() directly).
  disableTimer?: boolean;
}

// Tracks live streamable-HTTP sessions and reclaims their memory. A session is
// removed when (a) its transport closes normally, (b) it sits idle past the
// timeout, or (c) capacity is reached and it is the oldest idle session. In all
// three cases both the transport and its McpServer are closed so nothing stays
// pinned on the heap.
export class HttpSessionManager {
  private sessions = new Map<string, SessionEntry>();
  private sweep?: ReturnType<typeof setInterval>;

  private readonly maxSessions: number;
  private readonly idleTimeoutMs: number;
  private readonly now: () => number;

  constructor(opts: HttpSessionManagerOptions = {}) {
    this.maxSessions = opts.maxSessions ?? DEFAULT_MAX_SESSIONS;
    this.idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    this.now = opts.now ?? (() => Date.now());
    if (!opts.disableTimer) {
      this.sweep = setInterval(
        () => this.sweepIdle(),
        opts.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS
      );
      if (this.sweep.unref) this.sweep.unref();
    }
  }

  get size(): number {
    return this.sessions.size;
  }

  // Whether a NEW session can be admitted. When at capacity, tries to make room
  // by evicting the oldest idle session first. Returns false only when every
  // slot holds a session used more recently than the idle timeout.
  hasCapacity(): boolean {
    if (this.sessions.size < this.maxSessions) return true;
    return this.evictOldestIdle();
  }

  add(sessionId: string, transport: ClosableTransport, server: ClosableServer): void {
    this.sessions.set(sessionId, { transport, server, lastActivityMs: this.now() });
  }

  // Look up a session and mark it active (resets its idle clock).
  get(sessionId: string): ClosableTransport | undefined {
    const entry = this.sessions.get(sessionId);
    if (!entry) return undefined;
    entry.lastActivityMs = this.now();
    return entry.transport;
  }

  // Drop the map entry WITHOUT closing (the transport's own onclose already
  // fired). Idempotent.
  forget(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  // Evict all sessions idle longer than the timeout, closing their resources.
  sweepIdle(): void {
    const cutoff = this.now() - this.idleTimeoutMs;
    for (const [id, entry] of this.sessions) {
      if (entry.lastActivityMs <= cutoff) this.close(id, entry, 'idle timeout');
    }
  }

  // Close every session (server shutdown).
  dispose(): void {
    if (this.sweep) clearInterval(this.sweep);
    for (const [id, entry] of this.sessions) this.close(id, entry, 'shutdown');
  }

  private evictOldestIdle(): boolean {
    const cutoff = this.now() - this.idleTimeoutMs;
    let oldestId: string | undefined;
    let oldest = Infinity;
    for (const [id, entry] of this.sessions) {
      if (entry.lastActivityMs <= cutoff && entry.lastActivityMs < oldest) {
        oldest = entry.lastActivityMs;
        oldestId = id;
      }
    }
    if (oldestId === undefined) return false;
    this.close(oldestId, this.sessions.get(oldestId)!, 'capacity eviction');
    return true;
  }

  private close(sessionId: string, entry: SessionEntry, reason: string): void {
    this.sessions.delete(sessionId);
    logger.info({ sessionId, reason }, 'Closing MCP session');
    // Invoke close() synchronously (so the slot frees immediately) but never let
    // a failure of one session's close abort the sweep of the others.
    this.safeClose(sessionId, 'transport', () => entry.transport.close());
    this.safeClose(sessionId, 'server', () => entry.server.close());
  }

  private safeClose(sessionId: string, what: string, fn: () => Promise<void> | void): void {
    try {
      const result = fn();
      if (result && typeof (result as Promise<void>).catch === 'function') {
        (result as Promise<void>).catch((error) =>
          logger.warn({ sessionId, error: String(error) }, `${what} close failed`)
        );
      }
    } catch (error) {
      logger.warn({ sessionId, error: String(error) }, `${what} close failed`);
    }
  }
}
