import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { PkceChallenge, UpstreamToken } from './types.js';

// Short-lived state while the upstream (Dex) flow is in progress, keyed by the
// upstream `state` value.
export interface PendingAuth {
  upstreamState: string;
  upstreamPkce: PkceChallenge;
  clientRedirectUri: string;
  clientState?: string;
  clientCodeChallenge: string;
  clientId: string;
}

// State after the upstream exchange succeeds, keyed by the authorization code we
// mint for the MCP client.
export interface CompletedAuth {
  upstream: UpstreamToken;
  clientRedirectUri: string;
  clientState?: string;
  clientCodeChallenge: string;
  clientId: string;
}

// The real upstream token behind an issued opaque access token.
export interface StoredToken {
  upstream: UpstreamToken;
  clientId: string;
}

// The upstream refresh token behind an issued opaque refresh token.
export interface RefreshRecord {
  upstreamRefreshToken: string;
  clientId: string;
}

// All OAuth server-side state lives behind this interface so the deployment can
// pick in-memory (single replica) or Redis (horizontally scalable) without any
// change to the provider.
export interface TokenStore {
  // Dynamic client registrations (no expiry).
  putClient(client: OAuthClientInformationFull): Promise<void>;
  getClient(clientId: string): Promise<OAuthClientInformationFull | undefined>;

  // Pending upstream flow state (get-and-delete semantics).
  putPendingAuth(state: string, value: PendingAuth, ttlSec: number): Promise<void>;
  takePendingAuth(state: string): Promise<PendingAuth | undefined>;

  // Authorization codes we issue to MCP clients (get-and-delete semantics).
  putAuthCode(code: string, value: CompletedAuth, ttlSec: number): Promise<void>;
  takeAuthCode(code: string): Promise<CompletedAuth | undefined>;

  // Issued opaque access tokens.
  putAccessToken(opaque: string, value: StoredToken, ttlSec?: number): Promise<void>;
  getAccessToken(opaque: string): Promise<StoredToken | undefined>;
  deleteAccessToken(opaque: string): Promise<void>;

  // Issued opaque refresh tokens.
  putRefreshToken(opaque: string, value: RefreshRecord): Promise<void>;
  getRefreshToken(opaque: string): Promise<RefreshRecord | undefined>;
  deleteRefreshToken(opaque: string): Promise<void>;

  // Release resources (timers, connections).
  dispose(): void;
}
