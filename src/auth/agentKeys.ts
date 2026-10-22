import { createHash } from 'node:crypto';
import { resolveAuthMode } from './config.js';

// A machine caller of the oidc-mode server. The caller presents the key
// ("amk_" + 64 lowercase hex); the server holds only its SHA-256 and the ArgoCD
// API token the caller's requests are made with. Permissions are whatever
// ArgoCD RBAC grants that token's account — the server adds no authorization
// layer of its own.
export interface AgentKey {
  name: string;
  keySha256: Buffer;
  argocdToken: string;
}

// Exact shape of a presented key. Checked before routing so that an opaque OIDC
// token (43 base64url characters, an alphabet that includes "_") can never be
// mistaken for a machine key even when it happens to start with "amk_".
const AGENT_KEY_PATTERN = /^amk_[0-9a-f]{64}$/;
const NAME_PATTERN = /^[a-z0-9-]+$/;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

export const isAgentKeyShaped = (token: string): boolean => AGENT_KEY_PATTERN.test(token);

// SHA-256 of the whole key string, prefix included — the same function the
// deployment uses to fill keySha256 from the plaintext key.
export const hashAgentKey = (key: string): Buffer => createHash('sha256').update(key).digest();

const fail = (message: string): never => {
  throw new Error(`AGENT_API_KEYS: ${message}`);
};

// Read AGENT_API_KEYS, a JSON object {"<name>": {"keySha256": "<hex>",
// "argocdToken": "<token>"}}. Undefined when the variable is unset or blank
// (no machine path). Every malformed input fails startup, naming the problem,
// in the same fail-closed spirit as resolveAuthMode and the token registry:
// a half-read key list must never silently admit or deny the wrong caller.
export const loadAgentApiKeys = (env: NodeJS.ProcessEnv = process.env): AgentKey[] | undefined => {
  const raw = (env.AGENT_API_KEYS ?? '').trim();
  if (!raw) return undefined;

  // Token mode has no inbound authentication in this fork, so keys configured
  // there would gate nothing. Refuse rather than ignore.
  if (resolveAuthMode(env) !== 'oidc') {
    fail('is only supported with AUTH_MODE=oidc');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    fail(`invalid JSON (${error instanceof Error ? error.message : String(error)})`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    fail('expected a JSON object of named entries');
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length === 0) fail('must not be empty');

  const keys: AgentKey[] = [];
  const seenHashes = new Map<string, string>();
  for (const [name, value] of entries) {
    if (!NAME_PATTERN.test(name)) {
      fail(`entry name "${name}" must match ${NAME_PATTERN}`);
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      fail(`entry "${name}" must be an object`);
    }
    const { keySha256, argocdToken } = value as Record<string, unknown>;
    if (typeof keySha256 !== 'string' || !SHA256_HEX_PATTERN.test(keySha256)) {
      fail(`entry "${name}": keySha256 must be 64 lowercase hex characters`);
    }
    const duplicateOf = seenHashes.get(keySha256);
    if (duplicateOf !== undefined) {
      fail(`entries "${duplicateOf}" and "${name}" hold the same key`);
    }
    seenHashes.set(keySha256, name);
    if (typeof argocdToken !== 'string' || !argocdToken.trim()) {
      fail(`entry "${name}": argocdToken is required`);
    }
    keys.push({ name, keySha256: Buffer.from(keySha256, 'hex'), argocdToken: argocdToken.trim() });
  }
  return keys;
};
