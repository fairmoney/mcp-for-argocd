# Dual OIDC Client Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `derived` OIDC client mode that reuses ArgoCD's own `argo-cd` Dex static client (secret derived from `argocd-secret`'s `server.secretkey`), alongside the existing explicit `argocd-mcp` client mode.

**Architecture:** Single `OidcConfig` shape; mode resolved inside `loadOidcConfig()` in `src/auth/config.ts`. Derived mode sets `clientId="argo-cd"`, computes the secret as `base64url(sha256(server.secretkey))[:40]` (parity with ArgoCD's `DexOAuth2ClientSecret()`), and switches the callback path to `/auth/callback`. Downstream code is untouched — it consumes the config opaquely.

**Tech Stack:** TypeScript (Node 20+), node:test + node:assert (built-in runner via `npm test`), node:crypto, ESLint, tsup.

**Spec:** `docs/superpowers/specs/2026-07-22-dual-oidc-client-modes-design.md`

## Global Constraints

- Backward compatibility: unset/blank `ARGOCD_MCP_OIDC_CLIENT_MODE` must behave exactly as today (explicit mode, `/oauth/callback`). All existing tests pass unchanged.
- Fail closed: every invalid/missing/conflicting input throws at startup with the env var name in the message (match `resolveAuthMode` style in `src/auth/config.ts`).
- Known derivation vector (verified against Go `base64.URLEncoding`, Node `base64url`, Python): `sha256("test-server-signature-key")` → `cbeOgaLo8YsJi74TXZRRLozNtAZyTrTdNTrYedoF`.
- Test command: `npm test` (runs `node --import tsx --test "src/**/*.test.ts"`). To scope: `node --import tsx --test src/auth/config.test.ts`.
- Comment style: explain constraints/why, sentence-case, like the existing file.

---

### Task 1: Mode + derivation helpers in config.ts

**Files:**
- Modify: `src/auth/config.ts` (add exports; do not touch existing functions)
- Test: `src/auth/config.test.ts` (append)

**Interfaces:**
- Produces: `type OidcClientMode = 'explicit' | 'derived'`; `resolveOidcClientMode(env?): OidcClientMode`; `deriveDexClientSecret(serverSecretKey: string): string`. Task 2 consumes all three.

- [ ] **Step 1: Write the failing tests** — append to `src/auth/config.test.ts` (update the import line to include the new names):

```ts
// --- OIDC client mode + derived secret ---

test('resolveOidcClientMode defaults to explicit when unset or blank', () => {
  assert.equal(resolveOidcClientMode({}), 'explicit');
  assert.equal(resolveOidcClientMode({ ARGOCD_MCP_OIDC_CLIENT_MODE: '  ' }), 'explicit');
});

test('resolveOidcClientMode reads explicit and derived (case-insensitive)', () => {
  assert.equal(resolveOidcClientMode({ ARGOCD_MCP_OIDC_CLIENT_MODE: 'explicit' }), 'explicit');
  assert.equal(resolveOidcClientMode({ ARGOCD_MCP_OIDC_CLIENT_MODE: 'Derived' }), 'derived');
});

test('resolveOidcClientMode rejects unknown modes loudly', () => {
  assert.throws(
    () => resolveOidcClientMode({ ARGOCD_MCP_OIDC_CLIENT_MODE: 'auto' }),
    /ARGOCD_MCP_OIDC_CLIENT_MODE/
  );
});

test('deriveDexClientSecret matches ArgoCD DexOAuth2ClientSecret (Go parity vector)', () => {
  // Vector triple-checked against Go base64.URLEncoding, Node base64url, Python.
  assert.equal(
    deriveDexClientSecret('test-server-signature-key'),
    'cbeOgaLo8YsJi74TXZRRLozNtAZyTrTdNTrYedoF'
  );
});

test('deriveDexClientSecret always yields 40 chars', () => {
  assert.equal(deriveDexClientSecret('').length, 40);
  assert.equal(deriveDexClientSecret('x'.repeat(1000)).length, 40);
});
```

Import line becomes:

```ts
import {
  resolveAuthMode,
  resolveOidcClientMode,
  deriveDexClientSecret,
  loadOidcConfig,
  buildRedisUrl
} from './config.js';
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --import tsx --test src/auth/config.test.ts`
Expected: FAIL — `resolveOidcClientMode` / `deriveDexClientSecret` are not exported.

- [ ] **Step 3: Implement the helpers** — in `src/auth/config.ts`, add `import { createHash } from 'node:crypto';` at the top and, below `resolveAuthMode`:

```ts
export type OidcClientMode = 'explicit' | 'derived';

// Read ARGOCD_MCP_OIDC_CLIENT_MODE; default to the pre-existing explicit
// client behavior. Reject typos loudly (same convention as resolveAuthMode).
export const resolveOidcClientMode = (env: NodeJS.ProcessEnv = process.env): OidcClientMode => {
  const raw = (env.ARGOCD_MCP_OIDC_CLIENT_MODE ?? '').trim().toLowerCase();
  if (raw === '' || raw === 'explicit') return 'explicit';
  if (raw === 'derived') return 'derived';
  throw new Error(
    `Invalid ARGOCD_MCP_OIDC_CLIENT_MODE "${env.ARGOCD_MCP_OIDC_CLIENT_MODE}": expected "explicit" or "derived"`
  );
};

// Port of ArgoCD's DexOAuth2ClientSecret() (util/settings/settings.go): the
// bundled Dex "argo-cd" static client secret is not stored anywhere — every
// party derives base64url(sha256(server.secretkey)) truncated to 40 chars.
// Go uses padded base64.URLEncoding while Node's base64url is unpadded, but
// sha256 output encodes to 44 chars, so the first 40 are identical.
export const deriveDexClientSecret = (serverSecretKey: string): string =>
  createHash('sha256').update(serverSecretKey).digest('base64url').slice(0, 40);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --import tsx --test src/auth/config.test.ts`
Expected: PASS (all, including pre-existing).

- [ ] **Step 5: Commit**

```bash
git add src/auth/config.ts src/auth/config.test.ts
git commit -m "feat(auth): OIDC client mode resolver and Dex client-secret derivation"
```

---

### Task 2: Wire modes into loadOidcConfig and log the mode at startup

**Files:**
- Modify: `src/auth/config.ts` (`OidcConfig` interface, `CALLBACK_PATH` constants, `loadOidcConfig`)
- Modify: `src/server/transport.ts:164` area (startup log)
- Test: `src/auth/config.test.ts` (append)

**Interfaces:**
- Consumes: `resolveOidcClientMode`, `deriveDexClientSecret`, `OidcClientMode` from Task 1; existing `readSecretFile`, `resolveClientSecret`.
- Produces: `OidcConfig` gains `mode: OidcClientMode`; `callbackPath` is `/oauth/callback` (explicit) or `/auth/callback` (derived). New env `ARGOCD_SERVER_SECRETKEY_FILE`.

- [ ] **Step 1: Write the failing tests** — append to `src/auth/config.test.ts`:

```ts
// A minimal valid derived-mode env, parameterized by the secretkey file path.
const derivedEnv = (secretKeyPath: string): NodeJS.ProcessEnv => ({
  AUTH_MODE: 'oidc',
  ARGOCD_MCP_OIDC_CLIENT_MODE: 'derived',
  MCP_PUBLIC_URL: 'https://argocd-mcp.example.com/',
  ARGOCD_BASE_URL: 'https://argocd.example.com',
  ARGOCD_SERVER_SECRETKEY_FILE: secretKeyPath
});

test('loadOidcConfig in derived mode uses the argo-cd client and /auth/callback', () => {
  const { path, cleanup } = withSecretFile('test-server-signature-key\n');
  try {
    const cfg = loadOidcConfig(derivedEnv(path));
    assert.equal(cfg.mode, 'derived');
    assert.equal(cfg.clientId, 'argo-cd');
    assert.equal(cfg.clientSecret, 'cbeOgaLo8YsJi74TXZRRLozNtAZyTrTdNTrYedoF'); // trimmed file
    assert.equal(cfg.callbackPath, '/auth/callback');
    assert.equal(cfg.callbackUrl, 'https://argocd-mcp.example.com/auth/callback');
  } finally {
    cleanup();
  }
});

test('loadOidcConfig in derived mode requires ARGOCD_SERVER_SECRETKEY_FILE', () => {
  const env = derivedEnv('');
  delete env.ARGOCD_SERVER_SECRETKEY_FILE;
  assert.throws(() => loadOidcConfig(env), /ARGOCD_SERVER_SECRETKEY_FILE/);
});

test('loadOidcConfig in derived mode rejects conflicting explicit-client vars', () => {
  const { path, cleanup } = withSecretFile('k');
  try {
    for (const conflict of [
      { ARGOCD_MCP_OIDC_CLIENT_ID: 'argocd-mcp' },
      { ARGOCD_MCP_OIDC_CLIENT_SECRET: 's' },
      { ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE: path }
    ]) {
      assert.throws(
        () => loadOidcConfig({ ...derivedEnv(path), ...conflict }),
        new RegExp(Object.keys(conflict)[0])
      );
    }
  } finally {
    cleanup();
  }
});

test('loadOidcConfig defaults to explicit mode and keeps todays behavior', () => {
  const { path, cleanup } = withSecretFile('s3cret');
  try {
    const cfg = loadOidcConfig(validEnv(path));
    assert.equal(cfg.mode, 'explicit');
    assert.equal(cfg.clientId, 'argocd-mcp');
    assert.equal(cfg.callbackPath, '/oauth/callback');
  } finally {
    cleanup();
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --import tsx --test src/auth/config.test.ts`
Expected: FAIL — `cfg.mode` undefined, derived env throws on missing `ARGOCD_MCP_OIDC_CLIENT_ID`.

- [ ] **Step 3: Implement** — in `src/auth/config.ts`:

Replace `const CALLBACK_PATH = '/oauth/callback';` with:

```ts
const EXPLICIT_CALLBACK_PATH = '/oauth/callback';
// Derived mode reuses ArgoCD's own "argo-cd" Dex static client, whose extra
// redirect URIs are always <additionalUrls[i]>/auth/callback (argo-cd
// util/dex/config.go GenerateDexConfigYAML) — so our callback must live there.
const DERIVED_CALLBACK_PATH = '/auth/callback';
// ArgoCD's own Dex static client id (common.ArgoCDClientAppID upstream).
const ARGOCD_DEX_CLIENT_ID = 'argo-cd';
```

Extend the interface:

```ts
export interface OidcConfig {
  mode: OidcClientMode;
  publicUrl: string; // https, no trailing slash
  argocdBaseUrl: string;
  clientId: string;
  clientSecret: string;
  callbackPath: string; // '/oauth/callback' (explicit) | '/auth/callback' (derived)
  callbackUrl: string; // publicUrl + callbackPath
  tokenStore: 'memory' | 'redis';
  redisUrl?: string;
  encryptionKey?: Buffer;
}
```

In `loadOidcConfig`, replace the block that computes `clientId` and `clientSecret` (currently the `const clientId = ...` / `const clientSecret = resolveClientSecret(env);` lines) with:

```ts
  const mode = resolveOidcClientMode(env);
  let clientId: string;
  let clientSecret: string;
  let callbackPath: string;
  if (mode === 'derived') {
    // Fail closed on ambiguity: the explicit-client vars must not be set when
    // the client is derived from ArgoCD's server.secretkey.
    const conflicting = (
      [
        'ARGOCD_MCP_OIDC_CLIENT_ID',
        'ARGOCD_MCP_OIDC_CLIENT_SECRET',
        'ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE'
      ] as const
    ).filter((name) => (env[name] ?? '').trim() !== '');
    if (conflicting.length > 0) {
      throw new Error(
        `ARGOCD_MCP_OIDC_CLIENT_MODE=derived derives the client from ARGOCD_SERVER_SECRETKEY_FILE; unset ${conflicting.join(', ')}`
      );
    }
    if (!env.ARGOCD_SERVER_SECRETKEY_FILE || !env.ARGOCD_SERVER_SECRETKEY_FILE.trim()) {
      throw new Error('ARGOCD_MCP_OIDC_CLIENT_MODE=derived requires ARGOCD_SERVER_SECRETKEY_FILE');
    }
    const serverSecretKey = readSecretFile(
      env.ARGOCD_SERVER_SECRETKEY_FILE,
      'ArgoCD server secret key (ARGOCD_SERVER_SECRETKEY_FILE)'
    );
    clientId = ARGOCD_DEX_CLIENT_ID;
    clientSecret = deriveDexClientSecret(serverSecretKey);
    callbackPath = DERIVED_CALLBACK_PATH;
  } else {
    clientId = (env.ARGOCD_MCP_OIDC_CLIENT_ID ?? '').trim();
    if (!clientId) throw new Error('oidc mode requires ARGOCD_MCP_OIDC_CLIENT_ID');
    clientSecret = resolveClientSecret(env);
    callbackPath = EXPLICIT_CALLBACK_PATH;
  }
```

Update the return statement: add `mode,`, replace `callbackPath: CALLBACK_PATH,` with `callbackPath,` and `callbackUrl: `${normalizedPublic}${CALLBACK_PATH}`` with `` callbackUrl: `${normalizedPublic}${callbackPath}` ``.

In `src/server/transport.ts`, immediately after `const config = loadOidcConfig();` (line 164) add:

```ts
    logger.info(
      { clientMode: config.mode, clientId: config.clientId },
      'OIDC client mode resolved'
    );
```

(`logger` is already imported in transport.ts.)

- [ ] **Step 4: Run the full suite**

Run: `npm test`
Expected: PASS — including all pre-existing tests (backward-compat check).

- [ ] **Step 5: Commit**

```bash
git add src/auth/config.ts src/auth/config.test.ts src/server/transport.ts
git commit -m "feat(auth): derived OIDC client mode reusing ArgoCD's argo-cd Dex client"
```

---

### Task 3: Deploy manifests and documentation

**Files:**
- Create: `deploy/derived-mode.yaml`
- Modify: `deploy/README.md` (env table + new section), `README.md` (env table + mode paragraph), `deploy/dex-staticclient.yaml` (header note)

**Interfaces:**
- Consumes: env var names exactly as implemented in Task 2 (`ARGOCD_MCP_OIDC_CLIENT_MODE`, `ARGOCD_SERVER_SECRETKEY_FILE`).

- [ ] **Step 1: Create `deploy/derived-mode.yaml`** with this exact content:

```yaml
# Derived client mode: the MCP server reuses ArgoCD's own "argo-cd" Dex static
# client instead of a dedicated argocd-mcp client. No dex.config changes and no
# argocd-mcp-oidc secret are needed. Requires ArgoCD's BUNDLED Dex (with an
# external oidc.config, use explicit mode + allowedAudiences instead).
#
# SECURITY: server.secretkey is also ArgoCD's session-JWT signing key. A pod
# holding it can mint arbitrary ArgoCD sessions, so this places the MCP server
# in the same trust tier as the ArgoCD API server. Mount ONLY that key (items:)
# — never the whole argocd-secret.
#
# 1) Register the MCP callback on the argo-cd Dex client by adding the MCP
#    public URL to argocd-cm additionalUrls (ArgoCD then registers
#    <url>/auth/callback as a redirect URI):
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  additionalUrls: |
    - https://argocd-mcp.example.com
---
# 2) Patch for the MCP Deployment (replaces the explicit-client env and the
#    oidc-secret volume in mcp-deployment.yaml):
#
#    env:
#      - { name: AUTH_MODE, value: oidc }
#      - { name: ARGOCD_MCP_OIDC_CLIENT_MODE, value: derived }
#      - { name: ARGOCD_SERVER_SECRETKEY_FILE, value: /secrets/argocd/server.secretkey }
#    volumeMounts:
#      - { name: argocd-server-secretkey, mountPath: /secrets/argocd, readOnly: true }
#    volumes:
#      - name: argocd-server-secretkey
#        secret:
#          secretName: argocd-secret
#          items:
#            - key: server.secretkey
#              path: server.secretkey
```

- [ ] **Step 2: Update `deploy/README.md`** — in the env table, change the `ARGOCD_MCP_OIDC_CLIENT_ID` row's Required column from `Yes*` to `Yes*‡` (same for both secret rows) and add these rows after `AUTH_MODE`:

```markdown
| `ARGOCD_MCP_OIDC_CLIENT_MODE` | No | `explicit` | OIDC client mode. `explicit` uses a dedicated `argocd-mcp` Dex static client. `derived` reuses ArgoCD's own `argo-cd` client: the secret is derived from `argocd-secret`'s `server.secretkey` and the callback moves to `/auth/callback`. Requires ArgoCD's bundled Dex. |
| `ARGOCD_SERVER_SECRETKEY_FILE` | Yes*§ | — | Path to a mounted copy of `argocd-secret`'s `server.secretkey` (mount only that key via `items:`). Required (and only allowed) when `ARGOCD_MCP_OIDC_CLIENT_MODE=derived`. |
```

And extend the footnotes below the table:

```markdown
**‡ Explicit mode only. Setting any of these with `ARGOCD_MCP_OIDC_CLIENT_MODE=derived` fails startup.*
**§ Derived mode only. SECURITY: `server.secretkey` also signs ArgoCD session JWTs — derived mode places the MCP server in the same trust tier as the ArgoCD API server. See `deploy/derived-mode.yaml`.*
```

- [ ] **Step 3: Update `README.md`** — after the "Browser OAuth flow" paragraph (line ~301), add:

```markdown
**Client modes:** By default the server uses a dedicated confidential Dex client (`argocd-mcp`, explicit mode) — note that with ArgoCD's *bundled* Dex, the API server only accepts token audiences `argo-cd`/`argo-cd-cli`, so explicit mode requires an external `oidc.config` with `allowedAudiences`. Alternatively, set `ARGOCD_MCP_OIDC_CLIENT_MODE=derived` to reuse ArgoCD's own `argo-cd` client: the client secret is derived from `argocd-secret`'s `server.secretkey` exactly as ArgoCD derives it, the callback moves to `/auth/callback`, and the MCP public URL must be listed in `argocd-cm`'s `additionalUrls`. Tokens then carry `aud: argo-cd` and are accepted natively. See `deploy/derived-mode.yaml` for the trust-tier caveat.
```

Add the same two rows to the README env table (after `AUTH_MODE`), abbreviated:

```markdown
| `ARGOCD_MCP_OIDC_CLIENT_MODE` | No | `explicit` | `explicit` (dedicated `argocd-mcp` client) or `derived` (reuse ArgoCD's `argo-cd` client; secret derived from `server.secretkey`; callback `/auth/callback`; bundled Dex only). |
| `ARGOCD_SERVER_SECRETKEY_FILE` | Yes*§ | — | Derived mode only: path to a mounted copy of `argocd-secret`'s `server.secretkey`. |
```

with footnote:

```markdown
**§ Required when `ARGOCD_MCP_OIDC_CLIENT_MODE=derived`; forbidden otherwise. `server.secretkey` also signs ArgoCD session JWTs — see `deploy/derived-mode.yaml`.*
```

- [ ] **Step 4: Add a pointer in `deploy/dex-staticclient.yaml`** — append to the header comment block:

```yaml
# NOTE: this file is only needed in explicit client mode
# (ARGOCD_MCP_OIDC_CLIENT_MODE unset or "explicit"). Derived mode needs no
# dex.config changes — see deploy/derived-mode.yaml.
```

- [ ] **Step 5: Commit**

```bash
git add deploy/derived-mode.yaml deploy/README.md README.md deploy/dex-staticclient.yaml
git commit -m "docs(deploy): derived client mode manifests and env reference"
```

---

### Task 4: Full verification

- [ ] **Step 1:** Run: `npm test` — Expected: all pass.
- [ ] **Step 2:** Run: `npm run lint` — Expected: clean.
- [ ] **Step 3:** Run: `npm run build` — Expected: tsup succeeds.
- [ ] **Step 4:** If anything fails, fix and re-run before claiming completion. No commit (nothing should change).
