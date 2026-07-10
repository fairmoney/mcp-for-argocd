import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveAuthMode, loadOidcConfig } from './config.js';

const withSecretFile = (contents: string): { path: string; cleanup: () => void } => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-config-test-'));
  const path = join(dir, 'secret');
  writeFileSync(path, contents, 'utf8');
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
};

// A minimal valid env for oidc mode, parameterized by the secret file path.
const validEnv = (secretPath: string): NodeJS.ProcessEnv => ({
  AUTH_MODE: 'oidc',
  MCP_PUBLIC_URL: 'https://argocd-mcp.example.com/',
  ARGOCD_BASE_URL: 'https://argocd.example.com',
  ARGOCD_MCP_OIDC_CLIENT_ID: 'argocd-mcp',
  ARGOCD_MCP_OIDC_CLIENT_SECRET_FILE: secretPath
});

test('resolveAuthMode defaults to token when unset', () => {
  assert.equal(resolveAuthMode({}), 'token');
});

test('resolveAuthMode reads oidc', () => {
  assert.equal(resolveAuthMode({ AUTH_MODE: 'oidc' }), 'oidc');
});

test('resolveAuthMode rejects unknown modes', () => {
  assert.throws(() => resolveAuthMode({ AUTH_MODE: 'sso' }), /AUTH_MODE/);
});

test('loadOidcConfig parses a valid env, trims trailing slash, builds callbackUrl', () => {
  const { path, cleanup } = withSecretFile('  s3cret\n');
  try {
    const cfg = loadOidcConfig(validEnv(path));
    assert.equal(cfg.publicUrl, 'https://argocd-mcp.example.com');
    assert.equal(cfg.callbackUrl, 'https://argocd-mcp.example.com/oauth/callback');
    assert.equal(cfg.clientSecret, 's3cret'); // trimmed
    assert.equal(cfg.tokenStore, 'memory');
  } finally {
    cleanup();
  }
});

test('loadOidcConfig rejects a non-https public URL', () => {
  const { path, cleanup } = withSecretFile('s');
  try {
    assert.throws(
      () => loadOidcConfig({ ...validEnv(path), MCP_PUBLIC_URL: 'http://mcp.example.com' }),
      /https/
    );
  } finally {
    cleanup();
  }
});

test('loadOidcConfig rejects a malformed ARGOCD_BASE_URL', () => {
  const { path, cleanup } = withSecretFile('s');
  try {
    assert.throws(
      () => loadOidcConfig({ ...validEnv(path), ARGOCD_BASE_URL: 'not a url' }),
      /ARGOCD_BASE_URL/
    );
  } finally {
    cleanup();
  }
});

test('loadOidcConfig requires REDIS_URL when TOKEN_STORE=redis', () => {
  const { path, cleanup } = withSecretFile('s');
  try {
    assert.throws(() => loadOidcConfig({ ...validEnv(path), TOKEN_STORE: 'redis' }), /REDIS_URL/);
  } finally {
    cleanup();
  }
});

test('loadOidcConfig throws a clear error when the secret file is missing', () => {
  assert.throws(() => loadOidcConfig(validEnv('/does/not/exist')), /client secret/i);
});

// An oidc env with no secret file, parameterized by the direct client secret.
const envWithDirectSecret = (secret: string): NodeJS.ProcessEnv => ({
  AUTH_MODE: 'oidc',
  MCP_PUBLIC_URL: 'https://argocd-mcp.example.com/',
  ARGOCD_BASE_URL: 'https://argocd.example.com',
  ARGOCD_MCP_OIDC_CLIENT_ID: 'argocd-mcp',
  ARGOCD_MCP_OIDC_CLIENT_SECRET: secret
});

test('loadOidcConfig reads the client secret from ARGOCD_MCP_OIDC_CLIENT_SECRET when set', () => {
  const cfg = loadOidcConfig(envWithDirectSecret('  env-s3cret\n'));
  assert.equal(cfg.clientSecret, 'env-s3cret'); // trimmed, like the file path
});

test('loadOidcConfig prefers ARGOCD_MCP_OIDC_CLIENT_SECRET over the secret file when both are set', () => {
  const { path, cleanup } = withSecretFile('file-secret');
  try {
    const cfg = loadOidcConfig({ ...validEnv(path), ARGOCD_MCP_OIDC_CLIENT_SECRET: 'env-secret' });
    assert.equal(cfg.clientSecret, 'env-secret');
  } finally {
    cleanup();
  }
});

test('loadOidcConfig falls back to the secret file when the env var is set but empty', () => {
  const { path, cleanup } = withSecretFile('file-secret');
  try {
    const cfg = loadOidcConfig({ ...validEnv(path), ARGOCD_MCP_OIDC_CLIENT_SECRET: '   ' });
    assert.equal(cfg.clientSecret, 'file-secret');
  } finally {
    cleanup();
  }
});

test('loadOidcConfig errors when neither the client secret env var nor file is set', () => {
  assert.throws(
    () =>
      loadOidcConfig({
        AUTH_MODE: 'oidc',
        MCP_PUBLIC_URL: 'https://argocd-mcp.example.com/',
        ARGOCD_BASE_URL: 'https://argocd.example.com',
        ARGOCD_MCP_OIDC_CLIENT_ID: 'argocd-mcp'
      }),
    /client secret/i
  );
});
