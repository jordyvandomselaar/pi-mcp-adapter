import { mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import {
  FileAuthStore,
  FileInteractiveAuthSessionStore,
  buildAuthFingerprintSeed,
  createAuthFingerprint,
  createAuthFingerprintFromServer,
  getStoredTokens,
  redactAuthRecordForLogs,
} from "../auth-store.js";
import type { ServerEntry } from "../types.js";

describe("auth-store", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function makeTempDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "pi-mcp-auth-store-"));
    tempDirs.push(dir);
    return dir;
  }

  it("creates stable fingerprints from normalized server/issuer/client identity instead of server name", () => {
    const shared = {
      issuer: "https://auth.example.com/",
      grantType: "authorization_code" as const,
      clientMetadataUrl: "https://client.example.com/pi.json#fragment",
    };

    const first = createAuthFingerprint({
      serverUrl: "https://api.example.com/mcp/?unused=1#ignored",
      ...shared,
    });

    const second = createAuthFingerprint({
      serverUrl: "https://api.example.com/mcp",
      issuer: "https://auth.example.com",
      grantType: "authorization_code",
      clientMetadataUrl: "https://client.example.com/pi.json",
    });

    const third = createAuthFingerprint({
      serverUrl: "https://api.example.com/mcp",
      issuer: "https://auth.example.com",
      grantType: "authorization_code",
      clientMetadata: {
        softwareVersion: "1.0.0",
        clientName: "Pi",
        contacts: ["pi@example.com"],
      },
    });

    const fourth = createAuthFingerprint({
      serverUrl: "https://api.example.com/mcp/",
      issuer: "https://auth.example.com/",
      grantType: "authorization_code",
      clientMetadata: {
        contacts: ["pi@example.com"],
        clientName: "Pi",
        softwareVersion: "1.0.0",
        client_secret: "ignored-secret",
      } as Record<string, unknown>,
    });

    const differentClient = createAuthFingerprint({
      serverUrl: "https://api.example.com/mcp",
      issuer: "https://auth.example.com",
      grantType: "authorization_code",
      clientId: "different-client",
    });

    expect(first).toBe(second);
    expect(third).toBe(fourth);
    expect(first).not.toBe(differentClient);

    const serverDefinition: ServerEntry = {
      url: "https://api.example.com/mcp",
      auth: {
        type: "oauth",
        issuer: "https://auth.example.com",
        client: {
          metadataUrl: "https://client.example.com/pi.json",
        },
      },
    };

    expect(createAuthFingerprintFromServer(serverDefinition)).toBe(second);
    expect(buildAuthFingerprintSeed({
      serverUrl: "https://api.example.com/mcp",
      issuer: "https://auth.example.com",
      clientMetadataUrl: "https://client.example.com/pi.json",
    })).toEqual({
      serverUrl: "https://api.example.com/mcp",
      issuer: "https://auth.example.com/",
      grantType: "authorization_code",
      clientIdentity: "metadata_url:https://client.example.com/pi.json",
    });
  });

  it("persists durable tokens/client data separately from ephemeral verifier state", () => {
    const rootDir = makeTempDir();
    const store = new FileAuthStore({ rootDir, legacyRootDir: join(rootDir, "legacy") });
    const fingerprint = "fp-storage";
    const seed = buildAuthFingerprintSeed({
      serverUrl: "https://api.example.com/mcp",
      issuer: "https://auth.example.com",
      clientId: "client-123",
    });

    store.saveRecord({
      version: 1,
      fingerprint,
      seed,
      updatedAt: 0,
    });

    store.saveTokens(fingerprint, {
      access_token: "access-123",
      refresh_token: "refresh-123",
      token_type: "bearer",
      expires_in: 60,
    });
    store.saveClientInformation(fingerprint, {
      client_id: "client-123",
      client_secret: "secret-123",
    });
    store.saveCodeVerifier(fingerprint, "pkce-123");

    const loadedTokens = store.loadTokens(fingerprint);
    expect(loadedTokens).toMatchObject({
      access_token: "access-123",
      refresh_token: "refresh-123",
      token_type: "bearer",
      expires_in: 60,
    });
    expect(typeof loadedTokens?.expiresAt).toBe("number");
    expect(store.loadClientInformation(fingerprint)).toEqual({
      client_id: "client-123",
      client_secret: "secret-123",
    });
    expect(store.loadCodeVerifier(fingerprint)).toBe("pkce-123");

    const durablePath = join(rootDir, "records", `${fingerprint}.json`);
    const ephemeralPath = join(rootDir, "ephemeral", `${fingerprint}.json`);
    const durableText = readFileSync(durablePath, "utf-8");
    const ephemeralText = readFileSync(ephemeralPath, "utf-8");

    expect(durableText).toContain("access-123");
    expect(durableText).toContain("secret-123");
    expect(durableText).not.toContain("pkce-123");
    expect(ephemeralText).toContain("pkce-123");
    expect(ephemeralText).not.toContain("access-123");
    expect(ephemeralText).not.toContain("secret-123");

    store.invalidate(fingerprint, "tokens");
    expect(store.loadTokens(fingerprint)).toBeUndefined();
    expect(store.loadClientInformation(fingerprint)).toEqual({
      client_id: "client-123",
      client_secret: "secret-123",
    });
    expect(store.loadCodeVerifier(fingerprint)).toBe("pkce-123");

    store.invalidate(fingerprint, "client");
    expect(store.loadClientInformation(fingerprint)).toBeUndefined();
    expect(store.loadCodeVerifier(fingerprint)).toBe("pkce-123");

    store.invalidate(fingerprint, "verifier");
    expect(store.loadCodeVerifier(fingerprint)).toBeUndefined();

    store.saveTokens(fingerprint, { access_token: "fresh-token", token_type: "bearer" });
    store.invalidate(fingerprint, "all");
    expect(store.loadRecord(fingerprint)).toBeUndefined();
  });

  it("persists interactive auth session records on disk", () => {
    const rootDir = makeTempDir();
    const sessions = new FileInteractiveAuthSessionStore(rootDir);

    sessions.set({
      sessionId: "session-1",
      fingerprint: "fingerprint-1",
      state: "state-1",
      redirectUrl: "http://127.0.0.1:8123/callback",
      authorizationUrl: "https://auth.example.com/authorize?state=state-1",
      codeVerifier: "verifier-1",
      createdAt: 100,
      expiresAt: 200,
      status: "pending",
    });

    expect(sessions.getBySessionId("session-1")).toMatchObject({
      fingerprint: "fingerprint-1",
      state: "state-1",
      codeVerifier: "verifier-1",
    });
    expect(sessions.getByFingerprint("fingerprint-1")?.sessionId).toBe("session-1");
    expect(sessions.getByState("state-1")?.sessionId).toBe("session-1");
    expect(sessions.list()).toHaveLength(1);

    sessions.delete("session-1");
    expect(sessions.getBySessionId("session-1")).toBeUndefined();
  });

  it("imports legacy tokens once and never overwrites newer durable tokens on conflict", () => {
    const rootDir = makeTempDir();
    const legacyRootDir = join(rootDir, "legacy");
    const store = new FileAuthStore({ rootDir, legacyRootDir });
    const fingerprint = "fp-migrate";

    mkdirSync(join(legacyRootDir, "legacy-server"), { recursive: true });
    writeFileSync(
      join(legacyRootDir, "legacy-server", "tokens.json"),
      JSON.stringify({
        access_token: "legacy-access",
        refresh_token: "legacy-refresh",
        token_type: "bearer",
      }),
      "utf-8",
    );

    const imported = store.maybeMigrateLegacyTokens(fingerprint, "legacy-server");
    expect(imported).toMatchObject({
      access_token: "legacy-access",
      refresh_token: "legacy-refresh",
    });
    expect(store.getMigrationReceipt("legacy-server")?.status).toBe("imported");
    expect(store.loadTokens(fingerprint)).toMatchObject({
      access_token: "legacy-access",
      refresh_token: "legacy-refresh",
    });

    writeFileSync(
      join(legacyRootDir, "legacy-server", "tokens.json"),
      JSON.stringify({ access_token: "changed-legacy", token_type: "bearer" }),
      "utf-8",
    );
    expect(store.maybeMigrateLegacyTokens(fingerprint, "legacy-server")).toMatchObject({
      access_token: "legacy-access",
    });
    expect(store.loadTokens(fingerprint)?.access_token).toBe("legacy-access");

    const conflictFingerprint = "fp-conflict";
    store.saveRecord({
      version: 1,
      fingerprint: conflictFingerprint,
      seed: buildAuthFingerprintSeed({
        serverUrl: "https://api.example.com/mcp",
        issuer: "https://auth.example.com",
        clientId: "client-456",
      }),
      updatedAt: 0,
      tokens: {
        access_token: "durable-access",
        refresh_token: "durable-refresh",
        token_type: "bearer",
      },
    });

    mkdirSync(join(legacyRootDir, "conflict-server"), { recursive: true });
    writeFileSync(
      join(legacyRootDir, "conflict-server", "tokens.json"),
      JSON.stringify({ access_token: "legacy-conflict", token_type: "bearer" }),
      "utf-8",
    );

    const skipped = store.maybeMigrateLegacyTokens(conflictFingerprint, "conflict-server");
    expect(skipped).toMatchObject({ access_token: "durable-access" });
    expect(store.getMigrationReceipt("conflict-server")?.status).toBe("skipped-existing");
    expect(store.loadTokens(conflictFingerprint)?.access_token).toBe("durable-access");
  });

  it("serves migrated legacy tokens through the durable lookup helper and ignores expired entries", () => {
    const rootDir = makeTempDir();
    const legacyRootDir = join(rootDir, "legacy");
    const store = new FileAuthStore({ rootDir, legacyRootDir });
    const definition: ServerEntry = {
      url: "https://api.example.com/mcp",
      auth: {
        type: "oauth",
        grantType: "authorization_code",
      },
    };

    mkdirSync(join(legacyRootDir, "legacy-server"), { recursive: true });
    writeFileSync(
      join(legacyRootDir, "legacy-server", "tokens.json"),
      JSON.stringify({
        access_token: "legacy-access",
        refresh_token: "legacy-refresh",
        token_type: "bearer",
      }),
      "utf-8",
    );

    expect(getStoredTokens("legacy-server", definition, store)).toMatchObject({
      access_token: "legacy-access",
      refresh_token: "legacy-refresh",
      token_type: "bearer",
    });

    const fingerprint = createAuthFingerprintFromServer(definition);
    expect(fingerprint).toBeTruthy();
    expect(store.getMigrationReceipt("legacy-server")?.status).toBe("imported");
    expect(store.loadTokens(fingerprint!, { serverName: "legacy-server" })).toMatchObject({
      access_token: "legacy-access",
      refresh_token: "legacy-refresh",
      token_type: "bearer",
    });

    store.saveTokens(fingerprint!, {
      access_token: "expired-access",
      token_type: "bearer",
      expiresAt: Date.now() - 1_000,
    });

    expect(getStoredTokens("legacy-server", definition, store)).toBeUndefined();
  });

  it("redacts secrets for logs while keeping durable persistence intact", () => {
    const redacted = redactAuthRecordForLogs({
      version: 1,
      fingerprint: "fp-redact",
      seed: {
        serverUrl: "https://api.example.com/mcp",
        issuer: "https://auth.example.com/",
        grantType: "authorization_code",
        clientIdentity: "client_id:client-123",
      },
      updatedAt: 123,
      tokens: {
        access_token: "access-123",
        refresh_token: "refresh-123",
        id_token: "id-123",
        token_type: "bearer",
      },
      clientInformation: {
        client_id: "client-123",
        client_secret: "secret-123",
      },
    });

    expect(redacted).toEqual({
      version: 1,
      fingerprint: "fp-redact",
      seed: {
        serverUrl: "https://api.example.com/mcp",
        issuer: "https://auth.example.com/",
        grantType: "authorization_code",
        clientIdentity: "client_id:client-123",
      },
      updatedAt: 123,
      tokens: {
        access_token: "[redacted]",
        refresh_token: "[redacted]",
        id_token: "[redacted]",
        token_type: "bearer",
      },
      clientInformation: {
        client_id: "client-123",
        client_secret: "[redacted]",
      },
    });
  });
});
