// oauth-handler.ts - OAuth token compatibility helpers
import type { OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { FileAuthStore, createAuthFingerprintFromServer, readLegacyTokens } from "./auth-store.js";
import type { ServerEntry } from "./types.js";

const defaultAuthStore = new FileAuthStore();

/**
 * Get stored OAuth tokens for a server.
 *
 * Prefers the durable SDK-auth store keyed by auth fingerprint when a full
 * server definition is available. Falls back to the legacy token file lookup
 * by server name for older call sites.
 */
export function getStoredTokens(serverName: string, definition?: ServerEntry): OAuthTokens | undefined {
  const fingerprint = definition ? createAuthFingerprintFromServer(definition) : undefined;

  if (fingerprint) {
    const stored = defaultAuthStore.loadTokens(fingerprint, { serverName });
    if (!stored) {
      return undefined;
    }

    if (stored.expiresAt && Date.now() > stored.expiresAt) {
      return undefined;
    }

    return {
      access_token: stored.access_token,
      token_type: stored.token_type ?? "bearer",
      refresh_token: stored.refresh_token,
      expires_in: stored.expires_in,
      scope: stored.scope,
      id_token: stored.id_token,
    };
  }

  const legacy = readLegacyTokens(defaultAuthStore.paths.legacyRootDir, serverName);
  if (!legacy) {
    return undefined;
  }

  if (legacy.expiresAt && Date.now() > legacy.expiresAt) {
    return undefined;
  }

  return {
    access_token: legacy.access_token,
    token_type: legacy.token_type ?? "bearer",
    refresh_token: legacy.refresh_token,
    expires_in: legacy.expires_in,
    scope: legacy.scope,
    id_token: legacy.id_token,
  };
}
