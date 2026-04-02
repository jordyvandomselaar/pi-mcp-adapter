import {
  discoverAuthorizationServerMetadata,
  discoverOAuthProtectedResourceMetadata,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { getStoredTokens } from "./auth-store.js";
import {
  getDefaultOAuthAuthConfig,
  getResolvedOAuthAuthConfig,
  hasConfiguredAuthorizationHeader,
  isPotentiallyOAuthHttpServer,
  type ResolvedOAuthAuthConfig,
  type ServerDefinition,
} from "./types.js";

const oauthSupportCache = new Map<string, Promise<boolean>>();

export async function resolveRuntimeOAuthConfig(
  serverName: string,
  definition: ServerDefinition,
): Promise<ResolvedOAuthAuthConfig | undefined> {
  const explicit = getResolvedOAuthAuthConfig(definition);
  if (explicit) {
    return explicit;
  }

  if (!isPotentiallyOAuthHttpServer(definition)) {
    return undefined;
  }

  const storedTokens = getStoredTokens(serverName, definition, undefined, {
    includeExpired: true,
  });
  if (storedTokens) {
    return getDefaultOAuthAuthConfig();
  }

  const supportsOAuth = await detectOAuthSupport(definition);
  return supportsOAuth ? getDefaultOAuthAuthConfig() : undefined;
}

export async function detectOAuthSupport(definition: ServerDefinition): Promise<boolean> {
  if (!isPotentiallyOAuthHttpServer(definition)) {
    return false;
  }

  const cacheKey = createDiscoveryCacheKey(definition);
  const cached = oauthSupportCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const pending = discoverOAuthSupport(definition);
  oauthSupportCache.set(cacheKey, pending);
  return pending;
}

async function discoverOAuthSupport(definition: ServerDefinition): Promise<boolean> {
  if (!definition.url) {
    return false;
  }

  const fetchFn = createDiscoveryFetch(definition.headers);

  try {
    let authorizationServerUrl: string | URL | undefined;

    try {
      const resourceMetadata = await discoverOAuthProtectedResourceMetadata(
        definition.url,
        undefined,
        fetchFn,
      );

      if (Array.isArray(resourceMetadata.authorization_servers) && resourceMetadata.authorization_servers.length > 0) {
        authorizationServerUrl = resourceMetadata.authorization_servers[0];
      }
    } catch {
      authorizationServerUrl = undefined;
    }

    authorizationServerUrl ??= new URL("/", definition.url);
    const metadata = await discoverAuthorizationServerMetadata(authorizationServerUrl, {
      fetchFn,
    });
    return Boolean(metadata);
  } catch {
    return false;
  }
}

function createDiscoveryFetch(headers?: Record<string, string>) {
  const resolvedHeaders = resolveHeaders(headers);

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const mergedHeaders = new Headers(resolvedHeaders);
    const requestHeaders = new Headers(init?.headers);
    requestHeaders.forEach((value, key) => {
      mergedHeaders.set(key, value);
    });

    return fetch(input, {
      ...init,
      headers: mergedHeaders,
    });
  };
}

function createDiscoveryCacheKey(definition: ServerDefinition): string {
  const headers = resolveHeaders(definition.headers);
  const normalizedHeaders = Object.keys(headers)
    .sort((left, right) => left.localeCompare(right))
    .map((key) => `${key}:${headers[key]}`)
    .join("|");
  return `${definition.url ?? ""}::${normalizedHeaders}`;
}

function resolveHeaders(headers?: Record<string, string>): Record<string, string> {
  const resolved: Record<string, string> = {};
  if (!headers) {
    return resolved;
  }

  for (const [key, value] of Object.entries(headers)) {
    resolved[key] = value
      .replace(/\$\{(\w+)\}/g, (_, name: string) => process.env[name] ?? "")
      .replace(/\$env:(\w+)/g, (_, name: string) => process.env[name] ?? "");
  }

  return resolved;
}

export function getCurrentAuthModeLabel(definition: ServerDefinition): string {
  if (getResolvedOAuthAuthConfig(definition)) {
    return "oauth";
  }

  if (hasConfiguredAuthorizationHeader(definition.headers)) {
    return "bearer";
  }

  return "none";
}
