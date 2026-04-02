import { describe, expect, it, vi } from "vitest";
import { auth, type AuthResult } from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientInformationMixed,
  OAuthMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  createAuthorizationCodeProvider,
  createClientCredentialsProvider,
  redactAuthForLogs,
  resolveAuthPolicyDecision,
  type AuthInvalidationScope,
  type AuthProviderStore,
  type AuthorizationRedirectContext,
  type AuthProviderEvent,
  type ClientCredentialsProviderOptions,
  type AuthorizationCodeProviderOptions,
  InteractiveAuthorizationRequiredError,
} from "../auth-provider.js";

type FetchCall = {
  url: string;
  method: string;
  headers: Headers;
  body: string;
};

class MemoryAuthProviderStore implements AuthProviderStore {
  clientInformation?: OAuthClientInformationMixed;
  tokensValue?: OAuthTokens;
  codeVerifierValue?: string;
  invalidations: AuthInvalidationScope[] = [];
  saveCodeVerifierCalls = 0;
  loadCodeVerifierCalls = 0;

  async loadClientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    return this.clientInformation;
  }

  async saveClientInformation(clientInformation: OAuthClientInformationMixed): Promise<void> {
    this.clientInformation = clientInformation;
  }

  async loadTokens(): Promise<OAuthTokens | undefined> {
    return this.tokensValue;
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    this.tokensValue = tokens;
  }

  async loadCodeVerifier(): Promise<string | undefined> {
    this.loadCodeVerifierCalls += 1;
    return this.codeVerifierValue;
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    this.saveCodeVerifierCalls += 1;
    this.codeVerifierValue = codeVerifier;
  }

  async invalidate(scope: AuthInvalidationScope): Promise<void> {
    this.invalidations.push(scope);

    if (scope === "all" || scope === "client") {
      this.clientInformation = undefined;
    }

    if (scope === "all" || scope === "tokens") {
      this.tokensValue = undefined;
    }

    if (scope === "all" || scope === "verifier") {
      this.codeVerifierValue = undefined;
    }
  }
}

function createAuthMetadata(overrides: Partial<OAuthMetadata> = {}): OAuthMetadata {
  return {
    issuer: "https://auth.example.com",
    authorization_endpoint: new URL("https://auth.example.com/authorize"),
    token_endpoint: new URL("https://auth.example.com/token"),
    registration_endpoint: new URL("https://auth.example.com/register"),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

function normalizeBody(body: BodyInit | null | undefined): string {
  if (!body) return "";
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  return String(body);
}

function createSdkFetch(handler: (call: FetchCall) => Response | Promise<Response>) {
  const calls: FetchCall[] = [];

  const fetchFn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(String(input), init);
    const body = normalizeBody(init?.body ?? (input instanceof Request ? await input.clone().text() : undefined));
    const call: FetchCall = {
      url: request.url,
      method: request.method,
      headers: new Headers(request.headers),
      body,
    };
    calls.push(call);
    return await handler(call);
  });

  return { fetchFn, calls };
}

async function runAuth(
  provider: AuthorizationCodeProviderOptions | ClientCredentialsProviderOptions,
  options: { authorizationCode?: string; fetchFn: typeof fetch }
): Promise<AuthResult> {
  return await auth(
    "redirectUrl" in provider
      ? createAuthorizationCodeProvider(provider)
      : createClientCredentialsProvider(provider),
    {
      serverUrl: provider.serverUrl,
      authorizationCode: options.authorizationCode,
      fetchFn: options.fetchFn,
    }
  );
}

describe("auth-provider", () => {
  describe("registration precedence", () => {
    it("prefers static client information over CIMD and DCR", async () => {
      const store = new MemoryAuthProviderStore();
      store.codeVerifierValue = "pkce-verifier-123";
      const redirects = vi.fn();
      const metadata = createAuthMetadata();
      const { fetchFn, calls } = createSdkFetch(async (call) => {
        const url = new URL(call.url);

        if (url.pathname.includes("oauth-protected-resource")) {
          return new Response(null, { status: 404 });
        }

        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return jsonResponse(metadata);
        }

        if (url.pathname === "/token") {
          expect(call.body).toContain("grant_type=authorization_code");
          expect(call.body).toContain("code=auth-code-123");
          expect(call.body).toContain("client_id=static-client");
          expect(call.body).toContain("client_secret=static-secret");
          return jsonResponse({ access_token: "token-1", token_type: "bearer" });
        }

        if (url.pathname === "/register") {
          throw new Error("dynamic registration should not be attempted when static client information exists");
        }

        throw new Error(`Unexpected fetch: ${call.method} ${call.url}`);
      });

      const result = await runAuth(
        {
          serverUrl: "https://api.example.com/mcp",
          serverName: "demo",
          fingerprint: "fp-static",
          redirectUrl: "http://127.0.0.1:8310/callback",
          store,
          staticClientInformation: {
            client_id: "static-client",
            client_secret: "static-secret",
          },
          clientMetadataUrl: "https://client.example.com/metadata.json",
          redirectToAuthorization: redirects,
        },
        { authorizationCode: "auth-code-123", fetchFn }
      );

      expect(result).toBe("AUTHORIZED");
      expect(store.tokensValue?.access_token).toBe("token-1");
      expect(store.clientInformation).toBeUndefined();
      expect(redirects).not.toHaveBeenCalled();
      expect(calls.some((call) => new URL(call.url).pathname === "/register")).toBe(false);
    });

    it("prefers CIMD before DCR when the auth server supports URL-based client IDs", async () => {
      const store = new MemoryAuthProviderStore();
      const redirects: AuthorizationRedirectContext[] = [];
      const metadata = createAuthMetadata({
        client_id_metadata_document_supported: true,
      });
      const { fetchFn, calls } = createSdkFetch(async (call) => {
        const url = new URL(call.url);

        if (url.pathname.includes("oauth-protected-resource")) {
          return new Response(null, { status: 404 });
        }

        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return jsonResponse(metadata);
        }

        if (url.pathname === "/register") {
          throw new Error("dynamic registration should not be attempted when CIMD is supported");
        }

        throw new Error(`Unexpected fetch: ${call.method} ${call.url}`);
      });

      const redirectSpy = vi.fn(async (_authorizationUrl: URL, context: AuthorizationRedirectContext) => {
        redirects.push(context);
      });

      const result = await runAuth(
        {
          serverUrl: "https://api.example.com/mcp",
          serverName: "demo",
          fingerprint: "fp-cimd",
          redirectUrl: "http://127.0.0.1:8310/callback",
          store,
          clientMetadataUrl: "https://client.example.com/pi-mcp-adapter.json",
          redirectToAuthorization: redirectSpy,
        },
        { fetchFn }
      );

      expect(result).toBe("REDIRECT");
      expect(store.clientInformation).toEqual({
        client_id: "https://client.example.com/pi-mcp-adapter.json",
      });
      expect(store.codeVerifierValue).toBeTruthy();
      expect(redirects[0]?.decision.mode).toBe("interactive");
      expect(calls.some((call) => new URL(call.url).pathname === "/register")).toBe(false);
    });

    it("falls back to DCR when no static client info or CIMD support is available", async () => {
      const store = new MemoryAuthProviderStore();
      const metadata = createAuthMetadata({
        client_id_metadata_document_supported: false,
      });
      const { fetchFn, calls } = createSdkFetch(async (call) => {
        const url = new URL(call.url);

        if (url.pathname.includes("oauth-protected-resource")) {
          return new Response(null, { status: 404 });
        }

        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return jsonResponse(metadata);
        }

        if (url.pathname === "/register") {
          expect(call.method).toBe("POST");
          return jsonResponse({
            client_id: "dcr-client",
            client_secret: "dcr-secret",
            redirect_uris: ["http://127.0.0.1:8310/callback"],
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
          });
        }

        throw new Error(`Unexpected fetch: ${call.method} ${call.url}`);
      });

      const redirectSpy = vi.fn();
      const result = await runAuth(
        {
          serverUrl: "https://api.example.com/mcp",
          redirectUrl: "http://127.0.0.1:8310/callback",
          store,
          redirectToAuthorization: redirectSpy,
        },
        { fetchFn }
      );

      expect(result).toBe("REDIRECT");
      expect(store.clientInformation).toMatchObject({
        client_id: "dcr-client",
        client_secret: "dcr-secret",
      });
      expect(calls.some((call) => new URL(call.url).pathname === "/register")).toBe(true);
      expect(redirectSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe("client_credentials", () => {
    it("acquires tokens without browser interaction", async () => {
      const store = new MemoryAuthProviderStore();
      const metadata = createAuthMetadata({
        response_types_supported: ["code"],
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      });
      const { fetchFn } = createSdkFetch(async (call) => {
        const url = new URL(call.url);

        if (url.pathname.includes("oauth-protected-resource")) {
          return new Response(null, { status: 404 });
        }

        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return jsonResponse(metadata);
        }

        if (url.pathname === "/token") {
          expect(call.body).toContain("grant_type=client_credentials");
          expect(call.body).toContain("scope=");
          expect(call.body).toContain("client_id=svc-client");
          expect(call.body).toContain("client_secret=svc-secret");
          return jsonResponse({ access_token: "svc-token", token_type: "bearer" });
        }

        throw new Error(`Unexpected fetch: ${call.method} ${call.url}`);
      });

      const provider = createClientCredentialsProvider({
        serverUrl: "https://api.example.com/mcp",
        serverName: "svc",
        fingerprint: "fp-cc",
        store,
        staticClientInformation: {
          client_id: "svc-client",
          client_secret: "svc-secret",
        },
        interactiveAllowed: false,
        clientMetadata: { scope: "tools:read" },
      });

      const result = await auth(provider, {
        serverUrl: "https://api.example.com/mcp",
        fetchFn,
      });

      expect(result).toBe("AUTHORIZED");
      expect(store.tokensValue?.access_token).toBe("svc-token");
      expect(store.saveCodeVerifierCalls).toBe(0);
      expect(provider.getPolicyDecision().mode).toBe("non-interactive");
    });
  });

  describe("silent refresh", () => {
    it("refreshes tokens silently and preserves the refresh token when omitted by the server", async () => {
      const store = new MemoryAuthProviderStore();
      store.tokensValue = {
        access_token: "old-access-token",
        refresh_token: "refresh-token-1",
        token_type: "bearer",
      };

      const metadata = createAuthMetadata();
      const redirectSpy = vi.fn();
      const { fetchFn } = createSdkFetch(async (call) => {
        const url = new URL(call.url);

        if (url.pathname.includes("oauth-protected-resource")) {
          return new Response(null, { status: 404 });
        }

        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return jsonResponse(metadata);
        }

        if (url.pathname === "/token") {
          expect(call.body).toContain("grant_type=refresh_token");
          expect(call.body).toContain("refresh_token=refresh-token-1");
          return jsonResponse({
            access_token: "new-access-token",
            token_type: "bearer",
            expires_in: 3600,
          });
        }

        throw new Error(`Unexpected fetch: ${call.method} ${call.url}`);
      });

      const result = await runAuth(
        {
          serverUrl: "https://api.example.com/mcp",
          redirectUrl: "http://127.0.0.1:8310/callback",
          store,
          interactiveAllowed: false,
          interactionReason: "background",
          staticClientInformation: {
            client_id: "refresh-client",
            client_secret: "refresh-secret",
          },
          redirectToAuthorization: redirectSpy,
        },
        { fetchFn }
      );

      expect(result).toBe("AUTHORIZED");
      expect(store.tokensValue).toEqual({
        access_token: "new-access-token",
        token_type: "bearer",
        expires_in: 3600,
        refresh_token: "refresh-token-1",
      });
      expect(redirectSpy).not.toHaveBeenCalled();
    });
  });

  describe("invalid_grant invalidation", () => {
    it("invalidates tokens and refuses browser auth when background policy disables interaction", async () => {
      const store = new MemoryAuthProviderStore();
      store.tokensValue = {
        access_token: "old-access-token",
        refresh_token: "expired-refresh-token",
        token_type: "bearer",
      };

      const metadata = createAuthMetadata();
      const events: AuthProviderEvent[] = [];
      const redirectSpy = vi.fn();
      const { fetchFn } = createSdkFetch(async (call) => {
        const url = new URL(call.url);

        if (url.pathname.includes("oauth-protected-resource")) {
          return new Response(null, { status: 404 });
        }

        if (url.pathname === "/.well-known/oauth-authorization-server") {
          return jsonResponse(metadata);
        }

        if (url.pathname === "/token") {
          return jsonResponse(
            {
              error: "invalid_grant",
              error_description: "refresh token expired",
            },
            400
          );
        }

        throw new Error(`Unexpected fetch: ${call.method} ${call.url}`);
      });

      await expect(
        runAuth(
          {
            serverUrl: "https://api.example.com/mcp",
            serverName: "background-demo",
            fingerprint: "fp-invalid-grant",
            redirectUrl: "http://127.0.0.1:8310/callback",
            store,
            interactiveAllowed: false,
            interactionReason: "background",
            staticClientInformation: {
              client_id: "refresh-client",
              client_secret: "refresh-secret",
            },
            redirectToAuthorization: redirectSpy,
            onEvent: (event) => events.push(event),
          },
          { fetchFn }
        )
      ).rejects.toBeInstanceOf(InteractiveAuthorizationRequiredError);

      expect(store.invalidations).toEqual(["tokens"]);
      expect(store.tokensValue).toBeUndefined();
      expect(redirectSpy).not.toHaveBeenCalled();
      expect(events.some((event) => event.type === "interactive_authorization_blocked")).toBe(true);
    });
  });

  describe("policy decisions and redaction", () => {
    it("distinguishes interactive, silent-only, blocked, and non-interactive flows", () => {
      expect(
        resolveAuthPolicyDecision({
          flow: "authorization_code",
          interactiveAllowed: true,
          hasRefreshToken: false,
          interactionReason: "user",
        })
      ).toMatchObject({ mode: "interactive", willAttemptBrowser: true, canRefreshSilently: false });

      expect(
        resolveAuthPolicyDecision({
          flow: "authorization_code",
          interactiveAllowed: false,
          hasRefreshToken: true,
          interactionReason: "background",
        })
      ).toMatchObject({ mode: "silent-only", willAttemptBrowser: false, canRefreshSilently: true });

      expect(
        resolveAuthPolicyDecision({
          flow: "authorization_code",
          interactiveAllowed: false,
          hasRefreshToken: false,
          interactionReason: "background",
        })
      ).toMatchObject({ mode: "blocked", willAttemptBrowser: false, canRefreshSilently: false });

      expect(
        resolveAuthPolicyDecision({
          flow: "client_credentials",
          interactiveAllowed: false,
          hasRefreshToken: false,
          interactionReason: "background",
        })
      ).toMatchObject({ mode: "non-interactive", willAttemptBrowser: false, canRefreshSilently: false });
    });

    it("redacts tokens, client secrets, auth headers, state, and query strings before emitting details", async () => {
      const store = new MemoryAuthProviderStore();
      const events: AuthProviderEvent[] = [];
      const provider = createAuthorizationCodeProvider({
        serverUrl: "https://api.example.com/mcp",
        serverName: "demo",
        fingerprint: "fp-redaction",
        redirectUrl: "http://127.0.0.1:8310/callback",
        store,
        getState: async () => "sensitive-state",
        redirectToAuthorization: vi.fn(),
        onEvent: (event) => events.push(event),
      });

      await provider.saveTokens({
        access_token: "access-token-secret",
        refresh_token: "refresh-token-secret",
        token_type: "bearer",
      });
      await provider.saveCodeVerifier("verifier-secret");
      await provider.redirectToAuthorization(new URL("https://auth.example.com/authorize?code=abc&state=xyz"));

      expect(events.find((event) => event.type === "tokens_saved")?.detail).toMatchObject({
        tokens: {
          access_token: "[redacted]",
          refresh_token: "[redacted]",
        },
      });
      expect(events.find((event) => event.type === "code_verifier_saved")?.detail).toMatchObject({
        codeVerifier: "[redacted]",
      });
      expect(events.find((event) => event.type === "authorization_redirect_requested")?.detail).toMatchObject({
        authorizationUrl: "https://auth.example.com/authorize?<redacted>",
      });

      expect(
        redactAuthForLogs({
          authorization: "Bearer top-secret",
          headers: new Headers({ Authorization: "Basic abc123" }),
          client_secret: "hidden",
          nested: { state: "opaque-state" },
          callbackUrl: "https://auth.example.com/callback?code=123&state=456",
        })
      ).toEqual({
        authorization: "[redacted]",
        headers: { authorization: "[redacted]" },
        client_secret: "[redacted]",
        nested: { state: "[redacted]" },
        callbackUrl: "https://auth.example.com/callback?<redacted>",
      });
    });
  });
});
