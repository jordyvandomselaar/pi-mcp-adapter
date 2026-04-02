import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it, vi, afterEach } from "vitest";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InteractiveAuthorizationRequiredError } from "../auth-provider.js";
import { FileAuthStore, createAuthFingerprintFromServer } from "../auth-store.js";
import { McpServerManager, type ServerConnectOptions } from "../server-manager.js";
import type { ServerDefinition } from "../types.js";

class FakeHttpTransport {
  readonly kind: "streamable" | "sse";
  readonly requestInit?: RequestInit;
  readonly authProvider?: unknown;
  readonly close = vi.fn(async () => {});
  readonly finishAuth = vi.fn(async (_authorizationCode: string) => {});

  constructor(kind: "streamable" | "sse", options?: { requestInit?: RequestInit; authProvider?: unknown }) {
    this.kind = kind;
    this.requestInit = options?.requestInit;
    this.authProvider = options?.authProvider;
  }
}

class FakeAuthSessionManager {
  redirectUrl = "http://127.0.0.1:43123/callback";
  readonly start = vi.fn(async () => {});
  readonly openAuthorization = vi.fn(async (_authorizationUrl: string | URL) => {});
  readonly cancel = vi.fn(async (_reason?: string) => {});
  readonly waitForCallback = vi.fn(async () => ({
    sessionId: "session-1",
    fingerprint: "fingerprint-1",
    state: "state-1",
    authorizationCode: "auth-code-123",
    receivedAt: Date.now(),
  }));
  private sessionCount = 0;

  readonly startAttempt = vi.fn(async (fingerprint: string) => {
    this.sessionCount += 1;
    const state = `state-${this.sessionCount}`;
    return {
      sessionId: `session-${this.sessionCount}`,
      fingerprint,
      state,
      redirectUrl: this.redirectUrl,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      saveCodeVerifier: async () => {},
      getCodeVerifier: async () => "verifier-123",
      openAuthorization: this.openAuthorization,
      waitForCallback: this.waitForCallback,
      cancel: this.cancel,
    };
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function createOAuthDefinition(): ServerDefinition {
  return {
    url: "https://api.example.com/mcp",
    headers: {
      "x-test": "demo-header",
    },
    auth: {
      type: "oauth",
      grantType: "authorization_code",
      scope: "tools:read",
      client: {
        information: {
          clientId: "client-123",
          clientSecret: "secret-456",
        },
      },
    },
  };
}

function createTestManager(options: {
  connectHandler: (transport: FakeHttpTransport) => Promise<void>;
  sessionManager?: FakeAuthSessionManager;
  connectOptions?: ServerConnectOptions;
}) {
  const tmpRoot = mkdtempSync(join(tmpdir(), "pi-mcp-server-manager-"));
  const authStore = new FileAuthStore({
    rootDir: tmpRoot,
    legacyRootDir: join(tmpRoot, "legacy"),
  });
  const sessionManager = options.sessionManager ?? new FakeAuthSessionManager();
  const streamableTransports: FakeHttpTransport[] = [];
  const sseTransports: FakeHttpTransport[] = [];

  const createClient = vi.fn(() => ({
    connect: vi.fn(async (transport: FakeHttpTransport) => {
      await options.connectHandler(transport);
    }),
    close: vi.fn(async () => {}),
  }) as unknown as Client);

  const manager = new McpServerManager({
    authStore,
    authSessionManager: sessionManager,
    createClient,
    createStreamableTransport: (_url, transportOptions) => {
      const transport = new FakeHttpTransport("streamable", transportOptions);
      streamableTransports.push(transport);
      return transport as never;
    },
    createSseTransport: (_url, transportOptions) => {
      const transport = new FakeHttpTransport("sse", transportOptions);
      sseTransports.push(transport);
      return transport as never;
    },
  });

  const cleanup = () => {
    rmSync(tmpRoot, { recursive: true, force: true });
  };

  return {
    manager,
    authStore,
    sessionManager,
    streamableTransports,
    sseTransports,
    cleanup,
    connectOptions: options.connectOptions,
  };
}

describe("McpServerManager HTTP transport selection", () => {
  it("falls back to auth-aware SSE only after interactive auth completes and Streamable HTTP still mismatches", async () => {
    let streamableAttempts = 0;
    const harness = createTestManager({
      connectHandler: async (transport) => {
        if (transport.kind === "streamable") {
          streamableAttempts += 1;
          const provider = transport.authProvider as {
            state?: () => Promise<string>;
            redirectToAuthorization: (authorizationUrl: URL) => Promise<void>;
          };

          expect(provider).toBeTruthy();

          if (streamableAttempts === 1) {
            const state = await provider.state?.();
            expect(state).toBe("state-1");
            await provider.redirectToAuthorization(new URL(`https://auth.example.com/authorize?state=${state}`));
            throw new UnauthorizedError();
          }

          throw new StreamableHTTPError(405, "Method Not Allowed");
        }
      },
    });

    try {
      const transport = await (harness.manager as unknown as {
        createHttpTransport: (definition: ServerDefinition, serverName: string) => Promise<FakeHttpTransport>;
      }).createHttpTransport(createOAuthDefinition(), "demo-server");

      expect(transport.kind).toBe("sse");
      expect(harness.streamableTransports).toHaveLength(2);
      expect(harness.sseTransports).toHaveLength(2);
      expect(harness.streamableTransports[0].finishAuth).toHaveBeenCalledWith("auth-code-123");
      expect(harness.sessionManager.openAuthorization).toHaveBeenCalledTimes(1);
      expect(harness.sessionManager.waitForCallback).toHaveBeenCalledTimes(1);
      expect(harness.sseTransports[0].authProvider).toBeTruthy();
      expect(transport.authProvider).toBeTruthy();
      expect(transport.requestInit?.headers).toMatchObject({ "x-test": "demo-header" });
    } finally {
      harness.cleanup();
    }
  });

  it("short-circuits background OAuth reconnects without stored tokens before any browser-capable transport is created", async () => {
    const harness = createTestManager({
      connectOptions: {
        interactiveAllowed: false,
        interactionReason: "background",
      },
      connectHandler: async () => {
        throw new Error("connect should not run when background auth is already known to require user interaction");
      },
    });

    try {
      const promise = (harness.manager as unknown as {
        createHttpTransport: (
          definition: ServerDefinition,
          serverName: string,
          connectOptions: ServerConnectOptions,
        ) => Promise<FakeHttpTransport>;
      }).createHttpTransport(createOAuthDefinition(), "demo-server", harness.connectOptions ?? {});

      await expect(promise).rejects.toBeInstanceOf(InteractiveAuthorizationRequiredError);
      await expect(promise).rejects.toMatchObject({
        decision: expect.objectContaining({
          reason: "background",
          interactiveAllowed: false,
        }),
      });
      expect(harness.sessionManager.start).not.toHaveBeenCalled();
      expect(harness.sessionManager.startAttempt).not.toHaveBeenCalled();
      expect(harness.streamableTransports).toHaveLength(0);
      expect(harness.sseTransports).toHaveLength(0);
    } finally {
      harness.cleanup();
    }
  });

  it("still attempts silent background connects when durable tokens already exist", async () => {
    const harness = createTestManager({
      connectOptions: {
        interactiveAllowed: false,
        interactionReason: "background",
      },
      connectHandler: async (transport) => {
        expect(transport.authProvider).toBeTruthy();
      },
    });

    try {
      const definition = createOAuthDefinition();
      const fingerprint = createAuthFingerprintFromServer(definition);
      expect(fingerprint).toBeTruthy();
      harness.authStore.saveTokens(fingerprint!, {
        access_token: "access-token-123",
        token_type: "bearer",
      });

      const transport = await (harness.manager as unknown as {
        createHttpTransport: (
          definition: ServerDefinition,
          serverName: string,
          connectOptions: ServerConnectOptions,
        ) => Promise<FakeHttpTransport>;
      }).createHttpTransport(definition, "demo-server", harness.connectOptions ?? {});

      expect(transport.kind).toBe("streamable");
      expect(harness.streamableTransports.length).toBeGreaterThan(0);
      expect(harness.sseTransports).toHaveLength(0);
    } finally {
      harness.cleanup();
    }
  });

  it("infers OAuth for HTTP servers without explicit auth when discovery succeeds", async () => {
    const originalFetch = global.fetch;
    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const requestUrl = typeof input === "string"
        ? new URL(input)
        : input instanceof URL
          ? input
          : new URL(input.url);

      if (requestUrl.pathname === "/.well-known/oauth-protected-resource/api/v0/mcp") {
        return jsonResponse({
          resource: "https://relay.example.com/api/v0/mcp",
          authorization_servers: ["https://relay.example.com"],
          scopes_supported: ["mcp:full"],
        });
      }

      if (requestUrl.pathname === "/.well-known/oauth-authorization-server") {
        return jsonResponse({
          issuer: "https://relay.example.com",
          authorization_endpoint: "https://relay.example.com/oauth/authorize",
          token_endpoint: "https://relay.example.com/api/v0/oauth/token",
          registration_endpoint: "https://relay.example.com/api/v0/oauth/register",
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          token_endpoint_auth_methods_supported: ["none"],
        });
      }

      return new Response("not found", { status: 404 });
    }) as typeof fetch;

    const harness = createTestManager({
      connectHandler: async (transport) => {
        expect(transport.authProvider).toBeTruthy();
      },
    });

    try {
      const transport = await (harness.manager as unknown as {
        createHttpTransport: (
          definition: ServerDefinition,
          serverName: string,
          connectOptions: ServerConnectOptions,
        ) => Promise<FakeHttpTransport>;
      }).createHttpTransport(
        { url: "https://relay.example.com/api/v0/mcp" },
        "relay",
        { interactiveAllowed: true, interactionReason: "user" },
      );

      expect(transport.kind).toBe("streamable");
      expect(transport.authProvider).toBeTruthy();
    } finally {
      global.fetch = originalFetch;
      harness.cleanup();
    }
  });

  it("optimistically uses OAuth for direct user auth retries when discovery fails", async () => {
    const originalFetch = global.fetch;
    global.fetch = vi.fn(async () => {
      throw new Error("discovery unavailable");
    }) as typeof fetch;

    const harness = createTestManager({
      connectHandler: async (transport) => {
        expect(transport.authProvider).toBeTruthy();
      },
    });

    try {
      const transport = await (harness.manager as unknown as {
        createHttpTransport: (
          definition: ServerDefinition,
          serverName: string,
          connectOptions: ServerConnectOptions,
        ) => Promise<FakeHttpTransport>;
      }).createHttpTransport(
        { url: "https://relay.example.com/api/v0/mcp" },
        "relay",
        { interactiveAllowed: true, interactionReason: "user" },
      );

      expect(transport.kind).toBe("streamable");
      expect(transport.authProvider).toBeTruthy();
    } finally {
      global.fetch = originalFetch;
      harness.cleanup();
    }
  });

  it("resolves env-backed client_credentials client info for non-interactive auth", async () => {
    const originalClientId = process.env.PI_TEST_MACHINE_CLIENT_ID;
    const originalClientSecret = process.env.PI_TEST_MACHINE_CLIENT_SECRET;
    process.env.PI_TEST_MACHINE_CLIENT_ID = "machine-env-client";
    process.env.PI_TEST_MACHINE_CLIENT_SECRET = "machine-env-secret";

    const harness = createTestManager({
      connectHandler: async (transport) => {
        expect(transport.authProvider).toBeTruthy();
      },
    });

    try {
      const definition: ServerDefinition = {
        url: "https://machine.example.com/mcp",
        auth: {
          type: "oauth",
          grantType: "client_credentials",
          client: {
            information: {
              clientIdEnv: "PI_TEST_MACHINE_CLIENT_ID",
              clientSecretEnv: "PI_TEST_MACHINE_CLIENT_SECRET",
            },
          },
        },
      };

      const transport = await (harness.manager as unknown as {
        createHttpTransport: (definition: ServerDefinition, serverName: string) => Promise<FakeHttpTransport>;
      }).createHttpTransport(definition, "machine-server");

      const provider = transport.authProvider as {
        clientInformation: () => Promise<{ client_id?: string; client_secret?: string } | undefined>;
      };

      await expect(provider.clientInformation()).resolves.toEqual({
        client_id: "machine-env-client",
        client_secret: "machine-env-secret",
        client_id_issued_at: undefined,
        client_secret_expires_at: undefined,
      });
    } finally {
      harness.cleanup();
      if (originalClientId === undefined) delete process.env.PI_TEST_MACHINE_CLIENT_ID;
      else process.env.PI_TEST_MACHINE_CLIENT_ID = originalClientId;
      if (originalClientSecret === undefined) delete process.env.PI_TEST_MACHINE_CLIENT_SECRET;
      else process.env.PI_TEST_MACHINE_CLIENT_SECRET = originalClientSecret;
    }
  });

  it("does not treat 403 auth failures as transport incompatibility", async () => {
    const harness = createTestManager({
      connectHandler: async () => {
        throw new StreamableHTTPError(403, "Forbidden");
      },
    });

    try {
      const promise = (harness.manager as unknown as {
        createHttpTransport: (definition: ServerDefinition, serverName: string) => Promise<FakeHttpTransport>;
      }).createHttpTransport(createOAuthDefinition(), "demo-server");

      await expect(promise).rejects.toMatchObject({ code: 403 });
      expect(harness.sseTransports).toHaveLength(0);
    } finally {
      harness.cleanup();
    }
  });

  it("enforces registration.mode static with a clear config error", async () => {
    const harness = createTestManager({
      connectHandler: async () => {
        throw new Error("connect should not run when registration.mode static is misconfigured");
      },
    });

    try {
      const promise = (harness.manager as unknown as {
        createHttpTransport: (definition: ServerDefinition, serverName: string) => Promise<FakeHttpTransport>;
      }).createHttpTransport({
        url: "https://api.example.com/mcp",
        auth: {
          type: "oauth",
          registration: { mode: "static" },
        },
      }, "demo-server");

      await expect(promise).rejects.toThrow(
        'OAuth registration.mode "static" for "demo-server" requires client.information.clientId or clientIdEnv.',
      );
      expect(harness.streamableTransports).toHaveLength(0);
      expect(harness.sseTransports).toHaveLength(0);
    } finally {
      harness.cleanup();
    }
  });

  it("enforces metadata-url and dynamic registration semantics on the SDK auth provider", async () => {
    const harness = createTestManager({
      connectHandler: async (transport) => {
        expect(transport.authProvider).toBeTruthy();
      },
    });

    try {
      const metadataUrlDefinition: ServerDefinition = {
        url: "https://api.example.com/mcp",
        auth: {
          type: "oauth",
          registration: { mode: "metadata-url" },
          client: {
            metadataUrl: "https://client.example.com/pi.json",
            information: {
              clientId: "ignored-static-client",
              clientSecret: "ignored-static-secret",
            },
          },
        },
      };

      const metadataTransport = await (harness.manager as unknown as {
        createHttpTransport: (definition: ServerDefinition, serverName: string) => Promise<FakeHttpTransport>;
      }).createHttpTransport(metadataUrlDefinition, "metadata-server");

      const metadataProvider = metadataTransport.authProvider as {
        clientInformation: () => Promise<{ client_id?: string } | undefined>;
        clientMetadataUrl?: string;
        saveClientInformation?: unknown;
      };

      await expect(metadataProvider.clientInformation()).resolves.toBeUndefined();
      expect(metadataProvider.clientMetadataUrl).toBe("https://client.example.com/pi.json");
      expect(metadataProvider.saveClientInformation).toBeUndefined();

      const dynamicDefinition: ServerDefinition = {
        url: "https://api.example.com/mcp",
        auth: {
          type: "oauth",
          registration: { mode: "dynamic" },
          client: {
            metadataUrl: "https://client.example.com/ignored.json",
            information: {
              clientId: "ignored-static-client",
              clientSecret: "ignored-static-secret",
            },
          },
        },
      };

      const dynamicTransport = await (harness.manager as unknown as {
        createHttpTransport: (definition: ServerDefinition, serverName: string) => Promise<FakeHttpTransport>;
      }).createHttpTransport(dynamicDefinition, "dynamic-server");

      const dynamicProvider = dynamicTransport.authProvider as {
        clientInformation: () => Promise<{ client_id?: string } | undefined>;
        clientMetadataUrl?: string;
        saveClientInformation?: unknown;
      };

      await expect(dynamicProvider.clientInformation()).resolves.toBeUndefined();
      expect(dynamicProvider.clientMetadataUrl).toBeUndefined();
      expect(typeof dynamicProvider.saveClientInformation).toBe("function");
    } finally {
      harness.cleanup();
    }
  });

  it("applies configured OAuth resource indicators through the auth provider", async () => {
    const harness = createTestManager({
      connectHandler: async (transport) => {
        expect(transport.authProvider).toBeTruthy();
      },
    });

    try {
      const definition: ServerDefinition = {
        url: "https://api.example.com/mcp/v1",
        auth: {
          type: "oauth",
          resource: "https://api.example.com/mcp",
        },
      };

      const transport = await (harness.manager as unknown as {
        createHttpTransport: (definition: ServerDefinition, serverName: string) => Promise<FakeHttpTransport>;
      }).createHttpTransport(definition, "resource-server");

      const provider = transport.authProvider as {
        validateResourceURL?: (serverUrl: string | URL, resource?: string) => Promise<URL | undefined>;
      };

      await expect(provider.validateResourceURL?.("https://api.example.com/mcp/v1")).resolves.toEqual(
        new URL("https://api.example.com/mcp"),
      );
      await expect(
        provider.validateResourceURL?.("https://api.example.com/mcp/v1", "https://api.example.com/mcp"),
      ).resolves.toEqual(new URL("https://api.example.com/mcp"));
      await expect(
        provider.validateResourceURL?.("https://api.example.com/mcp/v1", "https://api.example.com/other"),
      ).rejects.toThrow("Configured OAuth resource https://api.example.com/mcp is not permitted");
    } finally {
      harness.cleanup();
    }
  });
});
