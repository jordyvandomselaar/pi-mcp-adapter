import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it, vi, afterEach } from "vitest";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InteractiveAuthorizationRequiredError } from "../auth-provider.js";
import { FileAuthStore } from "../auth-store.js";
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

  it("does not fall back to SSE when background reconnects require interactive reauth", async () => {
    const harness = createTestManager({
      connectOptions: {
        interactiveAllowed: false,
        interactionReason: "background",
      },
      connectHandler: async (transport) => {
        const provider = transport.authProvider as {
          state?: () => Promise<string>;
          redirectToAuthorization: (authorizationUrl: URL) => Promise<void>;
        };

        await provider.state?.();
        await provider.redirectToAuthorization(new URL("https://auth.example.com/authorize"));
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
      expect(harness.sseTransports).toHaveLength(0);
    } finally {
      harness.cleanup();
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
});
