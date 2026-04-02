import { afterEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { InvalidAuthCallbackError } from "../auth-session-manager.js";
import { serverNeedsAuth, type McpExtensionState } from "../state.js";

const {
  createMcpPanel,
  loadMetadataCache,
  getStoredTokens,
  updateMetadataCache,
  updateStatusBar,
  getFailureAgeSeconds,
} = vi.hoisted(() => ({
  createMcpPanel: vi.fn(),
  loadMetadataCache: vi.fn(() => ({ version: 1, servers: {} })),
  getStoredTokens: vi.fn(),
  updateMetadataCache: vi.fn(),
  updateStatusBar: vi.fn(),
  getFailureAgeSeconds: vi.fn(() => null),
}));

vi.mock("../mcp-panel.js", () => ({
  createMcpPanel,
}));

vi.mock("../config.js", async () => {
  const actual = await vi.importActual<typeof import("../config.js")>("../config.js");
  return {
    ...actual,
    getServerProvenance: vi.fn(() => new Map()),
    writeDirectToolsConfig: vi.fn(),
  };
});

vi.mock("../metadata-cache.js", async () => {
  const actual = await vi.importActual<typeof import("../metadata-cache.js")>("../metadata-cache.js");
  return {
    ...actual,
    loadMetadataCache,
  };
});

vi.mock("../auth-store.js", () => ({
  getStoredTokens,
}));

vi.mock("../init.js", async () => {
  const actual = await vi.importActual<typeof import("../init.js")>("../init.js");
  return {
    ...actual,
    updateMetadataCache,
    updateStatusBar,
    getFailureAgeSeconds,
  };
});

const { authenticateServer, openMcpPanel, showAuthOverview } = await import("../commands.js");

function createBaseState(): McpExtensionState {
  return {
    manager: {
      getConnection: vi.fn().mockReturnValue(undefined),
      getAllConnections: vi.fn(() => new Map()),
      close: vi.fn().mockResolvedValue(undefined),
      connect: vi.fn(),
    },
    lifecycle: {},
    toolMetadata: new Map(),
    config: {
      mcpServers: {},
      settings: {
        toolPrefix: "server",
      },
    },
    failureTracker: new Map(),
    authRequirements: new Map(),
    uiResourceHandler: {},
    consentManager: {},
    uiServer: null,
    completedUiSessions: [],
    openBrowser: vi.fn().mockResolvedValue(undefined),
  } as unknown as McpExtensionState;
}

function createUiHarness() {
  const notify = vi.fn();
  const custom = vi.fn((renderer, options) => {
    renderer({ requestRender: vi.fn() } as never, {} as never, {} as never, vi.fn());
    expect(options).toEqual({ overlay: true, overlayOptions: { anchor: "center", width: 82 } });
  });

  const ctx = {
    hasUI: true,
    ui: {
      custom,
      notify,
      setStatus: vi.fn(),
      theme: {
        fg: (_color: string, text: string) => text,
      },
    },
  } as unknown as ExtensionContext;

  const pi = {
    getFlag: vi.fn().mockReturnValue(undefined),
  } as unknown as ExtensionAPI;

  return { ctx, pi, notify, custom };
}

function notifiedText(notify: ReturnType<typeof vi.fn>): string {
  return notify.mock.calls.map(([message]) => String(message)).join("\n");
}

afterEach(() => {
  vi.clearAllMocks();
  loadMetadataCache.mockReturnValue({ version: 1, servers: {} });
  getStoredTokens.mockReturnValue(undefined);
  getFailureAgeSeconds.mockReturnValue(null);
});

describe("openMcpPanel", () => {
  it("hosts the panel in an overlay and reports needs-auth state", async () => {
    createMcpPanel.mockImplementation((_config, _cache, _provenance, callbacks, _tui, onDone) => {
      expect(callbacks.getConnectionStatus("demo")).toBe("needs-auth");
      onDone({ cancelled: true, changes: new Map() });
      return { close: vi.fn() };
    });

    const state = createBaseState();
    state.config = {
      mcpServers: {
        demo: {
          url: "https://api.example.com/mcp",
          auth: { type: "oauth" },
        },
      },
    };
    state.authRequirements.set("demo", {
      serverName: "demo",
      reason: "reconnect",
      updatedAt: Date.now(),
      message: "needs auth",
    });

    const { ctx, pi, custom } = createUiHarness();
    state.ui = ctx.ui;

    await openMcpPanel(state, pi, ctx);

    expect(custom).toHaveBeenCalledTimes(1);
    expect(createMcpPanel).toHaveBeenCalledTimes(1);
  });
});

describe("showAuthOverview", () => {
  it("summarizes interactive and non-interactive OAuth server state", async () => {
    const state = createBaseState();
    state.config = {
      mcpServers: {
        interactive: {
          url: "https://interactive.example.com/mcp",
          auth: "oauth",
        },
        machine: {
          url: "https://machine.example.com/mcp",
          auth: {
            type: "oauth",
            grantType: "client_credentials",
            registration: { mode: "static" },
            client: {
              information: {
                clientId: "machine-client",
                clientSecret: "super-secret",
              },
            },
          },
        },
      },
    };
    getStoredTokens.mockImplementation((serverName: string) => {
      if (serverName === "machine") {
        return { access_token: "token-123", token_type: "bearer" };
      }
      return undefined;
    });

    const { ctx, notify } = createUiHarness();
    await showAuthOverview(state, ctx);

    const text = notifiedText(notify);
    expect(text).toContain("interactive: browser sign-in required");
    expect(text).toContain("flow: authorization_code");
    expect(text).toContain("registration: auto (static client info -> metadata URL/CIMD -> dynamic registration)");
    expect(text).toContain("machine: cached machine token available");
    expect(text).toContain("flow: client_credentials");
    expect(text).toContain("registration: static");
    expect(text).toContain("client: static client information (machine-client)");
    expect(text).toContain("authorization_code reuses stored tokens and silent refresh first, then uses the system browser with a 127.0.0.1 loopback callback");
    expect(text).toContain("Pi stores tokens, client registration, and callback session state under ~/.pi/agent/mcp-auth.");
    expect(text).toContain("registration.mode=auto prefers static client info, then metadata URL/CIMD, then dynamic registration.");
    expect(text).toContain("HTTP auth failures stay auth failures; StreamableHTTP only falls back to SSE when the transport is incompatible.");
    expect(text).toContain("Use /mcp auth (or /mcp-auth) to show this summary again");
  });

  it("surfaces refresh-token-only interactive auth state without forcing needs-auth", async () => {
    const state = createBaseState();
    state.config = {
      mcpServers: {
        interactive: {
          url: "https://interactive.example.com/mcp",
          auth: "oauth",
        },
      },
    };

    getStoredTokens.mockImplementation((serverName: string, _definition: unknown, _store: unknown, options?: { includeExpired?: boolean }) => {
      if (serverName !== "interactive") {
        return undefined;
      }

      if (options?.includeExpired) {
        return {
          access_token: "expired-token",
          refresh_token: "refresh-token",
          token_type: "bearer",
        };
      }

      return undefined;
    });

    const { ctx, notify } = createUiHarness();
    await showAuthOverview(state, ctx);

    const text = notifiedText(notify);
    expect(text).toContain("interactive: stored refresh token available");
    expect(text).not.toContain("interactive: browser sign-in required");
  });

  it("describes env-backed static client info in auth summaries", async () => {
    const state = createBaseState();
    state.config = {
      mcpServers: {
        machine: {
          url: "https://machine.example.com/mcp",
          auth: {
            type: "oauth",
            grantType: "client_credentials",
            registration: { mode: "static" },
            client: {
              information: {
                clientIdEnv: "MACHINE_CLIENT_ID",
                clientSecretEnv: "MACHINE_CLIENT_SECRET",
              },
            },
          },
        },
      },
    };

    const { ctx, notify } = createUiHarness();
    await showAuthOverview(state, ctx);

    expect(notifiedText(notify)).toContain("client: static client information (clientId from $MACHINE_CLIENT_ID)");
  });
});

describe("authenticateServer", () => {
  it("infers browser OAuth for remote HTTP servers without explicit auth config", async () => {
    const originalFetch = global.fetch;
    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const requestUrl = typeof input === "string"
        ? new URL(input)
        : input instanceof URL
          ? input
          : new URL(input.url);

      if (requestUrl.pathname === "/.well-known/oauth-protected-resource/api/v0/mcp") {
        return new Response(JSON.stringify({
          resource: "https://relay.example.com/api/v0/mcp",
          authorization_servers: ["https://relay.example.com"],
          scopes_supported: ["mcp:full"],
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      if (requestUrl.pathname === "/.well-known/oauth-authorization-server") {
        return new Response(JSON.stringify({
          issuer: "https://relay.example.com",
          authorization_endpoint: "https://relay.example.com/oauth/authorize",
          token_endpoint: "https://relay.example.com/api/v0/oauth/token",
          registration_endpoint: "https://relay.example.com/api/v0/oauth/register",
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          token_endpoint_auth_methods_supported: ["none"],
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response("not found", { status: 404 });
    }) as typeof fetch;

    const state = createBaseState();
    state.config = {
      mcpServers: {
        relay: {
          url: "https://relay.example.com/api/v0/mcp",
        },
      },
      settings: {
        toolPrefix: "server",
      },
    };

    const manager = state.manager as unknown as {
      close: ReturnType<typeof vi.fn>;
      connect: ReturnType<typeof vi.fn>;
    };
    manager.connect.mockResolvedValue({ tools: [], resources: [] });

    try {
      const { ctx, notify } = createUiHarness();
      await authenticateServer(state, "relay", ctx);

      const text = notifiedText(notify);
      expect(text).not.toContain('does not use OAuth authentication');
      expect(text).toContain('MCP auth for "relay":');
      expect(text).toContain('flow: authorization_code');
      expect(text).toContain('Starting browser-based authorization_code auth.');
      expect(manager.connect).toHaveBeenCalledWith("relay", state.config.mcpServers.relay, {
        interactiveAllowed: true,
        interactionReason: "user",
      });
    } finally {
      global.fetch = originalFetch;
    }
  });

  it("optimistically starts browser OAuth for HTTP servers without explicit auth when direct discovery fails", async () => {
    const originalFetch = global.fetch;
    global.fetch = vi.fn(async () => {
      throw new Error("network unavailable during discovery");
    }) as typeof fetch;

    const state = createBaseState();
    state.config = {
      mcpServers: {
        relay: {
          url: "https://relay.example.com/api/v0/mcp",
        },
      },
      settings: {
        toolPrefix: "server",
      },
    };

    const manager = state.manager as unknown as {
      close: ReturnType<typeof vi.fn>;
      connect: ReturnType<typeof vi.fn>;
    };
    manager.connect.mockResolvedValue({ tools: [], resources: [] });

    try {
      const { ctx, notify } = createUiHarness();
      await authenticateServer(state, "relay", ctx);

      const text = notifiedText(notify);
      expect(text).not.toContain('does not use OAuth authentication');
      expect(text).toContain('MCP auth for "relay":');
      expect(text).toContain('flow: authorization_code');
      expect(text).toContain('Starting browser-based authorization_code auth.');
      expect(manager.connect).toHaveBeenCalledWith("relay", state.config.mcpServers.relay, {
        interactiveAllowed: true,
        interactionReason: "user",
      });
    } finally {
      global.fetch = originalFetch;
    }
  });

  it("treats legacy auth: 'oauth' config as authorization_code with auto registration", async () => {
    const state = createBaseState();
    state.config = {
      mcpServers: {
        demo: {
          url: "https://api.example.com/mcp",
          auth: "oauth",
        },
      },
      settings: {
        toolPrefix: "server",
      },
    };

    const manager = state.manager as unknown as {
      close: ReturnType<typeof vi.fn>;
      connect: ReturnType<typeof vi.fn>;
    };
    manager.connect.mockResolvedValue({
      tools: [
        {
          name: "ping",
          description: "Ping the service",
          inputSchema: { type: "object", properties: {} },
        },
      ],
      resources: [],
    });

    const { ctx, notify } = createUiHarness();
    await authenticateServer(state, "demo", ctx);

    expect(manager.close).toHaveBeenCalledWith("demo");
    expect(manager.connect).toHaveBeenCalledWith("demo", state.config.mcpServers.demo, {
      interactiveAllowed: true,
      interactionReason: "user",
    });
    expect(state.toolMetadata.get("demo")?.map((tool) => tool.name)).toEqual(["demo_ping"]);
    expect(updateMetadataCache).toHaveBeenCalledWith(state, "demo");
    expect(updateStatusBar).toHaveBeenCalledWith(state);

    const text = notifiedText(notify);
    expect(text).toContain('MCP auth for "demo":');
    expect(text).toContain("flow: authorization_code");
    expect(text).toContain("registration: auto (static client info -> metadata URL/CIMD -> dynamic registration)");
    expect(text).toContain("Starting browser-based authorization_code auth. Pi reuses stored tokens and silent refresh first; if sign-in is still required, it opens your system browser and waits for the 127.0.0.1 loopback callback.");
    expect(text).toContain("Pi stores tokens, client registration, and callback session state under ~/.pi/agent/mcp-auth.");
    expect(text).toContain("Background reconnects never open a browser; Pi only launches auth on an intentional retry.");
    expect(text).toContain("HTTP auth failures stay auth failures; StreamableHTTP only falls back to SSE when the transport itself is incompatible.");
    expect(text).toContain('Compatibility note: legacy auth: "oauth" config defaults to authorization_code with automatic registration.');
    expect(text).toContain("MCP: Reconnected to demo (1 tools, 0 resources)");
  });

  it("marks failed interactive reauth as needs-auth without leaking callback details", async () => {
    const state = createBaseState();
    state.config = {
      mcpServers: {
        demo: {
          url: "https://api.example.com/mcp",
          auth: { type: "oauth" },
        },
      },
      settings: {
        toolPrefix: "server",
      },
    };
    state.failureTracker.set("demo", Date.now());

    const manager = state.manager as unknown as {
      connect: ReturnType<typeof vi.fn>;
    };
    manager.connect.mockRejectedValue(
      new InvalidAuthCallbackError(
        "OAuth callback returned error: access_denied code=secret-code&state=secret-state",
      ),
    );

    const { ctx, notify } = createUiHarness();
    await authenticateServer(state, "demo", ctx);

    const text = notifiedText(notify);
    expect(text).toContain('Browser sign-in callback for "demo" did not complete successfully');
    expect(text).not.toContain("code=secret-code");
    expect(text).not.toContain("state=secret-state");
    expect(text).not.toContain("access_denied");
    expect(serverNeedsAuth(state, "demo")).toBe(true);
    expect(state.failureTracker.has("demo")).toBe(false);
  });

  it("keeps client_credentials auth non-interactive and explains failure semantics", async () => {
    const state = createBaseState();
    state.config = {
      mcpServers: {
        machine: {
          url: "https://machine.example.com/mcp",
          auth: {
            type: "oauth",
            grantType: "client_credentials",
            registration: { mode: "static" },
            client: {
              information: {
                clientId: "machine-client",
                clientSecret: "super-secret",
              },
            },
          },
        },
      },
      settings: {
        toolPrefix: "server",
      },
    };

    const manager = state.manager as unknown as {
      connect: ReturnType<typeof vi.fn>;
    };
    manager.connect.mockRejectedValue(new Error("invalid_client"));

    const { ctx, notify } = createUiHarness();
    await authenticateServer(state, "machine", ctx);

    const text = notifiedText(notify);
    expect(text).toContain("flow: client_credentials");
    expect(text).toContain("registration: static");
    expect(text).toContain("client: static client information (machine-client)");
    expect(text).toContain("Starting non-interactive client_credentials auth. No browser will open");
    expect(text).toContain("MCP: Failed to reconnect to machine: invalid_client");
    expect(text).toContain("MCP: machine uses client_credentials, so retries remain non-interactive.");
    expect(serverNeedsAuth(state, "machine")).toBe(false);
  });
});
