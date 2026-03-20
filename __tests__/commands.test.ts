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
    expect(text).toContain("authorization_code uses the system browser with a 127.0.0.1 loopback callback");
    expect(text).toContain("Tokens, client registration, and callback session state are stored under ~/.pi/agent/mcp-auth");
    expect(text).toContain("HTTP auth failures stay auth failures; StreamableHTTP only falls back to SSE when the transport is incompatible.");
    expect(text).toContain("Use /mcp auth (or /mcp-auth) to show this summary again");
  });
});

describe("authenticateServer", () => {
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
    expect(text).toContain("Starting browser-based authorization_code auth. Pi will use your system browser with a 127.0.0.1 loopback callback if fresh sign-in is required.");
    expect(text).toContain("Tokens, client registration, and callback session state are stored under ~/.pi/agent/mcp-auth and silently refreshed when possible.");
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
