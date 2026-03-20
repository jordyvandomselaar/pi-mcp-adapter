import { afterEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { InvalidAuthCallbackError } from "../auth-session-manager.js";
import { serverNeedsAuth, type McpExtensionState } from "../state.js";
import { openMcpPanel } from "../commands.js";

const { createMcpPanel, loadMetadataCache, getStoredTokens } = vi.hoisted(() => ({
  createMcpPanel: vi.fn(),
  loadMetadataCache: vi.fn(() => ({ version: 1, servers: {} })),
  getStoredTokens: vi.fn(),
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

vi.mock("../oauth-handler.js", () => ({
  getStoredTokens,
}));

afterEach(() => {
  vi.clearAllMocks();
  loadMetadataCache.mockReturnValue({ version: 1, servers: {} });
  getStoredTokens.mockReturnValue(undefined);
});

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
  const setStatus = vi.fn();
  const custom = vi.fn((renderer, options) => {
    renderer({ requestRender: vi.fn() } as never, {} as never, {} as never, vi.fn());
    expect(options).toEqual({ overlay: true, overlayOptions: { anchor: "center", width: 82 } });
  });

  const ctx = {
    hasUI: true,
    ui: {
      custom,
      notify,
      setStatus,
      theme: {
        fg: (_color: string, text: string) => text,
      },
    },
  } as unknown as ExtensionContext;

  const pi = {
    getFlag: vi.fn().mockReturnValue(undefined),
  } as unknown as ExtensionAPI;

  return { ctx, pi, notify, setStatus, custom };
}

describe("openMcpPanel auth-aware callbacks", () => {
  it("marks only authorization_code servers with missing tokens as needs-auth", async () => {
    createMcpPanel.mockImplementation((_config, _cache, _provenance, callbacks, _tui, onDone) => {
      expect(callbacks.getConnectionStatus("interactive")).toBe("needs-auth");
      expect(callbacks.getConnectionStatus("machine")).toBe("idle");
      onDone({ cancelled: true, changes: new Map() });
      return { close: vi.fn() };
    });

    const state = createBaseState();
    state.config = {
      mcpServers: {
        interactive: {
          url: "https://interactive.example.com/mcp",
          auth: { type: "oauth" },
        },
        machine: {
          url: "https://machine.example.com/mcp",
          auth: { type: "oauth", grantType: "client_credentials" },
        },
      },
    };

    const { ctx, pi, custom } = createUiHarness();
    state.ui = ctx.ui;

    await openMcpPanel(state, pi, ctx);

    expect(custom).toHaveBeenCalledTimes(1);
    expect(createMcpPanel).toHaveBeenCalledTimes(1);
  });

  it("intentionally retries reconnect from the panel and safely surfaces callback failures", async () => {
    const state = createBaseState();
    state.config = {
      mcpServers: {
        demo: {
          url: "https://api.example.com/mcp",
          auth: { type: "oauth" },
        },
      },
    };
    state.failureTracker.set("demo", Date.now());

    const callbackError = new InvalidAuthCallbackError(
      "OAuth callback returned error: access_denied code=secret-code&state=secret-state",
    );

    const manager = state.manager as unknown as {
      getConnection: ReturnType<typeof vi.fn>;
      close: ReturnType<typeof vi.fn>;
      connect: ReturnType<typeof vi.fn>;
    };
    manager.connect.mockRejectedValue(callbackError);

    const { ctx, pi, notify } = createUiHarness();
    state.ui = ctx.ui;

    createMcpPanel.mockImplementation((_config, _cache, _provenance, callbacks, _tui, onDone) => {
      void (async () => {
        const connected = await callbacks.reconnect("demo");
        expect(connected).toBe(false);
        expect(manager.close).toHaveBeenCalledWith("demo");
        expect(manager.connect).toHaveBeenCalledWith("demo", state.config.mcpServers.demo, {
          interactiveAllowed: true,
          interactionReason: "user",
        });
        expect(callbacks.getConnectionStatus("demo")).toBe("needs-auth");
        expect(serverNeedsAuth(state, "demo")).toBe(true);
        expect(state.failureTracker.has("demo")).toBe(false);

        const messages = notify.mock.calls.map(([message]) => String(message)).join("\n");
        expect(messages).toContain('Browser sign-in callback for "demo" did not complete successfully');
        expect(messages).not.toContain("code=secret-code");
        expect(messages).not.toContain("state=secret-state");
        expect(messages).not.toContain("access_denied");

        onDone({ cancelled: true, changes: new Map() });
      })();

      return { close: vi.fn() };
    });

    await openMcpPanel(state, pi, ctx);
  });
});
