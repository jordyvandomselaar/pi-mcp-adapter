import { describe, expect, it, vi } from "vitest";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { openMcpPanel } from "../commands.js";
import { markServerNeedsAuth, type McpExtensionState } from "../state.js";

const createMcpPanel = vi.fn();

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
    loadMetadataCache: vi.fn(() => ({ version: 1, servers: {} })),
  };
});

describe("openMcpPanel", () => {
  it("hosts the panel in an overlay and reports needs-auth state", async () => {
    createMcpPanel.mockImplementation((_config, _cache, _provenance, callbacks, _tui, onDone) => {
      expect(callbacks.getConnectionStatus("demo")).toBe("needs-auth");
      onDone({ cancelled: true, changes: new Map() });
      return { close: vi.fn() };
    });

    const state = {
      manager: {
        getConnection: vi.fn().mockReturnValue(undefined),
      },
      lifecycle: {},
      toolMetadata: new Map(),
      config: {
        mcpServers: {
          demo: {
            url: "https://api.example.com/mcp",
            auth: { type: "oauth" },
          },
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
    markServerNeedsAuth(state, "demo", { reason: "reconnect", message: "needs auth" });

    const custom = vi.fn((renderer, options) => {
      renderer({} as never, {} as never, {} as never, vi.fn());
      expect(options).toEqual({ overlay: true, overlayOptions: { anchor: "center", width: 82 } });
    });

    const ctx = {
      hasUI: true,
      ui: {
        custom,
        notify: vi.fn(),
      },
    } as unknown as ExtensionContext;
    const pi = {
      getFlag: vi.fn().mockReturnValue(undefined),
    } as unknown as ExtensionAPI;

    await openMcpPanel(state, pi, ctx);

    expect(custom).toHaveBeenCalledTimes(1);
    expect(createMcpPanel).toHaveBeenCalledTimes(1);
  });
});
