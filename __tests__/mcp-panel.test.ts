import { describe, expect, it, vi } from "vitest";
import type { MetadataCache, ServerCacheEntry } from "../metadata-cache.js";
import type { McpConfig, McpPanelCallbacks } from "../types.js";

vi.mock("@mariozechner/pi-tui", () => ({
  matchesKey: (data: string, key: string) => {
    switch (key) {
      case "return":
        return data === "\n" || data === "\r";
      case "ctrl+r":
        return data === "\x12";
      case "ctrl+c":
        return data === "\x03";
      case "ctrl+s":
        return data === "\x13";
      case "escape":
        return data === "\x1b";
      case "backspace":
        return data === "\x7f";
      case "space":
        return data === " ";
      case "up":
        return data === "\u001b[A";
      case "down":
        return data === "\u001b[B";
      case "left":
        return data === "\u001b[D";
      case "right":
        return data === "\u001b[C";
      case "tab":
        return data === "\t";
      default:
        return false;
    }
  },
  truncateToWidth: (text: string, width: number) => text.length <= width ? text.padEnd(width, " ") : `${text.slice(0, Math.max(0, width - 1))}…`,
  visibleWidth: (text: string) => text.replace(/\x1b\[[0-9;]*m/g, "").length,
}));

function stripAnsi(text: string): string {
  return text.replace(/\x1b\[[0-9;]*m/g, "");
}

function renderText(panel: { render(width: number): string[] }): string {
  return stripAnsi(panel.render(220).join("\n"));
}

function flushPromises(): Promise<void> {
  return Promise.resolve().then(() => undefined);
}

async function createPanel(options: {
  statusByServer: Record<string, "connected" | "idle" | "failed" | "needs-auth">;
  reconnect?: McpPanelCallbacks["reconnect"];
  refreshCacheAfterReconnect?: McpPanelCallbacks["refreshCacheAfterReconnect"];
  cache?: MetadataCache;
  config?: McpConfig;
}) {
  const config: McpConfig = options.config ?? {
    mcpServers: {
      demo: {
        url: "https://api.example.com/mcp",
        auth: { type: "oauth" },
      },
    },
  };

  const cache: MetadataCache = options.cache ?? {
    version: 1,
    servers: {
      demo: {
        configHash: "hash-demo",
        cachedAt: Date.now(),
        tools: [
          {
            name: "ping",
            description: "Ping the demo server",
            inputSchema: { type: "object", properties: {} },
          },
        ],
        resources: [],
      },
    },
  };

  const callbacks: McpPanelCallbacks = {
    reconnect: options.reconnect ?? vi.fn(async () => true),
    getConnectionStatus: (serverName) => options.statusByServer[serverName] ?? "idle",
    refreshCacheAfterReconnect: options.refreshCacheAfterReconnect ?? (() => cache.servers.demo as ServerCacheEntry),
  };

  const { createMcpPanel } = await import("../mcp-panel.js");

  const panel = createMcpPanel(
    config,
    cache,
    new Map(),
    callbacks,
    { requestRender: vi.fn() },
    vi.fn(),
  ) as unknown as {
    handleInput(data: string): void;
    render(width: number): string[];
    dispose(): void;
  };

  return { panel, callbacks };
}

describe("createMcpPanel auth UX", () => {
  it("renders needs-auth state and gives an intentional browser-auth hint", async () => {
    const { panel } = await createPanel({
      statusByServer: { demo: "needs-auth" },
    });

    try {
      expect(renderText(panel)).toContain("[needs auth]");

      panel.handleInput("\n");

      expect(renderText(panel)).toContain(
        "Auth required — Ctrl+R starts browser sign-in. Background reconnects stay no-browser.",
      );
    } finally {
      panel.dispose();
    }
  });

  it("shows flow-specific auth copy for client_credentials servers", async () => {
    const { panel } = await createPanel({
      statusByServer: { machine: "needs-auth" },
      config: {
        mcpServers: {
          machine: {
            url: "https://machine.example.com/mcp",
            auth: { type: "oauth", grantType: "client_credentials" },
          },
        },
      },
      cache: {
        version: 1,
        servers: {
          machine: {
            configHash: "hash-machine",
            cachedAt: Date.now(),
            tools: [
              {
                name: "sync",
                description: "Sync machine credentials",
                inputSchema: { type: "object", properties: {} },
              },
            ],
            resources: [],
          },
        },
      },
    });

    try {
      const initial = renderText(panel);
      expect(initial).toContain("machine (client credentials)");
      expect(initial).toContain("[needs auth]");

      panel.handleInput("\n");
      expect(renderText(panel)).toContain(
        "Auth required — Ctrl+R retries non-interactive client_credentials. No browser will open.",
      );
    } finally {
      panel.dispose();
    }
  });

  it("refreshes server status and cached tools after an intentional reconnect", async () => {
    const statusByServer: Record<string, "connected" | "needs-auth"> = { demo: "needs-auth" };
    const reconnect = vi.fn(async () => {
      statusByServer.demo = "connected";
      return true;
    });
    const refreshedEntry: ServerCacheEntry = {
      configHash: "hash-demo-2",
      cachedAt: Date.now(),
      tools: [
        {
          name: "ping_after_auth",
          description: "Ping after interactive auth",
          inputSchema: { type: "object", properties: {} },
        },
      ],
      resources: [],
    };

    const { panel } = await createPanel({
      statusByServer,
      reconnect,
      refreshCacheAfterReconnect: () => refreshedEntry,
      cache: {
        version: 1,
        servers: {},
      },
    });

    try {
      expect(renderText(panel)).toContain("[needs auth]");
      expect(renderText(panel)).toContain("(not cached)");

      panel.handleInput("\x12");
      await flushPromises();

      const afterReconnect = renderText(panel);
      expect(reconnect).toHaveBeenCalledWith("demo");
      expect(afterReconnect).toContain("[connected]");
      expect(afterReconnect).toContain("Connected to demo.");

      panel.handleInput("\n");
      expect(renderText(panel)).toContain("ping_after_auth");
    } finally {
      panel.dispose();
    }
  });
});
