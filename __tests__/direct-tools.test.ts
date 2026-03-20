import { describe, expect, it, vi } from "vitest";
import { InvalidAuthCallbackError } from "../auth-session-manager.js";
import type { MetadataCache } from "../metadata-cache.js";
import type { McpExtensionState } from "../state.js";
import type { McpConfig } from "../types.js";
import type { McpServerManager } from "../server-manager.js";

const loadMetadataCache = vi.fn(() => ({ version: 1, servers: {} }));
const saveMetadataCache = vi.fn();

vi.mock("../metadata-cache.js", async () => {
  const actual = await vi.importActual<typeof import("../metadata-cache.js")>(
    "../metadata-cache.js",
  );
  return {
    ...actual,
    loadMetadataCache,
    saveMetadataCache,
  };
});

describe("direct-tools", () => {
  it("documents the ui-messages action", async () => {
    const { buildProxyDescription } = await import("../direct-tools.js");
    const config: McpConfig = {
      mcpServers: {
        demo: {
          command: "npx",
          args: ["-y", "demo-server"],
        },
      },
    };

    const cache: MetadataCache = {
      version: 1,
      servers: {
        demo: {
          configHash: "hash",
          cachedAt: Date.now(),
          tools: [
            {
              name: "launch_app",
              description: "Launch the demo app",
              inputSchema: { type: "object", properties: {} },
            },
          ],
          resources: [],
        },
      },
    };

    const description = buildProxyDescription(config, cache, []);

    expect(description).toContain('mcp({ action: "ui-messages" })');
    expect(description).toContain(
      "Retrieve accumulated messages from completed UI sessions",
    );
  });

  it("preserves direct tool execution through auth-aware lazy connect", async () => {
    const { createDirectToolExecutor } = await import("../direct-tools.js");

    let connection:
      | {
          status: "connected";
          tools: Array<{
            name: string;
            description: string;
            inputSchema: unknown;
          }>;
          resources: [];
          client: {
            callTool: ReturnType<typeof vi.fn>;
          };
        }
      | undefined;

    const manager = {
      getConnection: vi.fn(() => connection),
      connect: vi.fn().mockImplementation(async () => {
        connection = {
          status: "connected",
          tools: [
            {
              name: "ping",
              description: "Ping directly",
              inputSchema: { type: "object", properties: {} },
            },
          ],
          resources: [],
          client: {
            callTool: vi.fn().mockResolvedValue({
              content: [{ type: "text", text: "pong" }],
            }),
          },
        };
        return connection;
      }),
      touch: vi.fn(),
      incrementInFlight: vi.fn(),
      decrementInFlight: vi.fn(),
    } as unknown as McpServerManager;

    const state = {
      manager,
      lifecycle: {},
      toolMetadata: new Map(),
      config: {
        mcpServers: {
          demo: {
            url: "https://api.example.com/mcp",
            auth: { type: "oauth" },
          },
        },
        settings: { toolPrefix: "server" },
      },
      failureTracker: new Map(),
      authRequirements: new Map(),
      uiResourceHandler: {},
      consentManager: {},
      uiServer: null,
      completedUiSessions: [],
      openBrowser: vi.fn().mockResolvedValue(undefined),
    } as unknown as McpExtensionState;

    const execute = createDirectToolExecutor(
      () => state,
      () => null,
      {
        serverName: "demo",
        originalName: "ping",
        prefixedName: "demo_ping",
        description: "Ping directly",
        inputSchema: { type: "object", properties: {} },
      },
    );

    const result = await execute("call-1", {});

    expect(manager.connect).toHaveBeenCalledWith(
      "demo",
      state.config.mcpServers.demo,
      {
        interactiveAllowed: true,
        interactionReason: "user",
      },
    );
    expect(connection?.client.callTool).toHaveBeenCalledWith({
      name: "ping",
      arguments: {},
      _meta: undefined,
    });
    expect(result.content).toEqual([{ type: "text", text: "pong" }]);
    expect(saveMetadataCache).toHaveBeenCalled();
  });

  it("returns needs-auth instead of generic unavailability after an interactive callback failure", async () => {
    const { createDirectToolExecutor } = await import("../direct-tools.js");

    const manager = {
      getConnection: vi.fn().mockReturnValue(undefined),
      connect: vi
        .fn()
        .mockRejectedValue(
          new InvalidAuthCallbackError(
            "OAuth callback returned error: access_denied code=secret-code&state=secret-state",
          ),
        ),
      touch: vi.fn(),
      incrementInFlight: vi.fn(),
      decrementInFlight: vi.fn(),
    } as unknown as McpServerManager;

    const state = {
      manager,
      lifecycle: {},
      toolMetadata: new Map(),
      config: {
        mcpServers: {
          demo: {
            url: "https://api.example.com/mcp",
            auth: { type: "oauth" },
          },
        },
        settings: { toolPrefix: "server" },
      },
      failureTracker: new Map(),
      authRequirements: new Map(),
      uiResourceHandler: {},
      consentManager: {},
      uiServer: null,
      completedUiSessions: [],
      openBrowser: vi.fn().mockResolvedValue(undefined),
    } as unknown as McpExtensionState;

    const execute = createDirectToolExecutor(
      () => state,
      () => null,
      {
        serverName: "demo",
        originalName: "ping",
        prefixedName: "demo_ping",
        description: "Ping directly",
        inputSchema: { type: "object", properties: {} },
      },
    );

    const result = await execute("call-1", {});

    expect(manager.connect).toHaveBeenCalledWith(
      "demo",
      state.config.mcpServers.demo,
      {
        interactiveAllowed: true,
        interactionReason: "user",
      },
    );
    expect(result.content).toEqual([
      {
        type: "text",
        text: 'MCP server "demo" needs authentication. Complete the browser flow and retry.',
      },
    ]);
    expect(result.details).toMatchObject({
      error: "needs_auth",
      server: "demo",
      message:
        'Browser sign-in callback for "demo" did not complete successfully. Retry authentication to continue.',
    });
    expect(JSON.stringify(result)).not.toContain("secret-code");
    expect(JSON.stringify(result)).not.toContain("secret-state");
    expect(JSON.stringify(result)).not.toContain("access_denied");
  });
});
