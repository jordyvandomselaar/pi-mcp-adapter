import { describe, expect, it, vi } from "vitest";
import { InvalidAuthCallbackError } from "../auth-session-manager.js";
import type { McpExtensionState } from "../state.js";
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

describe("executeCall", () => {
  it("preserves the single-proxy tool flow after auth-aware lazy connect", async () => {
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
              description: "Ping through the proxy",
              inputSchema: {
                type: "object",
                properties: { value: { type: "number" } },
              },
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

    const { executeCall } = await import("../proxy-modes.js");
    const result = await executeCall(state, "demo_ping", { value: 1 }, "demo");

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
      arguments: { value: 1 },
      _meta: undefined,
    });
    expect(result.content).toEqual([{ type: "text", text: "pong" }]);
    expect(saveMetadataCache).toHaveBeenCalled();
  });

  it("returns needs-auth instead of tool-not-found when lazy auth fails before metadata loads", async () => {
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

    const { executeCall } = await import("../proxy-modes.js");
    const result = await executeCall(state, "demo_ping", { value: 1 }, "demo");

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
        text: 'Server "demo" needs authentication. Complete the browser flow and retry.',
      },
    ]);
    expect(result.details).toMatchObject({
      mode: "call",
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
