import { beforeEach, describe, expect, it, vi } from "vitest";
import { InteractiveAuthorizationRequiredError } from "../auth-provider.js";
import { InvalidAuthCallbackError } from "../auth-session-manager.js";
import {
  clearServerNeedsAuth,
  markServerNeedsAuth,
  type McpExtensionState,
} from "../state.js";
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

function createState(manager: McpServerManager): McpExtensionState {
  return {
    manager,
    lifecycle: {} as McpExtensionState["lifecycle"],
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
    uiResourceHandler: {} as McpExtensionState["uiResourceHandler"],
    consentManager: {} as McpExtensionState["consentManager"],
    uiServer: null,
    completedUiSessions: [],
    openBrowser: vi.fn().mockResolvedValue(undefined),
  };
}

describe("lazyConnect", () => {
  beforeEach(() => {
    loadMetadataCache.mockClear();
    saveMetadataCache.mockClear();
  });

  it("marks a server as needs-auth instead of failed when background auth is required", async () => {
    const authError = new InteractiveAuthorizationRequiredError({
      decision: {
        flow: "authorization_code",
        interactiveAllowed: false,
        reason: "startup",
        hasRefreshToken: false,
        canRefreshSilently: false,
        willAttemptBrowser: false,
        mode: "blocked",
        summary: "startup auth is blocked",
      },
      serverUrl: "https://api.example.com/mcp",
      serverName: "demo",
      fingerprint: "fp-demo",
    });

    const manager = {
      getConnection: vi.fn().mockReturnValue(undefined),
      connect: vi.fn().mockRejectedValue(authError),
    } as unknown as McpServerManager;

    const state = createState(manager);
    const { lazyConnect } = await import("../init.js");

    await expect(lazyConnect(state, "demo")).resolves.toBe(false);

    expect(state.authRequirements.get("demo")).toMatchObject({
      serverName: "demo",
      reason: "startup",
    });
    expect(state.failureTracker.has("demo")).toBe(false);
    expect(saveMetadataCache).not.toHaveBeenCalled();
  });

  it("keeps callback failures in needs-auth state without leaking raw OAuth callback details", async () => {
    const manager = {
      getConnection: vi.fn().mockReturnValue(undefined),
      connect: vi
        .fn()
        .mockRejectedValue(
          new InvalidAuthCallbackError(
            "OAuth callback returned error: access_denied code=secret-code&state=secret-state",
          ),
        ),
    } as unknown as McpServerManager;

    const state = createState(manager);
    const { lazyConnect } = await import("../init.js");

    await expect(lazyConnect(state, "demo")).resolves.toBe(false);

    expect(state.authRequirements.get("demo")).toMatchObject({
      serverName: "demo",
      reason: "user",
      message:
        'Browser sign-in callback for "demo" did not complete successfully. Retry authentication to continue.',
    });
    expect(state.failureTracker.has("demo")).toBe(false);
    expect(state.authRequirements.get("demo")?.message).not.toContain(
      "secret-code",
    );
    expect(state.authRequirements.get("demo")?.message).not.toContain(
      "secret-state",
    );
    expect(state.authRequirements.get("demo")?.message).not.toContain(
      "access_denied",
    );
    expect(saveMetadataCache).not.toHaveBeenCalled();
  });

  it("clears needs-auth and refreshes metadata cache after a successful user reconnect", async () => {
    let connection:
      | {
          status: "connected";
          tools: Array<{
            name: string;
            description: string;
            inputSchema: unknown;
          }>;
          resources: [];
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
              description: "Ping the service",
              inputSchema: { type: "object", properties: {} },
            },
          ],
          resources: [],
        };
        return connection;
      }),
    } as unknown as McpServerManager;

    const state = createState(manager);
    markServerNeedsAuth(state, "demo", {
      reason: "reconnect",
      message: "auth required",
    });
    state.failureTracker.set("demo", Date.now());

    const { lazyConnect } = await import("../init.js");
    await expect(lazyConnect(state, "demo")).resolves.toBe(true);

    expect(manager.connect).toHaveBeenCalledWith(
      "demo",
      state.config.mcpServers.demo,
      {
        interactiveAllowed: true,
        interactionReason: "user",
      },
    );
    expect(state.authRequirements.has("demo")).toBe(false);
    expect(state.failureTracker.has("demo")).toBe(false);
    expect(state.toolMetadata.get("demo")?.map((tool) => tool.name)).toEqual([
      "demo_ping",
    ]);
    expect(saveMetadataCache).toHaveBeenCalledWith(
      expect.objectContaining({
        version: 1,
        servers: expect.objectContaining({
          demo: expect.objectContaining({
            tools: [expect.objectContaining({ name: "ping" })],
          }),
        }),
      }),
    );

    clearServerNeedsAuth(state, "demo");
  });
});
