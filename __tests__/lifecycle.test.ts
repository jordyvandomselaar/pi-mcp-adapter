import { afterEach, describe, expect, it, vi } from "vitest";
import { InteractiveAuthorizationRequiredError } from "../auth-provider.js";
import { McpLifecycleManager } from "../lifecycle.js";
import type { ServerDefinition } from "../types.js";
import type { McpServerManager } from "../server-manager.js";

function createManager(overrides: Partial<McpServerManager> = {}): McpServerManager {
  return {
    getConnection: vi.fn().mockReturnValue(undefined),
    connect: vi.fn(),
    isIdle: vi.fn().mockReturnValue(false),
    close: vi.fn().mockResolvedValue(undefined),
    closeAll: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as unknown as McpServerManager;
}

describe("McpLifecycleManager", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("suppresses browser auth during keep-alive reconnects and reports needs-auth instead", async () => {
    vi.useFakeTimers();

    const definition: ServerDefinition = {
      url: "https://api.example.com/mcp",
      lifecycle: "keep-alive",
      auth: { type: "oauth" },
    };
    const authError = new InteractiveAuthorizationRequiredError({
      decision: {
        flow: "authorization_code",
        interactiveAllowed: false,
        reason: "reconnect",
        hasRefreshToken: false,
        canRefreshSilently: false,
        willAttemptBrowser: false,
        mode: "blocked",
        summary: "interactive auth disabled for reconnect",
      },
      serverUrl: definition.url!,
      serverName: "demo",
      fingerprint: "fp-demo",
    });

    const manager = createManager({
      connect: vi.fn().mockRejectedValue(authError),
    });
    const lifecycle = new McpLifecycleManager(manager);
    const onReconnect = vi.fn();
    const onAuthRequired = vi.fn();

    lifecycle.markKeepAlive("demo", definition);
    lifecycle.setReconnectCallback(onReconnect);
    lifecycle.setAuthRequiredCallback(onAuthRequired);
    lifecycle.startHealthChecks(1000);

    await vi.advanceTimersByTimeAsync(1000);

    expect(manager.connect).toHaveBeenCalledWith("demo", definition, {
      interactiveAllowed: false,
      interactionReason: "reconnect",
    });
    expect(onAuthRequired).toHaveBeenCalledTimes(1);
    expect(onAuthRequired).toHaveBeenCalledWith("demo", authError);
    expect(onReconnect).not.toHaveBeenCalled();

    await lifecycle.gracefulShutdown();
  });

  it("still closes idle non-keepalive servers during health checks", async () => {
    vi.useFakeTimers();

    const manager = createManager({
      isIdle: vi.fn().mockReturnValue(true),
    });
    const lifecycle = new McpLifecycleManager(manager);

    lifecycle.registerServer("lazy-demo", { command: "npx", args: ["demo"] }, { idleTimeout: 1 });
    lifecycle.startHealthChecks(1000);

    await vi.advanceTimersByTimeAsync(1000);

    expect(manager.close).toHaveBeenCalledWith("lazy-demo");

    await lifecycle.gracefulShutdown();
  });
});
