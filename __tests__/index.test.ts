import { afterEach, describe, expect, it, vi } from "vitest";
import type { McpExtensionState } from "../state.js";

const {
  showStatus,
  showTools,
  reconnectServers,
  authenticateServer,
  openMcpPanel,
  showAuthOverview,
  initializeMcp,
  updateStatusBar,
} = vi.hoisted(() => ({
  showStatus: vi.fn(),
  showTools: vi.fn(),
  reconnectServers: vi.fn(),
  authenticateServer: vi.fn(),
  openMcpPanel: vi.fn(),
  showAuthOverview: vi.fn(),
  initializeMcp: vi.fn(),
  updateStatusBar: vi.fn(),
}));

vi.mock("../commands.js", () => ({
  showStatus,
  showTools,
  reconnectServers,
  authenticateServer,
  openMcpPanel,
  showAuthOverview,
}));

vi.mock("../config.js", () => ({
  loadMcpConfig: vi.fn(() => ({ mcpServers: {}, settings: {} })),
}));

vi.mock("../direct-tools.js", () => ({
  buildProxyDescription: vi.fn(() => "proxy description"),
  createDirectToolExecutor: vi.fn(() => vi.fn()),
  resolveDirectTools: vi.fn(() => []),
}));

vi.mock("../init.js", () => ({
  flushMetadataCache: vi.fn(),
  initializeMcp,
  updateStatusBar,
}));

vi.mock("../metadata-cache.js", () => ({
  loadMetadataCache: vi.fn(() => ({ version: 1, servers: {} })),
}));

vi.mock("../proxy-modes.js", () => ({
  executeCall: vi.fn(),
  executeConnect: vi.fn(),
  executeDescribe: vi.fn(),
  executeList: vi.fn(),
  executeSearch: vi.fn(),
  executeStatus: vi.fn(),
  executeUiMessages: vi.fn(),
}));

vi.mock("../utils.js", () => ({
  getConfigPathFromArgv: vi.fn(() => undefined),
}));

function createState(): McpExtensionState {
  return {
    manager: {} as McpExtensionState["manager"],
    lifecycle: { gracefulShutdown: vi.fn() } as McpExtensionState["lifecycle"],
    toolMetadata: new Map(),
    config: { mcpServers: {} },
    failureTracker: new Map(),
    authRequirements: new Map(),
    uiResourceHandler: {} as McpExtensionState["uiResourceHandler"],
    consentManager: {} as McpExtensionState["consentManager"],
    uiServer: null,
    completedUiSessions: [],
    openBrowser: vi.fn().mockResolvedValue(undefined),
  };
}

function createPiHarness() {
  const commands = new Map<string, { description: string; handler: (args: string | undefined, ctx: any) => Promise<void> }>();
  const eventHandlers = new Map<string, (event: unknown, ctx: any) => Promise<void>>();

  const pi = {
    registerTool: vi.fn(),
    registerFlag: vi.fn(),
    registerCommand: vi.fn((name: string, config: { description: string; handler: (args: string | undefined, ctx: any) => Promise<void> }) => {
      commands.set(name, config);
    }),
    getAllTools: vi.fn(() => []),
    getFlag: vi.fn(() => undefined),
    on: vi.fn((event: string, handler: (event: unknown, ctx: any) => Promise<void>) => {
      eventHandlers.set(event, handler);
    }),
    sendMessage: vi.fn(),
  };

  return { pi, commands, eventHandlers };
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("mcp command auth routing", () => {
  it("routes /mcp auth to the new auth UX while keeping /mcp-auth as compatibility", async () => {
    const state = createState();
    initializeMcp.mockResolvedValue(state);

    const { default: mcpAdapter } = await import("../index.js");
    const { pi, commands, eventHandlers } = createPiHarness();
    mcpAdapter(pi as never);

    const mcp = commands.get("mcp");
    expect(mcp).toBeTruthy();
    expect(mcp?.description).toBe("Show the MCP panel/status, manage auth, and reconnect MCP servers");

    const ctx = {
      hasUI: true,
      ui: {
        notify: vi.fn(),
      },
    };

    const sessionStart = eventHandlers.get("session_start");
    expect(sessionStart).toBeTruthy();
    await sessionStart?.({}, ctx);
    await Promise.resolve();
    await Promise.resolve();

    await mcp?.handler("auth", ctx);
    expect(showAuthOverview).toHaveBeenCalledWith(state, ctx);

    await mcp?.handler("auth status", ctx);
    expect(showAuthOverview).toHaveBeenCalledTimes(2);

    await mcp?.handler("auth help", ctx);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("/mcp auth <server>  Start or retry auth/token exchange for one OAuth-configured server"),
      "info",
    );

    await mcp?.handler("auth demo", ctx);
    expect(authenticateServer).toHaveBeenCalledWith(state, "demo", ctx);
  });
});

describe("mcp-auth command registration", () => {
  it("registers status/help semantics and routes auth requests", async () => {
    const state = createState();
    initializeMcp.mockResolvedValue(state);

    const { default: mcpAdapter } = await import("../index.js");
    const { pi, commands, eventHandlers } = createPiHarness();
    mcpAdapter(pi as never);

    const mcpAuth = commands.get("mcp-auth");
    expect(mcpAuth).toBeTruthy();
    expect(mcpAuth?.description).toBe("Show MCP auth status or start auth for a specific OAuth server");

    const ctx = {
      hasUI: true,
      ui: {
        notify: vi.fn(),
      },
    };

    const sessionStart = eventHandlers.get("session_start");
    expect(sessionStart).toBeTruthy();
    await sessionStart?.({}, ctx);
    await Promise.resolve();
    await Promise.resolve();

    await mcpAuth?.handler(undefined, ctx);
    expect(showAuthOverview).toHaveBeenCalledWith(state, ctx);

    await mcpAuth?.handler("status", ctx);
    expect(showAuthOverview).toHaveBeenCalledTimes(2);

    await mcpAuth?.handler("help", ctx);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("/mcp-auth <server>  Start or retry auth for one OAuth-configured server"),
      "info",
    );

    await mcpAuth?.handler("demo", ctx);
    expect(authenticateServer).toHaveBeenCalledWith(state, "demo", ctx);
    expect(updateStatusBar).toHaveBeenCalledWith(state);
  });
});
