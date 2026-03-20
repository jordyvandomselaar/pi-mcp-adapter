import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpExtensionState } from "../state.js";

const startUiServer = vi.fn();
const isGlimpseAvailable = vi.fn(() => false);
const openGlimpseWindow = vi.fn();

vi.mock("../ui-server.js", () => ({
  startUiServer,
}));

vi.mock("../glimpse-ui.js", () => ({
  isGlimpseAvailable,
  openGlimpseWindow,
}));

function createState(): McpExtensionState {
  return {
    manager: {
      registerUiStreamListener: vi.fn(),
      removeUiStreamListener: vi.fn(),
    } as unknown as McpExtensionState["manager"],
    lifecycle: {} as McpExtensionState["lifecycle"],
    toolMetadata: new Map(),
    config: { mcpServers: {} },
    failureTracker: new Map(),
    authRequirements: new Map(),
    uiResourceHandler: {
      readUiResource: vi.fn().mockResolvedValue({
        uri: "ui://demo/app",
        html: "<div>demo</div>",
        mimeType: "text/html",
        meta: {},
      }),
    } as unknown as McpExtensionState["uiResourceHandler"],
    consentManager: {} as McpExtensionState["consentManager"],
    uiServer: null,
    completedUiSessions: [],
    openBrowser: vi.fn().mockResolvedValue(undefined),
    ui: {
      notify: vi.fn(),
    } as unknown as McpExtensionState["ui"],
    sendMessage: vi.fn(),
  };
}

describe("maybeStartUiSession", () => {
  const originalViewer = process.env.MCP_UI_VIEWER;

  beforeEach(() => {
    startUiServer.mockReset();
    isGlimpseAvailable.mockReset();
    openGlimpseWindow.mockReset();
    isGlimpseAvailable.mockReturnValue(false);
    delete process.env.MCP_UI_VIEWER;

    startUiServer.mockResolvedValue({
      serverName: "demo",
      toolName: "launch_app",
      url: "http://127.0.0.1:4010/?session=demo",
      sendToolInput: vi.fn(),
      sendToolResult: vi.fn(),
      sendResultPatch: vi.fn(),
      sendToolCancelled: vi.fn(),
      close: vi.fn(),
      getSessionMessages: vi.fn(() => ({ prompts: [], notifications: [], intents: [] })),
      getStreamSummary: vi.fn(() => undefined),
    });
  });

  afterEach(() => {
    if (originalViewer === undefined) {
      delete process.env.MCP_UI_VIEWER;
    } else {
      process.env.MCP_UI_VIEWER = originalViewer;
    }
  });

  it("falls back to the Pi browser opener and forwards UI prompts back into Pi", async () => {
    const state = createState();
    const { maybeStartUiSession } = await import("../ui-session.js");

    const session = await maybeStartUiSession(state, {
      serverName: "demo",
      toolName: "launch_app",
      toolArgs: { mode: "interactive" },
      uiResourceUri: "ui://demo/app",
    });

    expect(session).not.toBeNull();
    expect(startUiServer).toHaveBeenCalledTimes(1);
    expect(state.openBrowser).toHaveBeenCalledWith("http://127.0.0.1:4010/?session=demo");

    const options = startUiServer.mock.calls[0][0];
    options.onMessage({ type: "prompt", prompt: "Analyze this chart" });

    expect(state.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        customType: "mcp-ui-prompt",
        display: "💬 UI Prompt: Analyze this chart",
        details: expect.objectContaining({
          server: "demo",
          tool: "launch_app",
          prompt: "Analyze this chart",
        }),
      }),
      { triggerTurn: true },
    );
  });

  it("opens a Glimpse window when requested and avoids the browser fallback", async () => {
    process.env.MCP_UI_VIEWER = "glimpse";
    isGlimpseAvailable.mockReturnValue(true);
    openGlimpseWindow.mockResolvedValue({ close: vi.fn() });

    const state = createState();
    const { maybeStartUiSession } = await import("../ui-session.js");

    const session = await maybeStartUiSession(state, {
      serverName: "demo",
      toolName: "launch_app",
      toolArgs: {},
      uiResourceUri: "ui://demo/app",
    });

    expect(session).not.toBeNull();
    expect(openGlimpseWindow).toHaveBeenCalledTimes(1);
    expect(openGlimpseWindow).toHaveBeenCalledWith(
      expect.stringContaining('<iframe src="http://127.0.0.1:4010/?session=demo"></iframe>'),
      expect.objectContaining({
        title: "MCP · demo · launch_app",
        width: 1000,
        height: 800,
      }),
    );
    expect(state.openBrowser).not.toHaveBeenCalled();
  });
});
