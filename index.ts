import type { ExtensionAPI, ExtensionContext, ToolInfo } from "@mariozechner/pi-coding-agent";
import type { McpExtensionState } from "./state.js";
import { Type } from "@sinclair/typebox";
import { showStatus, showTools, reconnectServers, authenticateServer, openMcpPanel, showAuthOverview } from "./commands.js";
import { loadMcpConfig } from "./config.js";
import { buildProxyDescription, createDirectToolExecutor, resolveDirectTools } from "./direct-tools.js";
import { flushMetadataCache, initializeMcp, updateStatusBar } from "./init.js";
import { loadMetadataCache } from "./metadata-cache.js";
import { executeCall, executeConnect, executeDescribe, executeList, executeSearch, executeStatus, executeUiMessages } from "./proxy-modes.js";
import { getConfigPathFromArgv } from "./utils.js";

function buildAuthCommandHelp(commandPrefix: "/mcp auth" | "/mcp-auth"): string {
  return [
    "Usage:",
    `  ${commandPrefix}           Show auth status, flow, registration strategy, and storage hints for configured MCP servers`,
    `  ${commandPrefix} status    Show the same auth status summary`,
    `  ${commandPrefix} <server>  Start or retry auth/token exchange for one OAuth-configured HTTP server`,
    "",
    "Notes:",
    "  authorization_code reuses stored tokens and silent refresh first, then opens your system browser if sign-in is still required.",
    "  The browser flow completes through a 127.0.0.1 loopback callback and Pi stores tokens, client registration, and callback state under ~/.pi/agent/mcp-auth.",
    "  client_credentials stays non-interactive. Background reconnects never open a browser.",
    commandPrefix === "/mcp-auth"
      ? "  Prefer /mcp auth for new usage; /mcp-auth remains a compatibility alias."
      : "  /mcp-auth remains a compatibility alias for the same flow.",
  ].join("\n");
}

export default function mcpAdapter(pi: ExtensionAPI) {
  let state: McpExtensionState | null = null;
  let initPromise: Promise<McpExtensionState> | null = null;

  const earlyConfigPath = getConfigPathFromArgv();
  const earlyConfig = loadMcpConfig(earlyConfigPath);
  const earlyCache = loadMetadataCache();
  const prefix = earlyConfig.settings?.toolPrefix ?? "server";

  const envRaw = process.env.MCP_DIRECT_TOOLS;
  const directSpecs = envRaw === "__none__"
    ? []
    : resolveDirectTools(
        earlyConfig,
        earlyCache,
        prefix,
        envRaw?.split(",").map(s => s.trim()).filter(Boolean),
      );

  for (const spec of directSpecs) {
    pi.registerTool({
      name: spec.prefixedName,
      label: `MCP: ${spec.originalName}`,
      description: spec.description || "(no description)",
      parameters: Type.Unsafe<Record<string, unknown>>(spec.inputSchema || { type: "object", properties: {} }),
      execute: createDirectToolExecutor(() => state, () => initPromise, spec),
    });
  }

  const getPiTools = (): ToolInfo[] => pi.getAllTools();

  pi.registerFlag("mcp-config", {
    description: "Path to MCP config file",
    type: "string",
  });

  pi.on("session_start", async (_event, ctx) => {
    initPromise = initializeMcp(pi, ctx);

    initPromise.then(s => {
      state = s;
      initPromise = null;
      updateStatusBar(s);
    }).catch(err => {
      console.error("MCP initialization failed:", err);
      initPromise = null;
    });
  });

  pi.on("session_shutdown", async () => {
    if (initPromise) {
      try {
        state = await initPromise;
      } catch {
        // Initialization failed, nothing to clean up
      }
    }

    if (state) {
      if (state.uiServer) {
        state.uiServer.close("session_shutdown");
        state.uiServer = null;
      }
      flushMetadataCache(state);
      await state.lifecycle.gracefulShutdown();
      state = null;
    }
  });

  pi.registerCommand("mcp", {
    description: "Show the MCP panel/status, manage auth, and reconnect MCP servers",
    handler: async (args, ctx) => {
      if (!state && initPromise) {
        try {
          state = await initPromise;
        } catch {
          if (ctx.hasUI) ctx.ui.notify("MCP initialization failed", "error");
          return;
        }
      }
      if (!state) {
        if (ctx.hasUI) ctx.ui.notify("MCP not initialized", "error");
        return;
      }

      const parts = args?.trim()?.split(/\s+/) ?? [];
      const subcommand = parts[0] ?? "";
      const targetServer = parts[1];

      switch (subcommand) {
        case "reconnect":
          await reconnectServers(state, ctx, targetServer);
          break;
        case "tools":
          await showTools(state, ctx);
          break;
        case "auth":
          if (!targetServer || (targetServer === "status" && !state.config.mcpServers.status)) {
            await showAuthOverview(state, ctx);
            break;
          }

          if (targetServer === "help" && !state.config.mcpServers.help) {
            if (ctx.hasUI) {
              ctx.ui.notify(buildAuthCommandHelp("/mcp auth"), "info");
            }
            break;
          }

          await authenticateServer(state, targetServer, ctx);
          break;
        case "status":
        case "":
        default:
          if (ctx.hasUI) {
            await openMcpPanel(state, pi, ctx, earlyConfigPath);
          } else {
            await showStatus(state, ctx);
          }
          break;
      }
    },
  });

  pi.registerCommand("mcp-auth", {
    description: "Show MCP auth status or start auth for a specific OAuth server",
    handler: async (args, ctx) => {
      if (!state && initPromise) {
        try {
          state = await initPromise;
        } catch {
          if (ctx.hasUI) ctx.ui.notify("MCP initialization failed", "error");
          return;
        }
      }
      if (!state) {
        if (ctx.hasUI) ctx.ui.notify("MCP not initialized", "error");
        return;
      }

      const value = args?.trim() ?? "";
      if (!value || (value === "status" && !state.config.mcpServers.status)) {
        await showAuthOverview(state, ctx);
        return;
      }

      if (value === "help" && !state.config.mcpServers.help) {
        if (ctx.hasUI) {
          ctx.ui.notify(buildAuthCommandHelp("/mcp-auth"), "info");
        }
        return;
      }

      await authenticateServer(state, value, ctx);
    },
  });

  pi.registerTool({
    name: "mcp",
    label: "MCP",
    description: buildProxyDescription(earlyConfig, earlyCache, directSpecs),
    parameters: Type.Object({
      tool: Type.Optional(Type.String({ description: "Tool name to call (e.g., 'xcodebuild_list_sims')" })),
      args: Type.Optional(Type.String({ description: "Arguments as JSON string (e.g., '{\"key\": \"value\"}')" })),
      connect: Type.Optional(Type.String({ description: "Server name to connect (lazy connect + metadata refresh)" })),
      describe: Type.Optional(Type.String({ description: "Tool name to describe (shows parameters)" })),
      search: Type.Optional(Type.String({ description: "Search tools by name/description" })),
      regex: Type.Optional(Type.Boolean({ description: "Treat search as regex (default: substring match)" })),
      includeSchemas: Type.Optional(Type.Boolean({ description: "Include parameter schemas in search results (default: true)" })),
      server: Type.Optional(Type.String({ description: "Filter to specific server (also disambiguates tool calls)" })),
      action: Type.Optional(Type.String({ description: "Action: 'ui-messages' to retrieve prompts/intents from UI sessions" })),
    }),
    async execute(_toolCallId, params: {
      tool?: string;
      args?: string;
      connect?: string;
      describe?: string;
      search?: string;
      regex?: boolean;
      includeSchemas?: boolean;
      server?: string;
      action?: string;
    }, _signal, _onUpdate, _ctx) {
      let parsedArgs: Record<string, unknown> | undefined;
      if (params.args) {
        try {
          parsedArgs = JSON.parse(params.args);
          if (typeof parsedArgs !== "object" || parsedArgs === null || Array.isArray(parsedArgs)) {
            const gotType = Array.isArray(parsedArgs) ? "array" : parsedArgs === null ? "null" : typeof parsedArgs;
            return {
              content: [{ type: "text" as const, text: `Invalid args: expected a JSON object, got ${gotType}` }],
              isError: true,
              details: { error: "invalid_args_type" },
            };
          }
        } catch (e) {
          return {
            content: [{ type: "text" as const, text: `Invalid args JSON: ${e instanceof Error ? e.message : e}` }],
            isError: true,
            details: { error: "invalid_args" },
          };
        }
      }

      if (!state && initPromise) {
        try {
          state = await initPromise;
        } catch {
          return {
            content: [{ type: "text" as const, text: "MCP initialization failed" }],
            details: { error: "init_failed" },
          };
        }
      }
      if (!state) {
        return {
          content: [{ type: "text" as const, text: "MCP not initialized" }],
          details: { error: "not_initialized" },
        };
      }

      if (params.action === "ui-messages") {
        return executeUiMessages(state);
      }
      if (params.tool) {
        return executeCall(state, params.tool, parsedArgs, params.server);
      }
      if (params.connect) {
        return executeConnect(state, params.connect);
      }
      if (params.describe) {
        return executeDescribe(state, params.describe);
      }
      if (params.search) {
        return executeSearch(state, params.search, params.regex, params.server, params.includeSchemas, getPiTools);
      }
      if (params.server) {
        return executeList(state, params.server);
      }
      return executeStatus(state);
    },
  });
}
