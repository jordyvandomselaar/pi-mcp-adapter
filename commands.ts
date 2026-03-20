import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import type { AuthInteractionReason } from "./auth-provider.js";
import {
  clearServerNeedsAuth,
  isNeedsAuthError,
  markServerNeedsAuth,
  serverNeedsAuth,
  type McpExtensionState,
} from "./state.js";
import type { McpConfig, ServerEntry, McpPanelCallbacks, McpPanelResult, ServerDefinition } from "./types.js";
import { getOAuthAuthConfig, getServerAuthType } from "./types.js";
import {
  AuthSessionCancelledError,
  AuthSessionError,
  AuthSessionExpiredError,
  InvalidAuthCallbackError,
} from "./auth-session-manager.js";
import { getServerProvenance, writeDirectToolsConfig } from "./config.js";
import { updateMetadataCache, updateStatusBar, getFailureAgeSeconds } from "./init.js";
import { loadMetadataCache } from "./metadata-cache.js";
import { getStoredTokens } from "./oauth-handler.js";
import { buildToolMetadata } from "./tool-metadata.js";

interface ManagedConnectOptions {
  interactiveAllowed?: boolean;
  interactionReason?: AuthInteractionReason;
}

function connectWithPolicy(
  state: McpExtensionState,
  serverName: string,
  definition: ServerDefinition,
  options?: ManagedConnectOptions,
): Promise<Awaited<ReturnType<McpExtensionState["manager"]["connect"]>>> {
  const managed = state.manager as unknown as {
    connect: (
      name: string,
      serverDefinition: ServerDefinition,
      connectOptions?: ManagedConnectOptions,
    ) => Promise<Awaited<ReturnType<McpExtensionState["manager"]["connect"]>>>;
  };

  return managed.connect(serverName, definition, options);
}

interface IntentionalReconnectResult {
  connected: boolean;
  failedTools: number;
  message: string;
  level: "info" | "warning" | "error";
}

function usesInteractiveOAuth(definition: ServerDefinition | undefined): boolean {
  const oauth = definition ? getOAuthAuthConfig(definition) : undefined;
  if (!oauth) {
    return false;
  }

  return (oauth.grantType ?? "authorization_code") === "authorization_code";
}

function summarizeAuthSessionFailure(serverName: string, error: AuthSessionError): string {
  if (error instanceof AuthSessionCancelledError) {
    return `MCP: Browser sign-in for "${serverName}" was cancelled. Press Ctrl+R or run /mcp-auth ${serverName} to try again.`;
  }

  if (error instanceof AuthSessionExpiredError) {
    return `MCP: Browser sign-in for "${serverName}" expired before completion. Press Ctrl+R or run /mcp-auth ${serverName} to try again.`;
  }

  if (error instanceof InvalidAuthCallbackError) {
    return `MCP: Browser sign-in callback for "${serverName}" did not complete successfully. Press Ctrl+R or run /mcp-auth ${serverName} to try again.`;
  }

  return `MCP: Browser sign-in for "${serverName}" did not complete. Press Ctrl+R or run /mcp-auth ${serverName} to try again.`;
}

async function reconnectServerWithUserIntent(
  state: McpExtensionState,
  serverName: string,
  definition: ServerDefinition,
): Promise<IntentionalReconnectResult> {
  await state.manager.close(serverName);

  try {
    const connection = await connectWithPolicy(state, serverName, definition, {
      interactiveAllowed: true,
      interactionReason: "user",
    });
    const prefix = state.config.settings?.toolPrefix ?? "server";

    clearServerNeedsAuth(state, serverName);
    const { metadata, failedTools } = buildToolMetadata(connection.tools, connection.resources, definition, serverName, prefix);
    state.toolMetadata.set(serverName, metadata);
    updateMetadataCache(state, serverName);
    state.failureTracker.delete(serverName);

    return {
      connected: true,
      failedTools: failedTools.length,
      message: `MCP: Reconnected to ${serverName} (${connection.tools.length} tools, ${connection.resources.length} resources)`,
      level: "info",
    };
  } catch (error) {
    if (isNeedsAuthError(error)) {
      state.failureTracker.delete(serverName);
      markServerNeedsAuth(state, serverName, {
        error,
        reason: "user",
        message: error instanceof Error ? error.message : String(error),
      });
      return {
        connected: false,
        failedTools: 0,
        message: `MCP: ${serverName} needs authentication. Continue or restart the browser sign-in flow, then retry.`,
        level: "warning",
      };
    }

    if (error instanceof AuthSessionError) {
      const message = summarizeAuthSessionFailure(serverName, error);
      state.failureTracker.delete(serverName);
      markServerNeedsAuth(state, serverName, { reason: "user", message });
      return {
        connected: false,
        failedTools: 0,
        message,
        level: "warning",
      };
    }

    const message = error instanceof Error ? error.message : String(error);
    state.failureTracker.set(serverName, Date.now());
    return {
      connected: false,
      failedTools: 0,
      message: `MCP: Failed to reconnect to ${serverName}: ${message}`,
      level: "error",
    };
  }
}

export async function showStatus(state: McpExtensionState, ctx: ExtensionContext): Promise<void> {
  if (!ctx.hasUI) return;

  const lines: string[] = ["MCP Server Status:", ""];

  for (const name of Object.keys(state.config.mcpServers)) {
    const connection = state.manager.getConnection(name);
    const metadata = state.toolMetadata.get(name);
    const toolCount = metadata?.length ?? 0;
    const failedAgo = getFailureAgeSeconds(state, name);
    let status = "not connected";
    let statusIcon = "○";
    let failed = false;

    if (connection?.status === "connected") {
      status = "connected";
      statusIcon = "✓";
    } else if (serverNeedsAuth(state, name)) {
      status = "needs auth";
      statusIcon = "!";
    } else if (failedAgo !== null) {
      status = `failed ${failedAgo}s ago`;
      statusIcon = "✗";
      failed = true;
    } else if (metadata !== undefined) {
      status = "cached";
    }

    const toolSuffix = failed ? "" : ` (${toolCount} tools${status === "cached" ? ", cached" : ""})`;
    lines.push(`${statusIcon} ${name}: ${status}${toolSuffix}`);
  }

  if (Object.keys(state.config.mcpServers).length === 0) {
    lines.push("No MCP servers configured");
  }

  ctx.ui.notify(lines.join("\n"), "info");
}

export async function showTools(state: McpExtensionState, ctx: ExtensionContext): Promise<void> {
  if (!ctx.hasUI) return;

  const allTools = [...state.toolMetadata.values()].flat().map(m => m.name);

  if (allTools.length === 0) {
    ctx.ui.notify("No MCP tools available", "info");
    return;
  }

  const lines = [
    "MCP Tools:",
    "",
    ...allTools.map(t => `  ${t}`),
    "",
    `Total: ${allTools.length} tools`,
  ];

  ctx.ui.notify(lines.join("\n"), "info");
}

export async function reconnectServers(
  state: McpExtensionState,
  ctx: ExtensionContext,
  targetServer?: string
): Promise<void> {
  if (targetServer && !state.config.mcpServers[targetServer]) {
    if (ctx.hasUI) {
      ctx.ui.notify(`Server "${targetServer}" not found in config`, "error");
    }
    return;
  }

  const entries = targetServer
    ? [[targetServer, state.config.mcpServers[targetServer]] as [string, ServerEntry]]
    : Object.entries(state.config.mcpServers);

  for (const [name, definition] of entries) {
    const result = await reconnectServerWithUserIntent(state, name, definition);

    if (ctx.hasUI) {
      ctx.ui.notify(result.message, result.level);
      if (result.connected && result.failedTools > 0) {
        ctx.ui.notify(`MCP: ${name} - ${result.failedTools} tools skipped`, "warning");
      }
    }
  }

  updateStatusBar(state);
}

export async function authenticateServer(
  serverName: string,
  config: McpConfig,
  ctx: ExtensionContext
): Promise<void> {
  if (!ctx.hasUI) return;

  const definition = config.mcpServers[serverName];
  if (!definition) {
    ctx.ui.notify(`Server "${serverName}" not found in config`, "error");
    return;
  }

  const authType = getServerAuthType(definition);

  if (authType !== "oauth") {
    ctx.ui.notify(
      `Server "${serverName}" does not use OAuth authentication.\n` +
      `Current auth mode: ${authType ?? "none"}`,
      "error"
    );
    return;
  }

  if (!definition.url) {
    ctx.ui.notify(
      `Server "${serverName}" has no URL configured (OAuth requires HTTP transport)`,
      "error"
    );
    return;
  }

  const tokenPath = `~/.pi/agent/mcp-oauth/${serverName}/tokens.json`;

  ctx.ui.notify(
    `OAuth setup for "${serverName}":\n\n` +
    `1. Obtain an access token from your OAuth provider\n` +
    `2. Create the token file:\n` +
    `   ${tokenPath}\n\n` +
    `3. Add your token:\n` +
    `   {\n` +
    `     "access_token": "your-token-here",\n` +
    `     "token_type": "bearer"\n` +
    `   }\n\n` +
    `4. Run /mcp reconnect to connect with the token`,
    "info"
  );
}

export async function openMcpPanel(
  state: McpExtensionState,
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  configOverridePath?: string,
): Promise<void> {
  const config = state.config;
  const cache = loadMetadataCache();
  const provenanceMap = getServerProvenance(pi.getFlag("mcp-config") as string | undefined ?? configOverridePath);

  const callbacks: McpPanelCallbacks = {
    reconnect: async (serverName: string) => {
      const definition = config.mcpServers[serverName];
      if (!definition) {
        if (ctx.hasUI) {
          ctx.ui.notify(`Server "${serverName}" not found in config`, "error");
        }
        return false;
      }

      const result = await reconnectServerWithUserIntent(state, serverName, definition);
      updateStatusBar(state);
      if (ctx.hasUI) {
        ctx.ui.notify(result.message, result.level);
        if (result.connected && result.failedTools > 0) {
          ctx.ui.notify(`MCP: ${serverName} - ${result.failedTools} tools skipped`, "warning");
        }
      }
      return result.connected;
    },
    getConnectionStatus: (serverName: string) => {
      const definition = config.mcpServers[serverName];
      const connection = state.manager.getConnection(serverName);
      if (connection?.status === "connected") return "connected";
      if (serverNeedsAuth(state, serverName)) return "needs-auth";
      if (usesInteractiveOAuth(definition) && getStoredTokens(serverName, definition) === undefined) {
        return "needs-auth";
      }
      if (getFailureAgeSeconds(state, serverName) !== null) return "failed";
      return "idle";
    },
    refreshCacheAfterReconnect: (serverName: string) => {
      const freshCache = loadMetadataCache();
      return freshCache?.servers?.[serverName] ?? null;
    },
  };

  const { createMcpPanel } = await import("./mcp-panel.js");

  return new Promise<void>((resolve) => {
    ctx.ui.custom(
      (tui, _theme, _keybindings, done) => {
        return createMcpPanel(config, cache, provenanceMap, callbacks, tui, (result: McpPanelResult) => {
          if (!result.cancelled && result.changes.size > 0) {
            writeDirectToolsConfig(result.changes, provenanceMap, config);
            ctx.ui.notify("Direct tools updated. Restart pi to apply.", "info");
          }
          done();
          resolve();
        });
      },
      { overlay: true, overlayOptions: { anchor: "center", width: 82 } },
    );
  });
}
