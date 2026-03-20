import type {
  ExtensionAPI,
  ExtensionContext,
} from "@mariozechner/pi-coding-agent";
import type { AuthInteractionReason } from "./auth-provider.js";
import {
  clearServerNeedsAuth,
  getServerNeedsAuth,
  isNeedsAuthError,
  markServerNeedsAuth,
  serverNeedsAuth,
  type McpExtensionState,
} from "./state.js";
import type {
  McpPanelCallbacks,
  McpPanelResult,
  ResolvedOAuthAuthConfig,
  ServerDefinition,
} from "./types.js";
import {
  getResolvedOAuthAuthConfig,
  getServerAuthType,
  usesClientCredentialsOAuth,
  usesInteractiveOAuth,
} from "./types.js";
import {
  AuthSessionCancelledError,
  AuthSessionError,
  AuthSessionExpiredError,
  InvalidAuthCallbackError,
} from "./auth-session-manager.js";
import { getServerProvenance, writeDirectToolsConfig } from "./config.js";
import {
  updateMetadataCache,
  updateStatusBar,
  getFailureAgeSeconds,
} from "./init.js";
import { loadMetadataCache } from "./metadata-cache.js";
import { getStoredTokens } from "./auth-store.js";
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

function describeOAuthClient(auth: ResolvedOAuthAuthConfig): string {
  const information = auth.client?.information;
  if (information) {
    if (information.clientId) {
      return `static client information (${information.clientId})`;
    }

    if (information.clientIdEnv) {
      return `static client information (clientId from $${information.clientIdEnv})`;
    }

    return "static client information (credentials configured)";
  }

  if (auth.client?.metadataUrl) {
    return `client metadata URL (${auth.client.metadataUrl})`;
  }

  if (auth.client?.metadata) {
    return "inline client metadata";
  }

  return "SDK-managed registration defaults";
}

function describeRegistrationMode(auth: ResolvedOAuthAuthConfig): string {
  switch (auth.registration.mode) {
    case "auto":
      return "auto (static client info -> metadata URL/CIMD -> dynamic registration)";
    case "metadata-url":
      return auth.client?.metadataUrl
        ? `metadata-url (${auth.client.metadataUrl})`
        : "metadata-url";
    default:
      return auth.registration.mode;
  }
}

function buildAuthBehaviorFooterLines(): string[] {
  return [
    "Behavior:",
    "  authorization_code reuses stored tokens and silent refresh first, then uses the system browser with a 127.0.0.1 loopback callback, PKCE, and single-use state validation if sign-in is still required.",
    "  Pi stores tokens, client registration, and callback session state under ~/.pi/agent/mcp-auth.",
    "  registration.mode=auto prefers static client info, then metadata URL/CIMD, then dynamic registration.",
    "  client_credentials stays non-interactive and can reuse durable auth state without opening a browser.",
    "  Background reconnects and keep-alive health checks never open a browser; Pi leaves the server in needs-auth until you retry intentionally.",
    "  HTTP auth failures stay auth failures; StreamableHTTP only falls back to SSE when the transport is incompatible.",
  ];
}

function getStoredTokenAvailability(
  serverName: string,
  definition: ServerDefinition,
): { hasUsableAccessToken: boolean; hasRefreshToken: boolean } {
  const usableTokens = getStoredTokens(serverName, definition);
  const storedTokens = getStoredTokens(serverName, definition, undefined, {
    includeExpired: true,
  });

  return {
    hasUsableAccessToken: usableTokens !== undefined,
    hasRefreshToken: Boolean(storedTokens?.refresh_token),
  };
}

function getAuthStatusSummary(
  state: McpExtensionState,
  serverName: string,
  definition: ServerDefinition,
): { summary: string; note?: string } {
  const requirement = getServerNeedsAuth(state, serverName);
  const connection = state.manager.getConnection(serverName);
  const tokenAvailability = getStoredTokenAvailability(serverName, definition);

  if (connection?.status === "connected") {
    return { summary: "connected" };
  }

  if (requirement) {
    return {
      summary: usesClientCredentialsOAuth(definition)
        ? "authentication required"
        : "browser sign-in required",
      note: requirement.message,
    };
  }

  if (usesInteractiveOAuth(definition)) {
    return {
      summary: tokenAvailability.hasUsableAccessToken
        ? "stored tokens available"
        : tokenAvailability.hasRefreshToken
          ? "stored refresh token available"
          : "browser sign-in required",
    };
  }

  if (usesClientCredentialsOAuth(definition)) {
    return {
      summary: tokenAvailability.hasUsableAccessToken
        ? "cached machine token available"
        : "ready for non-interactive token exchange",
    };
  }

  return { summary: "ready" };
}

function buildAuthSummaryLines(
  state: McpExtensionState,
  serverName: string,
  definition: ServerDefinition,
): string[] {
  const auth = getResolvedOAuthAuthConfig(definition);
  if (!auth) {
    return [`${serverName}: not configured for OAuth`];
  }

  const status = getAuthStatusSummary(state, serverName, definition);
  const lines = [
    `${serverName}: ${status.summary}`,
    `  flow: ${auth.grantType}`,
    `  registration: ${describeRegistrationMode(auth)}`,
    `  client: ${describeOAuthClient(auth)}`,
  ];

  if (status.note) {
    lines.push(`  last issue: ${status.note}`);
  }

  return lines;
}

export async function showAuthOverview(
  state: McpExtensionState,
  ctx: ExtensionContext,
): Promise<void> {
  if (!ctx.hasUI) return;

  const entries = Object.entries(state.config.mcpServers).filter(
    ([, definition]) => getServerAuthType(definition) === "oauth",
  );

  if (entries.length === 0) {
    ctx.ui.notify("No OAuth-authenticated MCP servers are configured.", "info");
    return;
  }

  const lines = ["MCP Auth:", ""];
  for (const [serverName, definition] of entries) {
    lines.push(...buildAuthSummaryLines(state, serverName, definition), "");
  }
  lines.push(...buildAuthBehaviorFooterLines(), "");
  lines.push(
    "Use /mcp auth (or /mcp-auth) to show this summary again, or /mcp auth <server> to start or retry authentication for a specific server.",
  );

  ctx.ui.notify(lines.join("\n"), "info");
}

function summarizeAuthSessionFailure(
  serverName: string,
  error: AuthSessionError,
): string {
  if (error instanceof AuthSessionCancelledError) {
    return `MCP: Browser sign-in for "${serverName}" was cancelled. Press Ctrl+R or run /mcp auth ${serverName} (or /mcp-auth ${serverName}) to try again.`;
  }

  if (error instanceof AuthSessionExpiredError) {
    return `MCP: Browser sign-in for "${serverName}" expired before completion. Press Ctrl+R or run /mcp auth ${serverName} (or /mcp-auth ${serverName}) to try again.`;
  }

  if (error instanceof InvalidAuthCallbackError) {
    return `MCP: Browser sign-in callback for "${serverName}" did not complete successfully. Confirm the auth server allows the 127.0.0.1 callback, then press Ctrl+R or run /mcp auth ${serverName} (or /mcp-auth ${serverName}) to try again.`;
  }

  return `MCP: Browser sign-in for "${serverName}" did not complete. Press Ctrl+R or run /mcp auth ${serverName} (or /mcp-auth ${serverName}) to try again.`;
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
    const { metadata, failedTools } = buildToolMetadata(
      connection.tools,
      connection.resources,
      definition,
      serverName,
      prefix,
    );
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

export async function showStatus(
  state: McpExtensionState,
  ctx: ExtensionContext,
): Promise<void> {
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

    const toolSuffix = failed
      ? ""
      : ` (${toolCount} tools${status === "cached" ? ", cached" : ""})`;
    lines.push(`${statusIcon} ${name}: ${status}${toolSuffix}`);
  }

  if (Object.keys(state.config.mcpServers).length === 0) {
    lines.push("No MCP servers configured");
  }

  ctx.ui.notify(lines.join("\n"), "info");
}

export async function showTools(
  state: McpExtensionState,
  ctx: ExtensionContext,
): Promise<void> {
  if (!ctx.hasUI) return;

  const allTools = [...state.toolMetadata.values()].flat().map((m) => m.name);

  if (allTools.length === 0) {
    ctx.ui.notify("No MCP tools available", "info");
    return;
  }

  const lines = [
    "MCP Tools:",
    "",
    ...allTools.map((t) => `  ${t}`),
    "",
    `Total: ${allTools.length} tools`,
  ];

  ctx.ui.notify(lines.join("\n"), "info");
}

export async function reconnectServers(
  state: McpExtensionState,
  ctx: ExtensionContext,
  targetServer?: string,
): Promise<void> {
  if (targetServer && !state.config.mcpServers[targetServer]) {
    if (ctx.hasUI) {
      ctx.ui.notify(`Server "${targetServer}" not found in config`, "error");
    }
    return;
  }

  const entries = targetServer
    ? [
        [targetServer, state.config.mcpServers[targetServer]] as [
          string,
          ServerDefinition,
        ],
      ]
    : Object.entries(state.config.mcpServers);

  for (const [name, definition] of entries) {
    const result = await reconnectServerWithUserIntent(state, name, definition);

    if (ctx.hasUI) {
      ctx.ui.notify(result.message, result.level);
      if (result.connected && result.failedTools > 0) {
        ctx.ui.notify(
          `MCP: ${name} - ${result.failedTools} tools skipped`,
          "warning",
        );
      }
    }
  }

  updateStatusBar(state);
}

export async function authenticateServer(
  state: McpExtensionState,
  serverName: string,
  ctx: ExtensionContext,
): Promise<void> {
  if (!ctx.hasUI) return;

  const definition = state.config.mcpServers[serverName];
  if (!definition) {
    ctx.ui.notify(`Server "${serverName}" not found in config`, "error");
    return;
  }

  const authType = getServerAuthType(definition);

  if (authType !== "oauth") {
    ctx.ui.notify(
      `Server "${serverName}" does not use OAuth authentication.\n` +
        `Current auth mode: ${authType ?? "none"}`,
      "error",
    );
    return;
  }

  if (!definition.url) {
    ctx.ui.notify(
      `Server "${serverName}" has no URL configured (OAuth requires HTTP transport)`,
      "error",
    );
    return;
  }

  const auth = getResolvedOAuthAuthConfig(definition);
  if (!auth) {
    ctx.ui.notify(
      `OAuth configuration for "${serverName}" is incomplete.`,
      "error",
    );
    return;
  }

  const introLines = [
    `MCP auth for "${serverName}":`,
    ...buildAuthSummaryLines(state, serverName, definition),
    "",
    usesInteractiveOAuth(definition)
      ? "Starting browser-based authorization_code auth. Pi reuses stored tokens and silent refresh first; if sign-in is still required, it opens your system browser and waits for the 127.0.0.1 loopback callback."
      : "Starting non-interactive client_credentials auth. No browser will open; Pi will request a token with the configured client credentials and reuse durable auth state when possible.",
    "Pi stores tokens, client registration, and callback session state under ~/.pi/agent/mcp-auth.",
    "Background reconnects never open a browser; Pi only launches auth on an intentional retry.",
    "HTTP auth failures stay auth failures; StreamableHTTP only falls back to SSE when the transport itself is incompatible.",
  ];

  if (definition.auth === "oauth") {
    introLines.push(
      'Compatibility note: legacy auth: "oauth" config defaults to authorization_code with automatic registration.',
    );
  }

  ctx.ui.notify(introLines.join("\n"), "info");

  const result = await reconnectServerWithUserIntent(
    state,
    serverName,
    definition,
  );
  updateStatusBar(state);
  ctx.ui.notify(result.message, result.level);
  if (result.connected && result.failedTools > 0) {
    ctx.ui.notify(
      `MCP: ${serverName} - ${result.failedTools} tools skipped`,
      "warning",
    );
  }

  if (
    usesClientCredentialsOAuth(definition) &&
    !result.connected &&
    !serverNeedsAuth(state, serverName)
  ) {
    ctx.ui.notify(
      `MCP: ${serverName} uses client_credentials, so retries remain non-interactive. Check the configured client credentials or token endpoint settings.`,
      "warning",
    );
  }
}

export async function openMcpPanel(
  state: McpExtensionState,
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  configOverridePath?: string,
): Promise<void> {
  const config = state.config;
  const cache = loadMetadataCache();
  const provenanceMap = getServerProvenance(
    (pi.getFlag("mcp-config") as string | undefined) ?? configOverridePath,
  );

  const callbacks: McpPanelCallbacks = {
    reconnect: async (serverName: string) => {
      const definition = config.mcpServers[serverName];
      if (!definition) {
        if (ctx.hasUI) {
          ctx.ui.notify(`Server "${serverName}" not found in config`, "error");
        }
        return false;
      }

      const result = await reconnectServerWithUserIntent(
        state,
        serverName,
        definition,
      );
      updateStatusBar(state);
      if (ctx.hasUI) {
        ctx.ui.notify(result.message, result.level);
        if (result.connected && result.failedTools > 0) {
          ctx.ui.notify(
            `MCP: ${serverName} - ${result.failedTools} tools skipped`,
            "warning",
          );
        }
      }
      return result.connected;
    },
    getConnectionStatus: (serverName: string) => {
      const definition = config.mcpServers[serverName];
      const connection = state.manager.getConnection(serverName);
      if (connection?.status === "connected") return "connected";
      if (serverNeedsAuth(state, serverName)) return "needs-auth";
      if (usesInteractiveOAuth(definition)) {
        const tokenAvailability = getStoredTokenAvailability(serverName, definition);
        if (!tokenAvailability.hasUsableAccessToken && !tokenAvailability.hasRefreshToken) {
          return "needs-auth";
        }
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
        return createMcpPanel(
          config,
          cache,
          provenanceMap,
          callbacks,
          tui,
          (result: McpPanelResult) => {
            if (!result.cancelled && result.changes.size > 0) {
              writeDirectToolsConfig(result.changes, provenanceMap, config);
              ctx.ui.notify(
                "Direct tools updated. Restart pi to apply.",
                "info",
              );
            }
            done();
            resolve();
          },
        );
      },
      { overlay: true, overlayOptions: { anchor: "center", width: 82 } },
    );
  });
}
