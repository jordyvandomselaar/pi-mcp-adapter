import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import type { ConsentManager } from "./consent-manager.js";
import type { McpLifecycleManager } from "./lifecycle.js";
import { isInteractiveAuthorizationRequiredError, type AuthInteractionReason } from "./auth-provider.js";
import type { McpServerManager } from "./server-manager.js";
import type { ToolMetadata, McpConfig, UiSessionMessages, UiStreamSummary } from "./types.js";
import type { UiResourceHandler } from "./ui-resource-handler.js";
import type { UiServerHandle } from "./ui-server.js";

export interface CompletedUiSession {
  serverName: string;
  toolName: string;
  completedAt: Date;
  reason: string;
  messages: UiSessionMessages;
  stream?: UiStreamSummary;
}

export type SendMessageFn = (
  message: {
    customType: string;
    content: Array<{ type: string; text: string }>;
    display?: string;
    details?: unknown;
  },
  options?: { triggerTurn?: boolean }
) => void;

export interface ServerAuthRequirement {
  serverName: string;
  reason: AuthInteractionReason | "unknown";
  updatedAt: number;
  message?: string;
}

export interface McpExtensionState {
  manager: McpServerManager;
  lifecycle: McpLifecycleManager;
  toolMetadata: Map<string, ToolMetadata[]>;
  config: McpConfig;
  failureTracker: Map<string, number>;
  authRequirements: Map<string, ServerAuthRequirement>;
  uiResourceHandler: UiResourceHandler;
  consentManager: ConsentManager;
  uiServer: UiServerHandle | null;
  completedUiSessions: CompletedUiSession[];
  openBrowser: (url: string) => Promise<void>;
  ui?: ExtensionContext["ui"];
  sendMessage?: SendMessageFn;
}

export function isNeedsAuthError(error: unknown): boolean {
  if (isInteractiveAuthorizationRequiredError(error)) {
    return true;
  }

  if (!error || typeof error !== "object") {
    return false;
  }

  const maybeError = error as { code?: unknown; name?: unknown };
  return maybeError.code === "interactive_authorization_required"
    || maybeError.name === "InteractiveAuthorizationRequiredError";
}

export function getNeedsAuthReason(error: unknown, fallback: AuthInteractionReason | "unknown" = "unknown"):
  AuthInteractionReason | "unknown" {
  if (!isInteractiveAuthorizationRequiredError(error)) {
    return fallback;
  }

  return error.decision.reason ?? fallback;
}

export function markServerNeedsAuth(
  state: McpExtensionState,
  serverName: string,
  options: {
    error?: unknown;
    reason?: AuthInteractionReason | "unknown";
    message?: string;
  } = {},
): void {
  const fallbackReason = options.reason ?? "unknown";
  const message = options.message
    ?? (options.error instanceof Error ? options.error.message : undefined);

  state.authRequirements.set(serverName, {
    serverName,
    reason: getNeedsAuthReason(options.error, fallbackReason),
    updatedAt: Date.now(),
    message,
  });
}

export function clearServerNeedsAuth(state: McpExtensionState, serverName: string): void {
  state.authRequirements.delete(serverName);
}

export function getServerNeedsAuth(state: McpExtensionState, serverName: string): ServerAuthRequirement | undefined {
  return state.authRequirements.get(serverName);
}

export function serverNeedsAuth(state: McpExtensionState, serverName: string): boolean {
  return state.authRequirements.has(serverName);
}
