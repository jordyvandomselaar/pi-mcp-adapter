import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import type { ConsentManager } from "./consent-manager.js";
import type { McpLifecycleManager } from "./lifecycle.js";
import {
  isInteractiveAuthorizationRequiredError,
  type AuthInteractionReason,
} from "./auth-provider.js";
import {
  AuthSessionCancelledError,
  AuthSessionError,
  AuthSessionExpiredError,
  InvalidAuthCallbackError,
} from "./auth-session-manager.js";
import type { McpServerManager } from "./server-manager.js";
import type {
  ToolMetadata,
  McpConfig,
  UiSessionMessages,
  UiStreamSummary,
} from "./types.js";
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
  options?: { triggerTurn?: boolean },
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
  if (
    isInteractiveAuthorizationRequiredError(error) ||
    error instanceof AuthSessionError
  ) {
    return true;
  }

  if (!error || typeof error !== "object") {
    return false;
  }

  const maybeError = error as { code?: unknown; name?: unknown };
  return (
    maybeError.code === "interactive_authorization_required" ||
    maybeError.name === "InteractiveAuthorizationRequiredError" ||
    maybeError.name === "AuthSessionError" ||
    maybeError.name === "AuthSessionCancelledError" ||
    maybeError.name === "AuthSessionExpiredError" ||
    maybeError.name === "InvalidAuthCallbackError"
  );
}

export function getNeedsAuthReason(
  error: unknown,
  fallback: AuthInteractionReason | "unknown" = "unknown",
): AuthInteractionReason | "unknown" {
  if (!isInteractiveAuthorizationRequiredError(error)) {
    return fallback;
  }

  return error.decision.reason ?? fallback;
}

export function getNeedsAuthMessage(
  error: unknown,
  serverName: string,
  fallbackMessage?: string,
): string | undefined {
  if (error instanceof AuthSessionCancelledError) {
    return `Browser sign-in for "${serverName}" was cancelled. Retry authentication to continue.`;
  }

  if (error instanceof AuthSessionExpiredError) {
    return `Browser sign-in for "${serverName}" expired before completion. Retry authentication to continue.`;
  }

  if (error instanceof InvalidAuthCallbackError) {
    return `Browser sign-in callback for "${serverName}" did not complete successfully. Retry authentication to continue.`;
  }

  if (error instanceof AuthSessionError) {
    return `Browser sign-in for "${serverName}" did not complete. Retry authentication to continue.`;
  }

  return (
    fallbackMessage ?? (error instanceof Error ? error.message : undefined)
  );
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
  const message = getNeedsAuthMessage(
    options.error,
    serverName,
    options.message,
  );

  state.authRequirements.set(serverName, {
    serverName,
    reason: getNeedsAuthReason(options.error, fallbackReason),
    updatedAt: Date.now(),
    message,
  });
}

export function clearServerNeedsAuth(
  state: McpExtensionState,
  serverName: string,
): void {
  state.authRequirements.delete(serverName);
}

export function getServerNeedsAuth(
  state: McpExtensionState,
  serverName: string,
): ServerAuthRequirement | undefined {
  return state.authRequirements.get(serverName);
}

export function serverNeedsAuth(
  state: McpExtensionState,
  serverName: string,
): boolean {
  return state.authRequirements.has(serverName);
}
