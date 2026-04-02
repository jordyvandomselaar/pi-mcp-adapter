import type { AuthInteractionReason } from "./auth-provider.js";
import { isNeedsAuthError } from "./state.js";
import type { ServerDefinition } from "./types.js";
import type { McpServerManager } from "./server-manager.js";
import { logger } from "./logger.js";

export type ReconnectCallback = (serverName: string) => void;
export type AuthRequiredCallback = (serverName: string, error: unknown) => void;

interface ManagedConnectOptions {
  interactiveAllowed?: boolean;
  interactionReason?: AuthInteractionReason;
}

function connectWithPolicy(
  manager: McpServerManager,
  name: string,
  definition: ServerDefinition,
  options?: ManagedConnectOptions,
): Promise<Awaited<ReturnType<McpServerManager["connect"]>>> {
  const managed = manager as unknown as {
    connect: (
      serverName: string,
      serverDefinition: ServerDefinition,
      connectOptions?: ManagedConnectOptions,
    ) => Promise<Awaited<ReturnType<McpServerManager["connect"]>>>;
  };

  return managed.connect(name, definition, options);
}

export class McpLifecycleManager {
  private manager: McpServerManager;
  private keepAliveServers = new Map<string, ServerDefinition>();
  private allServers = new Map<string, ServerDefinition>();
  private serverSettings = new Map<string, { idleTimeout?: number }>();
  private globalIdleTimeout: number = 10 * 60 * 1000;
  private healthCheckInterval?: NodeJS.Timeout;
  private onReconnect?: ReconnectCallback;
  private onAuthRequired?: AuthRequiredCallback;
  private onIdleShutdown?: (serverName: string) => void;
  
  constructor(manager: McpServerManager) {
    this.manager = manager;
  }
  
  /**
   * Set callback to be invoked after a successful auto-reconnect.
   * Use this to update tool metadata when a server reconnects.
   */
  setReconnectCallback(callback: ReconnectCallback): void {
    this.onReconnect = callback;
  }

  setAuthRequiredCallback(callback: AuthRequiredCallback): void {
    this.onAuthRequired = callback;
  }
  
  markKeepAlive(name: string, definition: ServerDefinition): void {
    this.keepAliveServers.set(name, definition);
  }

  registerServer(name: string, definition: ServerDefinition, settings?: { idleTimeout?: number }): void {
    this.allServers.set(name, definition);
    if (settings?.idleTimeout !== undefined) {
      this.serverSettings.set(name, settings);
    }
  }

  setGlobalIdleTimeout(minutes: number): void {
    this.globalIdleTimeout = minutes * 60 * 1000;
  }

  setIdleShutdownCallback(callback: (serverName: string) => void): void {
    this.onIdleShutdown = callback;
  }
  
  startHealthChecks(intervalMs = 30000): void {
    this.healthCheckInterval = setInterval(() => {
      this.checkConnections();
    }, intervalMs);
    this.healthCheckInterval.unref();
  }
  
  private async checkConnections(): Promise<void> {
    for (const [name, definition] of this.keepAliveServers) {
      const connection = this.manager.getConnection(name);
      
      if (!connection || connection.status !== "connected") {
        try {
          await connectWithPolicy(this.manager, name, definition, {
            interactiveAllowed: false,
            interactionReason: "reconnect",
          });
          logger.debug(`Reconnected to ${name}`);
          // Notify extension to update metadata
          this.onReconnect?.(name);
        } catch (error) {
          if (isNeedsAuthError(error)) {
            logger.debug(`MCP: ${name} needs authentication before background reconnect can continue`);
            this.onAuthRequired?.(name, error);
            continue;
          }
          console.error(`MCP: Failed to reconnect to ${name}:`, error);
        }
      }
    }

    for (const [name] of this.allServers) {
      if (this.keepAliveServers.has(name)) continue;
      const timeout = this.getIdleTimeout(name);
      if (timeout > 0 && this.manager.isIdle(name, timeout)) {
        await this.manager.close(name);
        this.onIdleShutdown?.(name);
      }
    }
  }

  private getIdleTimeout(name: string): number {
    const perServer = this.serverSettings.get(name)?.idleTimeout;
    if (perServer !== undefined) return perServer * 60 * 1000;
    return this.globalIdleTimeout;
  }
  
  async gracefulShutdown(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    await this.manager.closeAll();
  }
}
