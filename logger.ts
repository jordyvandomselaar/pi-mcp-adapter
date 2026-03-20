/**
 * Centralized logging for MCP UI operations.
 * Provides structured, contextual logs with levels.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogContext {
  server?: string;
  session?: string;
  tool?: string;
  uri?: string;
  [key: string]: unknown;
}

export interface LogEntry {
  level: LogLevel;
  message: string;
  context?: LogContext;
  error?: Error;
  timestamp: Date;
}

type LogHandler = (entry: LogEntry) => void;

const REDACTED = "[redacted]";
const CIRCULAR = "[circular]";

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LEVEL_PREFIX: Record<LogLevel, string> = {
  debug: "[MCP-UI:DEBUG]",
  info: "[MCP-UI]",
  warn: "[MCP-UI:WARN]",
  error: "[MCP-UI:ERROR]",
};

class Logger {
  private minLevel: LogLevel = "info";
  private handlers: LogHandler[] = [];
  private defaultContext: LogContext = {};

  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  setDefaultContext(context: LogContext): void {
    this.defaultContext = context;
  }

  addHandler(handler: LogHandler): void {
    this.handlers.push(handler);
  }

  clearHandlers(): void {
    this.handlers = [];
  }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[this.minLevel];
  }

  private emit(level: LogLevel, message: string, context?: LogContext, error?: Error): void {
    if (!this.shouldLog(level)) return;

    const mergedContext = { ...this.defaultContext, ...context };
    const sanitizedContext = sanitizeContext(mergedContext);
    const entry: LogEntry = {
      level,
      message,
      context: sanitizedContext,
      error,
      timestamp: new Date(),
    };

    // Default console output
    const prefix = LEVEL_PREFIX[level];
    const contextStr = formatContext(entry.context);
    const fullMessage = contextStr ? `${prefix} ${message} ${contextStr}` : `${prefix} ${message}`;

    if (level === "error") {
      console.error(fullMessage, error ?? "");
    } else if (level === "warn") {
      console.warn(fullMessage);
    } else if (level === "debug") {
      console.debug(fullMessage);
    } else {
      console.log(fullMessage);
    }

    // Custom handlers
    for (const handler of this.handlers) {
      try {
        handler(entry);
      } catch {
        // Ignore handler errors
      }
    }
  }

  debug(message: string, context?: LogContext): void {
    this.emit("debug", message, context);
  }

  info(message: string, context?: LogContext): void {
    this.emit("info", message, context);
  }

  warn(message: string, context?: LogContext): void {
    this.emit("warn", message, context);
  }

  error(message: string, error?: Error, context?: LogContext): void {
    this.emit("error", message, context, error);
  }

  /**
   * Create a child logger with additional default context.
   */
  child(context: LogContext): ChildLogger {
    return new ChildLogger(this, context);
  }
}

class ChildLogger {
  constructor(
    private parent: Logger,
    private context: LogContext
  ) {}

  debug(message: string, context?: LogContext): void {
    this.parent.debug(message, { ...this.context, ...context });
  }

  info(message: string, context?: LogContext): void {
    this.parent.info(message, { ...this.context, ...context });
  }

  warn(message: string, context?: LogContext): void {
    this.parent.warn(message, { ...this.context, ...context });
  }

  error(message: string, error?: Error, context?: LogContext): void {
    this.parent.error(message, error, { ...this.context, ...context });
  }

  child(context: LogContext): ChildLogger {
    return new ChildLogger(this.parent, { ...this.context, ...context });
  }
}

function formatContext(context?: LogContext): string {
  if (!context || Object.keys(context).length === 0) return "";
  const parts: string[] = [];
  for (const [key, value] of Object.entries(context)) {
    if (value !== undefined && value !== null) {
      parts.push(`${key}=${typeof value === "string" ? value : JSON.stringify(value)}`);
    }
  }
  return parts.length > 0 ? `(${parts.join(", ")})` : "";
}

function sanitizeContext(context?: LogContext): LogContext | undefined {
  if (!context) return undefined;
  return sanitizeValue(undefined, context, new WeakSet<object>()) as LogContext;
}

function sanitizeValue(key: string | undefined, value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (key && isSensitiveKey(key)) {
    return REDACTED;
  }

  if (typeof value === "string") {
    return sanitizeString(value);
  }

  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value;
  }

  if (value instanceof URL) {
    return sanitizeUrl(value);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeValue(key, entry, seen));
  }

  if (typeof Headers !== "undefined" && value instanceof Headers) {
    const headers: Record<string, string> = {};
    for (const [headerKey, headerValue] of value.entries()) {
      headers[headerKey] = String(sanitizeValue(headerKey, headerValue, seen));
    }
    return headers;
  }

  if (typeof value === "object") {
    if (seen.has(value)) {
      return CIRCULAR;
    }

    seen.add(value);
    const result: Record<string, unknown> = {};
    for (const [entryKey, entryValue] of Object.entries(value)) {
      result[entryKey] = sanitizeValue(entryKey, entryValue, seen);
    }
    seen.delete(value);
    return result;
  }

  return String(value);
}

function sanitizeString(value: string): string {
  if (/^(Bearer|Basic)\s+/i.test(value)) {
    return REDACTED;
  }

  try {
    const url = new URL(value);
    return sanitizeUrl(url);
  } catch {
    return value;
  }
}

function sanitizeUrl(url: URL): string {
  const hasQuery = Boolean(url.search);
  const hasHash = Boolean(url.hash);
  return `${url.origin}${url.pathname}${hasQuery ? "?<redacted>" : ""}${hasHash ? "#<redacted>" : ""}`;
}

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/-/g, "_").toLowerCase();
  return (
    normalized === "authorization" ||
    normalized === "proxy_authorization" ||
    normalized === "token" ||
    normalized === "code" ||
    normalized === "state" ||
    normalized === "client_secret" ||
    normalized === "code_verifier" ||
    normalized === "client_assertion" ||
    normalized === "jwt_bearer_assertion" ||
    normalized === "access_token" ||
    normalized === "refresh_token" ||
    normalized === "id_token"
  );
}

// Singleton instance
export const logger = new Logger();

// Enable debug mode via environment variable
if (process.env.MCP_UI_DEBUG === "1" || process.env.MCP_UI_DEBUG === "true") {
  logger.setLevel("debug");
}
