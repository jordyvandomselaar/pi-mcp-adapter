import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { logger } from "./logger.js";

const DEFAULT_CALLBACK_HOST = "127.0.0.1";
const DEFAULT_CALLBACK_PATH = "/callback";
const DEFAULT_SESSION_TTL_MS = 5 * 60 * 1000;
const DEFAULT_REPLAY_RETENTION_MS = 10 * 60 * 1000;
const DEFAULT_SUCCESS_HTML = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Authorization complete</title>
  </head>
  <body>
    <h1>Authorization complete</h1>
    <p>You can close this window and return to Pi.</p>
    <script>setTimeout(() => window.close(), 1500);</script>
  </body>
</html>`;

const LOOPBACK_REMOTE_ADDRESSES = new Set([
  "127.0.0.1",
  "::1",
  "::ffff:127.0.0.1",
]);

const SAFE_BROWSER_PROTOCOLS = new Set(["http:", "https:"]);

type SessionStatus = "pending" | "completed" | "expired" | "superseded" | "cancelled";
type FinalStateStatus = Exclude<SessionStatus, "pending"> | "replayed";

export interface InteractiveAuthSessionRecord {
  sessionId: string;
  fingerprint: string;
  state: string;
  redirectUrl: string;
  codeVerifier?: string;
  authorizationUrl?: string;
  createdAt: number;
  expiresAt: number;
  status: SessionStatus;
  completedAt?: number;
}

export interface InteractiveAuthSessionStore {
  getBySessionId(sessionId: string): InteractiveAuthSessionRecord | undefined | Promise<InteractiveAuthSessionRecord | undefined>;
  getByFingerprint(fingerprint: string): InteractiveAuthSessionRecord | undefined | Promise<InteractiveAuthSessionRecord | undefined>;
  getByState(state: string): InteractiveAuthSessionRecord | undefined | Promise<InteractiveAuthSessionRecord | undefined>;
  list(): InteractiveAuthSessionRecord[] | Promise<InteractiveAuthSessionRecord[]>;
  set(record: InteractiveAuthSessionRecord): void | Promise<void>;
  delete(sessionId: string): void | Promise<void>;
}

export interface InteractiveAuthSessionHandle {
  sessionId: string;
  fingerprint: string;
  state: string;
  redirectUrl: string;
  createdAt: number;
  expiresAt: number;
  saveCodeVerifier: (codeVerifier: string) => Promise<void>;
  getCodeVerifier: () => Promise<string>;
  openAuthorization: (authorizationUrl: string | URL) => Promise<void>;
  waitForCallback: () => Promise<AuthorizationCallbackResult>;
  cancel: (reason?: string) => Promise<void>;
}

export interface AuthorizationCallbackResult {
  sessionId: string;
  fingerprint: string;
  state: string;
  authorizationCode: string;
  receivedAt: number;
}

export interface InteractiveAuthSessionSummary {
  sessionId: string;
  fingerprint: string;
  state: string;
  redirectUrl: string;
  createdAt: number;
  expiresAt: number;
}

export interface InteractiveAuthSessionHooks {
  onSessionStarted?: (session: InteractiveAuthSessionSummary) => void | Promise<void>;
  onAuthorizationRequested?: (session: InteractiveAuthSessionSummary, authorizationUrl: URL) => void | Promise<void>;
  onSessionCompleted?: (session: InteractiveAuthSessionSummary, result: AuthorizationCallbackResult) => void | Promise<void>;
  onSessionRejected?: (session: InteractiveAuthSessionSummary, error: Error) => void | Promise<void>;
}

export interface AuthSessionManagerOptions {
  store?: InteractiveAuthSessionStore;
  browserOpener?: BrowserOpener;
  host?: string;
  port?: number;
  callbackPath?: string;
  sessionTtlMs?: number;
  replayRetentionMs?: number;
  hooks?: InteractiveAuthSessionHooks;
  successHtml?: string;
}

export type BrowserOpener = (url: URL) => void | Promise<void>;

export class AuthSessionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class AuthSessionExpiredError extends AuthSessionError {}
export class AuthSessionSupersededError extends AuthSessionError {}
export class AuthSessionCancelledError extends AuthSessionError {}
export class AuthSessionAlreadyCompletedError extends AuthSessionError {}
export class InvalidAuthCallbackError extends AuthSessionError {}

interface SessionRuntime {
  sessionId: string;
  fingerprint: string;
  state: string;
  redirectUrl: string;
  createdAt: number;
  expiresAt: number;
  completed: Promise<AuthorizationCallbackResult>;
  resolve: (value: AuthorizationCallbackResult) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

interface TombstoneRecord {
  status: FinalStateStatus;
  fingerprint: string;
  expiresAt: number;
}

export class MemoryInteractiveAuthSessionStore implements InteractiveAuthSessionStore {
  private sessions = new Map<string, InteractiveAuthSessionRecord>();
  private byFingerprint = new Map<string, string>();
  private byState = new Map<string, string>();

  getBySessionId(sessionId: string): InteractiveAuthSessionRecord | undefined {
    const record = this.sessions.get(sessionId);
    return record ? { ...record } : undefined;
  }

  getByFingerprint(fingerprint: string): InteractiveAuthSessionRecord | undefined {
    const sessionId = this.byFingerprint.get(fingerprint);
    return sessionId ? this.getBySessionId(sessionId) : undefined;
  }

  getByState(state: string): InteractiveAuthSessionRecord | undefined {
    const sessionId = this.byState.get(state);
    return sessionId ? this.getBySessionId(sessionId) : undefined;
  }

  list(): InteractiveAuthSessionRecord[] {
    return [...this.sessions.values()].map((record) => ({ ...record }));
  }

  set(record: InteractiveAuthSessionRecord): void {
    this.sessions.set(record.sessionId, { ...record });
    this.byFingerprint.set(record.fingerprint, record.sessionId);
    this.byState.set(record.state, record.sessionId);
  }

  delete(sessionId: string): void {
    const record = this.sessions.get(sessionId);
    if (!record) return;
    this.sessions.delete(sessionId);
    if (this.byFingerprint.get(record.fingerprint) === sessionId) {
      this.byFingerprint.delete(record.fingerprint);
    }
    if (this.byState.get(record.state) === sessionId) {
      this.byState.delete(record.state);
    }
  }
}

export class LoopbackAuthSessionManager {
  private readonly store: InteractiveAuthSessionStore;
  private readonly browserOpener: BrowserOpener;
  private readonly host: string;
  private readonly configuredPort?: number;
  private readonly callbackPath: string;
  private readonly sessionTtlMs: number;
  private readonly replayRetentionMs: number;
  private readonly hooks?: InteractiveAuthSessionHooks;
  private readonly successHtml: string;
  private server?: http.Server;
  private startPromise?: Promise<void>;
  private listeningPort?: number;
  private runtimeSessions = new Map<string, SessionRuntime>();
  private finalStates = new Map<string, TombstoneRecord>();
  private log = logger.child({ component: "AuthSessionManager" });

  constructor(options: AuthSessionManagerOptions = {}) {
    this.store = options.store ?? new MemoryInteractiveAuthSessionStore();
    this.browserOpener = options.browserOpener ?? openSystemBrowser;
    this.host = options.host ?? DEFAULT_CALLBACK_HOST;
    this.configuredPort = options.port;
    this.callbackPath = normalizeCallbackPath(options.callbackPath ?? DEFAULT_CALLBACK_PATH);
    this.sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    this.replayRetentionMs = options.replayRetentionMs ?? DEFAULT_REPLAY_RETENTION_MS;
    this.hooks = options.hooks;
    this.successHtml = options.successHtml ?? DEFAULT_SUCCESS_HTML;

    if (this.host !== DEFAULT_CALLBACK_HOST) {
      throw new Error(`Loopback auth listener must bind to ${DEFAULT_CALLBACK_HOST}`);
    }
  }

  get port(): number | undefined {
    return this.listeningPort;
  }

  get redirectUrl(): string {
    if (!this.listeningPort) {
      throw new Error("Auth session manager is not listening yet");
    }
    return buildRedirectUrl(this.host, this.listeningPort, this.callbackPath);
  }

  async start(): Promise<void> {
    if (this.startPromise) {
      await this.startPromise;
      return;
    }

    this.startPromise = new Promise<void>((resolve, reject) => {
      const server = http.createServer(async (req, res) => {
        try {
          await this.handleCallbackRequest(req, res);
        } catch (error) {
          const message = error instanceof Error ? error.message : "Unknown callback failure";
          this.respond(res, 500, "text/html", failureHtml("Authorization failed", message));
        }
      });

      server.once("error", (error) => {
        if (this.server === server) {
          this.server = undefined;
        }
        this.startPromise = undefined;
        reject(error);
      });

      server.listen(this.configuredPort ?? 0, this.host, () => {
        const address = server.address();
        if (!address || typeof address === "string") {
          reject(new Error("Could not determine callback listener port"));
          return;
        }

        this.server = server;
        this.listeningPort = address.port;
        this.log.debug("Auth callback listener started", { port: this.listeningPort });
        resolve();
      });
    });

    await this.startPromise;
  }

  async close(): Promise<void> {
    const runtimes = [...this.runtimeSessions.values()];
    this.runtimeSessions.clear();

    for (const runtime of runtimes) {
      clearTimeout(runtime.timeout);
      runtime.reject(new AuthSessionCancelledError("Auth session manager closed"));
      await this.store.delete(runtime.sessionId);
      this.writeFinalState(runtime.state, runtime.fingerprint, "cancelled", runtime.expiresAt);
    }

    const server = this.server;
    this.server = undefined;
    this.startPromise = undefined;
    this.listeningPort = undefined;

    if (server) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }
  }

  async startAttempt(
    fingerprint: string,
    options: { ttlMs?: number } = {},
  ): Promise<InteractiveAuthSessionHandle> {
    await this.start();
    await this.cleanupExpiredSessions();

    const existing = await this.store.getByFingerprint(fingerprint);
    if (existing && existing.status === "pending") {
      await this.rejectSession(
        existing.sessionId,
        new AuthSessionSupersededError("Auth session superseded by a newer attempt"),
        "superseded",
      );
    }

    const createdAt = Date.now();
    const expiresAt = createdAt + (options.ttlMs ?? this.sessionTtlMs);
    const state = createHighEntropyState();
    const sessionId = randomUUID();
    const redirectUrl = this.redirectUrl;

    const record: InteractiveAuthSessionRecord = {
      sessionId,
      fingerprint,
      state,
      redirectUrl,
      createdAt,
      expiresAt,
      status: "pending",
    };

    const runtime = this.createRuntime(record);
    this.runtimeSessions.set(sessionId, runtime);
    await this.store.set(record);
    await this.hooks?.onSessionStarted?.(this.toSummary(record));

    return {
      sessionId,
      fingerprint,
      state,
      redirectUrl,
      createdAt,
      expiresAt,
      saveCodeVerifier: async (codeVerifier: string) => {
        const active = await this.getActiveSession(sessionId);
        active.codeVerifier = codeVerifier;
        await this.store.set(active);
      },
      getCodeVerifier: async () => {
        const active = await this.getActiveSession(sessionId);
        if (!active.codeVerifier) {
          throw new AuthSessionError("No PKCE code verifier saved for auth session");
        }
        return active.codeVerifier;
      },
      openAuthorization: async (authorizationUrl: string | URL) => {
        const active = await this.getActiveSession(sessionId);
        const parsed = parseBrowserUrl(authorizationUrl);
        active.authorizationUrl = parsed.toString();
        await this.store.set(active);
        await this.hooks?.onAuthorizationRequested?.(this.toSummary(active), parsed);
        await this.browserOpener(parsed);
      },
      waitForCallback: () => runtime.completed,
      cancel: async (reason?: string) => {
        const message = reason ? `Auth session cancelled: ${reason}` : "Auth session cancelled";
        await this.rejectSession(sessionId, new AuthSessionCancelledError(message), "cancelled");
      },
    };
  }

  async cleanupExpiredSessions(now = Date.now()): Promise<string[]> {
    const expiredSessionIds: string[] = [];
    const sessions = await this.store.list();

    for (const record of sessions) {
      if (record.status === "pending" && record.expiresAt <= now) {
        expiredSessionIds.push(record.sessionId);
      }
    }

    for (const sessionId of expiredSessionIds) {
      await this.rejectSession(
        sessionId,
        new AuthSessionExpiredError("Auth session expired before callback completed"),
        "expired",
      );
    }

    for (const [state, tombstone] of [...this.finalStates.entries()]) {
      if (tombstone.expiresAt <= now) {
        this.finalStates.delete(state);
      }
    }

    return expiredSessionIds;
  }

  private createRuntime(record: InteractiveAuthSessionRecord): SessionRuntime {
    let resolve!: (value: AuthorizationCallbackResult) => void;
    let reject!: (error: Error) => void;
    const completed = new Promise<AuthorizationCallbackResult>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    void completed.catch(() => {});

    const timeout = setTimeout(() => {
      void this.rejectSession(
        record.sessionId,
        new AuthSessionExpiredError("Auth session expired before callback completed"),
        "expired",
      );
    }, Math.max(record.expiresAt - Date.now(), 1));

    return {
      sessionId: record.sessionId,
      fingerprint: record.fingerprint,
      state: record.state,
      redirectUrl: record.redirectUrl,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      completed,
      resolve,
      reject,
      timeout,
    };
  }

  private async handleCallbackRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    await this.cleanupExpiredSessions();

    const remoteAddress = req.socket.remoteAddress;
    if (remoteAddress && !LOOPBACK_REMOTE_ADDRESSES.has(remoteAddress)) {
      this.respond(res, 403, "text/html", failureHtml("Authorization rejected", "Callback must originate from the local machine."));
      return;
    }

    const requestUrl = new URL(req.url ?? "/", this.redirectUrl);
    if (requestUrl.pathname !== this.callbackPath) {
      this.respond(res, 404, "text/plain", "Not found");
      return;
    }

    if (req.method !== "GET") {
      this.respond(res, 405, "text/plain", "Method not allowed");
      return;
    }

    const state = requestUrl.searchParams.get("state");
    if (!state) {
      this.respond(res, 400, "text/html", failureHtml("Authorization failed", "Missing state parameter."));
      return;
    }

    const tombstone = this.finalStates.get(state);
    if (tombstone) {
      const { statusCode, title, message } = describeFinalState(tombstone.status);
      this.respond(res, statusCode, "text/html", failureHtml(title, message));
      return;
    }

    const record = await this.store.getByState(state);
    if (!record || record.status !== "pending") {
      this.respond(res, 400, "text/html", failureHtml("Authorization failed", "Unknown or invalid state parameter."));
      return;
    }

    if (record.expiresAt <= Date.now()) {
      await this.rejectSession(
        record.sessionId,
        new AuthSessionExpiredError("Auth session expired before callback completed"),
        "expired",
      );
      this.respond(res, 410, "text/html", failureHtml("Authorization expired", "This authorization session has expired. Please try again."));
      return;
    }

    const oauthError = requestUrl.searchParams.get("error");
    if (oauthError) {
      const errorDescription = requestUrl.searchParams.get("error_description") ?? oauthError;
      await this.rejectSession(
        record.sessionId,
        new InvalidAuthCallbackError(`OAuth callback returned error: ${errorDescription}`),
        "cancelled",
      );
      this.respond(res, 400, "text/html", failureHtml("Authorization failed", errorDescription));
      return;
    }

    const authorizationCode = requestUrl.searchParams.get("code");
    if (!authorizationCode) {
      await this.rejectSession(
        record.sessionId,
        new InvalidAuthCallbackError("OAuth callback did not include an authorization code"),
        "cancelled",
      );
      this.respond(res, 400, "text/html", failureHtml("Authorization failed", "Missing authorization code."));
      return;
    }

    const runtime = this.runtimeSessions.get(record.sessionId);
    if (!runtime) {
      await this.store.delete(record.sessionId);
      this.writeFinalState(record.state, record.fingerprint, "replayed", record.expiresAt);
      this.respond(res, 409, "text/html", failureHtml("Authorization rejected", "This authorization state has already been used."));
      return;
    }

    clearTimeout(runtime.timeout);
    this.runtimeSessions.delete(record.sessionId);
    await this.store.delete(record.sessionId);
    this.writeFinalState(record.state, record.fingerprint, "completed", record.expiresAt);

    const result: AuthorizationCallbackResult = {
      sessionId: record.sessionId,
      fingerprint: record.fingerprint,
      state: record.state,
      authorizationCode,
      receivedAt: Date.now(),
    };

    runtime.resolve(result);
    await this.hooks?.onSessionCompleted?.(this.toSummary(record), result);
    this.respond(res, 200, "text/html", this.successHtml);
  }

  private async getActiveSession(sessionId: string): Promise<InteractiveAuthSessionRecord> {
    await this.cleanupExpiredSessions();
    const record = await this.store.getBySessionId(sessionId);
    if (!record) {
      throw new AuthSessionError("Auth session not found");
    }
    if (record.status !== "pending") {
      throw new AuthSessionError(`Auth session is no longer active (${record.status})`);
    }
    if (record.expiresAt <= Date.now()) {
      await this.rejectSession(
        sessionId,
        new AuthSessionExpiredError("Auth session expired before callback completed"),
        "expired",
      );
      throw new AuthSessionExpiredError("Auth session expired before callback completed");
    }
    return record;
  }

  private async rejectSession(
    sessionId: string,
    error: Error,
    status: Exclude<SessionStatus, "pending" | "completed">,
  ): Promise<void> {
    const record = await this.store.getBySessionId(sessionId);
    if (!record) {
      return;
    }

    const runtime = this.runtimeSessions.get(sessionId);
    if (runtime) {
      clearTimeout(runtime.timeout);
      this.runtimeSessions.delete(sessionId);
      runtime.reject(error);
    }

    await this.store.delete(sessionId);
    this.writeFinalState(record.state, record.fingerprint, status, record.expiresAt);
    await this.hooks?.onSessionRejected?.(this.toSummary(record), error);
  }

  private writeFinalState(
    state: string,
    fingerprint: string,
    status: FinalStateStatus,
    sourceExpiry: number,
  ): void {
    this.finalStates.set(state, {
      status,
      fingerprint,
      expiresAt: Math.max(sourceExpiry, Date.now()) + this.replayRetentionMs,
    });
  }

  private toSummary(record: InteractiveAuthSessionRecord): InteractiveAuthSessionSummary {
    return {
      sessionId: record.sessionId,
      fingerprint: record.fingerprint,
      state: record.state,
      redirectUrl: record.redirectUrl,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
    };
  }

  private respond(res: ServerResponse, statusCode: number, contentType: string, body: string): void {
    res.writeHead(statusCode, {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
    });
    res.end(body);
  }
}

export async function openSystemBrowser(url: string | URL): Promise<void> {
  const parsed = parseBrowserUrl(url);

  await new Promise<void>((resolve, reject) => {
    let child;
    if (process.platform === "darwin") {
      child = spawn("open", [parsed.toString()], { detached: true, stdio: "ignore" });
    } else if (process.platform === "win32") {
      child = spawn("cmd", ["/c", "start", "", parsed.toString()], {
        detached: true,
        stdio: "ignore",
        windowsHide: true,
      });
    } else {
      child = spawn("xdg-open", [parsed.toString()], { detached: true, stdio: "ignore" });
    }

    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

function parseBrowserUrl(url: string | URL): URL {
  const parsed = url instanceof URL ? url : new URL(url);
  if (!SAFE_BROWSER_PROTOCOLS.has(parsed.protocol)) {
    throw new Error(`Refusing to open unsupported browser URL scheme: ${parsed.protocol}`);
  }
  return parsed;
}

function createHighEntropyState(): string {
  return randomBytes(32).toString("base64url");
}

function normalizeCallbackPath(pathname: string): string {
  if (!pathname.startsWith("/")) {
    return `/${pathname}`;
  }
  return pathname;
}

function buildRedirectUrl(host: string, port: number, callbackPath: string): string {
  return `http://${host}:${port}${callbackPath}`;
}

function failureHtml(title: string, message: string): string {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>${escapeHtml(title)}</title>
  </head>
  <body>
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function describeFinalState(status: FinalStateStatus): { statusCode: number; title: string; message: string } {
  switch (status) {
    case "completed":
    case "replayed":
      return {
        statusCode: 409,
        title: "Authorization rejected",
        message: "This authorization state has already been used.",
      };
    case "expired":
      return {
        statusCode: 410,
        title: "Authorization expired",
        message: "This authorization session has expired. Please try again.",
      };
    case "superseded":
      return {
        statusCode: 409,
        title: "Authorization rejected",
        message: "A newer authorization session replaced this one.",
      };
    case "cancelled":
      return {
        statusCode: 400,
        title: "Authorization cancelled",
        message: "This authorization session is no longer active.",
      };
  }
}
