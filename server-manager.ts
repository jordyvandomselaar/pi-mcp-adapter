import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
  type StreamableHTTPClientTransportOptions,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport, type SSEClientTransportOptions } from "@modelcontextprotocol/sdk/client/sse.js";
import { OAuthError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { ReadResourceResult } from "@modelcontextprotocol/sdk/types.js";
import type {
  McpTool,
  McpResource,
  OAuthClientInformationConfig,
  OAuthClientMetadataConfig,
  ServerDefinition,
  ServerStreamResultPatchNotification,
  Transport,
} from "./types.js";
import {
  getBearerAuthConfig,
  getResolvedOAuthAuthConfig,
  getServerAuthType,
  serverStreamResultPatchNotificationSchema,
  type OAuthRegistrationMode,
  type ResolvedOAuthAuthConfig,
} from "./types.js";
import {
  createSdkAuthProvider,
  InteractiveAuthorizationRequiredError,
  isInteractiveAuthorizationRequiredError,
  resolveAuthPolicyDecision,
  type AuthInteractionReason,
  type PiOAuthClientProvider,
} from "./auth-provider.js";
import { LoopbackAuthSessionManager, type InteractiveAuthSessionHandle } from "./auth-session-manager.js";
import { FileAuthStore, createAuthFingerprintFromServer } from "./auth-store.js";
import { resolveNpxBinary } from "./npx-resolver.js";
import { logger } from "./logger.js";

interface ServerConnection {
  client: Client;
  transport: Transport;
  definition: ServerDefinition;
  tools: McpTool[];
  resources: McpResource[];
  lastUsedAt: number;
  inFlight: number;
  status: "connected" | "closed";
}

export interface ServerConnectOptions {
  interactiveAllowed?: boolean;
  interactionReason?: AuthInteractionReason;
}

export interface McpServerManagerOptions {
  authStore?: FileAuthStore;
  authSessionManager?: Pick<LoopbackAuthSessionManager, "start" | "startAttempt" | "redirectUrl">;
  createClient?: (clientInfo: { name: string; version: string }) => Client;
  createStreamableTransport?: (
    url: URL,
    options?: StreamableHTTPClientTransportOptions,
  ) => StreamableHTTPClientTransport;
  createSseTransport?: (
    url: URL,
    options?: SSEClientTransportOptions,
  ) => SSEClientTransport;
}

type UiStreamListener = (serverName: string, notification: ServerStreamResultPatchNotification["params"]) => void;
type TransportKind = "streamable" | "sse";
type FinishAuthTransport = Transport & { finishAuth?: (authorizationCode: string) => Promise<void> };

interface PendingAuthorizationContext {
  hasPendingAuthorization(): boolean;
  completeAuthorization(transport: FinishAuthTransport): Promise<void>;
  discardPendingAuthorization(reason?: string): Promise<void>;
}

interface HttpTransportBundle {
  createTransport: () => Transport;
  authContext?: PendingAuthorizationContext;
}

export class McpServerManager {
  private connections = new Map<string, ServerConnection>();
  private connectPromises = new Map<string, Promise<ServerConnection>>();
  private uiStreamListeners = new Map<string, UiStreamListener>();
  private readonly authStore: FileAuthStore;
  private readonly authSessionManager: Pick<LoopbackAuthSessionManager, "start" | "startAttempt" | "redirectUrl">;
  private readonly clientFactory: (clientInfo: { name: string; version: string }) => Client;
  private readonly streamableTransportFactory: (
    url: URL,
    options?: StreamableHTTPClientTransportOptions,
  ) => StreamableHTTPClientTransport;
  private readonly sseTransportFactory: (
    url: URL,
    options?: SSEClientTransportOptions,
  ) => SSEClientTransport;

  constructor(options: McpServerManagerOptions = {}) {
    this.authStore = options.authStore ?? new FileAuthStore();
    this.authSessionManager = options.authSessionManager ?? new LoopbackAuthSessionManager();
    this.clientFactory = options.createClient ?? ((clientInfo) => new Client(clientInfo));
    this.streamableTransportFactory = options.createStreamableTransport
      ?? ((url, transportOptions) => new StreamableHTTPClientTransport(url, transportOptions));
    this.sseTransportFactory = options.createSseTransport
      ?? ((url, transportOptions) => new SSEClientTransport(url, transportOptions));
  }

  async connect(
    name: string,
    definition: ServerDefinition,
    options: ServerConnectOptions = {},
  ): Promise<ServerConnection> {
    // Dedupe concurrent connection attempts
    if (this.connectPromises.has(name)) {
      return this.connectPromises.get(name)!;
    }

    // Reuse existing connection if healthy
    const existing = this.connections.get(name);
    if (existing?.status === "connected") {
      existing.lastUsedAt = Date.now();
      return existing;
    }

    const promise = this.createConnection(name, definition, options);
    this.connectPromises.set(name, promise);

    try {
      const connection = await promise;
      this.connections.set(name, connection);
      return connection;
    } finally {
      this.connectPromises.delete(name);
    }
  }

  private async createConnection(
    name: string,
    definition: ServerDefinition,
    options: ServerConnectOptions,
  ): Promise<ServerConnection> {
    const client = this.createClient({ name: `pi-mcp-${name}`, version: "1.0.0" });

    let transport: Transport;

    if (definition.command) {
      let command = definition.command;
      let args = definition.args ?? [];

      if (command === "npx" || command === "npm") {
        const resolved = await resolveNpxBinary(command, args);
        if (resolved) {
          command = resolved.isJs ? "node" : resolved.binPath;
          args = resolved.isJs ? [resolved.binPath, ...resolved.extraArgs] : resolved.extraArgs;
          logger.debug(`${name} resolved to ${resolved.binPath} (skipping npm parent)`);
        }
      }

      transport = new StdioClientTransport({
        command,
        args,
        env: resolveEnv(definition.env),
        cwd: definition.cwd,
        stderr: definition.debug ? "inherit" : "ignore",
      });
    } else if (definition.url) {
      transport = await this.createHttpTransport(definition, name, options);
    } else {
      throw new Error(`Server ${name} has no command or url`);
    }

    try {
      await client.connect(transport);
      this.attachAdapterNotificationHandlers(name, client);

      // Discover tools and resources
      const [tools, resources] = await Promise.all([
        this.fetchAllTools(client),
        this.fetchAllResources(client),
      ]);

      return {
        client,
        transport,
        definition,
        tools,
        resources,
        lastUsedAt: Date.now(),
        inFlight: 0,
        status: "connected",
      };
    } catch (error) {
      // Clean up both client and transport on any error
      await client.close().catch(() => {});
      await transport.close().catch(() => {});
      throw error;
    }
  }

  private async createHttpTransport(
    definition: ServerDefinition,
    serverName?: string,
    options: ServerConnectOptions = {},
  ): Promise<Transport> {
    const streamable = await this.buildHttpTransportBundle("streamable", definition, serverName, options);

    try {
      await this.probeTransport(streamable);
      return streamable.createTransport();
    } catch (error) {
      await streamable.authContext?.discardPendingAuthorization("streamable transport probe failed");

      if (!isStreamableTransportMismatch(error)) {
        throw error;
      }

      const sse = await this.buildHttpTransportBundle("sse", definition, serverName, options);

      try {
        await this.probeTransport(sse);
        return sse.createTransport();
      } catch (sseError) {
        await sse.authContext?.discardPendingAuthorization("sse transport probe failed");
        throw sseError;
      }
    }
  }

  private async buildHttpTransportBundle(
    kind: TransportKind,
    definition: ServerDefinition,
    serverName: string | undefined,
    options: ServerConnectOptions,
  ): Promise<HttpTransportBundle> {
    const url = new URL(definition.url!);
    const headers = resolveHeaders(definition.headers) ?? {};
    const authType = getServerAuthType(definition);
    const bearer = getBearerAuthConfig(definition);

    if (authType === "bearer") {
      const token = bearer?.token
        ?? (bearer?.tokenEnv ? process.env[bearer.tokenEnv] : undefined);
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
    }

    const requestInit = Object.keys(headers).length > 0 ? { headers } : undefined;

    if (authType !== "oauth") {
      return {
        createTransport: () => this.createHttpClientTransport(kind, url, { requestInit }),
      };
    }

    if (!serverName) {
      throw new Error("Server name required for OAuth authentication");
    }

    const { authProvider, authContext } = await this.createOAuthAuthProvider(definition, serverName, options);

    return {
      authContext,
      createTransport: () => this.createHttpClientTransport(kind, url, {
        requestInit,
        authProvider,
      }),
    };
  }

  private createHttpClientTransport(
    kind: TransportKind,
    url: URL,
    options: { requestInit?: RequestInit; authProvider?: PiOAuthClientProvider },
  ): Transport {
    const transportUrl = new URL(url);

    if (kind === "streamable") {
      return this.streamableTransportFactory(transportUrl, {
        requestInit: options.requestInit,
        authProvider: options.authProvider,
      });
    }

    return this.sseTransportFactory(transportUrl, {
      requestInit: options.requestInit,
      authProvider: options.authProvider,
    });
  }

  private async createOAuthAuthProvider(
    definition: ServerDefinition,
    serverName: string,
    options: ServerConnectOptions,
  ): Promise<{ authProvider: PiOAuthClientProvider; authContext?: PendingAuthorizationContext }> {
    const oauth = getResolvedOAuthAuthConfig(definition);
    const fingerprint = createAuthFingerprintFromServer(definition);

    if (!definition.url || !oauth || !fingerprint) {
      throw new Error(`OAuth configuration for "${serverName}" is incomplete`);
    }

    const flow = oauth.grantType;
    const store = this.authStore.createProviderStore(fingerprint, { serverName });
    const staticClientInformation = toOAuthClientInformation(oauth.client?.information);
    const clientMetadata = toOAuthClientMetadata(oauth.client?.metadata, oauth.scope);
    const registration = resolveOAuthRegistrationRuntime(
      oauth,
      staticClientInformation,
      serverName,
    );
    const onEvent = (event: { type: string; detail?: unknown }) => {
      logger.debug(`OAuth provider event: ${event.type}`, {
        serverName,
        fingerprint,
        detail: event.detail,
      });
    };

    const finalizeAuthProvider = (authProvider: PiOAuthClientProvider): PiOAuthClientProvider => {
      if (!registration.allowDynamicClientRegistration) {
        (authProvider as PiOAuthClientProvider & { saveClientInformation?: unknown }).saveClientInformation = undefined;
      }

      if (oauth.resource) {
        (authProvider as PiOAuthClientProvider & {
          validateResourceURL?: (serverUrl: string | URL, resource?: string) => Promise<URL | undefined>;
        }).validateResourceURL = async (serverUrl, discoveredResource) => {
          return resolveConfiguredResourceUrl(serverUrl, oauth.resource!, discoveredResource);
        };
      }

      return authProvider;
    };

    if (flow === "client_credentials") {
      return {
        authProvider: finalizeAuthProvider(
          createSdkAuthProvider({
            flow,
            serverUrl: definition.url,
            serverName,
            fingerprint,
            store,
            staticClientInformation: registration.staticClientInformation,
            clientMetadata,
            clientMetadataUrl: registration.clientMetadataUrl,
            interactiveAllowed: options.interactiveAllowed,
            interactionReason: options.interactionReason,
            onEvent,
          }),
        ),
      };
    }

    const storedTokens = await store.loadTokens();
    if (!storedTokens && options.interactiveAllowed === false) {
      const decision = resolveAuthPolicyDecision({
        flow,
        interactiveAllowed: options.interactiveAllowed,
        interactionReason: options.interactionReason,
        hasRefreshToken: false,
      });

      throw new InteractiveAuthorizationRequiredError({
        decision,
        serverUrl: definition.url,
        serverName,
        fingerprint,
      });
    }

    await this.authSessionManager.start();

    let pendingSession: Promise<InteractiveAuthSessionHandle> | undefined;
    const ensureSession = () => {
      pendingSession ??= this.authSessionManager.startAttempt(fingerprint);
      return pendingSession;
    };
    const clearPendingSession = () => {
      pendingSession = undefined;
    };

    const authProvider = finalizeAuthProvider(
      createSdkAuthProvider({
        flow,
        serverUrl: definition.url,
        serverName,
        fingerprint,
        store,
        staticClientInformation: registration.staticClientInformation,
        clientMetadata,
        clientMetadataUrl: registration.clientMetadataUrl,
        redirectUrl: this.authSessionManager.redirectUrl,
        getState: async () => (await ensureSession()).state,
        redirectToAuthorization: async (authorizationUrl) => {
          const session = await ensureSession();
          await session.openAuthorization(authorizationUrl);
        },
        interactiveAllowed: options.interactiveAllowed,
        interactionReason: options.interactionReason,
        onEvent,
      }),
    );

    const authContext: PendingAuthorizationContext = {
      hasPendingAuthorization: () => pendingSession !== undefined,
      completeAuthorization: async (transport) => {
        const sessionPromise = pendingSession;
        if (!sessionPromise) {
          return;
        }

        const finishAuth = transport.finishAuth;
        if (typeof finishAuth !== "function") {
          throw new Error("Transport does not support finishAuth for OAuth authorization completion");
        }

        try {
          const session = await sessionPromise;
          const result = await session.waitForCallback();
          await finishAuth.call(transport, result.authorizationCode);
        } finally {
          clearPendingSession();
        }
      },
      discardPendingAuthorization: async (reason = "Interactive auth no longer needed") => {
        const sessionPromise = pendingSession;
        clearPendingSession();

        if (!sessionPromise) {
          return;
        }

        try {
          const session = await sessionPromise;
          await session.cancel(reason);
        } catch {
          // Ignore cancellation races; the session may have already completed or expired.
        }
      },
    };

    return { authProvider, authContext };
  }

  private async probeTransport(bundle: HttpTransportBundle): Promise<void> {
    let attemptedInteractiveCompletion = false;

    while (true) {
      const transport = bundle.createTransport();
      const client = this.createClient({ name: "pi-mcp-probe", version: "1.0.0" });

      try {
        await client.connect(transport);
        return;
      } catch (error) {
        const shouldCompleteInteractiveAuth =
          !attemptedInteractiveCompletion
          && bundle.authContext?.hasPendingAuthorization()
          && error instanceof UnauthorizedError;

        if (shouldCompleteInteractiveAuth) {
          attemptedInteractiveCompletion = true;
          await bundle.authContext!.completeAuthorization(transport as FinishAuthTransport);
          continue;
        }

        throw error;
      } finally {
        await client.close().catch(() => {});
        await transport.close().catch(() => {});
      }
    }
  }

  private createClient(clientInfo: { name: string; version: string }): Client {
    return this.clientFactory(clientInfo);
  }

  private async fetchAllTools(client: Client): Promise<McpTool[]> {
    const allTools: McpTool[] = [];
    let cursor: string | undefined;

    do {
      const result = await client.listTools(cursor ? { cursor } : undefined);
      allTools.push(...(result.tools ?? []));
      cursor = result.nextCursor;
    } while (cursor);

    return allTools;
  }

  private async fetchAllResources(client: Client): Promise<McpResource[]> {
    try {
      const allResources: McpResource[] = [];
      let cursor: string | undefined;

      do {
        const result = await client.listResources(cursor ? { cursor } : undefined);
        allResources.push(...(result.resources ?? []));
        cursor = result.nextCursor;
      } while (cursor);

      return allResources;
    } catch {
      // Server may not support resources
      return [];
    }
  }

  private attachAdapterNotificationHandlers(serverName: string, client: Client): void {
    client.setNotificationHandler(serverStreamResultPatchNotificationSchema, (notification) => {
      const listener = this.uiStreamListeners.get(notification.params.streamToken);
      if (!listener) return;
      listener(serverName, notification.params);
    });
  }

  registerUiStreamListener(streamToken: string, listener: UiStreamListener): void {
    this.uiStreamListeners.set(streamToken, listener);
  }

  removeUiStreamListener(streamToken: string): void {
    this.uiStreamListeners.delete(streamToken);
  }

  async readResource(name: string, uri: string): Promise<ReadResourceResult> {
    const connection = this.connections.get(name);
    if (!connection || connection.status !== "connected") {
      throw new Error(`Server "${name}" is not connected`);
    }

    try {
      this.touch(name);
      this.incrementInFlight(name);
      return await connection.client.readResource({ uri });
    } finally {
      this.decrementInFlight(name);
      this.touch(name);
    }
  }

  async close(name: string): Promise<void> {
    const connection = this.connections.get(name);
    if (!connection) return;

    // Delete from map BEFORE async cleanup to prevent a race where a
    // concurrent connect() creates a new connection that our deferred
    // delete() would then remove, orphaning the new server process.
    connection.status = "closed";
    this.connections.delete(name);
    await connection.client.close().catch(() => {});
    await connection.transport.close().catch(() => {});
  }

  async closeAll(): Promise<void> {
    const names = [...this.connections.keys()];
    await Promise.all(names.map(name => this.close(name)));
  }

  getConnection(name: string): ServerConnection | undefined {
    return this.connections.get(name);
  }

  getAllConnections(): Map<string, ServerConnection> {
    return new Map(this.connections);
  }

  touch(name: string): void {
    const connection = this.connections.get(name);
    if (connection) {
      connection.lastUsedAt = Date.now();
    }
  }

  incrementInFlight(name: string): void {
    const connection = this.connections.get(name);
    if (connection) {
      connection.inFlight = (connection.inFlight ?? 0) + 1;
    }
  }

  decrementInFlight(name: string): void {
    const connection = this.connections.get(name);
    if (connection && connection.inFlight) {
      connection.inFlight--;
    }
  }

  isIdle(name: string, timeoutMs: number): boolean {
    const connection = this.connections.get(name);
    if (!connection || connection.status !== "connected") return false;
    if (connection.inFlight > 0) return false;
    return (Date.now() - connection.lastUsedAt) > timeoutMs;
  }
}

function isStreamableTransportMismatch(error: unknown): boolean {
  if (isAuthRelatedTransportError(error)) {
    return false;
  }

  if (error instanceof StreamableHTTPError) {
    if (error.code === -1) {
      return true;
    }

    return error.code !== undefined && [400, 404, 405, 406, 415, 426, 501].includes(error.code);
  }

  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes("unexpected content type")
    || message.includes("method not allowed")
    || message.includes("not found")
    || message.includes("unsupported media type")
    || message.includes("not acceptable")
    || message.includes("upgrade required")
  );
}

function isAuthRelatedTransportError(error: unknown): boolean {
  if (isInteractiveAuthorizationRequiredError(error)) {
    return true;
  }

  if (error instanceof UnauthorizedError || error instanceof OAuthError) {
    return true;
  }

  if (error instanceof StreamableHTTPError && (error.code === 401 || error.code === 403)) {
    return true;
  }

  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes("unauthorized")
    || message.includes("forbidden")
    || message.includes("invalid_grant")
    || message.includes("insufficient_scope")
    || message.includes("interactive authorization")
  );
}

interface OAuthRegistrationRuntime {
  staticClientInformation?: OAuthClientInformationMixed;
  clientMetadataUrl?: string;
  allowDynamicClientRegistration: boolean;
}

function resolveOAuthRegistrationRuntime(
  auth: ResolvedOAuthAuthConfig,
  staticClientInformation: OAuthClientInformationMixed | undefined,
  serverName: string,
): OAuthRegistrationRuntime {
  switch (auth.registration.mode) {
    case "static":
      if (!staticClientInformation) {
        throw new Error(
          `OAuth registration.mode \"static\" for "${serverName}" requires client.information.clientId or clientIdEnv.`,
        );
      }

      return {
        staticClientInformation,
        allowDynamicClientRegistration: false,
      };
    case "metadata-url":
      if (!auth.client?.metadataUrl) {
        throw new Error(
          `OAuth registration.mode \"metadata-url\" for "${serverName}" requires client.metadataUrl.`,
        );
      }

      return {
        clientMetadataUrl: auth.client.metadataUrl,
        allowDynamicClientRegistration: false,
      };
    case "dynamic":
      return {
        allowDynamicClientRegistration: true,
      };
    case "auto":
    default:
      return {
        staticClientInformation,
        clientMetadataUrl: auth.client?.metadataUrl,
        allowDynamicClientRegistration: true,
      };
  }
}

function resolveConfiguredResourceUrl(
  serverUrl: string | URL,
  configuredResource: string | URL,
  discoveredResource?: string,
): URL {
  const defaultResource = new URL(String(serverUrl));
  defaultResource.hash = "";

  const configured = new URL(String(configuredResource));
  configured.hash = "";

  if (!isResourceAllowed(defaultResource, configured)) {
    throw new Error(
      `Configured OAuth resource ${configured.toString()} is not compatible with MCP server ${defaultResource.toString()}.`,
    );
  }

  if (discoveredResource) {
    const discovered = new URL(discoveredResource);
    discovered.hash = "";

    if (!isResourceAllowed(configured, discovered)) {
      throw new Error(
        `Configured OAuth resource ${configured.toString()} is not permitted by protected resource metadata ${discovered.toString()}.`,
      );
    }
  }

  return configured;
}

function isResourceAllowed(requestedResource: string | URL, configuredResource: string | URL): boolean {
  const requested = new URL(String(requestedResource));
  const configured = new URL(String(configuredResource));

  if (requested.origin !== configured.origin) {
    return false;
  }

  if (requested.pathname.length < configured.pathname.length) {
    return false;
  }

  const requestedPath = requested.pathname.endsWith("/")
    ? requested.pathname
    : `${requested.pathname}/`;
  const configuredPath = configured.pathname.endsWith("/")
    ? configured.pathname
    : `${configured.pathname}/`;
  return requestedPath.startsWith(configuredPath);
}

function toOAuthClientInformation(
  config?: OAuthClientInformationConfig,
): OAuthClientInformationMixed | undefined {
  const clientId = resolveConfiguredSecret(config?.clientId, config?.clientIdEnv);
  if (!clientId) {
    return undefined;
  }

  return {
    client_id: clientId,
    client_secret: resolveConfiguredSecret(config?.clientSecret, config?.clientSecretEnv),
    client_id_issued_at: config.clientIdIssuedAt,
    client_secret_expires_at: config.clientSecretExpiresAt,
  };
}

function resolveConfiguredSecret(value?: string, envName?: string): string | undefined {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }

  if (typeof envName === "string" && envName.length > 0) {
    return process.env[envName];
  }

  return undefined;
}

function toOAuthClientMetadata(
  config?: OAuthClientMetadataConfig,
  oauthScope?: string,
): Partial<OAuthClientMetadata> | undefined {
  const scope = config?.scope ?? oauthScope;
  const metadata: Partial<OAuthClientMetadata> = {
    redirect_uris: config?.redirectUris,
    token_endpoint_auth_method: config?.tokenEndpointAuthMethod,
    grant_types: config?.grantTypes,
    response_types: config?.responseTypes,
    client_name: config?.clientName,
    client_uri: config?.clientUri,
    logo_uri: config?.logoUri,
    scope,
    contacts: config?.contacts,
    tos_uri: config?.tosUri,
    policy_uri: config?.policyUri,
    jwks_uri: config?.jwksUri,
    jwks: config?.jwks as OAuthClientMetadata["jwks"],
    software_id: config?.softwareId,
    software_version: config?.softwareVersion,
    software_statement: config?.softwareStatement,
  };

  return Object.values(metadata).some((value) => value !== undefined) ? metadata : undefined;
}

/**
 * Resolve environment variables with interpolation.
 */
function resolveEnv(env?: Record<string, string>): Record<string, string> {
  // Copy process.env, filtering out undefined values
  const resolved: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) {
      resolved[key] = value;
    }
  }

  if (!env) return resolved;

  for (const [key, value] of Object.entries(env)) {
    // Support ${VAR} and $env:VAR interpolation
    resolved[key] = value
      .replace(/\$\{(\w+)\}/g, (_, name) => process.env[name] ?? "")
      .replace(/\$env:(\w+)/g, (_, name) => process.env[name] ?? "");
  }

  return resolved;
}

/**
 * Resolve headers with environment variable interpolation.
 */
function resolveHeaders(headers?: Record<string, string>): Record<string, string> | undefined {
  if (!headers) return undefined;

  const resolved: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    resolved[key] = value
      .replace(/\$\{(\w+)\}/g, (_, name) => process.env[name] ?? "")
      .replace(/\$env:(\w+)/g, (_, name) => process.env[name] ?? "");
  }
  return resolved;
}
