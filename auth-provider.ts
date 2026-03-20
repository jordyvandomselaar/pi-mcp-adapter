import type { AddClientAuthentication, OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";

export type AuthFlowType = "authorization_code" | "client_credentials";
export type AuthInvalidationScope = "all" | "client" | "tokens" | "verifier";
export type AuthInteractionReason = "user" | "background" | "startup" | "reconnect" | "refresh" | "unknown";
export type AuthPolicyMode = "interactive" | "silent-only" | "blocked" | "non-interactive";

export interface AuthProviderStore {
  loadClientInformation(): OAuthClientInformationMixed | undefined | Promise<OAuthClientInformationMixed | undefined>;
  saveClientInformation(clientInformation: OAuthClientInformationMixed): void | Promise<void>;
  loadTokens(): OAuthTokens | undefined | Promise<OAuthTokens | undefined>;
  saveTokens(tokens: OAuthTokens): void | Promise<void>;
  loadCodeVerifier(): string | undefined | Promise<string | undefined>;
  saveCodeVerifier(codeVerifier: string): void | Promise<void>;
  invalidate(scope: AuthInvalidationScope): void | Promise<void>;
}

export interface AuthPolicyDecision {
  flow: AuthFlowType;
  interactiveAllowed: boolean;
  reason: AuthInteractionReason;
  hasRefreshToken: boolean;
  canRefreshSilently: boolean;
  willAttemptBrowser: boolean;
  mode: AuthPolicyMode;
  summary: string;
}

export interface AuthProviderEvent {
  type:
    | "client_information_saved"
    | "client_information_ignored"
    | "tokens_saved"
    | "code_verifier_saved"
    | "credentials_invalidated"
    | "authorization_redirect_requested"
    | "interactive_authorization_blocked";
  flow: AuthFlowType;
  serverName?: string;
  fingerprint?: string;
  detail?: unknown;
}

export interface AuthProviderBaseOptions {
  serverUrl: string | URL;
  serverName?: string;
  fingerprint?: string;
  store: AuthProviderStore;
  clientMetadata?: Partial<OAuthClientMetadata>;
  staticClientInformation?: OAuthClientInformationMixed;
  clientMetadataUrl?: string | URL;
  addClientAuthentication?: AddClientAuthentication;
  interactiveAllowed?: boolean;
  interactionReason?: AuthInteractionReason;
  onEvent?: (event: AuthProviderEvent) => void;
}

export interface AuthorizationRedirectContext {
  flow: "authorization_code";
  serverUrl: string;
  serverName?: string;
  fingerprint?: string;
  decision: AuthPolicyDecision;
}

export interface AuthorizationCodeProviderOptions extends AuthProviderBaseOptions {
  redirectUrl: string | URL;
  getState?: () => string | Promise<string>;
  redirectToAuthorization: (authorizationUrl: URL, context: AuthorizationRedirectContext) => void | Promise<void>;
}

export interface ClientCredentialsProviderOptions extends AuthProviderBaseOptions {}

export type SdkAuthProviderOptions =
  | ({ flow: "authorization_code" } & AuthorizationCodeProviderOptions)
  | ({ flow: "client_credentials" } & ClientCredentialsProviderOptions);

export interface PiOAuthClientProvider extends OAuthClientProvider {
  readonly flow: AuthFlowType;
  readonly interactiveAllowed: boolean;
  getPolicyDecision(input?: { hasRefreshToken?: boolean }): AuthPolicyDecision;
}

export class InteractiveAuthorizationRequiredError extends Error {
  readonly code = "interactive_authorization_required" as const;
  readonly decision: AuthPolicyDecision;
  readonly serverUrl: string;
  readonly serverName?: string;
  readonly fingerprint?: string;

  constructor(options: {
    decision: AuthPolicyDecision;
    serverUrl: string;
    serverName?: string;
    fingerprint?: string;
  }) {
    const target = options.serverName ?? options.serverUrl;
    super(`Interactive authorization is required for ${target}, but browser launch is disabled (${options.decision.reason}).`);
    this.name = "InteractiveAuthorizationRequiredError";
    this.decision = options.decision;
    this.serverUrl = options.serverUrl;
    this.serverName = options.serverName;
    this.fingerprint = options.fingerprint;
  }
}

export function isInteractiveAuthorizationRequiredError(
  error: unknown
): error is InteractiveAuthorizationRequiredError {
  return error instanceof InteractiveAuthorizationRequiredError;
}

export function resolveAuthPolicyDecision(options: {
  flow: AuthFlowType;
  interactiveAllowed?: boolean;
  interactionReason?: AuthInteractionReason;
  hasRefreshToken?: boolean;
}): AuthPolicyDecision {
  const interactiveAllowed = options.interactiveAllowed ?? true;
  const reason = options.interactionReason ?? "unknown";
  const hasRefreshToken = options.hasRefreshToken ?? false;

  if (options.flow === "client_credentials") {
    return {
      flow: options.flow,
      interactiveAllowed,
      reason,
      hasRefreshToken,
      canRefreshSilently: false,
      willAttemptBrowser: false,
      mode: "non-interactive",
      summary: "Non-interactive client_credentials can fetch tokens without a browser.",
    };
  }

  if (interactiveAllowed) {
    return {
      flow: options.flow,
      interactiveAllowed,
      reason,
      hasRefreshToken,
      canRefreshSilently: hasRefreshToken,
      willAttemptBrowser: true,
      mode: "interactive",
      summary: hasRefreshToken
        ? "Authorization code flow may refresh silently and can fall back to browser authorization if needed."
        : "Authorization code flow may open the browser when fresh user authorization is required.",
    };
  }

  if (hasRefreshToken) {
    return {
      flow: options.flow,
      interactiveAllowed,
      reason,
      hasRefreshToken,
      canRefreshSilently: true,
      willAttemptBrowser: false,
      mode: "silent-only",
      summary: "Authorization code flow is limited to silent refresh because interactive auth is disabled.",
    };
  }

  return {
    flow: options.flow,
    interactiveAllowed,
    reason,
    hasRefreshToken,
    canRefreshSilently: false,
    willAttemptBrowser: false,
    mode: "blocked",
    summary: "Authorization code flow needs user interaction, but interactive auth is disabled.",
  };
}

export function buildAuthorizationCodeClientMetadata(
  redirectUrl: string | URL,
  metadata: Partial<OAuthClientMetadata> = {}
): OAuthClientMetadata {
  const normalizedRedirect = String(redirectUrl);
  const redirectUris = uniqueStrings([...(metadata.redirect_uris ?? []), normalizedRedirect]);
  const grantTypes = uniqueStrings([...(metadata.grant_types ?? []), "authorization_code", "refresh_token"]);
  const responseTypes = uniqueStrings([...(metadata.response_types ?? []), "code"]);

  return {
    ...metadata,
    redirect_uris: redirectUris,
    grant_types: grantTypes,
    response_types: responseTypes,
  };
}

export function buildClientCredentialsClientMetadata(
  metadata: Partial<OAuthClientMetadata> = {}
): OAuthClientMetadata {
  const grantTypes = uniqueStrings([...(metadata.grant_types ?? []), "client_credentials"]);

  return {
    ...metadata,
    redirect_uris: metadata.redirect_uris ?? [],
    grant_types: grantTypes,
  };
}

export function createSdkAuthProvider(options: SdkAuthProviderOptions): PiOAuthClientProvider {
  if (options.flow === "authorization_code") {
    return createAuthorizationCodeProvider(options);
  }
  return createClientCredentialsProvider(options);
}

export function createAuthorizationCodeProvider(
  options: AuthorizationCodeProviderOptions
): PiOAuthClientProvider {
  return new AuthorizationCodeSdkAuthProvider(options);
}

export function createClientCredentialsProvider(
  options: ClientCredentialsProviderOptions
): PiOAuthClientProvider {
  return new ClientCredentialsSdkAuthProvider(options);
}

abstract class BaseSdkAuthProvider implements PiOAuthClientProvider {
  readonly flow: AuthFlowType;
  abstract get redirectUrl(): string | URL | undefined;
  abstract redirectToAuthorization(authorizationUrl: URL): void | Promise<void>;

  readonly addClientAuthentication?: AddClientAuthentication;
  readonly clientMetadataUrl?: string;
  readonly interactiveAllowed: boolean;

  protected readonly serverUrl: string;
  protected readonly serverName?: string;
  protected readonly fingerprint?: string;
  protected readonly store: AuthProviderStore;
  protected readonly staticClientInformation?: OAuthClientInformationMixed;
  protected readonly onEvent?: (event: AuthProviderEvent) => void;
  protected readonly interactionReason: AuthInteractionReason;
  private readonly _clientMetadata: OAuthClientMetadata;

  constructor(flow: AuthFlowType, options: AuthProviderBaseOptions, clientMetadata: OAuthClientMetadata) {
    this.flow = flow;
    this.serverUrl = String(options.serverUrl);
    this.serverName = options.serverName;
    this.fingerprint = options.fingerprint;
    this.store = options.store;
    this.staticClientInformation = options.staticClientInformation;
    this.clientMetadataUrl = options.clientMetadataUrl ? String(options.clientMetadataUrl) : undefined;
    this.addClientAuthentication = options.addClientAuthentication;
    this.interactiveAllowed = options.interactiveAllowed ?? true;
    this.interactionReason = options.interactionReason ?? "unknown";
    this.onEvent = options.onEvent;
    this._clientMetadata = clientMetadata;
  }

  get clientMetadata(): OAuthClientMetadata {
    return this._clientMetadata;
  }

  getPolicyDecision(input?: { hasRefreshToken?: boolean }): AuthPolicyDecision {
    return resolveAuthPolicyDecision({
      flow: this.flow,
      interactiveAllowed: this.interactiveAllowed,
      interactionReason: this.interactionReason,
      hasRefreshToken: input?.hasRefreshToken,
    });
  }

  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    if (this.staticClientInformation) {
      return this.staticClientInformation;
    }

    return await this.store.loadClientInformation();
  }

  async saveClientInformation(clientInformation: OAuthClientInformationMixed): Promise<void> {
    if (this.staticClientInformation) {
      this.emit("client_information_ignored", {
        reason: "static_client_information_configured",
        clientInformation,
      });
      return;
    }

    await this.store.saveClientInformation(clientInformation);
    this.emit("client_information_saved", { clientInformation });
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    return await this.store.loadTokens();
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    await this.store.saveTokens(tokens);
    this.emit("tokens_saved", { tokens });
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    await this.store.saveCodeVerifier(codeVerifier);
    this.emit("code_verifier_saved", { codeVerifier });
  }

  async codeVerifier(): Promise<string> {
    const codeVerifier = await this.store.loadCodeVerifier();
    if (!codeVerifier) {
      throw new Error("No PKCE code verifier is available for the current OAuth session.");
    }
    return codeVerifier;
  }

  async invalidateCredentials(scope: AuthInvalidationScope): Promise<void> {
    await this.store.invalidate(scope);
    this.emit("credentials_invalidated", { scope });
  }

  protected emit(type: AuthProviderEvent["type"], detail?: unknown): void {
    this.onEvent?.({
      type,
      flow: this.flow,
      serverName: this.serverName,
      fingerprint: this.fingerprint,
      detail: redactAuthForLogs(detail),
    });
  }
}

class AuthorizationCodeSdkAuthProvider extends BaseSdkAuthProvider {
  readonly state?: () => Promise<string>;
  private readonly _redirectUrl: string;
  private readonly redirectHandler: AuthorizationCodeProviderOptions["redirectToAuthorization"];

  constructor(options: AuthorizationCodeProviderOptions) {
    super(
      "authorization_code",
      options,
      buildAuthorizationCodeClientMetadata(options.redirectUrl, options.clientMetadata)
    );

    this._redirectUrl = String(options.redirectUrl);
    this.redirectHandler = options.redirectToAuthorization;
    this.state = options.getState
      ? async () => String(await options.getState!())
      : undefined;
  }

  get redirectUrl(): string {
    return this._redirectUrl;
  }

  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    const decision = this.getPolicyDecision({ hasRefreshToken: false });

    if (!decision.willAttemptBrowser) {
      this.emit("interactive_authorization_blocked", {
        decision,
        authorizationUrl,
      });

      throw new InteractiveAuthorizationRequiredError({
        decision,
        serverUrl: this.serverUrl,
        serverName: this.serverName,
        fingerprint: this.fingerprint,
      });
    }

    this.emit("authorization_redirect_requested", {
      decision,
      authorizationUrl,
    });

    await this.redirectHandler(authorizationUrl, {
      flow: "authorization_code",
      serverUrl: this.serverUrl,
      serverName: this.serverName,
      fingerprint: this.fingerprint,
      decision,
    });
  }
}

class ClientCredentialsSdkAuthProvider extends BaseSdkAuthProvider {
  constructor(options: ClientCredentialsProviderOptions) {
    super(
      "client_credentials",
      options,
      buildClientCredentialsClientMetadata(options.clientMetadata)
    );
  }

  get redirectUrl(): undefined {
    return undefined;
  }

  redirectToAuthorization(_authorizationUrl: URL): void {
    throw new Error("redirectToAuthorization is not used for client_credentials flow.");
  }

  async saveCodeVerifier(_codeVerifier: string): Promise<void> {
    // client_credentials never uses PKCE
  }

  async codeVerifier(): Promise<string> {
    throw new Error("codeVerifier is not used for client_credentials flow.");
  }

  prepareTokenRequest(scope?: string): URLSearchParams {
    const params = new URLSearchParams({ grant_type: "client_credentials" });
    if (scope) {
      params.set("scope", scope);
    }
    return params;
  }
}

const REDACTED = "[redacted]";
const CIRCULAR = "[circular]";

export function redactAuthForLogs(value: unknown): unknown {
  return redactValue(undefined, value, new WeakSet<object>());
}

function redactValue(key: string | undefined, value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (key && isSensitiveAuthKey(key)) {
    return REDACTED;
  }

  if (typeof value === "string") {
    return redactString(value);
  }

  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value;
  }

  if (value instanceof URL) {
    return redactUrl(value);
  }

  if (typeof Headers !== "undefined" && value instanceof Headers) {
    const headers: Record<string, string> = {};
    value.forEach((headerValue, headerKey) => {
      headers[headerKey] = String(redactValue(headerKey, headerValue, seen));
    });
    return headers;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(key, item, seen));
  }

  if (typeof value === "object") {
    if (seen.has(value)) {
      return CIRCULAR;
    }

    seen.add(value);
    const result: Record<string, unknown> = {};
    for (const [entryKey, entryValue] of Object.entries(value)) {
      result[entryKey] = redactValue(entryKey, entryValue, seen);
    }
    seen.delete(value);
    return result;
  }

  return String(value);
}

function redactString(value: string): string {
  if (/^(Bearer|Basic)\s+/i.test(value)) {
    return REDACTED;
  }

  try {
    const url = new URL(value);
    return redactUrl(url);
  } catch {
    return value;
  }
}

function redactUrl(url: URL): string {
  const hasQuery = Boolean(url.search);
  const hasHash = Boolean(url.hash);
  return `${url.origin}${url.pathname}${hasQuery ? "?<redacted>" : ""}${hasHash ? "#<redacted>" : ""}`;
}

function isSensitiveAuthKey(key: string): boolean {
  const normalized = key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/-/g, "_")
    .toLowerCase();
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

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}
