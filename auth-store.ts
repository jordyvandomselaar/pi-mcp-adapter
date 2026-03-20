import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { logger } from "./logger.js";
import type {
  OAuthGrantType,
  OAuthRegistrationMode,
  ServerEntry,
} from "./types.js";
import { getResolvedOAuthAuthConfig } from "./types.js";

const AUTH_STORE_VERSION = 1;
const AUTH_STORE_ROOT = join(homedir(), ".pi", "agent", "mcp-auth");
const LEGACY_OAUTH_ROOT = join(homedir(), ".pi", "agent", "mcp-oauth");
const REDACTED = "[redacted]";

export type AuthInvalidationScope = "all" | "client" | "tokens" | "verifier";
export type LegacyMigrationStatus = "imported" | "skipped-existing";

export interface StoredOAuthTokens extends OAuthTokens {
  expiresAt?: number;
}

export interface AuthFingerprintInput {
  serverUrl: string | URL;
  issuer?: string | URL;
  resource?: string | URL;
  grantType?: OAuthGrantType;
  registrationMode?: OAuthRegistrationMode;
  clientId?: string;
  clientMetadataUrl?: string | URL;
  clientMetadata?: Partial<OAuthClientMetadata> | Record<string, unknown>;
}

export interface AuthFingerprintSeed {
  serverUrl: string;
  resource?: string;
  grantType: OAuthGrantType;
  registrationMode: OAuthRegistrationMode;
  clientIdentity: string;
}

export interface DurableAuthRecord {
  version: number;
  fingerprint: string;
  seed: AuthFingerprintSeed;
  updatedAt: number;
  tokens?: StoredOAuthTokens;
  clientInformation?: OAuthClientInformationMixed;
  clientMetadata?: OAuthClientMetadata;
  migratedFromLegacyServerNames?: string[];
}

export interface EphemeralAuthStateRecord {
  version: number;
  fingerprint: string;
  updatedAt: number;
  codeVerifier?: string;
}

export interface PersistedInteractiveAuthSessionRecord {
  sessionId: string;
  fingerprint: string;
  state: string;
  redirectUrl: string;
  codeVerifier?: string;
  authorizationUrl?: string;
  createdAt: number;
  expiresAt: number;
  status: "pending" | "completed" | "expired" | "superseded" | "cancelled";
  completedAt?: number;
}

export interface AuthStorePaths {
  rootDir: string;
  recordsDir: string;
  ephemeralDir: string;
  sessionsDir: string;
  migrationsDir: string;
  legacyRootDir: string;
}

export interface LegacyMigrationReceipt {
  version: number;
  serverName: string;
  fingerprint: string;
  status: LegacyMigrationStatus;
  migratedAt: number;
}

export interface ProviderStoreAdapter {
  loadClientInformation(): OAuthClientInformationMixed | undefined;
  saveClientInformation(clientInformation: OAuthClientInformationMixed): void;
  loadTokens(): StoredOAuthTokens | undefined;
  saveTokens(tokens: OAuthTokens): void;
  loadCodeVerifier(): string | undefined;
  saveCodeVerifier(codeVerifier: string): void;
  invalidate(scope: AuthInvalidationScope): void;
}

export interface FileAuthStoreOptions {
  rootDir?: string;
  legacyRootDir?: string;
}

export class FileAuthStore {
  readonly paths: AuthStorePaths;
  private readonly log = logger.child({ component: "AuthStore" });

  constructor(options: FileAuthStoreOptions = {}) {
    const rootDir = options.rootDir ?? AUTH_STORE_ROOT;
    this.paths = {
      rootDir,
      recordsDir: join(rootDir, "records"),
      ephemeralDir: join(rootDir, "ephemeral"),
      sessionsDir: join(rootDir, "sessions"),
      migrationsDir: join(rootDir, "migrations"),
      legacyRootDir: options.legacyRootDir ?? LEGACY_OAUTH_ROOT,
    };
  }

  createProviderStore(fingerprint: string, options: { serverName?: string } = {}): ProviderStoreAdapter {
    return {
      loadClientInformation: () => this.loadClientInformation(fingerprint),
      saveClientInformation: (clientInformation) => {
        this.saveClientInformation(fingerprint, clientInformation);
      },
      loadTokens: () => this.loadTokens(fingerprint, options),
      saveTokens: (tokens) => {
        this.saveTokens(fingerprint, tokens);
      },
      loadCodeVerifier: () => this.loadCodeVerifier(fingerprint),
      saveCodeVerifier: (codeVerifier) => {
        this.saveCodeVerifier(fingerprint, codeVerifier);
      },
      invalidate: (scope) => {
        this.invalidate(fingerprint, scope);
      },
    };
  }

  loadRecord(fingerprint: string, options: { serverName?: string } = {}): DurableAuthRecord | undefined {
    this.maybeMigrateLegacyTokens(fingerprint, options.serverName);
    const record = this.readJson<DurableAuthRecord>(this.getRecordPath(fingerprint));
    if (!record || record.version !== AUTH_STORE_VERSION || record.fingerprint !== fingerprint) {
      return undefined;
    }
    return record;
  }

  saveRecord(record: DurableAuthRecord): DurableAuthRecord {
    const next: DurableAuthRecord = {
      version: AUTH_STORE_VERSION,
      ...record,
      updatedAt: Date.now(),
    };
    this.writeJson(this.getRecordPath(record.fingerprint), next);
    return next;
  }

  loadTokens(fingerprint: string, options: { serverName?: string } = {}): StoredOAuthTokens | undefined {
    const record = this.loadRecord(fingerprint, options);
    return record?.tokens ? { ...record.tokens } : undefined;
  }

  saveTokens(fingerprint: string, tokens: OAuthTokens | StoredOAuthTokens): DurableAuthRecord {
    return this.updateRecord(fingerprint, (record) => {
      record.tokens = normalizeStoredTokens(tokens);
    });
  }

  loadClientInformation(fingerprint: string): OAuthClientInformationMixed | undefined {
    const record = this.loadRecord(fingerprint);
    return record?.clientInformation ? clone(record.clientInformation) : undefined;
  }

  saveClientInformation(fingerprint: string, clientInformation: OAuthClientInformationMixed): DurableAuthRecord {
    return this.updateRecord(fingerprint, (record) => {
      record.clientInformation = clone(clientInformation);
    });
  }

  loadClientMetadata(fingerprint: string): OAuthClientMetadata | undefined {
    const record = this.loadRecord(fingerprint);
    return record?.clientMetadata ? clone(record.clientMetadata) : undefined;
  }

  saveClientMetadata(fingerprint: string, clientMetadata: OAuthClientMetadata): DurableAuthRecord {
    return this.updateRecord(fingerprint, (record) => {
      record.clientMetadata = clone(clientMetadata);
    });
  }

  loadCodeVerifier(fingerprint: string): string | undefined {
    const state = this.readJson<EphemeralAuthStateRecord>(this.getEphemeralPath(fingerprint));
    return typeof state?.codeVerifier === "string" ? state.codeVerifier : undefined;
  }

  saveCodeVerifier(fingerprint: string, codeVerifier: string): EphemeralAuthStateRecord {
    const state: EphemeralAuthStateRecord = {
      version: AUTH_STORE_VERSION,
      fingerprint,
      codeVerifier,
      updatedAt: Date.now(),
    };
    this.writeJson(this.getEphemeralPath(fingerprint), state);
    return state;
  }

  clearCodeVerifier(fingerprint: string): void {
    rmSync(this.getEphemeralPath(fingerprint), { force: true });
  }

  invalidate(fingerprint: string, scope: AuthInvalidationScope): DurableAuthRecord | undefined {
    if (scope === "verifier") {
      this.clearCodeVerifier(fingerprint);
      return this.loadRecord(fingerprint);
    }

    if (scope === "all") {
      this.clearCodeVerifier(fingerprint);
      rmSync(this.getRecordPath(fingerprint), { force: true });
      return undefined;
    }

    return this.updateRecord(fingerprint, (record) => {
      if (scope === "client") {
        delete record.clientInformation;
        delete record.clientMetadata;
      }
      if (scope === "tokens") {
        delete record.tokens;
      }
    });
  }

  getMigrationReceipt(serverName: string): LegacyMigrationReceipt | undefined {
    const receipt = this.readJson<LegacyMigrationReceipt>(this.getMigrationReceiptPath(serverName));
    if (!receipt || receipt.version !== AUTH_STORE_VERSION || receipt.serverName !== serverName) {
      return undefined;
    }
    return receipt;
  }

  maybeMigrateLegacyTokens(fingerprint: string, serverName?: string): StoredOAuthTokens | undefined {
    if (!serverName) return undefined;

    const existingReceipt = this.getMigrationReceipt(serverName);
    if (existingReceipt) {
      const record = this.readJson<DurableAuthRecord>(this.getRecordPath(fingerprint));
      return record?.tokens ? { ...record.tokens } : undefined;
    }

    const legacyTokens = readLegacyTokens(this.paths.legacyRootDir, serverName);
    if (!legacyTokens) return undefined;

    const current = this.readJson<DurableAuthRecord>(this.getRecordPath(fingerprint));
    if (current?.tokens) {
      this.writeMigrationReceipt({
        version: AUTH_STORE_VERSION,
        serverName,
        fingerprint,
        status: "skipped-existing",
        migratedAt: Date.now(),
      });
      this.log.info("Skipped legacy OAuth import because durable tokens already exist", {
        server: serverName,
        fingerprint,
      });
      return { ...current.tokens };
    }

    const imported = this.updateRecord(fingerprint, (record) => {
      record.tokens = legacyTokens;
      record.migratedFromLegacyServerNames = uniqueStrings([
        ...(record.migratedFromLegacyServerNames ?? []),
        serverName,
      ]);
    });

    this.writeMigrationReceipt({
      version: AUTH_STORE_VERSION,
      serverName,
      fingerprint,
      status: "imported",
      migratedAt: Date.now(),
    });

    this.log.info("Imported legacy OAuth tokens into durable auth store", {
      server: serverName,
      fingerprint,
      source: "legacy-token-file",
    });

    return imported.tokens ? { ...imported.tokens } : undefined;
  }

  private updateRecord(
    fingerprint: string,
    mutate: (record: DurableAuthRecord) => void,
  ): DurableAuthRecord {
    const current = this.readJson<DurableAuthRecord>(this.getRecordPath(fingerprint));
    const record: DurableAuthRecord = current && current.version === AUTH_STORE_VERSION
      ? current
      : {
          version: AUTH_STORE_VERSION,
          fingerprint,
          seed: {
            serverUrl: "unknown",
            grantType: "authorization_code",
            registrationMode: "auto",
            clientIdentity: "default",
          },
          updatedAt: Date.now(),
        };

    mutate(record);
    return this.saveRecord(record);
  }

  private writeMigrationReceipt(receipt: LegacyMigrationReceipt): void {
    this.writeJson(this.getMigrationReceiptPath(receipt.serverName), receipt);
  }

  private getRecordPath(fingerprint: string): string {
    return join(this.paths.recordsDir, `${fingerprint}.json`);
  }

  private getEphemeralPath(fingerprint: string): string {
    return join(this.paths.ephemeralDir, `${fingerprint}.json`);
  }

  private getMigrationReceiptPath(serverName: string): string {
    return join(this.paths.migrationsDir, `${safeFileComponent(serverName)}.json`);
  }

  private readJson<T>(filePath: string): T | undefined {
    if (!existsSync(filePath)) return undefined;
    try {
      return JSON.parse(readFileSync(filePath, "utf-8")) as T;
    } catch {
      return undefined;
    }
  }

  private writeJson(filePath: string, value: unknown): void {
    mkdirSync(dirname(filePath), { recursive: true });
    const tmpPath = `${filePath}.${process.pid}.tmp`;
    writeFileSync(tmpPath, JSON.stringify(value, null, 2) + "\n", "utf-8");
    renameSync(tmpPath, filePath);
  }
}

export class FileInteractiveAuthSessionStore {
  constructor(private readonly rootDir: string = join(AUTH_STORE_ROOT, "sessions")) {}

  getBySessionId(sessionId: string): PersistedInteractiveAuthSessionRecord | undefined {
    return this.readSession(join(this.rootDir, `${sessionId}.json`));
  }

  getByFingerprint(fingerprint: string): PersistedInteractiveAuthSessionRecord | undefined {
    return this.list()
      .filter((record) => record.fingerprint === fingerprint)
      .sort((a, b) => b.createdAt - a.createdAt)[0];
  }

  getByState(state: string): PersistedInteractiveAuthSessionRecord | undefined {
    return this.list().find((record) => record.state === state);
  }

  list(): PersistedInteractiveAuthSessionRecord[] {
    if (!existsSync(this.rootDir)) return [];
    return readdirSync(this.rootDir)
      .filter((name) => name.endsWith(".json"))
      .map((name) => this.readSession(join(this.rootDir, name)))
      .filter((record): record is PersistedInteractiveAuthSessionRecord => Boolean(record));
  }

  set(record: PersistedInteractiveAuthSessionRecord): void {
    mkdirSync(this.rootDir, { recursive: true });
    const filePath = join(this.rootDir, `${record.sessionId}.json`);
    const tmpPath = `${filePath}.${process.pid}.tmp`;
    writeFileSync(tmpPath, JSON.stringify(record, null, 2) + "\n", "utf-8");
    renameSync(tmpPath, filePath);
  }

  delete(sessionId: string): void {
    rmSync(join(this.rootDir, `${sessionId}.json`), { force: true });
  }

  private readSession(filePath: string): PersistedInteractiveAuthSessionRecord | undefined {
    if (!existsSync(filePath)) return undefined;
    try {
      const parsed = JSON.parse(readFileSync(filePath, "utf-8")) as PersistedInteractiveAuthSessionRecord;
      return parsed?.sessionId ? parsed : undefined;
    } catch {
      return undefined;
    }
  }
}

const defaultAuthStore = new FileAuthStore();

export function getStoredTokens(
  serverName: string,
  definition: ServerEntry,
  authStore: FileAuthStore = defaultAuthStore,
  options: { includeExpired?: boolean } = {},
): OAuthTokens | undefined {
  const fingerprint = createAuthFingerprintFromServer(definition);
  if (!fingerprint) {
    return undefined;
  }

  const stored = authStore.loadTokens(fingerprint, { serverName });
  if (!stored) {
    return undefined;
  }

  if (!options.includeExpired && stored.expiresAt && Date.now() > stored.expiresAt) {
    return undefined;
  }

  return {
    access_token: stored.access_token,
    token_type: stored.token_type ?? "bearer",
    refresh_token: stored.refresh_token,
    expires_in: stored.expires_in,
    scope: stored.scope,
    id_token: stored.id_token,
  };
}

export function getDefaultAuthStoreRoot(): string {
  return AUTH_STORE_ROOT;
}

export function getDefaultLegacyOAuthRoot(): string {
  return LEGACY_OAUTH_ROOT;
}

export function buildAuthFingerprintSeed(input: AuthFingerprintInput): AuthFingerprintSeed {
  return {
    serverUrl: normalizeUrlLike(input.serverUrl),
    resource: input.resource ? normalizeUrlLike(input.resource) : undefined,
    grantType: input.grantType ?? "authorization_code",
    registrationMode: input.registrationMode ?? "auto",
    clientIdentity: resolveClientIdentity(input),
  };
}

export function createAuthFingerprint(input: AuthFingerprintInput): string {
  const seed = buildAuthFingerprintSeed(input);
  const normalized = stableStringify(seed);
  return createHash("sha256").update(normalized).digest("hex");
}

export function createAuthFingerprintFromServer(definition: ServerEntry): string | undefined {
  const input = getAuthFingerprintInputFromServer(definition);
  return input ? createAuthFingerprint(input) : undefined;
}

export function getAuthFingerprintInputFromServer(definition: ServerEntry): AuthFingerprintInput | undefined {
  const oauth = getResolvedOAuthAuthConfig(definition);
  if (!definition.url || !oauth) {
    return undefined;
  }

  return {
    serverUrl: definition.url,
    issuer: oauth.issuer,
    resource: oauth.resource,
    grantType: oauth.grantType,
    registrationMode: oauth.registration.mode,
    clientId: resolveConfiguredValue(
      oauth.client?.information?.clientId,
      oauth.client?.information?.clientIdEnv,
    ),
    clientMetadataUrl: oauth.client?.metadataUrl,
    clientMetadata: oauth.client?.metadata as Record<string, unknown> | undefined,
  };
}

export function readLegacyTokens(legacyRootDir: string, serverName: string): StoredOAuthTokens | undefined {
  const legacyPath = join(legacyRootDir, serverName, "tokens.json");
  if (!existsSync(legacyPath)) return undefined;

  try {
    const parsed = JSON.parse(readFileSync(legacyPath, "utf-8")) as StoredOAuthTokens;
    if (!parsed?.access_token || typeof parsed.access_token !== "string") {
      return undefined;
    }
    return normalizeStoredTokens(parsed);
  } catch {
    return undefined;
  }
}

export function normalizeStoredTokens(tokens: OAuthTokens | StoredOAuthTokens): StoredOAuthTokens {
  const now = Date.now();
  const normalized: StoredOAuthTokens = {
    ...tokens,
    token_type: tokens.token_type ?? "bearer",
  };

  if (normalized.expiresAt === undefined && typeof normalized.expires_in === "number" && Number.isFinite(normalized.expires_in)) {
    normalized.expiresAt = now + normalized.expires_in * 1000;
  }

  return normalized;
}

export function redactAuthRecordForLogs(record: DurableAuthRecord | undefined): unknown {
  if (!record) return record;
  return {
    ...record,
    tokens: record.tokens
      ? {
          ...record.tokens,
          access_token: REDACTED,
          refresh_token: record.tokens.refresh_token ? REDACTED : undefined,
          id_token: record.tokens.id_token ? REDACTED : undefined,
        }
      : undefined,
    clientInformation: record.clientInformation
      ? {
          ...record.clientInformation,
          client_secret: "client_secret" in record.clientInformation && record.clientInformation.client_secret
            ? REDACTED
            : undefined,
        }
      : undefined,
  };
}

function resolveConfiguredValue(value?: string, envName?: string): string | undefined {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }

  if (typeof envName === "string" && envName.length > 0) {
    return process.env[envName];
  }

  return undefined;
}

function resolveClientIdentity(input: AuthFingerprintInput): string {
  const mode = input.registrationMode ?? "auto";

  if (mode === "static") {
    return input.clientId ? `client_id:${input.clientId}` : "static";
  }

  if (mode === "metadata-url") {
    return input.clientMetadataUrl
      ? `metadata_url:${normalizeUrlLike(input.clientMetadataUrl)}`
      : "metadata-url";
  }

  if (mode === "dynamic") {
    if (input.clientMetadata && Object.keys(input.clientMetadata).length > 0) {
      const normalizedMetadata = normalizeFingerprintMetadata(input.clientMetadata);
      const digest = createHash("sha256").update(stableStringify(normalizedMetadata)).digest("hex");
      return `dynamic:${digest}`;
    }

    return "dynamic";
  }

  if (input.clientId) {
    return `client_id:${input.clientId}`;
  }

  if (input.clientMetadataUrl) {
    return `metadata_url:${normalizeUrlLike(input.clientMetadataUrl)}`;
  }

  if (input.clientMetadata && Object.keys(input.clientMetadata).length > 0) {
    const normalizedMetadata = normalizeFingerprintMetadata(input.clientMetadata);
    const digest = createHash("sha256").update(stableStringify(normalizedMetadata)).digest("hex");
    return `metadata:${digest}`;
  }

  return "default";
}

function normalizeFingerprintMetadata(metadata: Partial<OAuthClientMetadata> | Record<string, unknown>): Record<string, unknown> {
  const copy = clone(metadata) as Record<string, unknown>;
  delete copy.client_secret;
  return copy;
}

function normalizeUrlLike(value: string | URL): string {
  const url = new URL(String(value));
  url.hash = "";
  url.search = "";
  if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
    url.port = "";
  }
  const normalizedPath = url.pathname.replace(/\/+$/, "") || "/";
  url.pathname = normalizedPath;
  return url.toString();
}

function stableStringify(value: unknown): string {
  if (value === null || value === undefined || typeof value !== "object") {
    const serialized = JSON.stringify(value);
    return serialized === undefined ? "undefined" : serialized;
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`).join(",")}}`;
}

function safeFileComponent(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "_");
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}
