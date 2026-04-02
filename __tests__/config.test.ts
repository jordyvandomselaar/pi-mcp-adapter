import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { loadMcpConfig } from "../config.js";
import {
  getOAuthGrantType,
  getResolvedOAuthAuthConfig,
  getServerAuthType,
  type McpConfig,
} from "../types.js";

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2));
}

describe("loadMcpConfig auth parsing", () => {
  const originalCwd = process.cwd();
  const tempDirs: string[] = [];

  afterEach(() => {
    process.chdir(originalCwd);
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("preserves legacy auth: 'oauth' configs while exposing default SDK auth semantics", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-mcp-config-"));
    tempDirs.push(root);

    const configPath = join(root, "mcp.json");
    writeJson(configPath, {
      mcpServers: {
        demo: {
          url: "https://api.example.com/mcp",
          auth: "oauth",
        },
      },
    } satisfies McpConfig);

    const config = loadMcpConfig(configPath);
    const definition = config.mcpServers.demo;

    expect(definition.auth).toBe("oauth");
    expect(getServerAuthType(definition)).toBe("oauth");
    expect(getOAuthGrantType(definition)).toBe("authorization_code");
    expect(getResolvedOAuthAuthConfig(definition)).toEqual({
      type: "oauth",
      grantType: "authorization_code",
      registration: { mode: "auto" },
    });
  });

  it("retains explicit client_credentials auth settings and registration hints", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-mcp-config-"));
    tempDirs.push(root);

    const configPath = join(root, "mcp.json");
    writeJson(configPath, {
      mcpServers: {
        billing: {
          url: "https://billing.example.com/mcp",
          auth: {
            type: "oauth",
            grantType: "client_credentials",
            scope: "tools:read tools:write",
            registration: { mode: "static" },
            client: {
              information: {
                clientId: "billing-client",
                clientSecret: "top-secret",
              },
              metadata: {
                tokenEndpointAuthMethod: "client_secret_post",
                grantTypes: ["client_credentials"],
              },
            },
          },
        },
      },
    } satisfies McpConfig);

    const config = loadMcpConfig(configPath);
    const definition = config.mcpServers.billing;

    expect(getServerAuthType(definition)).toBe("oauth");
    expect(getResolvedOAuthAuthConfig(definition)).toMatchObject({
      type: "oauth",
      grantType: "client_credentials",
      scope: "tools:read tools:write",
      registration: { mode: "static" },
      client: {
        information: {
          clientId: "billing-client",
          clientSecret: "top-secret",
        },
        metadata: {
          tokenEndpointAuthMethod: "client_secret_post",
          grantTypes: ["client_credentials"],
        },
      },
    });
  });

  it("retains env-backed client_credentials config fields", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-mcp-config-"));
    tempDirs.push(root);

    const configPath = join(root, "mcp.json");
    writeJson(configPath, {
      mcpServers: {
        machine: {
          url: "https://machine.example.com/mcp",
          auth: {
            type: "oauth",
            grantType: "client_credentials",
            client: {
              information: {
                clientIdEnv: "MCP_CLIENT_ID",
                clientSecretEnv: "MCP_CLIENT_SECRET",
              },
            },
          },
        },
      },
    } satisfies McpConfig);

    const config = loadMcpConfig(configPath);
    const definition = config.mcpServers.machine;

    expect(getResolvedOAuthAuthConfig(definition)).toMatchObject({
      type: "oauth",
      grantType: "client_credentials",
      registration: { mode: "auto" },
      client: {
        information: {
          clientIdEnv: "MCP_CLIENT_ID",
          clientSecretEnv: "MCP_CLIENT_SECRET",
        },
      },
    });
  });

  it("imports OAuth object configs from supported external config files", () => {
    const root = mkdtempSync(join(tmpdir(), "pi-mcp-config-"));
    tempDirs.push(root);
    process.chdir(root);

    writeJson(join(root, ".vscode", "mcp.json"), {
      mcpServers: {
        imported: {
          url: "https://imported.example.com/mcp",
          auth: {
            type: "oauth",
            grantType: "client_credentials",
            registration: { mode: "metadata-url" },
            client: {
              metadataUrl: "https://imported.example.com/oauth/client-metadata",
            },
          },
        },
      },
    });

    const configPath = join(root, "mcp.json");
    writeJson(configPath, {
      imports: ["vscode"],
      mcpServers: {},
    } satisfies McpConfig);

    const config = loadMcpConfig(configPath);
    const definition = config.mcpServers.imported;

    expect(definition).toBeTruthy();
    expect(getResolvedOAuthAuthConfig(definition)).toEqual({
      type: "oauth",
      grantType: "client_credentials",
      registration: { mode: "metadata-url" },
      client: {
        metadataUrl: "https://imported.example.com/oauth/client-metadata",
      },
    });
  });
});
