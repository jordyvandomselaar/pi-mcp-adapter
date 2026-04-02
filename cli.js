#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import os from "node:os";
import { execSync } from "node:child_process";

const REPO_URL = "https://raw.githubusercontent.com/nicobailon/pi-mcp-adapter/main";
const EXT_DIR = path.join(os.homedir(), ".pi", "agent", "extensions", "pi-mcp-adapter");
const SETTINGS_FILE = path.join(os.homedir(), ".pi", "agent", "settings.json");
const EXT_PATH = "~/.pi/agent/extensions/pi-mcp-adapter/index.ts";

const FILES = [
  "index.ts",
  "state.ts",
  "utils.ts",
  "tool-metadata.ts",
  "init.ts",
  "ui-session.ts",
  "proxy-modes.ts",
  "direct-tools.ts",
  "commands.ts",
  "types.ts",
  "ui-stream-types.ts",
  "config.ts",
  "auth-provider.ts",
  "auth-session-manager.ts",
  "auth-store.ts",
  "server-manager.ts",
  "tool-registrar.ts",
  "resource-tools.ts",
  "lifecycle.ts",
  "metadata-cache.ts",
  "host-html-template.ts",
  "ui-resource-handler.ts",
  "consent-manager.ts",
  "ui-server.ts",
  "glimpse-ui.ts",
  "npx-resolver.ts",
  "mcp-panel.ts",
  "logger.ts",
  "errors.ts",
  "app-bridge.bundle.js",
  "package.json",
  "tsconfig.json",
  "README.md",
  "CHANGELOG.md",
  "LICENSE",
];

function download(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return download(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to download ${url}: ${res.statusCode}`));
      }
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve(data));
      res.on("error", reject);
    }).on("error", reject);
  });
}

async function main() {
  console.log("Installing pi-mcp-adapter...\n");

  fs.mkdirSync(EXT_DIR, { recursive: true });
  console.log(`Created directory: ${EXT_DIR}`);

  for (const file of FILES) {
    console.log(`Downloading ${file}...`);
    const content = await download(`${REPO_URL}/${file}`);
    fs.writeFileSync(path.join(EXT_DIR, file), content);
  }

  console.log("\nInstalling dependencies...");
  try {
    execSync("npm install --omit=dev", { cwd: EXT_DIR, stdio: "inherit" });
  } catch {
    console.error("Warning: npm install failed. You may need to run it manually.");
  }

  console.log(`\nUpdating settings: ${SETTINGS_FILE}`);
  
  let settings = {};
  if (fs.existsSync(SETTINGS_FILE)) {
    try {
      settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf-8"));
    } catch (err) {
      console.error(`Warning: Could not parse existing settings.json: ${err.message}`);
      console.error("Creating new settings file...");
    }
  }

  if (!Array.isArray(settings.extensions)) {
    settings.extensions = [];
  }

  const hasMcpExt = settings.extensions.some(p => 
    p === EXT_PATH || 
    p.includes("/extensions/pi-mcp-adapter/index.ts") || 
    p.includes("/extensions/pi-mcp-adapter")
  );

  if (!hasMcpExt) {
    settings.extensions.push(EXT_PATH);
    console.log(`Added "${EXT_PATH}" to extensions array`);
  } else {
    console.log("Extension already configured in settings.json");
  }

  fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + "\n");

  console.log("\nInstallation complete!");
  console.log("\nCreate ~/.pi/agent/mcp.json to configure MCP servers.");
  console.log("Restart pi to load the extension.");
  console.log("Use /mcp for the interactive panel. /mcp auth <server> intentionally starts or retries SDK-backed auth for HTTP MCP servers: system-browser authorization_code with a 127.0.0.1 callback when needed, or non-interactive client_credentials token exchange. /mcp-auth <server> remains a compatibility alias.");
}

main().catch((err) => {
  console.error(`\nInstallation failed: ${err.message}`);
  process.exit(1);
});
