<p>
  <img src="banner.png" alt="pi-mcp-adapter" width="1100">
</p>

# Pi MCP Adapter

Use MCP servers with [Pi](https://github.com/badlogic/pi-mono/) without burning your context window.

https://github.com/user-attachments/assets/4b7c66ff-e27e-4639-b195-22c3db406a5a

## Why This Exists

Mario wrote about [why you might not need MCP](https://mariozechner.at/posts/2025-11-02-what-if-you-dont-need-mcp/). The problem: tool definitions are verbose. A single MCP server can burn 10k+ tokens, and you're paying that cost whether you use those tools or not. Connect a few servers and you've burned half your context window before the conversation starts.

His take: skip MCP entirely, write simple CLI tools instead.

But the MCP ecosystem has useful stuff - databases, browsers, APIs. This adapter gives you access without the bloat. One proxy tool (~200 tokens) instead of hundreds. The agent discovers what it needs on-demand. Servers only start when you actually use them.

## Install

```bash
pi install npm:pi-mcp-adapter
```

Restart Pi after installation.

## Quick Start

Create `~/.pi/agent/mcp.json`:

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"]
    }
  }
}
```

Servers are **lazy by default** — they won't connect until you actually call one of their tools. The adapter caches tool metadata so search and describe work without live connections.

```
mcp({ search: "screenshot" })
```
```
chrome_devtools_take_screenshot
  Take a screenshot of the page or element.

  Parameters:
    format (enum: "png", "jpeg", "webp") [default: "png"]
    fullPage (boolean) - Full page instead of viewport
```
```
mcp({ tool: "chrome_devtools_take_screenshot", args: '{"format": "png"}' })
```

Note: `args` is a JSON string, not an object.

Two calls instead of 26 tools cluttering the context.

## Config

### Server Options

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "some-mcp-server"],
      "lifecycle": "lazy",
      "idleTimeout": 10
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `command` | Executable for stdio transport |
| `args` | Command arguments |
| `env` | Environment variables (`${VAR}` interpolation) |
| `cwd` | Working directory |
| `url` | HTTP endpoint (auth-aware StreamableHTTP; falls back to SSE only for transport incompatibility) |
| `auth` | `"bearer"`, `"oauth"`, or an auth object (`{ type: "oauth" | "bearer", ... }`) for HTTP auth, browser OAuth, or `client_credentials` |
| `bearerToken` / `bearerTokenEnv` | Token or env var name |
| `lifecycle` | `"lazy"` (default), `"eager"`, or `"keep-alive"` |
| `idleTimeout` | Minutes before idle disconnect (overrides global) |
| `exposeResources` | Expose MCP resources as tools (default: true) |
| `directTools` | `true`, `string[]`, or `false` — register tools individually instead of through proxy |
| `debug` | Show server stderr (default: false) |

### OAuth and HTTP Auth

For static bearer tokens, keep using either `auth: "bearer"` or the object form:

```json
{
  "mcpServers": {
    "internal-api": {
      "url": "https://api.example.com/mcp",
      "auth": {
        "type": "bearer",
        "tokenEnv": "INTERNAL_API_TOKEN"
      }
    }
  }
}
```

OAuth is available for HTTP transports only. Pi now uses the MCP SDK's auth-aware HTTP flow. Use either the legacy shorthand `auth: "oauth"` or the richer object form. The shorthand remains a compatibility alias for browser-based `authorization_code` with automatic registration (`grantType: "authorization_code"`, `registration.mode: "auto"`). For interactive auth, Pi reuses durable auth state and silent refresh first, then intentionally opens your system browser and completes the flow through a local `127.0.0.1` loopback callback if fresh sign-in is still required. There is no embedded browser or manual token copy/paste path.

If an HTTP MCP server omits `auth` entirely, Pi now follows a Codex-style fallback: explicit bearer config still wins, but otherwise Pi will treat the server as OAuth-capable when durable OAuth tokens already exist or the server advertises OAuth metadata/protected-resource metadata.

The auth object also accepts `scope` and `resource` when the upstream server requires them. `resource` overrides the RFC 8707 resource indicator selection, as long as it remains compatible with the MCP server URL / protected resource metadata. `issuer` is reserved for future auth-server discovery overrides and should be omitted for now.

```json
{
  "mcpServers": {
    "github": {
      "url": "https://mcp.example.com",
      "auth": {
        "type": "oauth",
        "scope": "read:org repo",
        "client": {
          "metadata": {
            "clientName": "Pi MCP Adapter"
          }
        }
      }
    }
  }
}
```

`registration.mode` controls how Pi identifies or registers the OAuth client:

- `auto` (default) — prefer static `client.information`, then `client.metadataUrl` / published client metadata (CIMD), then dynamic client registration
- `static` — use only `client.information`
- `metadata-url` — use `client.metadataUrl`
- `dynamic` — always attempt dynamic client registration

`auto` is the recommended default because it preserves explicit client identity when you have it, reuses published metadata when the server provides it, and only falls back to dynamic client registration when needed.

`client_credentials` is also supported for non-interactive machine auth. Prefer env-backed secrets over checking credentials into `mcp.json`:

```json
{
  "mcpServers": {
    "service-account": {
      "url": "https://mcp.example.com",
      "auth": {
        "type": "oauth",
        "grantType": "client_credentials",
        "registration": { "mode": "static" },
        "client": {
          "information": {
            "clientIdEnv": "SERVICE_ACCOUNT_CLIENT_ID",
            "clientSecretEnv": "SERVICE_ACCOUNT_CLIENT_SECRET"
          }
        }
      }
    }
  }
}
```

Behavior notes:

- `/mcp auth` shows OAuth status, flow, registration strategy, and storage hints. `/mcp auth <server>` intentionally starts or retries auth for a specific server. `/mcp-auth` remains a compatibility launcher for the same flow. In the `/mcp` panel, `Ctrl+R` does the same for the selected server.
- `authorization_code` always uses your system browser with a `127.0.0.1` loopback callback. The SDK handles PKCE, validates a single-use state, and only opens the browser when stored credentials or silent refresh are not enough.
- Tokens, client registration, and callback session state are stored under `~/.pi/agent/mcp-auth` and reused across restarts with silent refresh when possible.
- `client_credentials` stays non-interactive. Pi never opens a browser for that flow and can reuse durable auth state when the provider allows it.
- Background health checks and keep-alive reconnects never open a browser. They only use stored tokens / silent refresh and mark the server as needing auth if user interaction is required.
- HTTP auth uses auth-aware StreamableHTTP first and only falls back to SSE when the transport itself is incompatible. `401`/`403`, refresh failures, and other auth problems stay auth failures.
- Legacy tokens from `~/.pi/agent/mcp-oauth/<server>/tokens.json` are imported into the durable auth store on first use when possible.

### Lifecycle Modes

- **`lazy`** (default) — Don't connect at startup. Connect on first tool call. Disconnect after idle timeout. Cached metadata keeps search/list working without connections.
- **`eager`** — Connect at startup but don't auto-reconnect if the connection drops. No idle timeout by default (set `idleTimeout` explicitly to enable).
- **`keep-alive`** — Connect at startup. Auto-reconnect via health checks. No idle timeout. Use for servers you always need available.

### Settings

```json
{
  "settings": {
    "toolPrefix": "server",
    "idleTimeout": 10
  },
  "mcpServers": { }
}
```

| Setting | Description |
|---------|-------------|
| `toolPrefix` | `"server"` (default), `"short"` (strips `-mcp` suffix), or `"none"` |
| `idleTimeout` | Global idle timeout in minutes (default: 10, 0 to disable) |
| `directTools` | Global default for all servers (default: false). Per-server overrides this. |

Per-server `idleTimeout` overrides the global setting.

### Direct Tools

By default, all MCP tools are accessed through the single `mcp` proxy tool. This keeps context small but means the LLM has to discover tools via search. If you want specific tools to show up directly in the agent's tool list — alongside `read`, `bash`, `edit`, etc. — add `directTools` to your config.

Per-server:

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"],
      "directTools": true
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "directTools": ["search_repositories", "get_file_contents"]
    },
    "huge-server": {
      "command": "npx",
      "args": ["-y", "mega-mcp@latest"]
    }
  }
}
```

| Value | Behavior |
|-------|----------|
| `true` | Register all tools from this server as individual Pi tools |
| `["tool_a", "tool_b"]` | Register only these tools (use original MCP names) |
| Omitted or `false` | Proxy only (default) |

To set a global default for all servers:

```json
{
  "settings": {
    "directTools": true
  },
  "mcpServers": {
    "huge-server": {
      "directTools": false
    }
  }
}
```

Per-server `directTools` overrides the global setting. The example above registers direct tools for every server except `huge-server`.

Each direct tool costs ~150-300 tokens in the system prompt (name + description + schema). Good for targeted sets of 5-20 tools. For servers with 75+ tools, stick with the proxy or pick specific tools with a `string[]`.

Direct tools register from the metadata cache (`~/.pi/agent/mcp-cache.json`), so no server connections are needed at startup. On the first session after adding `directTools` to a new server, the cache won't exist yet — tools fall back to proxy-only and the cache populates in the background. Restart Pi and they'll be available. To force it: `/mcp reconnect <server>` then restart.

**Interactive configuration:** Run `/mcp` to open an interactive panel showing all servers with connection status, tools, and direct/proxy toggles. You can reconnect servers, intentionally start or retry auth for needs-auth servers with `Ctrl+R`, and toggle tools between direct and proxy — all from one overlay. `Ctrl+R` uses the same auth-aware reconnect path as `/mcp auth <server>`: system-browser `authorization_code` with a `127.0.0.1` callback when needed, non-interactive `client_credentials` when configured, and no surprise browser launches during background reconnects. Changes are written to your config file; restart Pi to apply.

**Subagent integration:** If you use the subagent extension, agents can request direct MCP tools in their frontmatter with `mcp:server-name` syntax. See the subagent README for details.

### MCP UI Integration

MCP servers can ship interactive UIs via the [MCP UI](https://github.com/MCP-UI-Org/mcp-ui) standard. When you call a tool that has a UI resource, the adapter opens it in a native macOS window via [Glimpse](https://github.com/hazat/glimpse) if available, otherwise falls back to the browser.

**How it works:**

1. Agent calls a tool like `launch_dashboard`
2. The tool's metadata includes `_meta.ui.resourceUri` pointing to a UI resource
3. pi-mcp-adapter fetches the UI HTML and opens it in an iframe
4. The UI can call MCP tools and send messages back to the agent

**Native rendering:** On macOS, if [Glimpse](https://github.com/hazat/glimpse) is installed (`pi install npm:glimpseui`), UIs open in a native WKWebView window instead of a browser tab. Set `MCP_UI_VIEWER=browser` to force the browser, or `MCP_UI_VIEWER=glimpse` to require native rendering.

**Bidirectional communication:** The UI talks back. When it sends a prompt or intent, the message is stored and `triggerTurn()` wakes the agent. The agent retrieves messages via `mcp({ action: "ui-messages" })` and responds, enabling conversational UIs where the app and agent collaborate in real-time.

**Session reuse:** When the agent calls the same tool again while its UI is already open, the adapter pushes the new result to the existing window instead of replacing it. This enables live updates — the agent can refine a chart, add data, or respond to user input without losing the current view. Different tools still replace the session as before.

**Message types from UI:**

| Type | Purpose |
|------|---------|
| `prompt` | User message that triggers an agent response |
| `intent` | Structured action with name + params |
| `notify` | Fire-and-forget notification |
| `message` | Generic message payload |
| (custom) | Any other type forwarded as intent |

**Retrieving UI messages:**

```
mcp({ action: "ui-messages" })
```

Returns accumulated messages from UI sessions. Each message includes `type`, `sessionId`, `serverName`, `toolName`, and `timestamp`. Prompt messages include `prompt`, intent messages include `intent` and `params`.

**Browser controls:**

- **Cmd/Ctrl+Enter** — Complete and close
- **Escape** — Cancel and close
- **Done/Cancel buttons** — Same as keyboard shortcuts

**Technical notes:**

- Tool consent gates whether UIs can call MCP tools (never/once-per-server/always)
- Works with both stdio and HTTP MCP servers
- Uses a local 408KB AppBridge bundle (MCP SDK + Zod) for browser↔server communication

### Local Example: Interactive Visualizer

A minimal MCP UI example at `examples/interactive-visualizer` demonstrating charts, bidirectional messaging, and streaming. From that directory:

```bash
npm install
npm run build
npm run install-local
```

Restart pi, then ask the agent to show a chart — it calls `show_chart` and opens the UI in Glimpse (macOS) or the browser. Use `npm run uninstall-local` to remove the MCP entry.

### Import Existing Configs

Already have MCP set up elsewhere? Import it:

```json
{
  "imports": ["cursor", "claude-code", "claude-desktop"],
  "mcpServers": { }
}
```

Supported: `cursor`, `claude-code`, `claude-desktop`, `vscode`, `windsurf`, `codex`

### Project Config

Add `.pi/mcp.json` in a project root for project-specific servers. Project config overrides global and imported servers.

## Usage

| Mode | Example |
|------|---------|
| Status | `mcp({ })` |
| List server | `mcp({ server: "name" })` |
| Search | `mcp({ search: "screenshot navigate" })` |
| Describe | `mcp({ describe: "tool_name" })` |
| Call | `mcp({ tool: "...", args: '{"key": "value"}' })` |
| Connect | `mcp({ connect: "server-name" })` |
| UI messages | `mcp({ action: "ui-messages" })` |

Search includes both MCP tools and Pi tools (from extensions). Pi tools appear first with `[pi tool]` prefix. Space-separated words are OR'd.

Tool names are fuzzy-matched on hyphens and underscores — `context7_resolve_library_id` finds `context7_resolve-library-id`.

## Commands

| Command | What it does |
|---------|--------------|
| `/mcp` | Interactive panel (server status, tool toggles, reconnect/auth via `Ctrl+R`, auth notices) |
| `/mcp tools` | List all tools |
| `/mcp reconnect` | Reconnect all servers |
| `/mcp reconnect <server>` | Connect or reconnect a single server |
| `/mcp auth` | Show OAuth status, flow, registration strategy, storage hints, and browser/no-browser behavior |
| `/mcp auth <server>` | Intentionally start or retry auth for one OAuth-configured HTTP server (`authorization_code` browser flow or `client_credentials` token exchange) |
| `/mcp-auth` | Compatibility launcher for `/mcp auth` |
| `/mcp-auth <server>` | Compatibility launcher for `/mcp auth <server>` |

## How It Works

- One `mcp` tool in context (~200 tokens) instead of hundreds
- Servers are lazy by default — they connect on first tool call, not at startup
- Tool metadata is cached to disk so search/list/describe work without live connections
- Idle servers disconnect after 10 minutes (configurable), reconnect automatically on next use
- npx-based servers resolve to direct binary paths, skipping the ~143 MB npm parent process
- MCP server validates arguments, not the adapter
- Keep-alive servers get health checks and auto-reconnect, but browser-based reauth only happens on intentional retries
- HTTP auth uses StreamableHTTP first and only falls back to SSE when the transport is incompatible, not when auth fails
- Auth-aware fallback preserves `needs-auth` state instead of misclassifying `401`/`403`, refresh failures, or rejected browser flows as transport incompatibility
- Specific tools can be promoted from the proxy to first-class Pi tools via `directTools` config, so the LLM sees them directly instead of having to search

## Limitations

- Cross-session server sharing not yet implemented (each Pi session runs its own server processes)
- OAuth auth is only available for HTTP/SSE transports, not stdio-only servers
- Interactive `authorization_code` currently requires your system browser and an auth provider that accepts a `127.0.0.1` loopback redirect; embedded/copy-paste auth is not supported
- Background reconnects intentionally avoid surprise browser launches; if silent refresh is not possible, the server stays in a needs-auth state until you retry interactively

## OAuth Troubleshooting

| Symptom | What to do |
|---------|------------|
| Browser did not open during a reconnect | Expected for background reconnects. Run `/mcp auth <server>` (or `/mcp-auth <server>`) or highlight the server in `/mcp` and press `Ctrl+R` to start an intentional browser flow. |
| Browser sign-in opened but never completed | Make sure the browser can reach a local callback on `127.0.0.1`, the auth server allows loopback redirects, and your system browser is the one completing the flow, then retry `/mcp auth <server>` (or `/mcp-auth <server>`). |
| Provider rejects the redirect URI or callback | Confirm the provider allows `http://127.0.0.1:<port>/...` loopback redirects. Pi uses the system browser + loopback callback only; there is no manual copy/paste fallback. |
| Server stays in `needs-auth` after a failed sign-in | Retry `/mcp auth <server>` (or `/mcp-auth <server>`). Cancelled, expired, rejected, or callback-failed browser attempts intentionally stay in `needs-auth` until you retry. |
| `client_credentials` keeps failing | Check `clientId` / `clientSecret`, env var names, and any required `scope` or `resource` hints. Pi will not open a browser for this flow. |
| `registration.mode: "auto"` picked the wrong strategy | Set `registration.mode` explicitly to `static`, `metadata-url`, or `dynamic`. The default order is static client info -> metadata URL/CIMD -> dynamic registration. |
| You had old tokens under `~/.pi/agent/mcp-oauth/...` | They are imported into `~/.pi/agent/mcp-auth` on first use when possible. If migration cannot be used, rerun `/mcp auth <server>` (or `/mcp-auth <server>`) to establish fresh auth. |
| An HTTP server reports auth errors | Treat it as auth, not transport selection. StreamableHTTP only falls back to SSE for transport incompatibility, not `401`/`403` or refresh failures. |
