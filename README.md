# Blockade 

A transparent security proxy that sits between any AI coding assistant and the MCP (Model Context Protocol) servers it connects to. It intercepts every tool call, evaluates it against your security policy, and logs every decision — giving you visibility and control over what AI agents can actually do on your machine.

Built by [Ishaani Prashant](https://github.com/mindxflayer).

---

## What This Does

When you connect an AI assistant (Claude Desktop, Cursor, Windsurf, etc.) to an MCP server like `filesystem`, `github`, or `bash`, the AI gets direct access to powerful tools. There is no built-in way to monitor, filter, or approve what the AI does with those tools.

Blockade fixes that. It wraps any MCP server and acts as a transparent middleman:

```
  AI IDE (Claude, Cursor, etc.)
          │
          ▼
  ┌─────────────────────┐
  │       Blockade       │  ← intercepts every request
  │                      │  ← evaluates policy rules
  │                      │  ← logs to SQLite
  │                      │  ← optionally asks for approval
  └──────────┬──────────┘
             ▼
  Real MCP Server (filesystem, github, bash, etc.)
```

The AI IDE sees it as a normal MCP server. The real MCP server sees it as a normal client. Neither side knows Blockade is there.

---

## Features

- **Policy Profiles** — Define per-tool rules: `allow`, `deny`, `audit`, `judge`, `approve`, `sandbox`. Use glob patterns to match tool names.
- **LLM Risk Scoring** — Uses Google Gemini (Flash) or a local Ollama model to score each tool call for injection, exfiltration, or path traversal risks.
- **Human Approval Gate** — Optionally require manual approval (via CLI prompt or a local web dashboard) before high-risk tool calls execute.
- **Taint Tracking** — Flags when data from an untrusted source (like `fetch`) flows into a sensitive sink (like `run_command`). Blocks confused deputy attacks.
- **Tool Schema Pinning** — Fingerprints tool definitions on first run. If a downstream server changes or adds tools mid-session (rug-pull), Blockade blocks it.
- **Docker Sandboxing** — Routes risky commands into an ephemeral, network-isolated Alpine Linux container.
- **Audit Logging** — Every decision (allow, deny, reason, timestamps) is logged to a local SQLite database with automatic secret redaction.

---

## Quick Start

### Step 1: Install

**From PyPI:**
```bash
pip install blockade
```

**From source (GitHub clone):**
```bash
git clone https://github.com/mindxflayer/blockade.git
cd blockade
python -m venv .venv

# Windows
.\.venv\Scripts\activate

# Mac/Linux
source .venv/bin/activate

pip install -e .
```

### Step 2: Initialize

Run the setup wizard. It will ask you to pick an LLM provider and enter your API key:
```bash
blockade init
```

This creates a `.env` file in your current directory (or globally at `~/.config/blockade/config.env`).

### Step 3: Configure Your AI IDE

See the [IDE Setup Guide](#ide-setup-guide) section below for your specific IDE.

---

## IDE Setup Guide

Blockade works with any AI IDE or agent that supports the MCP protocol. Below are tested configurations for popular tools.

> **Important:** Replace `C:/path/to/your/folder` with the actual folder you want the AI to access. If the path has spaces, wrap it in quotes.

---

### Claude Desktop

Open the config file:
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Add this configuration:
```json
{
  "mcpServers": {
    "filesystem-secured": {
      "command": "blockade",
      "args": [
        "wrap",
        "npx", "-y",
        "@modelcontextprotocol/server-filesystem",
        "C:/path/to/your/folder"
      ],
      "env": {
        "JUDGE_PROVIDER": "gemini",
        "GEMINI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Restart Claude Desktop. You should see the server listed with a green dot under the plug icon (🔌) at the bottom of the chat.

---

### Google Antigravity (Gemini Code Assist)

Open or create the global config file at:
```
~/.gemini/config/mcp_config.json
```
On Windows, that is: `C:\Users\<YourName>\.gemini\config\mcp_config.json`

Add this configuration:
```json
{
  "mcpServers": {
    "filesystem-secured": {
      "command": "blockade",
      "args": [
        "wrap",
        "npx", "-y",
        "@modelcontextprotocol/server-filesystem",
        "C:/path/to/your/folder"
      ],
      "env": {
        "JUDGE_PROVIDER": "gemini",
        "GEMINI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Restart Antigravity. Go to **Settings → Customizations → Installed MCP Servers** and verify `filesystem-secured` shows a green dot.

**Note:** Antigravity has its own built-in file tools that bypass MCP. Blockade monitors tool calls made through the MCP protocol layer. For full coverage, use Blockade to wrap external tools that the IDE doesn't have built-in (like `fetch`, `github`, `database`, etc.).

---

### Cursor

Open Cursor settings:
- Go to **Settings → MCP** or open `~/.cursor/mcp.json`

Add:
```json
{
  "mcpServers": {
    "filesystem-secured": {
      "command": "blockade",
      "args": [
        "wrap",
        "npx", "-y",
        "@modelcontextprotocol/server-filesystem",
        "C:/path/to/your/folder"
      ],
      "env": {
        "JUDGE_PROVIDER": "gemini",
        "GEMINI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Restart Cursor.

---

### Windsurf

Open the MCP config file at:
- `~/.codeium/windsurf/mcp_config.json`

Add:
```json
{
  "mcpServers": {
    "filesystem-secured": {
      "command": "blockade",
      "args": [
        "wrap",
        "npx", "-y",
        "@modelcontextprotocol/server-filesystem",
        "C:/path/to/your/folder"
      ],
      "env": {
        "JUDGE_PROVIDER": "gemini",
        "GEMINI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Restart Windsurf.

---

### VS Code + Cline / Continue / Roo Code

These extensions use standard MCP configuration. Check the extension's settings panel for an "MCP Servers" section and add the same JSON structure as above, using `"command": "blockade"`.

---

### CLI (Direct Usage)

You can also run Blockade directly from the command line without any IDE:

```bash
blockade wrap npx -y @modelcontextprotocol/server-filesystem "C:/path/to/your/folder"
```

This starts Blockade as a stdio proxy. You can pipe JSON-RPC messages to it for testing:

```bash
echo {"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"read_file","arguments":{"path":"README.md"}}} | blockade wrap npx -y @modelcontextprotocol/server-filesystem .
```

---

## Policy Configuration

Blockade reads its policy from `~/.config/blockade/policies.yaml`. This file is auto-generated on first run with safe defaults.

You can also place a `policies.yaml` in your project directory, or point to a custom path with the `MCP_POLICY_PATH` environment variable.

### Example Policy

```yaml
default_profile: default
profiles:
  default:
    tools:
      "read_file": "allow"
      "write_file": "approve_medium"
      "run_command": "approve_high"
      "search_files": "allow"
      "list_directory": "allow"
      "*": "judge"
```

### Available Actions

| Action | What it does |
|---|---|
| `allow` | Let the call through, log it |
| `deny` | Block the call immediately |
| `audit` | Same as allow, but flagged in logs |
| `judge` | Send to the LLM judge for risk scoring. Block if high risk |
| `approve` | Always require human approval |
| `approve_medium` | Require approval only if judge scores medium or higher risk |
| `approve_high` | Require approval only if judge scores high risk |
| `sandbox` | Execute inside a Docker container instead of the host |

### Glob Patterns

Tool names support glob matching:
- `"read_*"` matches `read_file`, `read_directory`, etc.
- `"*"` matches everything (catch-all, put it last)
- `"github:*"` matches all tools from a github server

---

## Checking Audit Logs

Every decision is stored in a SQLite database at `~/.config/blockade/audit.db`.

To view the last 10 decisions:
```bash
python -c "import sqlite3; conn = sqlite3.connect('C:/Users/<YourName>/.config/blockade/audit.db'); [print(r) for r in conn.execute('SELECT timestamp, tool_name, profile, final_action FROM audit_logs ORDER BY id DESC LIMIT 10').fetchall()]"
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `JUDGE_PROVIDER` | `gemini` | LLM provider for risk scoring (`gemini` or `ollama`) |
| `GEMINI_API_KEY` | — | Your Google Gemini API key |
| `APPROVAL_MODE` | `cli` | Human approval interface (`cli` or `web`) |
| `MCP_PROFILE` | `default` | Which policy profile to use |
| `MCP_POLICY_PATH` | `~/.config/blockade/policies.yaml` | Custom path to your policy file |
| `MCP_AUDIT_DB_PATH` | `~/.config/blockade/audit.db` | Custom path to the audit database |
| `MCP_SERVER_ID` | auto-generated | Unique ID for tool schema pinning |
| `ALLOW_UNSANDBOXED_FALLBACK` | `false` | If `true`, runs sandboxed commands locally when Docker is unavailable |

---

## How This is Different

Most MCP security discussions focus on server-side validation. Blockade takes a different approach — it operates **client-side**, sitting between the AI and the server, so you don't need to modify or trust the downstream server at all.

| Capability | Blockade | No Firewall |
|---|---|---|
| Per-tool allow/deny rules | ✅ | ❌ |
| LLM-based risk scoring on every call | ✅ | ❌ |
| Human approval before dangerous actions | ✅ | ❌ |
| Taint tracking (confused deputy defense) | ✅ | ❌ |
| Tool schema pinning (rug-pull defense) | ✅ | ❌ |
| Full audit trail with secret redaction | ✅ | ❌ |
| Docker sandboxing for risky commands | ✅ | ❌ |
| Works with any MCP client, no code changes | ✅ | — |

---

## Development & Testing

```bash
git clone https://github.com/mindxflayer/blockade.git
cd blockade
python -m venv .venv
.\.venv\Scripts\activate   # Windows
pip install -e ".[dev]"
pytest
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
