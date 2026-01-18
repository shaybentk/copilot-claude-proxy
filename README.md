# Copilot Claude Proxy

Anthropic-compatible proxy that lets **Claude Code CLI** send requests to **GitHub Copilot**.

This server exposes:
- **Anthropic Messages API** (`/v1/messages`) for Claude Code CLI
- **OpenAI Chat Completions** (`/v1/chat/completions`) for tools like Cursor

Under the hood it calls GitHub Copilot's internal completions endpoint.

## Why this exists
Claude Code CLI speaks **Anthropic Messages API** only. GitHub Copilot proxies expose **OpenAI-style** endpoints. This server translates Anthropic requests into OpenAI chat requests and forwards them to a Copilot proxy.

> Note: This implementation runs in **direct Copilot mode** (it talks directly to Copilot), it does not require a separate OpenAI-compatible proxy.

## Requirements
- Node.js 18+
- GitHub account with an active **Copilot subscription**

## Configure
Create a `.env` file:

```
PORT=3000
# NOTE: The default port in code is 8082 if PORT is not set.
COPILOT_DEFAULT_MODEL=gpt-4.1
GITHUB_COPILOT_CLIENT_ID=Iv1.b507a08c87ecfe98
RATE_LIMIT_DEFAULT=60
RATE_LIMIT_CHAT_COMPLETIONS=20
MAX_TOKENS_PER_REQUEST=128000
MAX_TOKENS_PER_MINUTE=200000
LOG_LEVEL=info
```

### About `COPILOT_DEFAULT_MODEL`
The default model to use when the client doesn't specify one. 

### ⚠️ IMPORTANT: Real Model Support!
**This proxy now supports REAL models from GitHub Copilot including:**
- ✅ **Claude Sonnet 4 / 4.5** - Real Anthropic Claude models
- ✅ **Claude Haiku 4.5** - Fast Anthropic model
- ✅ **GPT-5 / GPT-5 mini** - Latest OpenAI models
- ✅ **GPT-4.1 / GPT-4o** - OpenAI GPT-4 variants

**Available Models:**
- `claude-sonnet-4` - Claude Sonnet 4 � **Agent Mode Support**
- `claude-sonnet-4.5` - Claude Sonnet 4.5 (best) 🤖 **Agent Mode Support**
- `claude-haiku-4.5` - Claude Haiku 4.5 (fast) 🤖 **Agent Mode Support**
- `gpt-5` - GPT-5 🤖 **Agent Mode Support**
- `gpt-5-mini` - GPT-5 mini 🤖 **Agent Mode Support**
- `gpt-4.1` - GPT-4.1 (default) 🤖 **Agent Mode Support**
- `gpt-4o` - GPT-4o 🤖 **Agent Mode Support**

### 🤖 Agent Mode (Function Calling)

All models support **agent mode** - the ability to call functions/tools to perform actions like editing files, running commands, searching code, etc.

**How to enable:**
Include a `tools` parameter in your request with function definitions:

```json
{
  "model": "claude-sonnet-4-5-20251101",
  "messages": [{"role": "user", "content": "Edit the README file"}],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "edit_file",
        "description": "Edit a file",
        "parameters": {
          "type": "object",
          "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"}
          }
        }
      }
    }
  ]
}
```

**Logs will show:**
```
[info] agent_mode_enabled: {"toolCount":3,"toolNames":"edit_file, create_file, run_command"}
```

**With AI clients that support function calling:**
- **Cursor IDE** - Built-in agent mode
- **Continue.dev** - Agent capabilities with tools
- **OpenAI-compatible clients** - Pass tools array in requests

**Note:** Claude CLI doesn't natively support function calling, but you can use OpenAI-compatible clients that do.

**How it works:**
- The proxy fetches the list of available models from GitHub Copilot
- You can specify any model in your requests
- Use `GET /v1/models` to see all available models
- Model selection is passed through to GitHub Copilot's API

## Run
```
npm install
npm start
```

### Windows note
PowerShell doesn't support `cd dir && command` in older modes. Prefer:
```bat
cd copilot-claude-proxy
npm start
```

### Quick Start with GitHub Token
If you already have a GitHub token with Copilot access:

**Windows PowerShell:**
```powershell
cd copilot-claude-proxy
$env:GITHUB_TOKEN="gho_your_token_here"
npm start
```

**macOS/Linux:**
```bash
cd copilot-claude-proxy
export GITHUB_TOKEN="gho_your_token_here"
npm start
```

The server will automatically use your GitHub token to obtain a Copilot token.

## Auth (Device Flow)
1. Start the server.
2. POST `http://localhost:8082/auth/login` to get `verification_uri` and `user_code`.
3. Visit the URI and enter the code.
4. POST `http://localhost:8082/auth/check` until authenticated.

### Auto-refresh
The proxy will automatically refresh the Copilot token (using the saved GitHub OAuth token) when it expires.
If refresh fails, you'll get a **401** and need to redo the device flow.

## Use with Claude Code CLI
Claude Code CLI expects Anthropic env vars. You can now use **real Claude models**!

### macOS/Linux
```bash
export ANTHROPIC_BASE_URL=http://localhost:8082
export ANTHROPIC_AUTH_TOKEN=test  # any value is fine
export ANTHROPIC_MODEL=claude-sonnet-4.5  # optional: specify model
claude
```

### Windows PowerShell (current session)
```powershell
$env:ANTHROPIC_BASE_URL = "http://localhost:8082"
$env:ANTHROPIC_AUTH_TOKEN = "test"
$env:ANTHROPIC_MODEL = "claude-sonnet-4.5"  # optional: specify model
claude
```

### Test available models
```powershell
curl http://localhost:8082/v1/models -H "Authorization: Bearer test" | jq '.data[].id'
```

## Use with OpenAI-compatible clients (Cursor etc.)
Set your OpenAI Base URL to:
```
http://localhost:8082
```
Then use `/v1/chat/completions`.

## Supported endpoints
- `POST /auth/login`
- `POST /auth/check`
- `GET /auth/status`
- `POST /auth/logout`
- `POST /v1/messages`
- `POST /v1/messages/count_tokens` (lightweight estimate)
- `GET /v1/models`
- `POST /v1/chat/completions` (OpenAI-compatible; supports streaming)
- `GET /usage/summary`
- `GET /usage/details`
- `POST /usage/reset/:sessionId`
- `POST /usage/reset-all`
- `GET /` (health)

## Notes
- Tool calls are flattened to text for Copilot compatibility.
- Streaming:
  - `/v1/messages` streams **Anthropic-style** SSE events
  - `/v1/chat/completions` streams **OpenAI-style** SSE chunks

## Security
Run locally only. Do **not** expose this server publicly.
Anyone who can reach it can use your Copilot quota.

## Deep-Dive Findings (github-copilot-proxy src)
These are the pieces mirrored:

### Auth + Tokens
- Device flow via `@octokit/auth-oauth-device` with scopes `read:user`.
- Copilot token fetch from `https://api.github.com/copilot_internal/v2/token` using GitHub OAuth token.
- Token validity uses a 60s expiry buffer.

### Copilot completions endpoint + headers
- Completions are sent to:
  - `https://copilot-proxy.githubusercontent.com/v1/engines/copilot-codex/completions`
- Required headers:
  - `Authorization: Bearer <copilotToken>`
  - `X-Request-Id`, `Machine-Id`, `User-Agent`, `Editor-Version`, `Editor-Plugin-Version`, `Openai-Organization`, `Openai-Intent`

### OpenAI API surface
- `/v1/chat/completions` supports streaming + non-streaming; streaming is SSE.
- `/v1/models` exists (simple compatibility list).

### Middleware
- github-copilot-proxy uses request logging, error handler, and rate limiting based on per-minute requests and token estimates.
- Implemented here.

### Usage tracking
- github-copilot-proxy tracks per-session request count + token usage; exposes `/usage/summary` + `/usage/details`.
- Implemented here.

## Differences vs github-copilot-proxy
- This project is a **single-file** implementation (no TS build).
- Model selection is best-effort / compatibility only.

## Troubleshooting

### CLI hangs / gets stuck
Check logs for stream lifecycle events. Enable debug logging:
```powershell
$env:LOG_LEVEL = "debug"
node server.js
```

Look for these log messages:
- `stream_start_anthropic` - Stream initiated
- `stream_completed_anthropic` - All chunks received
- `stream_closed_anthropic` - Response ended
- `stream_error_anthropic` - Error occurred

If you see `stream_completed` but not `stream_closed`, the issue is stream closure.

### Enable detailed logging
Set `LOG_LEVEL=debug` to see:
- Individual stream chunks
- Parse errors
- Token counts
- Stream lifecycle events

### Model confusion
The proxy now supports **real Claude Sonnet, Claude Haiku, GPT-5, and GPT-4.1 models** via GitHub Copilot Business API. Use `GET /v1/models` to see the full list of available models.
