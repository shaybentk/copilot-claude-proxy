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
COPILOT_OPENAI_MODEL=gpt-4o
GITHUB_COPILOT_CLIENT_ID=Iv1.b507a08c87ecfe98
RATE_LIMIT_DEFAULT=60
RATE_LIMIT_CHAT_COMPLETIONS=20
MAX_TOKENS_PER_REQUEST=4000
MAX_TOKENS_PER_MINUTE=20000
LOG_LEVEL=info
```

### About `COPILOT_OPENAI_MODEL`
This is mainly used as **response metadata** (what we report back to clients).
Copilot's internal completions endpoint does not provide a supported/official way to force a specific model.

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

## Auth (Device Flow)
1. Start the server.
2. POST `http://localhost:8082/auth/login` to get `verification_uri` and `user_code`.
3. Visit the URI and enter the code.
4. POST `http://localhost:8082/auth/check` until authenticated.

### Auto-refresh
The proxy will automatically refresh the Copilot token (using the saved GitHub OAuth token) when it expires.
If refresh fails, you'll get a **401** and need to redo the device flow.

## Use with Claude Code CLI
Claude Code CLI expects Anthropic env vars.

### macOS/Linux
```bash
export ANTHROPIC_BASE_URL=http://localhost:8082
export ANTHROPIC_AUTH_TOKEN=test  # any value is fine; this proxy doesn’t validate it
claude
```

### Windows PowerShell (current session)
```powershell
$env:ANTHROPIC_BASE_URL = "http://localhost:8082"
$env:ANTHROPIC_AUTH_TOKEN = "test"  # any value is fine; this proxy doesn’t validate it
claude
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
