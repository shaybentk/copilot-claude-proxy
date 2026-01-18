import express from "express";
import fetch from "node-fetch";
import { createOAuthDeviceAuth } from "@octokit/auth-oauth-device";
import crypto from "crypto";
import os from "os";

const PORT = Number(process.env.PORT || 8082);
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const COPILOT_OPENAI_BASE_URL = process.env.COPILOT_OPENAI_BASE_URL || null;
const COPILOT_OPENAI_MODEL = process.env.COPILOT_OPENAI_MODEL || "gpt-4o";
const GITHUB_COPILOT_CLIENT_ID = process.env.GITHUB_COPILOT_CLIENT_ID || "Iv1.b507a08c87ecfe98";
const GITHUB_COPILOT_TOKEN_URL = "https://api.github.com/copilot_internal/v2/token";
const GITHUB_COPILOT_COMPLETIONS_URL = "https://copilot-proxy.githubusercontent.com/v1/engines/copilot-codex/completions";
const RATE_LIMIT_DEFAULT = Number(process.env.RATE_LIMIT_DEFAULT || 60);
const RATE_LIMIT_CHAT_COMPLETIONS = Number(process.env.RATE_LIMIT_CHAT_COMPLETIONS || 20);
const MAX_TOKENS_PER_REQUEST = Number(process.env.MAX_TOKENS_PER_REQUEST || 4000);
const MAX_TOKENS_PER_MINUTE = Number(process.env.MAX_TOKENS_PER_MINUTE || 20000);

let githubToken = null;
let copilotToken = null;

const usage = {};

const log = (level, message, meta) => {
  const levels = { error: 0, warn: 1, info: 2, debug: 3 };
  const current = levels[LOG_LEVEL] ?? 2;
  if ((levels[level] ?? 2) <= current) {
    const payload = meta ? ` ${JSON.stringify(meta)}` : "";
    console.log(`[${level.toUpperCase()}] ${message}${payload}`);
  }
};

const fetchJson = async (url, body, options = {}) => {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const text = await response.text();
    const error = new Error(`Upstream error ${response.status}: ${text}`);
    error.status = response.status;
    throw error;
  }

  return response.json();
};

const extractClientToken = (req) => {
  // Prefer explicit auth headers. Fall back to empty string.
  // OpenAI-style: Authorization: Bearer <token>
  const authHeader = req.headers?.authorization || req.headers?.Authorization;
  if (typeof authHeader === "string") {
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (match?.[1]) return match[1].trim();
  }

  // Anthropic-style headers
  const xApiKey = req.headers?.["x-api-key"];
  if (typeof xApiKey === "string" && xApiKey.trim()) return xApiKey.trim();

  const anthropicApiKey = req.headers?.["anthropic-api-key"];
  if (typeof anthropicApiKey === "string" && anthropicApiKey.trim()) return anthropicApiKey.trim();

  // Some tools use x-api-key variants
  const openaiApiKey = req.headers?.["openai-api-key"];
  if (typeof openaiApiKey === "string" && openaiApiKey.trim()) return openaiApiKey.trim();

  return "";
};

const getMachineId = () => {
  // Deterministic machine id (similar intent to github-copilot-proxy)
  try {
    const nets = os.networkInterfaces();
    const invalid = new Set(["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]);
    for (const name of Object.keys(nets)) {
      for (const ni of nets[name] || []) {
        const mac = ni?.mac;
        if (mac && !invalid.has(mac)) {
          return crypto.createHash("sha256").update(mac, "utf8").digest("hex");
        }
      }
    }
  } catch {
    // ignore
  }
  return "copilot-claude-proxy";
};

const initiateDeviceFlow = async () => {
  const auth = createOAuthDeviceAuth({
    clientType: "oauth-app",
    clientId: GITHUB_COPILOT_CLIENT_ID,
    scopes: ["read:user"],
    onVerification(verification) {
      log("info", "device_flow", {
        verification_uri: verification.verification_uri,
        user_code: verification.user_code,
        expires_in: verification.expires_in,
        interval: verification.interval
      });
    }
  });

  const verification = await auth({ type: "oauth" });
  return {
    verification_uri: verification.verification_uri,
    user_code: verification.user_code,
    expires_in: verification.expires_in,
    interval: verification.interval,
    status: "pending_verification"
  };
};

const checkDeviceFlowAuth = async () => {
  if (githubToken && copilotToken) return true;

  const auth = createOAuthDeviceAuth({
    clientType: "oauth-app",
    clientId: GITHUB_COPILOT_CLIENT_ID,
    scopes: ["read:user"]
  });

  try {
    const tokenAuth = await auth({ type: "oauth" });
    if (tokenAuth?.token) {
      githubToken = tokenAuth.token;
      await refreshCopilotToken();
      return true;
    }
    return false;
  } catch (error) {
    if (String(error?.message || "").includes("authorization_pending")) {
      return false;
    }
    throw error;
  }
};

const refreshCopilotToken = async () => {
  if (!githubToken) {
    throw new Error("GitHub token is required for refresh");
  }

  const response = await fetch(GITHUB_COPILOT_TOKEN_URL, {
    method: "GET",
    headers: {
      Authorization: `token ${githubToken}`,
      "Editor-Version": "Cursor-IDE/1.0.0",
      "Editor-Plugin-Version": "copilot-cursor/1.0.0"
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to get Copilot token: ${response.status} ${response.statusText}`);
  }

  copilotToken = await response.json();
  return copilotToken;
};

const isTokenValid = () => {
  if (!copilotToken?.token) return false;
  const now = Math.floor(Date.now() / 1000);
  return now < (copilotToken.expires_at - 60);
};

const ensureCopilotAuth = async () => {
  // If we have a still-valid copilot token, we're good.
  if (isTokenValid()) return;

  // If token exists but expired, try refresh (requires githubToken).
  if (copilotToken?.token && githubToken) {
    try {
      await refreshCopilotToken();
      if (isTokenValid()) return;
    } catch (e) {
      // If refresh fails, force re-auth.
      githubToken = null;
      copilotToken = null;
      const err = new Error("Authentication required. Token refresh failed. Call /auth/login then /auth/check.");
      err.status = 401;
      err.code = "authentication_failed";
      throw err;
    }
  }

  // Otherwise, user must run device flow again.
  const err = new Error("Authentication required. Call /auth/login then /auth/check.");
  err.status = 401;
  err.code = "authentication_required";
  throw err;
};

const requireAuth = (handler) => {
  return async (req, res, next) => {
    try {
      await ensureCopilotAuth();
      await handler(req, res, next);
      return;
    } catch (err) {
      return next(err);
    }
  };
};

const initializeUsage = (sessionId) => {
  if (!usage[sessionId]) {
    usage[sessionId] = {
      requestCount: 0,
      tokenCount: 0,
      lastRequestTime: Date.now(),
      startTime: Date.now(),
      tokenTimestamps: [],
      requestTimestamps: []
    };
  }
};

const recordRequest = (sessionId) => {
  if (!usage[sessionId]) initializeUsage(sessionId);
  const now = Date.now();
  usage[sessionId].requestCount += 1;
  usage[sessionId].lastRequestTime = now;
  usage[sessionId].requestTimestamps.push(now);

  // keep 5 minutes of request timestamps
  const fiveMinutesAgo = now - 5 * 60 * 1000;
  usage[sessionId].requestTimestamps = usage[sessionId].requestTimestamps.filter((t) => t >= fiveMinutesAgo);
};

const recordTokens = (sessionId, tokenCount = 0) => {
  if (!usage[sessionId]) initializeUsage(sessionId);
  if (!tokenCount || tokenCount <= 0) return;
  const now = Date.now();
  usage[sessionId].tokenCount += tokenCount;
  usage[sessionId].tokenTimestamps.push({ tokens: tokenCount, timestamp: now });

  // keep 5 minutes of token timestamps
  const fiveMinutesAgo = now - 5 * 60 * 1000;
  usage[sessionId].tokenTimestamps = usage[sessionId].tokenTimestamps.filter((entry) => entry.timestamp >= fiveMinutesAgo);
};

const getUsage = (sessionId) => usage[sessionId] || null;

const getAllUsage = () => ({ ...usage });

const getTokenUsageInWindow = (sessionId, windowMs) => {
  if (!usage[sessionId]) return 0;
  const now = Date.now();
  const windowStart = now - windowMs;
  return usage[sessionId].tokenTimestamps
    .filter((entry) => entry.timestamp >= windowStart)
    .reduce((sum, entry) => sum + entry.tokens, 0);
};

const getRequestCountInWindow = (sessionId, windowMs) => {
  if (!usage[sessionId]) return 0;
  const now = Date.now();
  const windowStart = now - windowMs;
  return usage[sessionId].requestTimestamps.filter((t) => t >= windowStart).length;
};

const checkRateLimit = (sessionId, maxRequestsPerMinute = 60) => {
  if (!usage[sessionId]) return { limited: false, retryAfter: 0 };
  const now = Date.now();
  const windowMs = 60 * 1000;
  const countInWindow = getRequestCountInWindow(sessionId, windowMs);
  if (countInWindow >= maxRequestsPerMinute) {
    // Retry when the oldest request inside the window expires
    const oldest = usage[sessionId].requestTimestamps.reduce((min, t) => Math.min(min, t), now);
    const retryAfter = Math.ceil((oldest + windowMs - now) / 1000);
    return { limited: true, retryAfter: Math.max(1, retryAfter) };
  }
  return { limited: false, retryAfter: 0 };
};

const resetUsage = (sessionId) => {
  if (usage[sessionId]) {
    usage[sessionId] = {
      requestCount: 0,
      tokenCount: 0,
      lastRequestTime: Date.now(),
      startTime: Date.now(),
      tokenTimestamps: [],
      requestTimestamps: []
    };
  }
};

const getUsageSummary = () => {
  const sessions = Object.keys(usage);
  const totalRequests = sessions.reduce((sum, key) => sum + usage[key].requestCount, 0);
  const totalTokens = sessions.reduce((sum, key) => sum + usage[key].tokenCount, 0);
  return {
    totalRequests,
    totalTokens,
    activeSessions: sessions.length,
    averageTokensPerRequest: totalRequests > 0 ? totalTokens / totalRequests : 0
  };
};

const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  const { method, url } = req;
  log("debug", "request_received", { method, url });
  res.on("finish", () => {
    const duration = Date.now() - startTime;
    const { statusCode } = res;
    if (statusCode >= 500) {
      log("error", "request_finished", { method, url, statusCode, duration });
    } else if (statusCode >= 400) {
      log("warn", "request_finished", { method, url, statusCode, duration });
    } else {
      log("info", "request_finished", { method, url, statusCode, duration });
    }
  });
  next();
};

const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || "Internal Server Error";
  const code = err.code || "INTERNAL_ERROR";
  log("error", "handler_error", { status, message, path: req.originalUrl, method: req.method });
  res.status(status).json({
    error: {
      message,
      code,
      status
    }
  });
};

const rateLimiter = (maxRequestsPerMinute) => {
  return (req, res, next) => {
    const route = req.path;
    const routeLimit = route === "/v1/chat/completions" ? RATE_LIMIT_CHAT_COMPLETIONS : undefined;
    const effectiveLimit = maxRequestsPerMinute || routeLimit || RATE_LIMIT_DEFAULT;
    const token = extractClientToken(req);
    const ipAddress = req.ip || req.socket.remoteAddress || "";
    const sessionId = token
      ? crypto.createHash("sha256").update(token).digest("hex")
      : crypto.createHash("sha256").update(ipAddress).digest("hex");

    // Ensure usage exists (so token/rate checks can run)
    initializeUsage(sessionId);

    // Request-based rate limiting (sliding window)
    const { limited, retryAfter } = checkRateLimit(sessionId, effectiveLimit);
    if (limited) {
      res.setHeader("Retry-After", retryAfter.toString());
      return res.status(429).json({
        error: {
          message: `Rate limit exceeded. Try again in ${retryAfter} seconds.`,
          type: "rate_limit_exceeded",
          code: 429
        }
      });
    }

    if (route === "/v1/chat/completions" || route === "/v1/messages") {
      const tokensPastMinute = getTokenUsageInWindow(sessionId, 60 * 1000);
      if (tokensPastMinute > MAX_TOKENS_PER_MINUTE) {
        res.setHeader("Retry-After", "60");
        return res.status(429).json({
          error: {
            message: "Token usage rate limit exceeded. Try again in 60 seconds.",
            type: "token_rate_limit_exceeded",
            code: 429
          }
        });
      }

      // Request size guard (OpenAI-style requests use `messages: [{content: string}]`)
      // Anthropic-style requests use `messages: [{content: string|array}]` as well.
      if (req.body?.messages) {
        const estimatedTokens = req.body.messages.reduce((total, msg) => {
          if (!msg) return total;
          if (typeof msg.content === "string") return total + Math.ceil(msg.content.length / 4);
          if (Array.isArray(msg.content)) {
            const text = msg.content
              .map((b) => (b && b.type === "text" ? b.text : ""))
              .filter(Boolean)
              .join("\n");
            return total + Math.ceil(text.length / 4);
          }
          return total;
        }, 0);
        if (estimatedTokens > MAX_TOKENS_PER_REQUEST) {
          return res.status(429).json({
            error: {
              message: "Request exceeds maximum token limit. Please reduce the size of your messages.",
              type: "max_tokens_exceeded",
              code: 429
            }
          });
        }
      }
    }

    // Count this request after passing the checks
    recordRequest(sessionId);

    res.locals.sessionId = sessionId;
    res.locals.token = token;
    next();
  };
};

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(requestLogger);

const toOpenAIChat = (anthropicRequest) => {
  const { messages = [], system, max_tokens, temperature, top_p, stream } = anthropicRequest;

  const openaiMessages = [];
  if (system) {
    if (typeof system === "string") {
      openaiMessages.push({ role: "system", content: system });
    } else if (Array.isArray(system)) {
      const systemText = system
        .map((block) => (block && block.type === "text" ? block.text : ""))
        .filter(Boolean)
        .join("\n\n");
      if (systemText) {
        openaiMessages.push({ role: "system", content: systemText });
      }
    }
  }

  for (const msg of messages) {
    if (!msg || !msg.role) continue;
    if (typeof msg.content === "string") {
      openaiMessages.push({ role: msg.role, content: msg.content });
      continue;
    }

    if (Array.isArray(msg.content)) {
      let text = "";
      for (const block of msg.content) {
        if (!block || !block.type) continue;
        if (block.type === "text") {
          text += `${block.text}\n`;
        } else if (block.type === "tool_result") {
          const toolId = block.tool_use_id || "unknown";
          text += `Tool result for ${toolId}: `;
          if (typeof block.content === "string") {
            text += `${block.content}\n`;
          } else if (Array.isArray(block.content)) {
            for (const item of block.content) {
              if (item && item.type === "text") {
                text += `${item.text}\n`;
              } else if (item) {
                text += `${JSON.stringify(item)}\n`;
              }
            }
          } else if (block.content) {
            text += `${JSON.stringify(block.content)}\n`;
          }
        } else if (block.type === "tool_use") {
          text += `Tool call ${block.name || "tool"}: ${JSON.stringify(block.input || {})}\n`;
        } else if (block.type === "image") {
          text += `[Image content]\n`;
        }
      }
      openaiMessages.push({ role: msg.role, content: text.trim() || "..." });
    }
  }

  return {
    model: COPILOT_OPENAI_MODEL,
    messages: openaiMessages,
    max_tokens: Math.min(max_tokens || 1024, 4096),
    temperature: typeof temperature === "number" ? temperature : 0.7,
    top_p: typeof top_p === "number" ? top_p : 1,
    stream: Boolean(stream)
  };
};

const buildCopilotPrompt = (messages) => {
  if (!messages || !Array.isArray(messages)) return "";
  let systemPrompt = "";
  let userPrompts = "";
  let assistantResponses = "";
  for (const message of messages) {
    if (!message?.role || !message?.content) continue;
    if (message.role === "system") {
      systemPrompt += `${message.content}\n\n`;
    } else if (message.role === "user") {
      userPrompts += `User: ${message.content}\n\n`;
    } else if (message.role === "assistant") {
      assistantResponses += `Assistant: ${message.content}\n\n`;
    }
  }
  const lastMessage = messages[messages.length - 1];
  const needsAssistantPrompt = lastMessage?.role !== "user";
  return systemPrompt + userPrompts + assistantResponses + (needsAssistantPrompt ? "" : "Assistant: ");
};

const detectLanguageFromOpenAIMessages = (messages) => {
  if (!Array.isArray(messages) || messages.length === 0) return "javascript";
  const lastUser = [...messages].reverse().find((m) => m?.role === "user" && typeof m?.content === "string");
  const content = lastUser?.content || "";
  const codeBlockMatch = content.match(/```(\w+)/);
  if (codeBlockMatch?.[1]) return codeBlockMatch[1].toLowerCase();
  const fileExtensionMatch = content.match(/\.([a-zA-Z0-9]+)(?:\s|"|')/);
  if (fileExtensionMatch?.[1]) {
    const ext = fileExtensionMatch[1].toLowerCase();
    const map = {
      js: "javascript",
      ts: "typescript",
      py: "python",
      java: "java",
      c: "c",
      cpp: "cpp",
      cs: "csharp",
      go: "go",
      rb: "ruby",
      php: "php",
      html: "html",
      css: "css",
      json: "json",
      md: "markdown"
    };
    return map[ext] || "javascript";
  }
  return "javascript";
};

const toAnthropicResponse = (openaiResponse, requestedModel) => {
  const choice = openaiResponse?.choices?.[0];
  const content = choice?.message?.content ?? "";
  const finish = choice?.finish_reason || "stop";
  const usage = openaiResponse?.usage || {};

  return {
    id: openaiResponse?.id || `msg_${crypto.randomUUID()}`,
    model: requestedModel,
    role: "assistant",
    type: "message",
    content: [{ type: "text", text: content || "" }],
    stop_reason: finish === "length" ? "max_tokens" : finish === "tool_calls" ? "tool_use" : "end_turn",
    stop_sequence: null,
    usage: {
      input_tokens: usage.prompt_tokens || 0,
      output_tokens: usage.completion_tokens || 0,
      cache_creation_input_tokens: 0,
      cache_read_input_tokens: 0
    }
  };
};

const streamCopilotToAnthropic = async (res, copilotPayload, requestedModel, sessionId) => {
  const controller = new AbortController();
  res.on("close", () => controller.abort());

  const response = await fetch(GITHUB_COPILOT_COMPLETIONS_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${copilotToken.token}`,
      "X-Request-Id": crypto.randomUUID(),
      "Machine-Id": getMachineId(),
      "User-Agent": "GitHubCopilotChat/0.12.0",
      "Editor-Version": "Claude-CLI/1.0.0",
      "Editor-Plugin-Version": "copilot-claude-proxy/0.1.0",
      "Openai-Organization": "github-copilot",
      "Openai-Intent": "copilot-ghost"
    },
    body: JSON.stringify({ ...copilotPayload, stream: true }),
    signal: controller.signal
  });

  if (!response.ok || !response.body) {
    const text = await response.text();
    throw new Error(`Upstream streaming error ${response.status}: ${text}`);
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const messageId = `msg_${crypto.randomUUID()}`;
  res.write(`event: message_start\ndata: ${JSON.stringify({
    type: "message_start",
    message: {
      id: messageId,
      type: "message",
      role: "assistant",
      model: requestedModel,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: {
        input_tokens: 0,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
        output_tokens: 0
      }
    }
  })}\n\n`);

  res.write(`event: content_block_start\ndata: ${JSON.stringify({
    type: "content_block_start",
    index: 0,
    content_block: { type: "text", text: "" }
  })}\n\n`);

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.startsWith("data:")) continue;
      const data = line.replace(/^data:\s?/, "").trim();
      if (!data || data === "[DONE]") continue;

      let parsed;
      try {
        parsed = JSON.parse(data);
      } catch {
        continue;
      }

      const delta = parsed?.choices?.[0]?.text;
      if (delta) {
        // very rough estimate: ~4 chars per token
        if (sessionId) recordTokens(sessionId, Math.ceil(delta.length / 4));
        res.write(`event: content_block_delta\ndata: ${JSON.stringify({
          type: "content_block_delta",
          index: 0,
          delta: { type: "text_delta", text: delta }
        })}\n\n`);
      }
    }
  }

  res.write(`event: content_block_stop\ndata: ${JSON.stringify({ type: "content_block_stop", index: 0 })}\n\n`);
  res.write(`event: message_delta\ndata: ${JSON.stringify({
    type: "message_delta",
    delta: { stop_reason: "end_turn", stop_sequence: null },
    usage: { output_tokens: 0 }
  })}\n\n`);
  res.write(`event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
};

const streamCopilotToOpenAI = async (res, copilotPayload, openaiModel, sessionId) => {
  const controller = new AbortController();
  res.on("close", () => controller.abort());

  const response = await fetch(GITHUB_COPILOT_COMPLETIONS_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${copilotToken.token}`,
      "X-Request-Id": crypto.randomUUID(),
      "Machine-Id": getMachineId(),
      "User-Agent": "GitHubCopilotChat/0.12.0",
      "Editor-Version": "Cursor-IDE/1.0.0",
      "Editor-Plugin-Version": "copilot-claude-proxy/0.1.0",
      "Openai-Organization": "github-copilot",
      "Openai-Intent": "copilot-ghost"
    },
    body: JSON.stringify({ ...copilotPayload, stream: true }),
    signal: controller.signal
  });

  if (!response.ok || !response.body) {
    const text = await response.text();
    throw new Error(`Upstream streaming error ${response.status}: ${text}`);
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const streamId = `chatcmpl-${crypto.randomUUID()}`;

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.startsWith("data:")) continue;
      const data = line.replace(/^data:\s?/, "").trim();
      if (!data) continue;
      if (data === "[DONE]") {
        res.write("data: [DONE]\n\n");
        continue;
      }

      let parsed;
      try {
        parsed = JSON.parse(data);
      } catch {
        continue;
      }

      const delta = parsed?.choices?.[0]?.text;
      if (!delta) continue;
      if (sessionId) recordTokens(sessionId, Math.ceil(delta.length / 4));

      const chunk = {
        id: streamId,
        object: "chat.completion.chunk",
        created: Math.floor(Date.now() / 1000),
        model: openaiModel,
        choices: [
          {
            index: 0,
            delta: { content: delta },
            finish_reason: parsed?.choices?.[0]?.finish_reason || null
          }
        ]
      };

      res.write(`data: ${JSON.stringify(chunk)}\n\n`);
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
};

app.get("/auth/status", async (req, res) => {
  if (isTokenValid()) {
    return res.json({ status: "authenticated", expiresAt: copilotToken.expires_at });
  }
  if (copilotToken && !isTokenValid()) {
    try {
      const token = await refreshCopilotToken();
      return res.json({ status: "authenticated", expiresAt: token.expires_at });
    } catch (error) {
      githubToken = null;
      copilotToken = null;
      return res.json({ status: "unauthenticated", error: "Token refresh failed" });
    }
  }
  return res.json({ status: "unauthenticated" });
});

app.post("/auth/login", async (req, res) => {
  if (isTokenValid()) {
    return res.json({ status: "authenticated" });
  }
  try {
    const verification = await initiateDeviceFlow();
    return res.json(verification);
  } catch (error) {
    res.status(500).json({ error: String(error) });
  }
});

app.post("/auth/check", async (req, res) => {
  if (isTokenValid()) {
    return res.json({ status: "authenticated" });
  }
  try {
    const success = await checkDeviceFlowAuth();
    return res.json({ status: success ? "authenticated" : "pending_verification" });
  } catch (error) {
    if (String(error?.message || "").includes("authorization_pending")) {
      return res.json({ status: "pending_verification" });
    }
    res.status(500).json({ error: String(error) });
  }
});

app.post("/auth/logout", (req, res) => {
  githubToken = null;
  copilotToken = null;
  res.json({ status: "logged_out" });
});

app.post(
  "/v1/messages",
  rateLimiter(),
  requireAuth(async (req, res) => {
  try {
    const anthropicRequest = req.body || {};
    const requestedModel = anthropicRequest.model || "claude";
    const openaiRequest = toOpenAIChat(anthropicRequest);

    const copilotPayload = {
      prompt: buildCopilotPrompt(openaiRequest.messages),
      suffix: "",
      max_tokens: openaiRequest.max_tokens || 500,
      temperature: openaiRequest.temperature || 0.7,
      top_p: openaiRequest.top_p || 1,
      n: 1,
      stream: Boolean(openaiRequest.stream),
      stop: ["\n\n"],
      extra: {
        language: detectLanguageFromOpenAIMessages(openaiRequest.messages),
        next_indent: 0,
        trim_by_indentation: true
      }
    };

    if (openaiRequest.stream) {
      await streamCopilotToAnthropic(res, copilotPayload, requestedModel, res.locals.sessionId);
      return;
    }

    const response = await fetch(GITHUB_COPILOT_COMPLETIONS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${copilotToken.token}`,
        "X-Request-Id": crypto.randomUUID(),
        "Machine-Id": getMachineId(),
        "User-Agent": "GitHubCopilotChat/0.12.0",
        "Editor-Version": "Claude-CLI/1.0.0",
        "Editor-Plugin-Version": "copilot-claude-proxy/0.1.0",
        "Openai-Organization": "github-copilot",
        "Openai-Intent": "copilot-ghost"
      },
      body: JSON.stringify(copilotPayload)
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Copilot error ${response.status}: ${text}`);
    }

    const data = await response.json();
    const openaiResponse = {
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: COPILOT_OPENAI_MODEL,
      choices: data.choices.map((choice, index) => ({
        index,
        message: {
          role: "assistant",
          content: choice.text
        },
        finish_reason: choice.finish_reason || "stop"
      })),
      usage: data.usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
    };

    const anthropicResponse = toAnthropicResponse(openaiResponse, requestedModel);
    recordTokens(res.locals.sessionId, openaiResponse?.usage?.total_tokens || 0);
    res.json(anthropicResponse);
  } catch (error) {
    log("error", "request_failed", { error: String(error) });
    res.status(error.status || 500).json({ error: String(error) });
  }
  })
);

app.post("/v1/messages/count_tokens", rateLimiter(), (req, res) => {
  const { messages = [], system } = req.body || {};
  let text = "";
  if (system) {
    text += typeof system === "string" ? system : JSON.stringify(system);
  }
  for (const msg of messages) {
    if (typeof msg?.content === "string") {
      text += msg.content;
    } else if (Array.isArray(msg?.content)) {
      for (const block of msg.content) {
        if (block?.text) text += block.text;
      }
    }
  }
  const estimated = Math.ceil(text.length / 4);
  res.json({ input_tokens: estimated });
});

// Optional: also expose a health endpoint without auth
app.get("/", (req, res) => {
  res.json({ status: "ok", proxy: "copilot-claude-proxy" });
});

app.get(
  "/v1/models",
  rateLimiter(),
  requireAuth((req, res) => {
    res.json({
      object: "list",
      data: [
        { id: "gpt-4", object: "model", created: Date.now(), owned_by: "github-copilot" },
        { id: "gpt-4o", object: "model", created: Date.now(), owned_by: "github-copilot" },
        { id: "gpt-3.5-turbo", object: "model", created: Date.now(), owned_by: "github-copilot" }
      ]
    });
  })
);

app.post(
  "/v1/chat/completions",
  rateLimiter(RATE_LIMIT_CHAT_COMPLETIONS),
  requireAuth(async (req, res) => {
  const openaiRequest = req.body || {};
  try {
    const copilotPayload = {
      prompt: buildCopilotPrompt(openaiRequest.messages || []),
      suffix: "",
      max_tokens: openaiRequest.max_tokens || 500,
      temperature: openaiRequest.temperature || 0.7,
      top_p: openaiRequest.top_p || 1,
      n: openaiRequest.n || 1,
      stream: Boolean(openaiRequest.stream),
      stop: ["\n\n"],
      extra: {
        language: detectLanguageFromOpenAIMessages(openaiRequest.messages || []),
        next_indent: 0,
        trim_by_indentation: true
      }
    };

    if (openaiRequest.stream) {
      await streamCopilotToOpenAI(res, copilotPayload, openaiRequest.model || COPILOT_OPENAI_MODEL, res.locals.sessionId);
      return;
    }

    const response = await fetch(GITHUB_COPILOT_COMPLETIONS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${copilotToken.token}`,
        "X-Request-Id": crypto.randomUUID(),
        "Machine-Id": getMachineId(),
        "User-Agent": "GitHubCopilotChat/0.12.0",
        "Editor-Version": "Cursor-IDE/1.0.0",
        "Editor-Plugin-Version": "copilot-claude-proxy/0.1.0",
        "Openai-Organization": "github-copilot",
        "Openai-Intent": "copilot-ghost"
      },
      body: JSON.stringify(copilotPayload)
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Copilot error ${response.status}: ${text}`);
    }

    const data = await response.json();
    const responsePayload = {
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: openaiRequest.model || "copilot",
      choices: data.choices.map((choice, index) => ({
        index,
        message: {
          role: "assistant",
          content: choice.text
        },
        finish_reason: choice.finish_reason || "stop"
      })),
      usage: data.usage || { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
    };
    recordTokens(res.locals.sessionId, responsePayload.usage.total_tokens || 0);
    res.json(responsePayload);
  } catch (error) {
    log("error", "copilot_completion_failed", { error: String(error) });
    res.status(500).json({ error: String(error) });
  }
  })
);

app.get(
  "/usage/summary",
  requireAuth((req, res) => {
  const summary = getUsageSummary();
  res.json({
    ...summary,
    averageTokensPerRequest: Math.round(summary.averageTokensPerRequest * 100) / 100
  });
  })
);

app.get(
  "/usage/details",
  requireAuth((req, res) => {
  const allUsage = getAllUsage();
  const usageArray = Object.entries(allUsage).map(([sessionId, metrics]) => ({
    sessionId: sessionId.substring(0, 8) + "...",
    startTime: new Date(metrics.startTime).toISOString(),
    lastRequestTime: new Date(metrics.lastRequestTime).toISOString(),
    requestCount: metrics.requestCount,
    tokenCount: metrics.tokenCount,
    duration: Math.round((Date.now() - metrics.startTime) / 1000 / 60) + " minutes"
  }));
  res.json(usageArray);
  })
);

app.post(
  "/usage/reset/:sessionId",
  requireAuth((req, res) => {
  const { sessionId } = req.params;
  const allUsage = getAllUsage();
  const fullSessionId = Object.keys(allUsage).find((id) => id.startsWith(sessionId));
  if (!fullSessionId) {
    return res.status(404).json({ error: { message: "Session ID not found", code: "session_not_found" } });
  }
  resetUsage(fullSessionId);
  res.json({ success: true, message: `Usage reset for session: ${sessionId}` });
  })
);

app.post(
  "/usage/reset-all",
  requireAuth((req, res) => {
  const allUsage = getAllUsage();
  Object.keys(allUsage).forEach((sessionId) => resetUsage(sessionId));
  res.json({ success: true, message: "All usage metrics reset" });
  })
);

app.use(errorHandler);

app.listen(PORT, () => {
  log("info", "server_started", { port: PORT, copilotBase: COPILOT_OPENAI_BASE_URL });
});
