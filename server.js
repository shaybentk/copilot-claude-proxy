import express from "express";
import fetch from "node-fetch";
import { createOAuthDeviceAuth } from "@octokit/auth-oauth-device";
import crypto from "crypto";
import os from "os";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const PORT = Number(process.env.PORT || 8082);
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const COPILOT_OPENAI_BASE_URL = process.env.COPILOT_OPENAI_BASE_URL || null;
const COPILOT_DEFAULT_MODEL = process.env.COPILOT_DEFAULT_MODEL || "claude-sonnet-4.5"; // Default model
const GITHUB_COPILOT_CLIENT_ID = process.env.GITHUB_COPILOT_CLIENT_ID || "Iv1.b507a08c87ecfe98";
const TOKEN_FILE = path.join(os.homedir(), ".copilot-claude-proxy-tokens.json");
const GITHUB_COPILOT_TOKEN_URL = "https://api.github.com/copilot_internal/v2/token";
const GITHUB_COPILOT_CHAT_URL = "https://api.business.githubcopilot.com/chat/completions";
const GITHUB_COPILOT_MODELS_URL = "https://api.business.githubcopilot.com/models";
const RATE_LIMIT_DEFAULT = Number(process.env.RATE_LIMIT_DEFAULT || 60);
const RATE_LIMIT_CHAT_COMPLETIONS = Number(process.env.RATE_LIMIT_CHAT_COMPLETIONS || 20);
const MAX_TOKENS_PER_REQUEST = Number(process.env.MAX_TOKENS_PER_REQUEST || 128000); // Match Claude Sonnet 4.5 context
const MAX_TOKENS_PER_MINUTE = Number(process.env.MAX_TOKENS_PER_MINUTE || 200000); // Increased for long conversations

let githubToken = null;
let copilotToken = null;
let deviceFlowAuth = null; // Store the auth instance
let authCheckPromise = null; // Store the ongoing auth check
let availableModels = null; // Cache available models
let modelsLastFetched = null; // Last fetch time

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

const saveTokens = () => {
  try {
    const data = {
      githubToken,
      copilotToken,
      savedAt: Date.now()
    };
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(data, null, 2), "utf8");
    log("debug", "tokens_saved", { file: TOKEN_FILE });
  } catch (error) {
    log("error", "token_save_failed", { error: String(error) });
  }
};

const loadExistingCopilotTokens = () => {
  // Try GitHub CLI first (best option - uses keyring)
  try {
    log("debug", "checking_github_cli");
    const token = execSync("gh auth token", { encoding: "utf8" }).trim();
    if (token && (token.startsWith("gho_") || token.startsWith("ghp_"))) {
      log("info", "found_github_cli_token", { 
        message: "Using GitHub CLI authentication (from keyring)" 
      });
      return token;
    }
  } catch (error) {
    log("debug", "github_cli_not_available", { error: String(error) });
  }

  // Try Windows Credential Manager via PowerShell
  if (os.platform() === "win32") {
    try {
      log("debug", "checking_windows_credential_manager");
      
      const psScript = `
Add-Type -AssemblyName System.Security
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class CredMan {
    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);
    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern void CredFree(IntPtr credentialPtr);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct Credential {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
}
"@

$targets = @("vscode.github-authentication", "cursor.github-authentication", "github.auth")
foreach ($target in $targets) {
    try {
        $credPtr = [IntPtr]::Zero
        if ([CredMan]::CredRead($target, 1, 0, [ref]$credPtr)) {
            $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [type][CredMan+Credential])
            $password = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($cred.CredentialBlob, $cred.CredentialBlobSize / 2)
            [CredMan]::CredFree($credPtr)
            if ($password -match '^(gho_|ghp_|github_pat_)') {
                Write-Output $password
                exit 0
            }
        }
    } catch {}
}
`;
      
      const token = execSync(`powershell -NoProfile -Command "${psScript}"`, { 
        encoding: "utf8",
        stdio: ["pipe", "pipe", "ignore"]
      }).trim();
      
      if (token && (token.startsWith("gho_") || token.startsWith("ghp_") || token.startsWith("github_pat_"))) {
        log("info", "found_token_in_credential_manager", { 
          message: "Using GitHub token from Windows Credential Manager" 
        });
        return token;
      }
    } catch (error) {
      log("debug", "credential_manager_extraction_failed", { error: String(error) });
    }
  }
  
  // Try environment variable
  if (process.env.GITHUB_TOKEN) {
    log("info", "using_env_github_token");
    return process.env.GITHUB_TOKEN;
  }
  
  // Try to read from VS Code GitHub Copilot extension config files
  const possiblePaths = [
    path.join(os.homedir(), "AppData", "Roaming", "GitHub Copilot", "hosts.json"),
    path.join(os.homedir(), "AppData", "Local", "github-copilot", "hosts.json"),
    path.join(os.homedir(), ".config", "github-copilot", "hosts.json"),
    path.join(os.homedir(), "Library", "Application Support", "github-copilot", "hosts.json")
  ];

  for (const configPath of possiblePaths) {
    try {
      if (fs.existsSync(configPath)) {
        log("debug", "checking_copilot_config", { path: configPath });
        const content = fs.readFileSync(configPath, "utf8");
        const config = JSON.parse(content);
        
        const githubConfig = config["github.com"];
        if (githubConfig?.oauth_token) {
          log("info", "found_existing_copilot_token", { path: configPath });
          return githubConfig.oauth_token;
        }
      }
    } catch (error) {
      log("debug", "failed_to_read_config", { path: configPath });
    }
  }
  
  log("warn", "no_existing_copilot_tokens", { 
    message: "Could not find existing GitHub Copilot tokens. Will need to authenticate."
  });
  return null;
};

const loadTokens = () => {
  try {
    // First, try to load from our saved tokens
    if (fs.existsSync(TOKEN_FILE)) {
      const content = fs.readFileSync(TOKEN_FILE, "utf8");
      const data = JSON.parse(content);
      if (data.githubToken && data.copilotToken) {
        githubToken = data.githubToken;
        copilotToken = data.copilotToken;
        log("info", "tokens_loaded", { file: TOKEN_FILE });
        return true;
      }
    }

    // If no saved tokens, try to load from existing Copilot installation
    const existingToken = loadExistingCopilotTokens();
    if (existingToken) {
      githubToken = existingToken;
      log("info", "using_existing_copilot_token");
      return true;
    }
  } catch (error) {
    log("error", "token_load_failed", { error: String(error) });
  }
  return false;
};

const clearTokens = () => {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      fs.unlinkSync(TOKEN_FILE);
      log("info", "tokens_cleared", { file: TOKEN_FILE });
    }
  } catch (error) {
    log("error", "token_clear_failed", { error: String(error) });
  }
};

const initiateDeviceFlow = async () => {
  return new Promise((resolve, reject) => {
    deviceFlowAuth = createOAuthDeviceAuth({
      clientType: "oauth-app",
      clientId: GITHUB_COPILOT_CLIENT_ID,
      scopes: ["read:user"],
      onVerification(verification) {
        log("info", "device_flow_started", {
          verification_uri: verification.verification_uri,
          user_code: verification.user_code,
          expires_in: verification.expires_in
        });
        resolve({
          verification_uri: verification.verification_uri,
          user_code: verification.user_code,
          expires_in: verification.expires_in,
          interval: verification.interval,
          status: "pending_verification"
        });
      }
    });

    deviceFlowAuth({ type: "oauth" }).catch(reject);
  });
};

const checkDeviceFlowAuth = async () => {
  if (githubToken && copilotToken) return true;

  if (!deviceFlowAuth) {
    throw new Error("Device flow not initiated. Call /auth/login first.");
  }
// If already checking, return pending
  if (authCheckPromise) {
    return false;
  }

  try {
    // Start the auth check but don't wait for it
    authCheckPromise = deviceFlowAuth({ type: "oauth" })
      .then(async (tokenAuth) => {
        if (tokenAuth?.token) {
          githubToken = tokenAuth.token;
          await refreshCopilotToken();
          saveTokens();
          deviceFlowAuth = null;
          authCheckPromise = null;
          log("info", "authentication_successful");
          return true;
        }
        authCheckPromise = null;
        return false;
      })
      .catch((error) => {
        authCheckPromise = null;
        if (String(error?.message || "").includes("authorization_pending") || 
            String(error?.message || "").includes("slow_down")) {
          return false;
        }
        deviceFlowAuth = null;
        throw error;
      });

    // Return immediately - don't wait
    return false;
  } catch (error) {
    authCheckPromise = null;
    if (String(error?.message || "").includes("authorization_pending") || 
        String(error?.message || "").includes("slow_down")) {
      return false;
    }
    deviceFlowAuth = null;
    deviceFlowAuth = null; // Clear on other errors
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
  saveTokens();
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

  // Try to load tokens from disk if not in memory
  if (!githubToken || !copilotToken) {
    const loaded = loadTokens();
    if (loaded && githubToken) {
      // We have a GitHub token, now get/refresh the Copilot token
      try {
        await refreshCopilotToken();
        if (isTokenValid()) return;
      } catch (e) {
        log("warn", "copilot_token_refresh_failed", { error: String(e) });
      }
    }
  }

  // If token exists but expired, try refresh (requires githubToken).
  if (githubToken && (!copilotToken || !isTokenValid())) {
    try {
      await refreshCopilotToken();
      if (isTokenValid()) return;
    } catch (e) {
      log("error", "token_refresh_failed", { error: String(e) });
      // Don't clear tokens yet, might be temporary network issue
    }
  }

  // If still no valid token, user needs to authenticate
  if (!isTokenValid()) {
    const err = new Error("Authentication required. No valid Copilot subscription found. Make sure you have an active GitHub Copilot subscription and run: npm start");
    err.status = 401;
    err.code = "authentication_required";
    throw err;
  }
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
  log("error", "handler_error", { 
    status, 
    message, 
    path: req.originalUrl, 
    method: req.method,
    stack: err.stack
  });
  
  if (!res.headersSent) {
    res.status(status).json({
      error: {
        message,
        code,
        status
      }
    });
  }
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
    messages: openaiMessages,
    max_tokens: Math.min(max_tokens || 1024, 16384), // Increased limit for new models
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

// Fetch available models from GitHub Copilot
const fetchAvailableModels = async () => {
  // Cache for 1 hour
  if (availableModels && modelsLastFetched && (Date.now() - modelsLastFetched) < 3600000) {
    return availableModels;
  }

  try {
    log("info", "fetching_copilot_models");
    const response = await fetch(GITHUB_COPILOT_MODELS_URL, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${copilotToken.token}`,
        "X-GitHub-Api-Version": "2023-07-07",
        "Copilot-Integration-Id": "vscode-chat",
        "Editor-Plugin-Version": "copilot-chat/0.22.4",
        "Editor-Version": "vscode/1.95.0",
        "User-Agent": "GitHubCopilotChat/0.22.4"
      }
    });

    if (!response.ok) {
      log("error", "failed_to_fetch_models", { status: response.status });
      // Return a default list if API fails
      return {
        data: [
          { id: "gpt-4.1", name: "GPT-4.1", vendor: "Azure OpenAI" },
          { id: "gpt-4o", name: "GPT-4o", vendor: "Azure OpenAI" },
          { id: "claude-sonnet-4.5", name: "Claude Sonnet 4.5", vendor: "Anthropic" }
        ]
      };
    }

    const data = await response.json();
    availableModels = data;
    modelsLastFetched = Date.now();
    log("info", "models_fetched", { count: data?.data?.length || 0 });
    return data;
  } catch (error) {
    log("error", "fetch_models_error", { error: error.message });
    // Return default list on error
    return {
      data: [
        { id: "gpt-4.1", name: "GPT-4.1", vendor: "Azure OpenAI" },
        { id: "gpt-4o", name: "GPT-4o", vendor: "Azure OpenAI" },
        { id: "claude-sonnet-4.5", name: "Claude Sonnet 4.5", vendor: "Anthropic" }
      ]
    };
  }
};

// Map Anthropic model names to GitHub Copilot model names
const mapModelName = (requestedModel) => {
  if (!requestedModel) return COPILOT_DEFAULT_MODEL;

  // Direct mappings for common Anthropic model names
  const modelMappings = {
    "claude-3-5-sonnet-20241022": "claude-sonnet-4",
    "claude-3-5-sonnet-20240620": "claude-sonnet-4",
    "claude-sonnet-3.5": "claude-sonnet-4",
    "claude-3-sonnet": "claude-sonnet-4",
    "claude-sonnet-4-5-20251001": "claude-sonnet-4.5",
    "claude-sonnet-4-5-20250929": "claude-sonnet-4.5",
    "claude-3-5-haiku-20241022": "claude-sonnet-4.5", // Force Sonnet instead of Haiku
    "claude-haiku-4-5-20251001": "claude-sonnet-4.5", // Force Sonnet instead of Haiku
    "claude-opus-4-5-20251101": "claude-sonnet-4.5", // Map opus to sonnet 4.5 (closest available)
    "gpt-4-turbo": "gpt-4.1",
    "gpt-4-turbo-preview": "gpt-4.1",
    "gpt-4-0125-preview": "gpt-4.1"
  };

  // Check direct mapping first
  if (modelMappings[requestedModel]) {
    log("debug", "model_mapped", { from: requestedModel, to: modelMappings[requestedModel] });
    return modelMappings[requestedModel];
  }

  // If it looks like a valid GitHub Copilot model ID, use it directly
  if (requestedModel.startsWith("gpt-") || requestedModel.startsWith("claude-")) {
    return requestedModel;
  }

  // Fallback to default
  log("debug", "model_fallback", { requested: requestedModel, fallback: COPILOT_DEFAULT_MODEL });
  return COPILOT_DEFAULT_MODEL;
};

const streamCopilotToAnthropic = async (res, copilotPayload, requestedModel, sessionId) => {
  const controller = new AbortController();
  res.on("close", () => controller.abort());

  // Map the requested model to a GitHub Copilot model
  const copilotModel = mapModelName(requestedModel);
  log("info", "using_copilot_model", { requested: requestedModel, actual: copilotModel });

  const response = await fetch(GITHUB_COPILOT_CHAT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${copilotToken.token}`,
      "X-Request-Id": crypto.randomUUID(),
      "X-GitHub-Api-Version": "2025-10-01",
      "Copilot-Integration-Id": "vscode-chat",
      "Editor-Plugin-Version": "copilot-chat/0.36.1",
      "Editor-Version": "vscode/1.108.1",
      "Openai-Intent": "conversation-agent",
      "X-Interaction-Type": "conversation-agent",
      "X-Interaction-Id": crypto.randomUUID(),
      "User-Agent": "GitHubCopilotChat/0.36.1"
    },
    body: JSON.stringify({ ...copilotPayload, model: copilotModel, stream: true }),
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
  log("info", "stream_start_anthropic", { messageId, model: requestedModel });
  
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

  const streamId = `msg_${crypto.randomUUID()}`;

  // State tracking for proper content block management (like copilot-api)
  const streamState = {
    contentBlockIndex: 0,
    contentBlockOpen: false,
    toolCalls: {}  // Map of tool call index -> {id, name, anthropicBlockIndex}
  };

  // Handle node-fetch stream (async iterator)
  let chunkCount = 0;
  let totalChars = 0;
  try {
    for await (const chunk of response.body) {
      chunkCount++;
      const text = new TextDecoder().decode(chunk);
      const lines = text.split("\n");

      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const data = line.replace(/^data:\s?/, "").trim();
        if (!data || data === "[DONE]") {
          log("debug", "stream_done_marker", { messageId });
          continue;
        }

        let parsed;
        try {
          parsed = JSON.parse(data);
        } catch (parseErr) {
          // Silently skip incomplete JSON chunks (common during tool call streaming)
          continue;
        }

        const choice = parsed?.choices?.[0];
        if (!choice) continue;

        const delta = choice.delta?.content || choice.text;
        const toolCalls = choice.delta?.tool_calls;

        // Handle text content
        if (delta) {
          // Check if a tool block is currently open
          const isToolBlockOpen = streamState.contentBlockOpen && 
            Object.values(streamState.toolCalls).some(tc => tc.anthropicBlockIndex === streamState.contentBlockIndex);
          
          if (isToolBlockOpen) {
            // Close the tool block before starting text
            res.write(`event: content_block_stop\ndata: ${JSON.stringify({
              type: "content_block_stop",
              index: streamState.contentBlockIndex
            })}\n\n`);
            streamState.contentBlockIndex++;
            streamState.contentBlockOpen = false;
          }

          if (!streamState.contentBlockOpen) {
            // Start new text block
            res.write(`event: content_block_start\ndata: ${JSON.stringify({
              type: "content_block_start",
              index: streamState.contentBlockIndex,
              content_block: { type: "text", text: "" }
            })}\n\n`);
            streamState.contentBlockOpen = true;
          }

          totalChars += delta.length;
          if (sessionId) recordTokens(sessionId, Math.ceil(delta.length / 4));
          
          res.write(`event: content_block_delta\ndata: ${JSON.stringify({
            type: "content_block_delta",
            index: streamState.contentBlockIndex,
            delta: { type: "text_delta", text: delta }
          })}\n\n`);
        }

        // Handle tool calls (agent mode)
        if (toolCalls && toolCalls.length > 0) {
          log("info", "tool_call_received", { 
            toolCalls: toolCalls,
            messageId: messageId 
          });
          
          for (const toolCall of toolCalls) {
            // New tool call starting (has id and name)
            if (toolCall.id && toolCall.function?.name) {
              // Close any currently open block first
              if (streamState.contentBlockOpen) {
                res.write(`event: content_block_stop\ndata: ${JSON.stringify({
                  type: "content_block_stop",
                  index: streamState.contentBlockIndex
                })}\n\n`);
                streamState.contentBlockIndex++;
                streamState.contentBlockOpen = false;
              }

              const anthropicBlockIndex = streamState.contentBlockIndex;
              streamState.toolCalls[toolCall.index] = {
                id: toolCall.id,
                name: toolCall.function.name,
                anthropicBlockIndex
              };

              log("info", "tool_call_start", { 
                toolName: toolCall.function.name, 
                toolId: toolCall.id,
                index: anthropicBlockIndex
              });

              res.write(`event: content_block_start\ndata: ${JSON.stringify({
                type: "content_block_start",
                index: anthropicBlockIndex,
                content_block: {
                  type: "tool_use",
                  id: toolCall.id,
                  name: toolCall.function.name,
                  input: {}
                }
              })}\n\n`);
              streamState.contentBlockOpen = true;
            }

            // Tool arguments chunk (may be partial JSON)
            if (toolCall.function?.arguments) {
              const toolCallInfo = streamState.toolCalls[toolCall.index];
              if (toolCallInfo) {
                res.write(`event: content_block_delta\ndata: ${JSON.stringify({
                  type: "content_block_delta",
                  index: toolCallInfo.anthropicBlockIndex,
                  delta: {
                    type: "input_json_delta",
                    partial_json: toolCall.function.arguments
                  }
                })}\n\n`);
              }
            }
          }
        }

        // Handle finish_reason
        if (choice.finish_reason) {
          if (streamState.contentBlockOpen) {
            res.write(`event: content_block_stop\ndata: ${JSON.stringify({
              type: "content_block_stop",
              index: streamState.contentBlockIndex
            })}\n\n`);
            streamState.contentBlockOpen = false;
          }
        }
      }
    }
    log("info", "stream_completed_anthropic", { messageId, chunkCount, totalChars });
  } catch (streamErr) {
    log("error", "stream_error_anthropic", { messageId, error: streamErr.message, stack: streamErr.stack });
    throw streamErr;
  }

  // Don't send content_block_stop here - it's already sent when finish_reason is encountered
  
  res.write(`event: message_delta\ndata: ${JSON.stringify({
    type: "message_delta",
    delta: { stop_reason: "end_turn", stop_sequence: null },
    usage: { output_tokens: 0 }
  })}\n\n`);
  log("debug", "stream_message_delta", { messageId });
  
  res.write(`event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`);
  log("debug", "stream_message_stop", { messageId });
  
  // Ensure all data is flushed before ending
  if (typeof res.flush === 'function') res.flush();
  
  res.end();
  log("info", "stream_closed_anthropic", { messageId });
};

const streamCopilotToOpenAI = async (res, copilotPayload, openaiModel, sessionId) => {
  const controller = new AbortController();
  res.on("close", () => {
    log("info", "client_closed_connection_openai", { streamId: "pending" });
    controller.abort();
  });

  // Map the requested model
  const copilotModel = mapModelName(openaiModel);
  log("info", "using_copilot_model_openai", { requested: openaiModel, actual: copilotModel });

  const response = await fetch(GITHUB_COPILOT_CHAT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${copilotToken.token}`,
      "X-Request-Id": crypto.randomUUID(),
      "X-GitHub-Api-Version": "2025-10-01",
      "Copilot-Integration-Id": "vscode-chat",
      "Editor-Plugin-Version": "copilot-chat/0.36.1",
      "Editor-Version": "vscode/1.108.1",
      "Openai-Intent": "conversation-agent",
      "X-Interaction-Type": "conversation-agent",
      "X-Interaction-Id": crypto.randomUUID(),
      "User-Agent": "GitHubCopilotChat/0.36.1"
    },
    body: JSON.stringify({ ...copilotPayload, model: copilotModel, stream: true }),
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
  log("info", "stream_start_openai", { streamId, model: openaiModel });

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  // Handle node-fetch stream (async iterator)
  let chunkCount = 0;
  let totalChars = 0;
  try {
    for await (const chunk of response.body) {
      chunkCount++;
      const text = new TextDecoder().decode(chunk);
      const lines = text.split("\n");
      
      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const data = line.replace(/^data:\s?/, "").trim();
        
        if (data === "[DONE]") {
          log("debug", "stream_done_marker_openai", { streamId });
          res.write("data: [DONE]\n\n");
          continue;
        }
        
        if (!data) continue;

        let parsed;
        try {
          parsed = JSON.parse(data);
        } catch (parseErr) {
          log("debug", "stream_parse_error_openai", { line: data.substring(0, 100) });
          continue;
        }

        // New chat completions format: choices[0].delta.content
        const delta = parsed?.choices?.[0]?.delta?.content || parsed?.choices?.[0]?.text;
        if (!delta) continue;
        
        totalChars += delta.length;
        if (sessionId) recordTokens(sessionId, Math.ceil(delta.length / 4));

        const responseChunk = {
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

        res.write(`data: ${JSON.stringify(responseChunk)}\n\n`);
      }
    }
    log("info", "stream_completed_openai", { streamId, chunkCount, totalChars });
  } catch (streamErr) {
    log("error", "stream_error_openai", { streamId, error: streamErr.message, stack: streamErr.stack });
    throw streamErr;
  }

  res.write("data: [DONE]\n\n");
  log("info", "stream_end_signal_sent_openai", { streamId });
  
  // Ensure all data is flushed before ending
  if (typeof res.flush === 'function') res.flush();
  
  res.end();
  log("info", "stream_closed_openai", { streamId });
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
  clearTokens();
  res.json({ status: "logged_out" });
});

// Stub endpoint for Claude CLI event logging (prevents 404 errors)
app.post("/api/event_logging/batch", (req, res) => {
  log("debug", "event_logging_received", { events: req.body?.length || 0 });
  res.status(200).json({ success: true });
});

app.post(
  "/v1/messages",
  rateLimiter(),
  requireAuth(async (req, res) => {
  try {
    const anthropicRequest = req.body || {};
    const requestedModel = anthropicRequest.model || "claude";
    const openaiRequest = toOpenAIChat(anthropicRequest);

    // Check for tools (agent mode)
    const hasTools = anthropicRequest.tools && anthropicRequest.tools.length > 0;
    
    // Check for thinking mode
    const thinkingBudget = anthropicRequest.thinking_budget || anthropicRequest.thinking?.budget_tokens;

    // Calculate max_tokens: must be > thinking_budget if thinking mode is enabled
    let maxTokens = openaiRequest.max_tokens || 4096;
    if (thinkingBudget) {
      // max_tokens must be greater than thinking_budget
      // Add at least 4096 tokens for the actual response after thinking
      maxTokens = Math.max(maxTokens, thinkingBudget + 4096);
    }

    // Log the converted request for debugging
    log("info", "request_details", { 
      model: anthropicRequest.model,
      messageCount: openaiRequest.messages?.length || 0,
      agentMode: hasTools,
      toolCount: anthropicRequest.tools?.length || 0,
      thinkingMode: !!thinkingBudget,
      thinkingBudget: thinkingBudget,
      maxTokens: maxTokens,
      stream: anthropicRequest.stream
    });

    // New chat completions format - messages array directly
    const copilotPayload = {
      messages: openaiRequest.messages || [],
      max_tokens: maxTokens,
      temperature: openaiRequest.temperature || 0.7,
      top_p: openaiRequest.top_p || 1,
      n: 1,
      stream: true
    };

    // Add tools for agent mode (function calling)
    // Transform Anthropic tool format to OpenAI/GitHub Copilot format
    if (hasTools) {
      copilotPayload.tools = anthropicRequest.tools.map(tool => {
        // Anthropic format: {name, description, input_schema}
        // GitHub Copilot expects: {type: "function", function: {name, description, parameters}}
        const transformed = {
          type: "function",
          function: {
            name: tool.name,
            description: tool.description || "",
            parameters: tool.input_schema || {}
          }
        };
        
        // Log first tool for debugging
        if (tool.name === "Write") {
          log("debug", "tool_transformation_example", { 
            original: tool, 
            transformed: transformed 
          });
        }
        
        return transformed;
      });
      
      // Transform tool_choice if present
      if (anthropicRequest.tool_choice) {
        if (typeof anthropicRequest.tool_choice === "object" && anthropicRequest.tool_choice.name) {
          // Anthropic: {type: "tool", name: "tool_name"}
          // GitHub: {type: "function", function: {name: "tool_name"}}
          copilotPayload.tool_choice = {
            type: "function",
            function: { name: anthropicRequest.tool_choice.name }
          };
        } else if (anthropicRequest.tool_choice === "auto" || anthropicRequest.tool_choice === "any") {
          copilotPayload.tool_choice = "auto";
        }
      } else {
        // If no tool_choice specified but tools are provided, default to "auto"
        // This tells GitHub Copilot it should actively consider using the tools
        copilotPayload.tool_choice = "auto";
      }
      
      // Enable parallel tool calls
      copilotPayload.parallel_tool_calls = true;
      
      log("info", "agent_mode_enabled", { 
        model: requestedModel, 
        toolCount: anthropicRequest.tools.length,
        toolNames: anthropicRequest.tools.map(t => t.name).join(", "),
        tool_choice: copilotPayload.tool_choice
      });
    }

    // Add thinking configuration if requested (GitHub Copilot format)
    if (thinkingBudget) {
      copilotPayload.thinking = {
        budget_tokens: thinkingBudget
      };
      log("info", "thinking_mode_enabled", { 
        budget: thinkingBudget,
        message: "Extended thinking enabled with budget"
      });
    }

    if (openaiRequest.stream) {
      await streamCopilotToAnthropic(res, copilotPayload, requestedModel, res.locals.sessionId);
      return;
    }

    // Non-streaming: collect the stream and return as single response
    const copilotModel = mapModelName(requestedModel);
    log("info", "using_copilot_model_nonstreaming", { requested: requestedModel, actual: copilotModel });
    
    const response = await fetch(GITHUB_COPILOT_CHAT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${copilotToken.token}`,
        "X-Request-Id": crypto.randomUUID(),
        "X-GitHub-Api-Version": "2023-07-07",
        "Copilot-Integration-Id": "vscode-chat",
        "Editor-Plugin-Version": "copilot-chat/0.22.4",
        "Editor-Version": "vscode/1.95.0",
        "User-Agent": "GitHubCopilotChat/0.22.4"
      },
      body: JSON.stringify({ ...copilotPayload, model: copilotModel, stream: true })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Copilot error ${response.status}: ${text}`);
    }

    // Collect streaming response
    let fullText = "";
    
    if (!response.body) {
      throw new Error("No response body from Copilot");
    }

    // Handle node-fetch stream (Node.js stream, not web stream)
    for await (const chunk of response.body) {
      const text = new TextDecoder().decode(chunk);
      const lines = text.split("\n");
      
      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const data = line.replace(/^data:\s?/, "").trim();
        if (!data || data === "[DONE]") continue;

        try {
          const parsed = JSON.parse(data);
          // New format: delta.content or old format: text
          const delta = parsed?.choices?.[0]?.delta?.content || parsed?.choices?.[0]?.text;
          if (delta) {
            fullText += delta;
          }
        } catch (e) {
          // Skip invalid JSON
        }
      }
    }

    const openaiResponse = {
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: copilotModel,
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content: fullText
        },
        finish_reason: "stop"
      }],
      usage: { 
        prompt_tokens: Math.ceil(JSON.stringify(copilotPayload.messages).length / 4), 
        completion_tokens: Math.ceil(fullText.length / 4), 
        total_tokens: Math.ceil((JSON.stringify(copilotPayload.messages).length + fullText.length) / 4) 
      }
    };

    const anthropicResponse = toAnthropicResponse(openaiResponse, requestedModel);
    recordTokens(res.locals.sessionId, openaiResponse.usage.total_tokens || 0);
    res.json(anthropicResponse);
  } catch (error) {
    log("error", "request_failed", { 
      error: String(error),
      stack: error.stack,
      path: "/v1/messages"
    });
    if (!res.headersSent) {
      res.status(error.status || 500).json({ 
        error: {
          message: String(error),
          type: "request_failed"
        }
      });
    }
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
  requireAuth(async (req, res) => {
    try {
      const models = await fetchAvailableModels();
      
      // Convert to OpenAI format for compatibility
      const openaiModels = (models?.data || []).map(model => ({
        id: model.id,
        object: "model",
        created: Date.now(),
        owned_by: model.vendor || "github-copilot",
        permission: [],
        root: model.id,
        parent: null
      }));

      res.json({
        object: "list",
        data: openaiModels
      });
    } catch (error) {
      log("error", "models_endpoint_error", { error: error.message });
      res.status(500).json({ error: "Failed to fetch models" });
    }
  })
);

app.post(
  "/v1/chat/completions",
  rateLimiter(RATE_LIMIT_CHAT_COMPLETIONS),
  requireAuth(async (req, res) => {
  const openaiRequest = req.body || {};
  try {
    // Check for tools (agent mode)
    const hasTools = openaiRequest.tools && openaiRequest.tools.length > 0;
    
    if (hasTools) {
      log("info", "agent_mode_enabled", { 
        toolCount: openaiRequest.tools.length,
        toolNames: openaiRequest.tools.map(t => t.function?.name || t.name).join(", ")
      });
    }

    // New chat completions format - messages array directly
    const copilotPayload = {
      messages: openaiRequest.messages || [],
      max_tokens: openaiRequest.max_tokens || 4096,
      temperature: openaiRequest.temperature || 0.7,
      top_p: openaiRequest.top_p || 1,
      n: openaiRequest.n || 1,
      stream: Boolean(openaiRequest.stream)
    };

    // Add tools for agent mode (function calling)
    if (hasTools) {
      copilotPayload.tools = openaiRequest.tools;
      if (openaiRequest.tool_choice) {
        copilotPayload.tool_choice = openaiRequest.tool_choice;
      }
    }

    log("debug", "chat_completions_request", {
      model: openaiRequest.model,
      messageCount: copilotPayload.messages.length,
      stream: copilotPayload.stream,
      hasTools: hasTools
    });

    if (openaiRequest.stream) {
      await streamCopilotToOpenAI(res, copilotPayload, openaiRequest.model || COPILOT_DEFAULT_MODEL, res.locals.sessionId);
      return;
    }

    const copilotModel = mapModelName(openaiRequest.model || COPILOT_DEFAULT_MODEL);
    log("info", "using_copilot_model_openai_nonstreaming", { requested: openaiRequest.model, actual: copilotModel });

    const response = await fetch(GITHUB_COPILOT_CHAT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${copilotToken.token}`,
        "X-Request-Id": crypto.randomUUID(),
        "X-GitHub-Api-Version": "2023-07-07",
        "Copilot-Integration-Id": "vscode-chat",
        "Editor-Plugin-Version": "copilot-chat/0.22.4",
        "Editor-Version": "vscode/1.95.0",
        "User-Agent": "GitHubCopilotChat/0.22.4"
      },
      body: JSON.stringify({ ...copilotPayload, model: copilotModel, stream: true })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Copilot error ${response.status}: ${text}`);
    }

    // Collect streaming response
    let fullText = "";
    
    if (!response.body) {
      throw new Error("No response body from Copilot");
    }

    // Handle node-fetch stream (Node.js stream, not web stream)
    for await (const chunk of response.body) {
      const text = new TextDecoder().decode(chunk);
      const lines = text.split("\n");
      
      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const data = line.replace(/^data:\s?/, "").trim();
        if (!data || data === "[DONE]") continue;

        try {
          const parsed = JSON.parse(data);
          // New format: delta.content or old format: text
          const delta = parsed?.choices?.[0]?.delta?.content || parsed?.choices?.[0]?.text;
          if (delta) {
            fullText += delta;
          }
        } catch (e) {
          // Skip invalid JSON
        }
      }
    }

    const responsePayload = {
      id: `chatcmpl-${crypto.randomUUID()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: copilotModel,
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content: fullText
        },
        finish_reason: "stop"
      }],
      usage: { 
        prompt_tokens: Math.ceil(JSON.stringify(copilotPayload.messages).length / 4), 
        completion_tokens: Math.ceil(fullText.length / 4), 
        total_tokens: Math.ceil((JSON.stringify(copilotPayload.messages).length + fullText.length) / 4) 
      }
    };
    recordTokens(res.locals.sessionId, responsePayload.usage.total_tokens || 0);
    res.json(responsePayload);
  } catch (error) {
    log("error", "copilot_completion_failed", { 
      error: String(error),
      stack: error.stack,
      path: "/v1/chat/completions"
    });
    if (!res.headersSent) {
      res.status(500).json({ 
        error: {
          message: String(error),
          type: "completion_failed"
        }
      });
    }
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

// Load tokens on startup
(async () => {
  log("info", "server_starting", { port: PORT });
  
  // Try to load existing tokens from our saved file
  let loaded = loadTokens();
  
  // If no saved tokens, try to find existing Copilot installation
  if (!loaded || !githubToken) {
    log("info", "checking_for_existing_copilot_auth");
    const existingToken = loadExistingCopilotTokens();
    if (existingToken) {
      githubToken = existingToken;
      loaded = true;
    }
  }
  
  // If we have a GitHub token, get the Copilot token
  if (loaded && githubToken) {
    try {
      log("info", "refreshing_copilot_token");
      await refreshCopilotToken();
      log("info", "server_ready", { 
        port: PORT, 
        authenticated: true,
        message: "✓ Authenticated with GitHub Copilot - Ready to use!"
      });
    } catch (error) {
      log("error", "token_refresh_failed", { 
        error: String(error),
        message: "GitHub token found but Copilot access failed. You may need an active Copilot subscription."
      });
      log("info", "manual_auth_required", {
        message: "Run: Invoke-RestMethod -Uri http://localhost:8082/auth/login -Method Post"
      });
    }
  } else {
    log("warn", "no_authentication_found", {
      message: "No GitHub Copilot authentication found. Please authenticate:"
    });
    log("info", "auth_instructions", {
      step1: "Invoke-RestMethod -Uri http://localhost:8082/auth/login -Method Post",
      step2: "Go to the URL and enter the code shown",
      step3: "Invoke-RestMethod -Uri http://localhost:8082/auth/check -Method Post"
    });
  }
  
  app.listen(PORT);
})();

