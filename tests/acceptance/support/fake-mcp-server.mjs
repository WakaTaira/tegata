#!/usr/bin/env node
/**
 * Fake stdio MCP server for the hosted-MCP acceptance tests (Issue #20,
 * AC-135..141). Owned by the acceptance suite (gauntlet); do not modify
 * during implementation.
 *
 * Pinned test contract:
 *   - started by the executor as `<node> <this file> [<log file>]`; the
 *     credential arrives only through env TOKEN (config `env`).
 *   - speaks newline-delimited JSON-RPC 2.0 on stdin / stdout (MCP stdio).
 *   - tools: `whoami` -> sha256 hex of TOKEN, `leak` -> TOKEN verbatim,
 *     `pid` -> this process's pid, each as one text content item.
 *   - when a log file is given, appends one JSON line per event:
 *     `{"event":"start","pid":n}` at startup and
 *     `{"event":"request","line":"<raw line>"}` for every stdin line. The log
 *     never records TOKEN.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import readline from "node:readline";

const logPath = process.argv[2];
const token = process.env.TOKEN ?? "";

// ログは受信確認（AC-139 / AC-140）のためだけに用い、TOKEN を含めない。
function log(record) {
  if (logPath === undefined || logPath === "") return;
  fs.appendFileSync(logPath, `${JSON.stringify(record)}\n`);
}

function send(message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
}

const TOOLS = [
  { name: "whoami", description: "sha256 hex of the configured token" },
  { name: "leak", description: "the configured token verbatim" },
  { name: "pid", description: "the server's process id" },
].map((tool) => ({
  ...tool,
  inputSchema: { type: "object", properties: {} },
}));

function toolText(name) {
  switch (name) {
    case "whoami":
      return createHash("sha256").update(token).digest("hex");
    case "leak":
      return token;
    case "pid":
      return String(process.pid);
    default:
      return undefined;
  }
}

function handle(request) {
  switch (request.method) {
    case "initialize":
      return {
        result: {
          protocolVersion: request.params?.protocolVersion ?? "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "tegata-fake-mcp", version: "0.0.0" },
        },
      };
    case "ping":
      return { result: {} };
    case "tools/list":
      return { result: { tools: TOOLS } };
    case "tools/call": {
      const text = toolText(request.params?.name);
      if (text === undefined)
        return { error: { code: -32602, message: "unknown tool" } };
      return { result: { content: [{ type: "text", text }] } };
    }
    default:
      return { error: { code: -32601, message: "method not found" } };
  }
}

log({ event: "start", pid: process.pid });

const input = readline.createInterface({ input: process.stdin });
input.on("line", (line) => {
  if (line.trim() === "") return;
  log({ event: "request", line });
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    send({ id: null, error: { code: -32700, message: "parse error" } });
    return;
  }
  // id を持たない通知（notifications/initialized 等）には応答しない。
  if (request === null || typeof request !== "object" || !("id" in request))
    return;
  send({ id: request.id, ...handle(request) });
});
input.on("close", () => process.exit(0));
