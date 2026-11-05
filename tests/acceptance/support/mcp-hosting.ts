/**
 * Hosted stdio MCP server acceptance-test support (Issue #20, AC-135..141).
 * Owned by the acceptance suite (gauntlet); do not modify during
 * implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - the `[[mcp_server]]` config shape: `name`, `cred_id`, `command`
 *     (absolute path), optional `args`, and the `[mcp_server.env]` table whose
 *     values may carry `{{secret}}` / `{{username}}` / `{{totp}}`
 *   - the RPC `open_mcp_server {name}` -> `{session_id, port, stream_secret}`
 *   - the stream protocol: connect to 127.0.0.1:<port>, send
 *     `<stream_secret>\n`, then newline-delimited MCP JSON-RPC both ways
 *   - the agent-side runner `node packages/tegata-mcp/dist/run.js <name>`
 *     (env TEGATA_SOCKET, TEGATA_BRIDGE=1 behind a bridge), overridable with
 *     env TEGATA_MCP_RUN_ENTRY; it is a plain stdio MCP server to its client
 */
import { createHash } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  type ApiProxyDaemon,
  type ApiProxyDaemonOptions,
  startApiProxyDaemon,
} from "./api-proxy.js";
import {
  bins,
  type CanarySet,
  defaultEntries,
  type McpResult,
  REPO_ROOT,
} from "./harness.js";

/** The fake MCP server script (an absolute path on the host). */
export const FAKE_MCP_SERVER = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fake-mcp-server.mjs",
);

/** The JavaScript entry of the agent-side runner `tegata-mcp-run`. */
export function runnerEntry(): string {
  return (
    process.env.TEGATA_MCP_RUN_ENTRY ??
    path.join(REPO_ROOT, "packages/tegata-mcp/dist/run.js")
  );
}

/** The config shape of `[[mcp_server]]`, fixed by the acceptance tests. */
export interface McpServerSpec {
  name: string;
  cred_id: string;
  command: string;
  args?: string[];
  env: Record<string, string>;
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

/** Generates the TOML fragment for the `[[mcp_server]]` entries. */
export function renderMcpServers(servers: McpServerSpec[]): string {
  const lines: string[] = [];
  for (const server of servers) {
    lines.push(
      "",
      "[[mcp_server]]",
      `name = ${tomlString(server.name)}`,
      `cred_id = ${tomlString(server.cred_id)}`,
      `command = ${tomlString(server.command)}`,
    );
    if (server.args !== undefined)
      lines.push(`args = [${server.args.map(tomlString).join(", ")}]`);
    lines.push("", "[mcp_server.env]");
    for (const [key, value] of Object.entries(server.env))
      lines.push(`${key} = ${tomlString(value)}`);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * Returns the `[[mcp_server]]` of the fake MCP server. command is the absolute path of node,
 * and args are the absolute path of the script and the path of the receive log.
 */
export function fakeServerSpec(
  serverLog: string,
  overrides: Partial<McpServerSpec> = {},
): McpServerSpec {
  return {
    name: "fake",
    cred_id: "mock:site",
    command: process.execPath,
    args: [FAKE_MCP_SERVER, serverLog],
    env: { TOKEN: "{{secret}}" },
    ...overrides,
  };
}

export type FakeServerLogRecord =
  | { event: "start"; pid: number }
  | { event: "request"; line: string };

/** Reads the fake server's receive log (undefined if not yet created). */
export function readServerLog(
  serverLog: string,
): FakeServerLogRecord[] | undefined {
  if (!fs.existsSync(serverLog)) return undefined;
  return fs
    .readFileSync(serverLog, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as FakeServerLogRecord);
}

/** Parses and returns the JSON-RPC requests (those with an id) in the receive log. */
export function receivedRequests(
  serverLog: string,
): Array<{ id?: unknown; method?: string }> {
  const out: Array<{ id?: unknown; method?: string }> = [];
  for (const record of readServerLog(serverLog) ?? []) {
    if (record.event !== "request") continue;
    try {
      out.push(JSON.parse(record.line) as { id?: unknown; method?: string });
    } catch {
      out.push({});
    }
  }
  return out;
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export interface OpenMcpServer {
  session_id: string;
  port: number;
  stream_secret: string;
}

export interface HostedMcpStack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: ApiProxyDaemon;
  /**
   * The fake server's receive log. It is a server-side resource, not a surface visible to the
   * agent.
   */
  serverLog: string;
  serverDir: string;
  agentDir: string;
  observe(label: string, value: unknown): void;
}

export interface HostedMcpStackOptions {
  top?: Pick<
    ApiProxyDaemonOptions,
    "sessionTtlSecs" | "approveCmd" | "approveTimeoutSecs"
  >;
  daemon?: Pick<
    ApiProxyDaemonOptions,
    "transport" | "tcpBind" | "tcpPort" | "operatorUids"
  >;
  servers?: (serverLog: string) => McpServerSpec[];
}

/** Builds a daemon that has the fake MCP server in `[[mcp_server]]`, plus the leak guard. */
export async function startHostedMcpStack(
  opts: HostedMcpStackOptions = {},
): Promise<HostedMcpStack> {
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-agent-"));
  const serverDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-mcp-srv-"));
  const serverLog = path.join(serverDir, "received.jsonl");
  const guard = await createLeakGuard({
    leakscanBin: bins().leakscan,
    agentVisibleRoots: [agentDir, process.cwd()],
    psSampleIntervalMs: 200,
  });
  const canaries: CanarySet = {
    username: guard.canary("username"),
    password: guard.canary("password"),
    totpSeed: guard.canary("totp_seed"),
    wrongPassword: guard.canary("wrong_password"),
  };
  const observe = (label: string, value: unknown) =>
    guard.observe(label, value);
  try {
    const servers = (opts.servers ?? ((log) => [fakeServerSpec(log)]))(
      serverLog,
    );
    const daemon = await startApiProxyDaemon({
      entries: defaultEntries(canaries),
      apiProxies: [],
      extraToml: renderMcpServers(servers),
      ...opts.top,
      ...opts.daemon,
    });
    return {
      guard,
      canaries,
      daemon,
      serverLog,
      serverDir,
      agentDir,
      observe,
    };
  } catch (error) {
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    fs.rmSync(serverDir, { recursive: true, force: true });
    throw error;
  }
}

/** Stops the daemon and forces a full leak guard scan. */
export async function stopHostedMcpStack(stack: HostedMcpStack): Promise<void> {
  await stack.daemon.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
    fs.rmSync(stack.serverDir, { recursive: true, force: true });
  }
}

/**
 * A Transport that passes every message and error appearing on the runner's stdout to observe.
 * The Client overwrites onmessage on connect, so the inner transport is wrapped.
 */
class ObservedTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor(
    private readonly inner: StdioClientTransport,
    observe: (label: string, value: unknown) => void,
    onExit: () => void,
  ) {
    inner.onmessage = (message) => {
      observe("runner:stdout", message);
      this.onmessage?.(message);
    };
    inner.onerror = (error) => {
      observe("runner:error", String(error));
      this.onerror?.(error);
    };
    inner.onclose = () => {
      onExit();
      this.onclose?.();
    };
  }

  start(): Promise<void> {
    return this.inner.start();
  }

  send(message: JSONRPCMessage): Promise<void> {
    return this.inner.send(message);
  }

  close(): Promise<void> {
    return this.inner.close();
  }
}

export interface RunnerSession {
  /** Calls a tool. Rejects if no response arrives within timeoutMs or the connection drops. */
  callTool(
    name: string,
    args?: Record<string, unknown>,
    timeoutMs?: number,
  ): Promise<McpResult>;
  /** Resolves when the runner process has exited. */
  readonly exited: Promise<void>;
  /** The pid of the runner (or of `docker exec`). */
  readonly pid: number | null;
  stderr(): string;
  /** Closes stdin and shuts the runner down with the SDK's default procedure. */
  close(): Promise<void>;
}

/**
 * Starts `tegata-mcp-run <name>` with the SDK's stdio client and completes the MCP
 * initialize. `spawnAs` is the replacement used when starting inside a container.
 */
export async function connectRunner(opts: {
  socketPath: string;
  name: string;
  observe: (label: string, value: unknown) => void;
  extraEnv?: Record<string, string>;
  spawnAs?: { command: string; args: string[] };
}): Promise<RunnerSession> {
  const inner = new StdioClientTransport({
    command: opts.spawnAs?.command ?? process.execPath,
    args: opts.spawnAs?.args ?? [runnerEntry(), opts.name],
    env: {
      ...process.env,
      TEGATA_SOCKET: opts.socketPath,
      ...opts.extraEnv,
    } as Record<string, string>,
    stderr: "pipe",
  });
  let stderr = "";
  inner.stderr?.on("data", (chunk: Buffer | string) => {
    stderr += chunk.toString();
  });
  let markExited: () => void = () => {};
  const exited = new Promise<void>((resolve) => {
    markExited = resolve;
  });
  const transport = new ObservedTransport(inner, opts.observe, markExited);
  const client = new Client({ name: "acceptance", version: "0.0.0" });
  try {
    await client.connect(transport);
  } catch (error) {
    await client.close().catch(() => {});
    throw new Error(`tegata-mcp-run failed to start: ${error}; ${stderr}`);
  }
  return {
    async callTool(name, args = {}, timeoutMs = 10_000) {
      const res = await client.callTool({ name, arguments: args }, undefined, {
        timeout: timeoutMs,
      });
      opts.observe(`runner:${name}`, res);
      const text = (res.content as Array<{ type: string; text?: string }>)
        .filter((c) => c.type === "text")
        .map((c) => c.text ?? "")
        .join("");
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
      return { isError: res.isError === true, text, json };
    },
    exited,
    pid: inner.pid,
    stderr: () => stderr,
    close: () => client.close(),
  };
}

/** Returns true if the Promise resolves within timeoutMs. */
export async function settlesWithin(
  promise: Promise<unknown>,
  timeoutMs: number,
): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const timedOut = new Promise<false>((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs);
  });
  try {
    return await Promise.race([
      promise.then(
        () => true,
        () => true,
      ),
      timedOut,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export interface StreamExchange {
  /** The lines received from the peer. */
  lines: string[];
  /** Whether the peer closed the connection (within timeoutMs). */
  closed: boolean;
  socket: net.Socket;
}

/**
 * Connects to 127.0.0.1:<port>, writes `payload`, and collects lines until `waitFor` is
 * satisfied, the peer closes, or timeoutMs passes. The connection is returned without being closed.
 */
export async function streamExchange(
  port: number,
  payload: string,
  opts: { waitFor?: (lines: string[]) => boolean; timeoutMs?: number } = {},
): Promise<StreamExchange> {
  const socket = net.connect({ host: "127.0.0.1", port });
  await once(socket, "connect");
  const lines: string[] = [];
  let buffer = "";
  let closed = false;
  socket.setEncoding("utf8");
  // EPIPE / ECONNRESET from a write after disconnection are treated as an observation that the
  // connection was cut.
  socket.on("error", () => {});
  const done = new Promise<void>((resolve) => {
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      let index = buffer.indexOf("\n");
      while (index >= 0) {
        lines.push(buffer.slice(0, index));
        buffer = buffer.slice(index + 1);
        index = buffer.indexOf("\n");
      }
      if (opts.waitFor?.(lines) === true) resolve();
    });
    socket.on("close", () => {
      closed = true;
      resolve();
    });
  });
  socket.write(payload);
  await settlesWithin(done, opts.timeoutMs ?? 5_000);
  return { lines, closed, socket };
}
