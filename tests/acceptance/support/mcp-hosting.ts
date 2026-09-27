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

/** 偽 MCP サーバーのスクリプト（ホスト側の絶対パス）。 */
export const FAKE_MCP_SERVER = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fake-mcp-server.mjs",
);

/** agent 側ランナー `tegata-mcp-run` の JavaScript entry。 */
export function runnerEntry(): string {
  return (
    process.env.TEGATA_MCP_RUN_ENTRY ??
    path.join(REPO_ROOT, "packages/tegata-mcp/dist/run.js")
  );
}

/** `[[mcp_server]]` の受け入れテストで固定する設定形状。 */
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

/** `[[mcp_server]]` 群の TOML 断片を生成する。 */
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
 * 偽 MCP サーバーの `[[mcp_server]]` を返す。command は node の絶対パス、
 * args はスクリプトの絶対パスと受信ログのパスである。
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

/** 偽サーバーの受信ログを読む（未作成なら undefined）。 */
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

/** 受信ログのうち JSON-RPC 要求（id を持つもの）を解析して返す。 */
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
  /** 偽サーバーの受信ログ。サーバー側の資源であり agent 可視面ではない。 */
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

/** 偽 MCP サーバーを `[[mcp_server]]` に持つ daemon と leak guard を構成する。 */
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

/** daemon を停止し、leak guard の全走査を強制する。 */
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
 * ランナーの stdout に現れた全メッセージとエラーを observe へ渡す Transport。
 * Client は connect 時に onmessage を上書きするため、内側の transport を包む。
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
  /** ツールを呼ぶ。応答が無いまま timeoutMs を過ぎるか接続が切れると reject する。 */
  callTool(
    name: string,
    args?: Record<string, unknown>,
    timeoutMs?: number,
  ): Promise<McpResult>;
  /** ランナーのプロセスが終了した時点で解決する。 */
  readonly exited: Promise<void>;
  /** ランナー（または `docker exec`）の pid。 */
  readonly pid: number | null;
  stderr(): string;
  /** stdin を閉じ、SDK の既定手順でランナーを終了させる。 */
  close(): Promise<void>;
}

/**
 * `tegata-mcp-run <name>` を SDK の stdio client で起動し、MCP の
 * initialize まで済ませる。`spawnAs` は container 内で起動する場合の置換である。
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

/** Promise が timeoutMs 以内に解決すれば true を返す。 */
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
  /** 相手から受け取った行。 */
  lines: string[];
  /** 相手が接続を閉じたか（timeoutMs 以内）。 */
  closed: boolean;
  socket: net.Socket;
}

/**
 * 127.0.0.1:<port> へ接続して `payload` を書き、`waitFor` が満たされるか
 * 相手が閉じるか timeoutMs が過ぎるまで行を集める。接続は閉じずに返す。
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
  // 切断後の書き込みで生じる EPIPE / ECONNRESET は「切断された」観測として扱う。
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
