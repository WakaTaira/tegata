import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  defaultEntries,
  type McpSession,
  type MockEntry,
  rawRpc,
} from "./harness.js";

/** `[[api_proxy]]` の受け入れテストで固定する設定形状。 */
export interface ApiProxySpec {
  name: string;
  cred_id: string;
  upstream: string;
  header: string;
  value: string;
}

export interface ApiProxyFixture {
  port: number;
  url: string;
  stop(): Promise<void>;
}

export interface ApiProxyDaemon extends ApiProxyDaemonLayout {
  stop(): Promise<void>;
}

interface ApiProxyDaemonLayout {
  daemonDir: string;
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  tcpPort?: number;
}

export interface ApiProxyDaemonOptions {
  entries: MockEntry[];
  apiProxies: ApiProxySpec[];
  sessionTtlSecs?: number;
  approveCmd?: string;
  approveTimeoutSecs?: number;
  auditLogMaxBytes?: number;
  /** `listen` は UNIX と TCP の両方を使うコンテナ試験用である。 */
  transport?: "legacy" | "listen";
  tcpBind?: string;
  tcpPort?: number;
  operatorUids?: number[];
}

export interface ApiProxyStack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: ApiProxyDaemon;
  fixture: ApiProxyFixture;
  mcp: McpSession;
  agentDir: string;
}

export interface ApiProxyStackOptions {
  apiProxies: (fixture: ApiProxyFixture, canaries: CanarySet) => ApiProxySpec[];
  top?: Pick<
    ApiProxyDaemonOptions,
    "sessionTtlSecs" | "approveCmd" | "approveTimeoutSecs" | "auditLogMaxBytes"
  >;
  fixtureListenHost?: string;
  fixtureUrlHost?: string;
}

export interface ApiProxyDaemonExit {
  code: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function renderEntry(lines: string[], entry: MockEntry): void {
  lines.push(
    "",
    "[[providers.entries]]",
    `id = ${tomlString(entry.id)}`,
    `name = ${tomlString(entry.name)}`,
    `uri = ${tomlString(entry.uri)}`,
    `kind = ${tomlString(entry.kind)}`,
    `username = ${tomlString(entry.username)}`,
    `password = ${tomlString(entry.password)}`,
  );
  if (entry.totpSeed !== undefined)
    lines.push(`totp_seed = ${tomlString(entry.totpSeed)}`);
  if (entry.totpExposable !== undefined)
    lines.push(`totp_exposable = ${entry.totpExposable}`);
}

/** 既存の daemon config に `[[api_proxy]]` を加えた文字列を生成する。 */
export function renderApiProxyConfig(
  opts: ApiProxyDaemonOptions & {
    socketPath: string;
    stateDir: string;
    auditLogPath: string;
  },
): string {
  const lines = [
    `state_dir = ${tomlString(opts.stateDir)}`,
    `audit_log_path = ${tomlString(opts.auditLogPath)}`,
  ];
  if (opts.sessionTtlSecs !== undefined)
    lines.push(`session_ttl_secs = ${opts.sessionTtlSecs}`);
  if (opts.approveCmd !== undefined)
    lines.push(`approve_cmd = ${tomlString(opts.approveCmd)}`);
  if (opts.approveTimeoutSecs !== undefined)
    lines.push(`approve_timeout_secs = ${opts.approveTimeoutSecs}`);
  if (opts.auditLogMaxBytes !== undefined)
    lines.push(`audit_log_max_bytes = ${opts.auditLogMaxBytes}`);

  if (opts.transport === "listen") {
    lines.push(
      "",
      "[[listen]]",
      'kind = "unix"',
      `path = ${tomlString(opts.socketPath)}`,
      `allowed_uids = [${os.userInfo().uid}]`,
    );
    if (opts.operatorUids !== undefined)
      lines.push(`operator_uids = [${opts.operatorUids.join(", ")}]`);
    if (opts.tcpPort !== undefined) {
      lines.push(
        "",
        "[[listen]]",
        'kind = "tcp"',
        `bind = ${tomlString(opts.tcpBind ?? "127.0.0.1")}`,
        `port = ${opts.tcpPort}`,
      );
    }
  } else {
    lines.push(
      `socket_path = ${tomlString(opts.socketPath)}`,
      `allowed_uids = [${os.userInfo().uid}]`,
    );
  }

  lines.push("", "[[providers]]", 'namespace = "mock"', 'type = "mock"');
  for (const entry of opts.entries) renderEntry(lines, entry);

  for (const proxy of opts.apiProxies) {
    lines.push(
      "",
      "[[api_proxy]]",
      `name = ${tomlString(proxy.name)}`,
      `cred_id = ${tomlString(proxy.cred_id)}`,
      `upstream = ${tomlString(proxy.upstream)}`,
      `header = ${tomlString(proxy.header)}`,
      `value = ${tomlString(proxy.value)}`,
    );
  }
  return `${lines.join("\n")}\n`;
}

async function waitForDaemonSocket(
  child: ChildProcess,
  socketPath: string,
): Promise<void> {
  const exited = new Promise<never>((_, reject) => {
    child.once("exit", (code) =>
      reject(new Error(`tegatad exited early (code ${code})`)),
    );
  });
  const ready = (async () => {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      if (fs.existsSync(socketPath)) {
        try {
          const response = await rawRpc(socketPath, "status", {});
          if (response.result !== undefined) return;
        } catch {
          // ソケット作成直後の接続失敗は起動待ちとして扱う。
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error("timed out waiting for the tegatad socket");
  })();
  await Promise.race([ready, exited]);
  child.removeAllListeners("exit");
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 3_000);
  await once(child, "exit").catch(() => {});
  clearTimeout(timer);
}

function createDaemonLayout(): ApiProxyDaemonLayout & { configPath: string } {
  const daemonDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegatad-api-proxy-"),
  );
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  return {
    daemonDir,
    socketPath: path.join(daemonDir, "tegatad.sock"),
    stateDir,
    auditLogPath: path.join(stateDir, "audit.log"),
    configPath: path.join(daemonDir, "config.toml"),
  };
}

function writeDaemonConfig(
  layout: ApiProxyDaemonLayout & { configPath: string },
  opts: ApiProxyDaemonOptions,
): void {
  fs.writeFileSync(
    layout.configPath,
    renderApiProxyConfig({
      ...opts,
      socketPath: layout.socketPath,
      stateDir: layout.stateDir,
      auditLogPath: layout.auditLogPath,
    }),
    { mode: 0o600 },
  );
}

/** `[[api_proxy]]` を含む config で daemon を起動し、UNIX RPC を待つ。 */
export async function startApiProxyDaemon(
  opts: ApiProxyDaemonOptions,
): Promise<ApiProxyDaemon> {
  const layout = createDaemonLayout();
  writeDaemonConfig(layout, opts);
  const child = spawn(bins().tegatad, ["--config", layout.configPath], {
    stdio: ["ignore", "inherit", "inherit"],
    cwd: layout.daemonDir,
  });
  try {
    await waitForDaemonSocket(child, layout.socketPath);
  } catch (error) {
    await stopChild(child).catch(() => {});
    fs.rmSync(layout.daemonDir, { recursive: true, force: true });
    throw error;
  }
  return {
    daemonDir: layout.daemonDir,
    socketPath: layout.socketPath,
    stateDir: layout.stateDir,
    auditLogPath: layout.auditLogPath,
    tcpPort: opts.tcpPort,
    stop: async () => {
      await stopChild(child);
      fs.rmSync(layout.daemonDir, { recursive: true, force: true });
    },
  };
}

/** 起動拒否条件を、終了コードと stderr を保持したまま確認する。 */
export async function runApiProxyDaemonUntilExit(
  opts: ApiProxyDaemonOptions,
  timeoutMs = 2_000,
): Promise<ApiProxyDaemonExit> {
  const layout = createDaemonLayout();
  writeDaemonConfig(layout, opts);
  const child = spawn(bins().tegatad, ["--config", layout.configPath], {
    stdio: ["ignore", "ignore", "pipe"],
    cwd: layout.daemonDir,
  });
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const exited = once(child, "exit").then(([code, signal]) => ({
    code: code as number | null,
    signal: signal as NodeJS.Signals | null,
  }));
  const outcome = await Promise.race([
    exited,
    new Promise<undefined>((resolve) =>
      setTimeout(() => resolve(undefined), timeoutMs),
    ),
  ]);
  if (outcome === undefined) {
    child.kill("SIGKILL");
    await exited.catch(() => {});
    fs.rmSync(layout.daemonDir, { recursive: true, force: true });
    return { code: null, signal: null, stderr };
  }
  fs.rmSync(layout.daemonDir, { recursive: true, force: true });
  return { ...outcome, stderr };
}

/** Bearer 値を検証し、`/api/whoami` の到達数を HTTP で照会できる fixture。 */
async function closeApiProxyFixture(server: http.Server): Promise<void> {
  if (!server.listening) return;
  server.closeIdleConnections();
  server.closeAllConnections();
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
}

async function listenApiProxyFixture(
  server: http.Server,
  host: string,
): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    let settled = false;

    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      server.removeListener("error", onError);
      server.removeListener("listening", onListening);
      void closeApiProxyFixture(server).finally(() => reject(error));
    };
    const onError = (error: Error): void => fail(error);
    const onListening = (): void => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        fail(new Error("api-proxy fixture did not receive a network address"));
        return;
      }
      settled = true;
      server.removeListener("error", onError);
      resolve(address.port);
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ host, port: 0 });
  });
}

export async function startApiProxyFixture(
  credentials: { username: string; password: string },
  opts: { listenHost?: string; urlHost?: string } = {},
): Promise<ApiProxyFixture> {
  let whoamiRequests = 0;
  const server = http.createServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", "http://fixture.invalid");
    if (
      request.method === "GET" &&
      requestUrl.pathname === "/api/whoami/count"
    ) {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ count: whoamiRequests }));
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/api/whoami") {
      whoamiRequests += 1;
      const authorized =
        request.headers.authorization === `Bearer ${credentials.password}`;
      response.writeHead(authorized ? 200 : 401, {
        "Content-Type": "application/json",
      });
      response.end(
        JSON.stringify(
          authorized ? { user: "fixture" } : { error: "unauthorized" },
        ),
      );
      return;
    }
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("not found");
  });
  const listenHost = opts.listenHost ?? "127.0.0.1";
  const port = await listenApiProxyFixture(server, listenHost);
  const host = opts.urlHost ?? listenHost;
  let stopPromise: Promise<void> | undefined;
  return {
    port,
    url: `http://${host}:${port}`,
    stop: () => {
      stopPromise ??= closeApiProxyFixture(server);
      return stopPromise;
    },
  };
}

/** API proxy の host-side stack を構成し、終了時に leak guard まで実行する。 */
export async function startApiProxyStack(
  opts: ApiProxyStackOptions,
): Promise<ApiProxyStack> {
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-agent-"));
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
  let fixture: ApiProxyFixture | undefined;
  let daemon: ApiProxyDaemon | undefined;
  let mcp: McpSession | undefined;
  try {
    fixture = await startApiProxyFixture(
      { username: canaries.username, password: canaries.password },
      {
        listenHost: opts.fixtureListenHost,
        urlHost: opts.fixtureUrlHost,
      },
    );
    daemon = await startApiProxyDaemon({
      entries: defaultEntries(canaries),
      apiProxies: opts.apiProxies(fixture, canaries),
      ...opts.top,
    });
    mcp = await connectMcp(daemon.socketPath, (label, value) =>
      guard.observe(label, value),
    );
    return { guard, canaries, daemon, fixture, mcp, agentDir };
  } catch (error) {
    await mcp?.close().catch(() => {});
    await fixture?.stop().catch(() => {});
    await daemon?.stop().catch(() => {});
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    throw error;
  }
}

/** host-side API proxy stack を逆順に停止する。 */
export async function stopApiProxyStack(stack: ApiProxyStack): Promise<void> {
  await stack.mcp.close().catch(() => {});
  await stack.fixture.stop().catch(() => {});
  await stack.daemon.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
  }
}
