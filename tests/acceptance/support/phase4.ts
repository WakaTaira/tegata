/**
 * Phase 4a acceptance-test support (identity and session sharing). Owned by
 * the acceptance suite (gauntlet); do not modify during implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - the Phase 4 daemon TOML config: the `[[listen]]` array replaces the
 *     transport keys. `kind = "unix"` carries `path`, `allowed_uids` and the
 *     optional `operator_uids`; `kind = "tcp"` carries `bind` and `port`.
 *     Top-level `max_pending_connections` caps unauthenticated TCP
 *     connections (default 8). Providers keep the Phase 1 shape.
 *   - the admin RPCs `admin_peer_issue {label}` -> `{peer_id, token}`,
 *     `admin_peer_revoke {peer_id}` -> `{ok}`, `admin_peer_list` ->
 *     `[{peer_id, label, issued_at, revoked_at}]`, callable over the UNIX
 *     socket by uid 0 or a uid listed in `operator_uids`; anyone else gets
 *     `ADMIN_REQUIRED`
 *   - the Linux TCP front: the same line-delimited preamble protocol as the
 *     Windows transport (`{"v":1,"auth":"<token>"}` then JSON-RPC lines,
 *     silent on success; `{"v":1,"auth":"<token>","tunnel":{session_id,port}}`
 *     answered by `{"ok":true}` or `{"ok":false,"error":"<code>"}`). A
 *     tunnel to a session the caller does not own answers `NOT_FOUND`.
 *   - the `login` result gains `target_id`; `login` accepts `exclusive`;
 *     `logout` of a session the caller does not own answers `NOT_FOUND`
 *   - `status` -> `{ok: true, browsers: n, leases: n}`
 *   - audit peer fields: `principal` ("uid:<n>" / "peer:<peer_id>"),
 *     `peer_id` + `peer_label` for named tokens, and `shared` on login
 *   - browser count = number of `tegata-executor` children of the daemon
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  defaultEntries,
  fixtureSteps,
  type McpSession,
  type MockEntry,
  rawRpc,
} from "./harness.js";

function tomlString(s: string): string {
  return JSON.stringify(s);
}

export interface Phase4ConfigOptions {
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  allowedUids: number[];
  operatorUids?: number[];
  /** When set, a `kind = "tcp"` listener bound to `tcpBind` is rendered. */
  tcpPort?: number;
  /**
   * Address of the TCP listener (default 127.0.0.1). Phase 4b binds the
   * gateway address of a docker bridge; unspecified addresses are refused.
   */
  tcpBind?: string;
  sessionTtlSecs?: number;
  maxPendingConnections?: number;
  entries: MockEntry[];
}

/** Render the Phase 4 daemon TOML config. This shape is a pinned contract. */
export function renderPhase4Config(opts: Phase4ConfigOptions): string {
  const lines = [
    `state_dir = ${tomlString(opts.stateDir)}`,
    `audit_log_path = ${tomlString(opts.auditLogPath)}`,
  ];
  if (opts.sessionTtlSecs !== undefined)
    lines.push(`session_ttl_secs = ${opts.sessionTtlSecs}`);
  if (opts.maxPendingConnections !== undefined)
    lines.push(`max_pending_connections = ${opts.maxPendingConnections}`);
  lines.push(
    "",
    "[[listen]]",
    `kind = "unix"`,
    `path = ${tomlString(opts.socketPath)}`,
    `allowed_uids = [${opts.allowedUids.join(", ")}]`,
  );
  if (opts.operatorUids !== undefined)
    lines.push(`operator_uids = [${opts.operatorUids.join(", ")}]`);
  if (opts.tcpPort !== undefined) {
    lines.push(
      "",
      "[[listen]]",
      `kind = "tcp"`,
      `bind = ${tomlString(opts.tcpBind ?? "127.0.0.1")}`,
      `port = ${opts.tcpPort}`,
    );
  }
  lines.push("", "[[providers]]", `namespace = "mock"`, `type = "mock"`);
  for (const e of opts.entries) {
    lines.push(
      "",
      "[[providers.entries]]",
      `id = ${tomlString(e.id)}`,
      `name = ${tomlString(e.name)}`,
      `uri = ${tomlString(e.uri)}`,
      `kind = ${tomlString(e.kind)}`,
      `username = ${tomlString(e.username)}`,
      `password = ${tomlString(e.password)}`,
    );
    if (e.totpSeed !== undefined)
      lines.push(`totp_seed = ${tomlString(e.totpSeed)}`);
    if (e.totpExposable !== undefined)
      lines.push(`totp_exposable = ${e.totpExposable}`);
  }
  return `${lines.join("\n")}\n`;
}

/** Reserve a free TCP port on `host` (listen on 0, read it back, close). */
export async function freeTcpPort(host = "127.0.0.1"): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("could not reserve a port");
  const port = address.port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

export interface Phase4Daemon {
  socketPath: string;
  stateDir: string;
  daemonDir: string;
  auditLogPath: string;
  /** Present when the daemon was started with a TCP listener. */
  tcpPort?: number;
  /** Address the TCP listener is bound to (present with `tcpPort`). */
  tcpBind?: string;
  pid: number;
  stop(): Promise<void>;
}

export interface Phase4DaemonOptions {
  entries: MockEntry[];
  operatorUids?: number[];
  tcp?: boolean;
  /** Address for the TCP listener (default 127.0.0.1); needs `tcp: true`. */
  tcpBind?: string;
  sessionTtlSecs?: number;
  maxPendingConnections?: number;
}

/** Start tegatad with a Phase 4 config in a private temp directory. */
export async function startPhase4Daemon(
  opts: Phase4DaemonOptions,
): Promise<Phase4Daemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-p4-"));
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const auditLogPath = path.join(stateDir, "audit.log");
  const tcpBind = opts.tcpBind ?? "127.0.0.1";
  const tcpPort = opts.tcp ? await freeTcpPort(tcpBind) : undefined;
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    renderPhase4Config({
      socketPath,
      stateDir,
      auditLogPath,
      allowedUids: [os.userInfo().uid],
      operatorUids: opts.operatorUids,
      tcpPort,
      tcpBind,
      sessionTtlSecs: opts.sessionTtlSecs,
      maxPendingConnections: opts.maxPendingConnections,
      entries: opts.entries,
    }),
    { mode: 0o600 },
  );
  const child = spawn(bins().tegatad, ["--config", configPath], {
    stdio: ["ignore", "inherit", "inherit"],
    cwd: daemonDir,
  });
  const exited = new Promise<never>((_, reject) => {
    child.once("exit", (code) =>
      reject(new Error(`tegatad exited early (code ${code})`)),
    );
  });
  const deadline = Date.now() + 15_000;
  await Promise.race([
    (async () => {
      for (;;) {
        if (Date.now() > deadline)
          throw new Error("timed out waiting for the tegatad socket");
        if (fs.existsSync(socketPath)) {
          try {
            const res = await rawRpc(socketPath, "status", {});
            if (res.result !== undefined) return;
          } catch {
            // keep polling
          }
        }
        await new Promise((r) => setTimeout(r, 100));
      }
    })(),
    exited,
  ]);
  child.removeAllListeners("exit");
  if (child.pid === undefined) throw new Error("tegatad has no pid");
  return {
    socketPath,
    stateDir,
    daemonDir,
    auditLogPath,
    tcpPort,
    tcpBind: opts.tcp ? tcpBind : undefined,
    pid: child.pid,
    stop: async () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGTERM");
        const timer = setTimeout(() => child.kill("SIGKILL"), 3_000);
        await once(child, "exit").catch(() => {});
        clearTimeout(timer);
      }
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
  };
}

/**
 * Number of live browsers behind a daemon, counted as its `tegata-executor`
 * child processes (one executor per browser; Chromium is the executor's own
 * child). Defunct children carry no argument vector and are not counted.
 */
export function countExecutors(daemonPid: number): number {
  const res = spawnSync(
    "ps",
    ["-o", "pid=,args=", "--ppid", String(daemonPid)],
    {
      encoding: "utf8",
    },
  );
  if (res.error) throw res.error;
  return res.stdout
    .split("\n")
    .filter((line) => line.includes("tegata-executor")).length;
}

export interface CountingFixture {
  port: number;
  url: string;
  /** Number of `POST /login` requests served so far. */
  loginPosts(): number;
  stop(): Promise<void>;
}

/** `<title>` of the counting fixture's login form. */
export const LOGIN_PAGE_TITLE = "tegata fixture: login";
/** `<title>` of the counting fixture's page after a successful login. */
export const LOGGED_IN_PAGE_TITLE = "tegata fixture: logged in";

function loginForm(error: boolean): string {
  const errorMessage = error
    ? '<div id="login-error">invalid credentials</div>'
    : "";
  return `<!doctype html>
<html lang="en">
<head><title>${LOGIN_PAGE_TITLE}</title></head>
<body>
${errorMessage}
<form method="POST" action="/login">
<input id="username" name="username">
<input id="password" name="password" type="password">
<button id="submit" type="submit">Log in</button>
</form>
</body>
</html>`;
}

const LOGGED_IN_PAGE = `<!doctype html><html lang="en"><head><title>${LOGGED_IN_PAGE_TITLE}</title></head><body><div id="welcome">login-ok</div></body></html>`;

/**
 * In-process replica of the target fixture's login site that counts
 * `POST /login` requests. The stock fixture exposes no counter, and the
 * sharing contract is stated in terms of how many logins actually hit the
 * site. Same form (`#username`, `#password`, `#submit`) and same result
 * markers (`#welcome`, `#login-error`) as the stock fixture.
 */
export async function startCountingFixture(creds: {
  username: string;
  password: string;
}): Promise<CountingFixture> {
  const sessions = new Set<string>();
  let posts = 0;
  const server = http.createServer((request, response) => {
    if (request.method === "GET" && request.url === "/") {
      const cookie = request.headers.cookie ?? "";
      const session = cookie
        .split(";")
        .map((c) => c.trim())
        .find((c) => c.startsWith("session="))
        ?.slice("session=".length);
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      response.end(
        session !== undefined && sessions.has(session)
          ? LOGGED_IN_PAGE
          : loginForm(false),
      );
      return;
    }
    if (request.method === "POST" && request.url === "/login") {
      posts += 1;
      let body = "";
      request.setEncoding("utf8");
      request.on("data", (chunk: string) => {
        body += chunk;
      });
      request.on("end", () => {
        const form = new URLSearchParams(body);
        if (
          form.get("username") === creds.username &&
          form.get("password") === creds.password
        ) {
          const session = randomBytes(32).toString("hex");
          sessions.add(session);
          response.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Set-Cookie": `session=${session}; HttpOnly; Path=/; SameSite=Lax`,
          });
          response.end(LOGGED_IN_PAGE);
        } else {
          response.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
          });
          response.end(loginForm(true));
        }
      });
      return;
    }
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("not found");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("counting fixture did not receive a network address");
  return {
    port: address.port,
    url: `http://127.0.0.1:${address.port}`,
    loginPosts: () => posts,
    stop: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export interface LoginResult {
  session_id: string;
  target_id?: string;
  channel: { kind: string; endpoint: string };
}

/** The `login` parameters for the counting fixture (same steps as stock). */
export function loginParams(
  fixtureUrl: string,
  credId: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    cred_id: credId,
    target_url: fixtureUrl,
    ...fixtureSteps(),
    ...extra,
  };
}

export interface RawExchange {
  /** Every line the server sent, in order, until it closed or we gave up. */
  lines: string[];
  /** True when the server closed the connection. */
  closed: boolean;
  /** Milliseconds from connect until the first line (or close). */
  firstLineMs: number;
}

/**
 * Talk to the daemon's loopback TCP listener directly with raw lines. Waits
 * for `expectLines` lines (then returns without waiting for close) or for the
 * server to close, whichever comes first.
 */
export async function tcpExchange(
  port: number,
  inputLines: string[],
  opts: { expectLines?: number; timeoutMs?: number } = {},
): Promise<RawExchange> {
  const expectLines = opts.expectLines ?? 1;
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const sock = net.connect(port, "127.0.0.1");
  const rl = readline.createInterface({ input: sock });
  const lines: string[] = [];
  const started = Date.now();
  let firstLineMs = -1;
  let closed = false;
  const done = new Promise<void>((resolve) => {
    rl.on("line", (line) => {
      lines.push(line);
      if (firstLineMs < 0) firstLineMs = Date.now() - started;
      if (lines.length >= expectLines) resolve();
    });
    sock.once("close", () => {
      closed = true;
      if (firstLineMs < 0) firstLineMs = Date.now() - started;
      resolve();
    });
    sock.once("error", () => resolve());
  });
  const timer = setTimeout(() => sock.destroy(), timeoutMs);
  try {
    await once(sock, "connect");
    sock.write(`${inputLines.join("\n")}\n`);
    await done;
  } finally {
    clearTimeout(timer);
    rl.close();
    sock.destroy();
  }
  return { lines, closed, firstLineMs };
}

export function preambleLine(token: string): string {
  return JSON.stringify({ v: 1, auth: token });
}

export function tunnelPreambleLine(
  token: string,
  sessionId: string,
  port: number,
): string {
  return JSON.stringify({
    v: 1,
    auth: token,
    tunnel: { session_id: sessionId, port },
  });
}

export interface RpcReply {
  result?: unknown;
  error?: { code: number; message?: string };
  /** Set instead of result/error when the preamble itself was refused. */
  preamble?: { ok: boolean; error?: string };
}

/** One JSON-RPC call over the TCP front as a named peer. */
export async function tcpRpc(
  port: number,
  token: string,
  method: string,
  params: unknown,
  timeoutMs = 60_000,
): Promise<RpcReply> {
  const exchange = await tcpExchange(
    port,
    [
      preambleLine(token),
      JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    ],
    { expectLines: 1, timeoutMs },
  );
  if (exchange.lines.length === 0)
    throw new Error("tcp rpc: connection closed without a response");
  const first = JSON.parse(exchange.lines[0]);
  if (first.jsonrpc === undefined && typeof first.ok === "boolean")
    return { preamble: first };
  return first;
}

/** Open a tunnel preamble and return the daemon's one-line verdict. */
export async function tcpTunnel(
  port: number,
  token: string,
  sessionId: string,
  cdpPort: number,
): Promise<{ ok: boolean; error?: string }> {
  const exchange = await tcpExchange(
    port,
    [tunnelPreambleLine(token, sessionId, cdpPort)],
    { expectLines: 1, timeoutMs: 10_000 },
  );
  if (exchange.lines.length === 0)
    throw new Error("tcp tunnel: connection closed without a verdict");
  return JSON.parse(exchange.lines[0]);
}

export interface Peer {
  peer_id: string;
  label: string;
  token: string;
}

/** Issue a named token over the UNIX socket (caller must be an operator). */
export async function issuePeer(
  socketPath: string,
  label: string,
): Promise<Peer> {
  const res = await rawRpc(socketPath, "admin_peer_issue", { label });
  if (res.error !== undefined)
    throw new Error(`admin_peer_issue failed: ${JSON.stringify(res.error)}`);
  const result = res.result as { peer_id?: unknown; token?: unknown };
  if (typeof result.peer_id !== "string" || typeof result.token !== "string")
    throw new Error("admin_peer_issue returned no peer_id/token");
  return { peer_id: result.peer_id, label, token: result.token };
}

/** Port of a `ws://127.0.0.1:<port>/...` CDP endpoint. */
export function endpointPort(endpoint: string): number {
  return Number(new URL(endpoint).port);
}

/**
 * Minimal raw CDP client over the browser websocket (same shape as the one in
 * file-url-guard.test.ts; kept local to the Phase 4 support on purpose).
 */
export class CdpClient {
  private ws: WebSocket;
  private nextId = 1;
  private pending = new Map<
    number,
    (msg: { result?: unknown; error?: { message: string } }) => void
  >();

  private constructor(ws: WebSocket) {
    this.ws = ws;
    this.ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        this.pending.get(msg.id)?.(msg);
        this.pending.delete(msg.id);
      }
    };
  }

  static async connect(endpoint: string): Promise<CdpClient> {
    const ws = new WebSocket(endpoint);
    await new Promise<void>((resolve, reject) => {
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new Error("CDP websocket failed to open"));
    });
    return new CdpClient(ws);
  }

  send(method: string, params: unknown = {}): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, (msg) =>
        msg.error
          ? reject(new Error(`${method}: ${msg.error.message}`))
          : resolve(msg.result as Record<string, unknown>),
      );
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  /** Ids of the browser's page targets. */
  async pageTargetIds(): Promise<string[]> {
    const { targetInfos } = await this.send("Target.getTargets");
    return (targetInfos as Array<{ targetId: string; type: string }>)
      .filter((t) => t.type === "page")
      .map((t) => t.targetId);
  }

  close(): void {
    this.ws.close();
  }
}

export interface Phase4Stack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: Phase4Daemon;
  fixture: CountingFixture;
  mcp: McpSession;
  /** Agent-visible scratch dir; part of the guard's scan roots. */
  agentDir: string;
  /** Record a raw RPC result on the guard's observed surface. */
  observe(label: string, value: unknown): void;
}

/**
 * Full-stack composition for the Phase 4a suite: leak guard + Phase 4 daemon
 * (mock provider, operator uid = the test uid, optional TCP front) + the
 * counting fixture + an MCP session over the UNIX socket, torn down (and
 * leak-checked) in reverse order via `stopPhase4Stack`.
 */
export async function startPhase4Stack(
  opts: {
    tcp?: boolean;
    operator?: boolean;
    sessionTtlSecs?: number;
    maxPendingConnections?: number;
    entries?: (canaries: CanarySet) => MockEntry[];
  } = {},
): Promise<Phase4Stack> {
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
  let daemon: Phase4Daemon | undefined;
  let fixture: CountingFixture | undefined;
  let mcp: McpSession | undefined;
  try {
    daemon = await startPhase4Daemon({
      entries: (opts.entries ?? defaultEntries)(canaries),
      operatorUids: opts.operator === false ? [] : [os.userInfo().uid],
      tcp: opts.tcp,
      sessionTtlSecs: opts.sessionTtlSecs,
      maxPendingConnections: opts.maxPendingConnections,
    });
    fixture = await startCountingFixture({
      username: canaries.username,
      password: canaries.password,
    });
    mcp = await connectMcp(daemon.socketPath, (label, value) =>
      guard.observe(label, value),
    );
    return {
      guard,
      canaries,
      daemon,
      fixture,
      mcp,
      agentDir,
      observe: (label, value) => guard.observe(label, value),
    };
  } catch (error) {
    await mcp?.close().catch(() => {});
    await fixture?.stop().catch(() => {});
    await daemon?.stop().catch(() => {});
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    throw error;
  }
}

/** Tear down and enforce the leak check, mirroring `stopStack`. */
export async function stopPhase4Stack(stack: Phase4Stack): Promise<void> {
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

/** Login over the UNIX socket as the test uid; asserts success. */
export async function unixLogin(
  stack: Phase4Stack,
  credId = "mock:site",
  extra: Record<string, unknown> = {},
): Promise<LoginResult> {
  const res = await rawRpc(
    stack.daemon.socketPath,
    "login",
    loginParams(stack.fixture.url, credId, extra),
  );
  stack.observe("rpc:login", res);
  if (res.error !== undefined)
    throw new Error(`login failed: ${JSON.stringify(res.error)}`);
  return res.result as LoginResult;
}

/** Login over the TCP front as a named peer; asserts success. */
export async function peerLogin(
  stack: Phase4Stack,
  peer: Peer,
  credId = "mock:site",
  extra: Record<string, unknown> = {},
): Promise<LoginResult> {
  if (stack.daemon.tcpPort === undefined)
    throw new Error("peerLogin needs a daemon with a TCP listener");
  const res = await tcpRpc(
    stack.daemon.tcpPort,
    peer.token,
    "login",
    loginParams(stack.fixture.url, credId, extra),
  );
  stack.observe("tcp:login", res);
  if (res.preamble !== undefined || res.error !== undefined)
    throw new Error(`peer login failed: ${JSON.stringify(res)}`);
  return res.result as LoginResult;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export interface DaemonExit {
  /** Exit code; null when the daemon was still running at the deadline. */
  code: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}

/**
 * Start tegatad with `configPath` and wait for it to exit on its own (Phase
 * 4b startup guards). A daemon that is still running after `timeoutMs` is
 * killed and reported with `code: null`; refusal tests read that as "the
 * daemon started although it must not have".
 */
export async function runDaemonUntilExit(
  configPath: string,
  cwd: string,
  timeoutMs = 10_000,
): Promise<DaemonExit> {
  const child = spawn(bins().tegatad, ["--config", configPath], {
    stdio: ["ignore", "ignore", "pipe"],
    cwd,
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const exited = once(child, "exit").then(
    ([code, signal]) =>
      ({ code, signal }) as {
        code: number | null;
        signal: NodeJS.Signals | null;
      },
  );
  const outcome = await Promise.race([
    exited,
    sleep(timeoutMs).then(() => undefined),
  ]);
  if (outcome === undefined) {
    child.kill("SIGKILL");
    await exited.catch(() => {});
    return { code: null, signal: null, stderr };
  }
  return { ...outcome, stderr };
}
