/**
 * Issue #45 acceptance-test support (persistent cookies per credential).
 * Owned by the acceptance suite (gauntlet); do not modify during
 * implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - the provider key `persist_cookies` (list of backend ids, `"*"` = every
 *     credential of the provider), accepted by every provider type; the rest
 *     of the config is the Phase 4 `[[listen]]` shape
 *   - the store directory `<state_dir>/cookies/` (0700) holding one file per
 *     (principal, namespace, cred_id), mode 0600, named by the hex sha256 of
 *     the key plus an extension (Linux `.json`, plain JSON carrying
 *     `version`, `principal`, `namespace`, `cred_id`, `saved_at`, `cookies`)
 *   - audit fields: `cookies` ("restored" | "none") and `steps_skipped` on
 *     login records of persisted credentials, `cookies_saved` on their
 *     session-end records
 *   - the admin RPC `admin_cookies_forget` (`{cred_id}` or `{all: true}`,
 *     result `{removed: n}`) and the Unix CLI
 *     `tegatad cookies forget <cred_id> | --all [--socket <path>]`
 *   - the target fixture's `/persistent-cookies/` site: `GET /` serves the
 *     logged-in page to a valid `device` cookie, `POST /login` issues
 *     `device` (one day) and `sid` (session); `GET /state` reports
 *     `{login_posts, requests: [{method, path, cookies}], device_values,
 *     sid_values}`; `POST /invalidate` voids every issued `device`
 */
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  fixtureSteps,
  type McpSession,
  type MockEntry,
  rawRpc,
  startTargetFixture,
  type TargetFixture,
} from "./harness.js";
import { type AuditRecord, readAuditRecords, waitUntil } from "./phase3.js";
import { countExecutors, freeTcpPort } from "./phase4.js";

function tomlString(s: string): string {
  return JSON.stringify(s);
}

function tomlStringList(values: string[]): string {
  return `[${values.map(tomlString).join(", ")}]`;
}

export interface CookieMockProvider {
  type: "mock";
  namespace: string;
  entries: MockEntry[];
  /** Rendered as `persist_cookies`; omitted when undefined. */
  persistCookies?: string[];
}

export interface CookieAgeProvider {
  type: "age-file";
  namespace: string;
  entriesPath: string;
  identityPath: string;
  persistCookies?: string[];
}

export type CookieProviderSpec = CookieMockProvider | CookieAgeProvider;

function renderProvider(p: CookieProviderSpec): string[] {
  const lines = ["", "[[providers]]", `namespace = ${tomlString(p.namespace)}`];
  if (p.type === "age-file") {
    lines.push(
      `type = "age-file"`,
      `entries_path = ${tomlString(p.entriesPath)}`,
      `identity_path = ${tomlString(p.identityPath)}`,
    );
    if (p.persistCookies !== undefined)
      lines.push(`persist_cookies = ${tomlStringList(p.persistCookies)}`);
    return lines;
  }
  lines.push(`type = "mock"`);
  if (p.persistCookies !== undefined)
    lines.push(`persist_cookies = ${tomlStringList(p.persistCookies)}`);
  for (const e of p.entries) {
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
  return lines;
}

/** Render a Phase 4 shaped config whose providers may carry persist_cookies. */
export function renderCookieConfig(opts: {
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  uid: number;
  tcpPort?: number;
  providers: CookieProviderSpec[];
}): string {
  const lines = [
    `state_dir = ${tomlString(opts.stateDir)}`,
    `audit_log_path = ${tomlString(opts.auditLogPath)}`,
    "",
    "[[listen]]",
    `kind = "unix"`,
    `path = ${tomlString(opts.socketPath)}`,
    `allowed_uids = [${opts.uid}]`,
    `operator_uids = [${opts.uid}]`,
  ];
  if (opts.tcpPort !== undefined)
    lines.push(
      "",
      "[[listen]]",
      `kind = "tcp"`,
      `bind = "127.0.0.1"`,
      `port = ${opts.tcpPort}`,
    );
  for (const p of opts.providers) lines.push(...renderProvider(p));
  return `${lines.join("\n")}\n`;
}

export interface CookieDaemon {
  socketPath: string;
  stateDir: string;
  daemonDir: string;
  auditLogPath: string;
  tcpPort?: number;
  /** Pid of the running daemon process. */
  pid(): number;
  /** Everything the daemon (and its children) wrote to stderr so far. */
  stderr(): string;
  /** Stop the daemon normally, rewrite the config, start it again. */
  restart(providers: CookieProviderSpec[]): Promise<void>;
  stop(): Promise<void>;
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
  await once(child, "exit").catch(() => {});
  clearTimeout(timer);
}

/** Start tegatad in a private temp directory; the state dir survives restarts. */
export async function startCookieDaemon(opts: {
  providers: CookieProviderSpec[];
  tcp?: boolean;
}): Promise<CookieDaemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-ck-"));
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const auditLogPath = path.join(stateDir, "audit.log");
  const configPath = path.join(daemonDir, "config.toml");
  const tcpPort = opts.tcp ? await freeTcpPort() : undefined;
  let stderr = "";
  let child: ChildProcess | undefined;

  const launch = async (providers: CookieProviderSpec[]) => {
    fs.writeFileSync(
      configPath,
      renderCookieConfig({
        socketPath,
        stateDir,
        auditLogPath,
        uid: os.userInfo().uid,
        tcpPort,
        providers,
      }),
      { mode: 0o600 },
    );
    const proc = spawn(bins().tegatad, ["--config", configPath], {
      stdio: ["ignore", "inherit", "pipe"],
      cwd: daemonDir,
    });
    child = proc;
    proc.stderr?.setEncoding("utf8");
    proc.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const exited = new Promise<never>((_, reject) => {
      proc.once("exit", (code) =>
        reject(new Error(`tegatad exited early (code ${code}): ${stderr}`)),
      );
    });
    try {
      await Promise.race([
        waitUntil("the tegatad socket", async () => {
          if (!fs.existsSync(socketPath)) return false;
          try {
            const res = await rawRpc(socketPath, "status", {});
            return res.result !== undefined;
          } catch {
            return false;
          }
        }),
        exited,
      ]);
    } catch (error) {
      proc.removeAllListeners("exit");
      await stopChild(proc);
      throw error;
    }
    proc.removeAllListeners("exit");
  };

  try {
    await launch(opts.providers);
  } catch (error) {
    fs.rmSync(daemonDir, { recursive: true, force: true });
    throw error;
  }
  return {
    socketPath,
    stateDir,
    daemonDir,
    auditLogPath,
    tcpPort,
    pid: () => {
      if (child?.pid === undefined) throw new Error("tegatad has no pid");
      return child.pid;
    },
    stderr: () => stderr,
    restart: async (providers) => {
      if (child !== undefined) await stopChild(child);
      await launch(providers);
    },
    stop: async () => {
      if (child !== undefined) await stopChild(child);
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
  };
}

/** `<state_dir>/cookies/`. */
export function cookieStoreDir(stateDir: string): string {
  return path.join(stateDir, "cookies");
}

/** Regular files directly inside the cookie store (missing dir: empty). */
export function cookieStoreFiles(stateDir: string): string[] {
  const dir = cookieStoreDir(stateDir);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((ent) => ent.isFile())
    .map((ent) => path.join(dir, ent.name));
}

export interface CookieFixtureState {
  login_posts: number;
  requests: Array<{ method: string; path: string; cookies: string[] }>;
  device_values: string[];
  sid_values: string[];
}

/** Read the `/persistent-cookies/` site's record. */
export async function cookieFixtureState(
  fixture: TargetFixture,
): Promise<CookieFixtureState> {
  const res = await fetch(`${fixture.url}/persistent-cookies/state`);
  if (!res.ok) throw new Error(`fixture state failed: ${res.status}`);
  return (await res.json()) as CookieFixtureState;
}

/** Void every `device` cookie the fixture has issued. */
export async function invalidateDeviceCookies(
  fixture: TargetFixture,
): Promise<void> {
  const res = await fetch(`${fixture.url}/persistent-cookies/invalidate`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`fixture invalidate failed: ${res.status}`);
}

/** Login parameters for the fixture's persistent-cookie site. */
export function cookieLoginParams(
  fixture: TargetFixture,
  credId: string,
): Record<string, unknown> {
  return {
    cred_id: credId,
    target_url: `${fixture.url}/persistent-cookies/`,
    ...fixtureSteps(),
  };
}

/** Credentials used by the persistent-cookie suite: A = site, B = site-b. */
export function cookieEntries(c: CanarySet): MockEntry[] {
  return [
    {
      id: "site",
      name: "Persistent Cookie Site A",
      uri: "http://127.0.0.1",
      kind: "login",
      username: c.username,
      password: c.password,
      totpSeed: c.totpSeed,
      totpExposable: true,
    },
    {
      id: "site-b",
      name: "Persistent Cookie Site B",
      uri: "http://127.0.0.1",
      kind: "login",
      username: c.username,
      password: c.password,
    },
  ];
}

export interface CookieStack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: CookieDaemon;
  fixture: TargetFixture;
  mcp: McpSession;
  agentDir: string;
  /** Daemon-side provider material (age files). Not scanned. */
  materialsDir: string;
  observe(label: string, value: unknown): void;
  /** Reconnect the MCP session (after a daemon restart). */
  reconnectMcp(): Promise<void>;
}

/**
 * Leak guard + daemon (operator uid = the test uid, optional TCP front) +
 * stock target fixture + MCP session, torn down via `stopCookieStack`.
 */
export async function startCookieStack(opts: {
  providers: (
    canaries: CanarySet,
    materialsDir: string,
  ) => CookieProviderSpec[];
  tcp?: boolean;
}): Promise<CookieStack> {
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-agent-"));
  const materialsDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegata-materials-"),
  );
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
  let daemon: CookieDaemon | undefined;
  let fixture: TargetFixture | undefined;
  let mcp: McpSession | undefined;
  try {
    daemon = await startCookieDaemon({
      providers: opts.providers(canaries, materialsDir),
      tcp: opts.tcp,
    });
    fixture = await startTargetFixture({
      username: canaries.username,
      password: canaries.password,
    });
    mcp = await connectMcp(daemon.socketPath, observe);
    const stack: CookieStack = {
      guard,
      canaries,
      daemon,
      fixture,
      mcp,
      agentDir,
      materialsDir,
      observe,
      reconnectMcp: async () => {
        await stack.mcp.close().catch(() => {});
        stack.mcp = await connectMcp(stack.daemon.socketPath, observe);
      },
    };
    return stack;
  } catch (error) {
    await mcp?.close().catch(() => {});
    await fixture?.stop().catch(() => {});
    await daemon?.stop().catch(() => {});
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    fs.rmSync(materialsDir, { recursive: true, force: true });
    throw error;
  }
}

/** Tear down and enforce the leak check, mirroring `stopStack`. */
export async function stopCookieStack(stack: CookieStack): Promise<void> {
  await stack.mcp.close().catch(() => {});
  await stack.fixture.stop().catch(() => {});
  await stack.daemon.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
    fs.rmSync(stack.materialsDir, { recursive: true, force: true });
  }
}

/** Number of live browsers behind the daemon. */
export function browserCount(stack: CookieStack): number {
  return countExecutors(stack.daemon.pid());
}

/** Wait until the daemon has `count` live browsers (a session end completed). */
export async function waitForBrowserCount(
  stack: CookieStack,
  count: number,
): Promise<void> {
  await waitUntil(
    `the browser count to reach ${count}`,
    () => browserCount(stack) === count,
    15_000,
  );
}

/** The successful login audit record of a session. */
export function loginRecord(
  stack: CookieStack,
  sessionId: string,
): AuditRecord | undefined {
  return readAuditRecords(stack.daemon.auditLogPath).records.find(
    (r) =>
      r.method === "login" && r.outcome === "ok" && r.session_id === sessionId,
  );
}

/** Non-login audit records of a session that carry `cookies_saved`. */
export function sessionEndRecords(
  stack: CookieStack,
  sessionId: string,
): AuditRecord[] {
  return readAuditRecords(stack.daemon.auditLogPath).records.filter(
    (r) =>
      r.method !== "login" &&
      r.session_id === sessionId &&
      "cookies_saved" in r,
  );
}

export interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Run the Unix admin CLI `tegatad cookies forget ...` against the socket. */
export function cookiesForgetCli(
  socketPath: string,
  target: { credId: string } | { all: true },
): CliResult {
  const selector = "credId" in target ? [target.credId] : ["--all"];
  const res = spawnSync(
    bins().tegatad,
    ["cookies", "forget", ...selector, "--socket", socketPath],
    { encoding: "utf8", timeout: 30_000 },
  );
  if (res.error) throw res.error;
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}
