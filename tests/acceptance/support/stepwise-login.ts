/**
 * Issue #46 acceptance-test support (stepwise login). Owned by the
 * acceptance suite (gauntlet); do not modify during implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - the RPC methods / MCP tools `login_begin` ({cred_id, target_url,
 *     success_selector, failure_selector?, exclusive?}) and `login_step`
 *     ({login_id, action, ...fields of that action}, e.g.
 *     `{login_id, action: "click", selector}`); their results are
 *     `{state: "pending", login_id, snapshot}`, `{state: "done", session_id,
 *     target_id, channel: {kind: "cdp", endpoint}}` or `{state: "aborted"}`
 *   - the snapshot shape `{url, title, text, elements: [{tag, type, id, name,
 *     role, placeholder, aria-label, autocomplete, href, disabled, text,
 *     selector}], settled, truncated?}` with the username masked as
 *     `[username]`
 *   - the top-level config keys `stepwise_idle_secs` / `stepwise_max_secs`
 *     (the rest of the config is the Phase 4 `[[listen]]` shape with the
 *     Issue #45 provider key `persist_cookies`)
 *   - audit: `login_begin` records carry `stepwise: true`; an expired
 *     stepwise login is one `stepwise_expired` record
 *   - the target fixture's `/stepwise/` sites: `GET /stepwise/` (username ->
 *     password -> 2FA push page -> authenticator app -> `/stepwise/home`
 *     showing `#signed-in` "Signed in as <username>"; a persistent
 *     `stepwise_session` cookie serves the signed-in page directly),
 *     `/stepwise/echo/?kind=text|attr|query` (echoes the submitted password),
 *     `/stepwise/sticky/` (keeps a wrong password in its field and reports
 *     the field length on every click), and `GET /stepwise/state` reporting
 *     `{requests, posts, inputs, totp, sticky_reports}` with every field
 *     value masked (`<empty>`, `<username>`, `<password>`, `<totp>`, or
 *     `sha256:<hex>`)
 */
import { type ChildProcess, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  type McpResult,
  type McpSession,
  type MockEntry,
  rawRpc,
  startTargetFixture,
  type TargetFixture,
} from "./harness.js";
import {
  type CookieProviderSpec,
  renderCookieConfig,
} from "./persistent-cookies.js";
import { waitUntil } from "./phase3.js";
import { countExecutors, freeTcpPort } from "./phase4.js";

function tomlString(s: string): string {
  return JSON.stringify(s);
}

/** Top-level daemon keys used by the stepwise suite. */
export interface StepwiseTopLevel {
  stepwiseIdleSecs?: number;
  stepwiseMaxSecs?: number;
  approveCmd?: string;
}

/**
 * Render a Phase 4 shaped config with the stepwise top-level keys. The keys
 * precede the first table, so they stay top-level.
 */
export function renderStepwiseConfig(opts: {
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  uid: number;
  tcpPort?: number;
  top: StepwiseTopLevel;
  providers: CookieProviderSpec[];
}): string {
  const top: string[] = [];
  if (opts.top.stepwiseIdleSecs !== undefined)
    top.push(`stepwise_idle_secs = ${opts.top.stepwiseIdleSecs}`);
  if (opts.top.stepwiseMaxSecs !== undefined)
    top.push(`stepwise_max_secs = ${opts.top.stepwiseMaxSecs}`);
  if (opts.top.approveCmd !== undefined)
    top.push(`approve_cmd = ${tomlString(opts.top.approveCmd)}`);
  const body = renderCookieConfig({
    socketPath: opts.socketPath,
    stateDir: opts.stateDir,
    auditLogPath: opts.auditLogPath,
    uid: opts.uid,
    tcpPort: opts.tcpPort,
    providers: opts.providers,
  });
  return top.length === 0 ? body : `${top.join("\n")}\n${body}`;
}

export interface StepwiseDaemon {
  socketPath: string;
  stateDir: string;
  daemonDir: string;
  auditLogPath: string;
  tcpPort?: number;
  pid: number;
  /** Everything the daemon (and its children) wrote to stderr so far. */
  stderr(): string;
  stop(): Promise<void>;
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
  await once(child, "exit").catch(() => {});
  clearTimeout(timer);
}

/** Start tegatad in a private temp directory with its stderr captured. */
export async function startStepwiseDaemon(opts: {
  top: StepwiseTopLevel;
  providers: CookieProviderSpec[];
  tcp?: boolean;
}): Promise<StepwiseDaemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-sw-"));
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const auditLogPath = path.join(stateDir, "audit.log");
  const configPath = path.join(daemonDir, "config.toml");
  const tcpPort = opts.tcp ? await freeTcpPort() : undefined;
  fs.writeFileSync(
    configPath,
    renderStepwiseConfig({
      socketPath,
      stateDir,
      auditLogPath,
      uid: os.userInfo().uid,
      tcpPort,
      top: opts.top,
      providers: opts.providers,
    }),
    { mode: 0o600 },
  );
  let stderr = "";
  const child = spawn(bins().tegatad, ["--config", configPath], {
    stdio: ["ignore", "inherit", "pipe"],
    cwd: daemonDir,
  });
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const exited = new Promise<never>((_, reject) => {
    child.once("exit", (code) =>
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
    child.removeAllListeners("exit");
    await stopChild(child);
    fs.rmSync(daemonDir, { recursive: true, force: true });
    throw error;
  }
  child.removeAllListeners("exit");
  if (child.pid === undefined) throw new Error("tegatad has no pid");
  return {
    socketPath,
    stateDir,
    daemonDir,
    auditLogPath,
    tcpPort,
    pid: child.pid,
    stderr: () => stderr,
    stop: async () => {
      await stopChild(child);
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
  };
}

/**
 * Credentials of the stepwise suite. `site` is the fixture's account (with
 * the TOTP seed), `site-badpass` has a wrong password, and `echo-<kind>` are
 * separate credentials (separate rate-limit keys) for the echo pages.
 */
export function stepwiseEntries(c: CanarySet): MockEntry[] {
  const entry = (id: string, name: string, password: string): MockEntry => ({
    id,
    name,
    uri: "http://127.0.0.1",
    kind: "login",
    username: c.username,
    password,
    totpSeed: c.totpSeed,
    totpExposable: true,
  });
  return [
    entry("site", "Stepwise Site", c.password),
    entry("site-badpass", "Stepwise Site (bad password)", c.wrongPassword),
    entry("echo-text", "Stepwise Echo (text)", c.password),
    entry("echo-attr", "Stepwise Echo (attribute)", c.password),
    entry("echo-query", "Stepwise Echo (query)", c.password),
  ];
}

export interface StepwiseStack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: StepwiseDaemon;
  fixture: TargetFixture;
  mcp: McpSession;
  agentDir: string;
  observe(label: string, value: unknown): void;
}

/**
 * Leak guard + daemon (mock provider over `stepwiseEntries`, operator uid =
 * the test uid, optional TCP front, stderr captured) + target fixture in TOTP
 * mode + MCP session, torn down via `stopStepwiseStack`.
 */
export async function startStepwiseStack(
  opts: {
    top?: StepwiseTopLevel;
    persistCookies?: string[];
    tcp?: boolean;
  } = {},
): Promise<StepwiseStack> {
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
  const observe = (label: string, value: unknown) =>
    guard.observe(label, value);
  let daemon: StepwiseDaemon | undefined;
  let fixture: TargetFixture | undefined;
  let mcp: McpSession | undefined;
  try {
    daemon = await startStepwiseDaemon({
      top: opts.top ?? {},
      providers: [
        {
          type: "mock",
          namespace: "mock",
          entries: stepwiseEntries(canaries),
          persistCookies: opts.persistCookies,
        },
      ],
      tcp: opts.tcp,
    });
    fixture = await startTargetFixture({
      username: canaries.username,
      password: canaries.password,
      totp_seed: canaries.totpSeed,
    });
    mcp = await connectMcp(daemon.socketPath, observe);
    return { guard, canaries, daemon, fixture, mcp, agentDir, observe };
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
export async function stopStepwiseStack(stack: StepwiseStack): Promise<void> {
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

/** Number of live browsers behind the daemon. */
export function browserCount(stack: StepwiseStack): number {
  return countExecutors(stack.daemon.pid);
}

/** Wait until the daemon has `count` live browsers. */
export async function waitForBrowserCount(
  stack: StepwiseStack,
  count: number,
): Promise<void> {
  await waitUntil(
    `the browser count to reach ${count}`,
    () => browserCount(stack) === count,
    15_000,
  );
}

export interface SnapshotElement {
  tag: string;
  type?: string | null;
  id?: string | null;
  name?: string | null;
  role?: string | null;
  text?: string | null;
  href?: string | null;
  selector: string;
  [key: string]: unknown;
}

export interface Snapshot {
  url: string;
  title: string;
  text: string;
  elements: SnapshotElement[];
  settled: boolean;
  truncated?: boolean;
  [key: string]: unknown;
}

export interface PendingResult {
  state: "pending";
  login_id: string;
  snapshot: Snapshot;
}

export interface DoneResult {
  state: "done";
  session_id: string;
  target_id?: string;
  channel: { kind: string; endpoint: string };
}

export type StepwiseResult =
  | PendingResult
  | DoneResult
  | { state: "aborted" }
  | { state: string; [key: string]: unknown };

/** One call's outcome: a result, or an error code. `raw` is the wire text. */
export type StepOutcome =
  | { result: StepwiseResult; error?: undefined; raw: string }
  | { result?: undefined; error: string; raw: string };

/** Calls one of `login_begin` / `login_step` through some surface. */
export type StepwiseCaller = (
  method: "login_begin" | "login_step",
  params: Record<string, unknown>,
) => Promise<StepOutcome>;

function fromMcp(res: McpResult): StepOutcome {
  const raw = JSON.stringify(res);
  if (res.isError) return { error: res.text, raw };
  return { result: res.json as StepwiseResult, raw };
}

/** Caller over the MCP tools (the agent-facing surface). */
export function mcpCaller(stack: StepwiseStack): StepwiseCaller {
  return async (method, params) =>
    fromMcp(await stack.mcp.callTool(method, params));
}

/** Caller over the UNIX socket (raw JSON-RPC), observed by the guard. */
export function rpcCaller(stack: StepwiseStack): StepwiseCaller {
  return async (method, params) => {
    const res = await rawRpc(stack.daemon.socketPath, method, params);
    stack.observe(`rpc:${method}`, res);
    const raw = JSON.stringify(res);
    if (res.error !== undefined)
      return { error: res.error.message ?? String(res.error.code), raw };
    return { result: res.result as StepwiseResult, raw };
  };
}

/** `login_begin` parameters for the fixture's stepwise site (1). */
export function beginParams(
  fixture: TargetFixture,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    cred_id: "mock:site",
    target_url: `${fixture.url}/stepwise/`,
    success_selector: "#signed-in",
    failure_selector: "#login-error",
    ...extra,
  };
}

export interface StepwiseFixtureState {
  requests: Array<{ method: string; path: string }>;
  posts: Array<{
    path: string;
    kind: string | null;
    fields: Record<string, string>;
  }>;
  inputs: Array<{ path: string; field: string; value: string }>;
  totp: Array<{ code: string; valid: boolean }>;
  sticky_reports: Array<{
    when: string;
    target: string;
    password_length: number;
  }>;
}

/** Read the `/stepwise/` sites' record. */
export async function stepwiseState(
  fixture: TargetFixture,
): Promise<StepwiseFixtureState> {
  const res = await fetch(`${fixture.url}/stepwise/state`);
  if (!res.ok) throw new Error(`fixture state failed: ${res.status}`);
  return (await res.json()) as StepwiseFixtureState;
}

/** The fixture's masked form of a non-credential value. */
export function maskedDigest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
