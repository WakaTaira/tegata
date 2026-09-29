/**
 * Issue #49 acceptance-test support (persistent cookies for authorize_device
 * and the OAuth proxy login). Owned by the acceptance suite (gauntlet); do
 * not modify during implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - the #45 provider key `persist_cookies` and store `<state_dir>/cookies/`,
 *     shared by `login`, `authorize_device`, and the OAuth proxy login
 *   - audit fields `cookies` ("restored" | "none") and `steps_skipped` on the
 *     `authorize_device` and OAuth `open_api_proxy` records of persisted
 *     credentials
 *   - the target fixture's `/device-cookies/` pages: `GET /login` serves the
 *     `/persistent-cookies/` login form, `GET /device` and the `POST /device`
 *     / `POST /approve` steps require the `device` cookie or `sid` session
 *     that login issues (anything else is 302'd to `/login`), `GET /open`
 *     shows the empty form to anyone, `POST /oauth/device_authorization`
 *     returns `/device-cookies/device` as `verification_uri`; `GET /state`
 *     reports `{login_posts, approvals, requests: [{method, path, cookies}]}`
 *     and `POST /invalidate` voids every `device` cookie and `sid` session
 */
import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import { type ApiProxySpec, renderApiProxyConfig } from "./api-proxy.js";
import {
  bins,
  type CanarySet,
  connectMcp,
  type McpSession,
  type MockEntry,
  rawRpc,
  startTargetFixture,
  type TargetFixture,
} from "./harness.js";
import { waitUntil } from "./phase3.js";
import { freeTcpPort } from "./phase4.js";

/** Name of the OAuth `[[api_proxy]]` of the suite. */
export const OAUTH_PROXY_NAME = "fxc";

export interface DeviceCookieDaemon {
  socketPath: string;
  stateDir: string;
  daemonDir: string;
  auditLogPath: string;
  tcpPort?: number;
  pid(): number;
  /** Everything the daemon (and its children) wrote to stderr so far. */
  stderr(): string;
  stop(): Promise<void>;
}

export interface DeviceCookieStack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: DeviceCookieDaemon;
  fixture: TargetFixture;
  mcp: McpSession;
  agentDir: string;
  observe(label: string, value: unknown): void;
}

export interface DeviceCookieStackOptions {
  /** Rendered as the mock provider's `persist_cookies`; omitted when undefined. */
  persistCookies?: string[];
  approveCmd?: string;
  /** Configure the OAuth proxy `OAUTH_PROXY_NAME` over the fixture. */
  oauth?: boolean;
  /** Add a loopback TCP front for peer-token principals. */
  tcp?: boolean;
}

export interface DeviceCookieFixtureState {
  login_posts: number;
  approvals: number;
  requests: Array<{ method: string; path: string; cookies: string[] }>;
}

function tomlStringList(values: string[]): string {
  return `[${values.map((v) => JSON.stringify(v)).join(", ")}]`;
}

/** `/device-cookies/device`: the approval page gated by the login cookies. */
export function gatedVerificationUrl(fixture: TargetFixture): string {
  return `${fixture.url}/device-cookies/device`;
}

/** `/device-cookies/open`: the approval form shown even without a login. */
export function openVerificationUrl(fixture: TargetFixture): string {
  return `${fixture.url}/device-cookies/open`;
}

/**
 * Credentials A (site) and B (site-b). Their uri is the fixture's login page,
 * so authorize_device and the OAuth proxy log in there by default detection.
 */
export function deviceCookieEntries(
  c: CanarySet,
  fixture: TargetFixture,
): MockEntry[] {
  const uri = `${fixture.url}/device-cookies/login`;
  return [
    {
      id: "site",
      name: "Device Cookie Site A",
      uri,
      kind: "login",
      username: c.username,
      password: c.password,
    },
    {
      id: "site-b",
      name: "Device Cookie Site B",
      uri,
      kind: "login",
      username: c.username,
      password: c.password,
    },
  ];
}

/** OAuth proxy whose device authorization points at the gated approval page. */
export function deviceCookieOAuthProxy(fixture: TargetFixture): ApiProxySpec {
  return {
    name: OAUTH_PROXY_NAME,
    upstream: fixture.url,
    header: "Authorization",
    value: "Bearer {{secret}}",
    oauth: {
      client_id: "tegata-test",
      device_authorization_url: `${fixture.url}/device-cookies/oauth/device_authorization`,
      token_url: `${fixture.url}/oauth/token`,
      revocation_url: `${fixture.url}/oauth/revoke`,
      login_cred_id: "mock:site",
      success_selector: "#device-ok",
      failure_selector: "#device-error",
    },
  };
}

/**
 * The api-proxy config (`[[listen]]` shape, operator = the test uid) with
 * `persist_cookies` added to its mock provider.
 */
export function renderDeviceCookieConfig(opts: {
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  tcpPort?: number;
  entries: MockEntry[];
  apiProxies: ApiProxySpec[];
  approveCmd?: string;
  persistCookies?: string[];
}): string {
  const config = renderApiProxyConfig({
    entries: opts.entries,
    apiProxies: opts.apiProxies,
    approveCmd: opts.approveCmd,
    transport: "listen",
    operatorUids: [os.userInfo().uid],
    tcpPort: opts.tcpPort,
    socketPath: opts.socketPath,
    stateDir: opts.stateDir,
    auditLogPath: opts.auditLogPath,
  });
  if (opts.persistCookies === undefined) return config;
  const marker = 'namespace = "mock"\ntype = "mock"\n';
  if (!config.includes(marker))
    throw new Error("mock provider header not found in the rendered config");
  return config.replace(
    marker,
    `${marker}persist_cookies = ${tomlStringList(opts.persistCookies)}\n`,
  );
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
  await once(child, "exit").catch(() => {});
  clearTimeout(timer);
}

async function startDeviceCookieDaemon(
  opts: DeviceCookieStackOptions & {
    entries: MockEntry[];
    apiProxies: ApiProxySpec[];
  },
): Promise<DeviceCookieDaemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-dck-"));
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const auditLogPath = path.join(stateDir, "audit.log");
  const configPath = path.join(daemonDir, "config.toml");
  const tcpPort = opts.tcp ? await freeTcpPort() : undefined;
  fs.writeFileSync(
    configPath,
    renderDeviceCookieConfig({
      socketPath,
      stateDir,
      auditLogPath,
      tcpPort,
      entries: opts.entries,
      apiProxies: opts.apiProxies,
      approveCmd: opts.approveCmd,
      persistCookies: opts.persistCookies,
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
  return {
    socketPath,
    stateDir,
    daemonDir,
    auditLogPath,
    tcpPort,
    pid: () => {
      if (child.pid === undefined) throw new Error("tegatad has no pid");
      return child.pid;
    },
    stderr: () => stderr,
    stop: async () => {
      await stopChild(child);
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
  };
}

/**
 * Leak guard + stock target fixture + daemon (credentials pointing at the
 * fixture's `/device-cookies/login`) + MCP session, torn down via
 * `stopDeviceCookieStack`.
 */
export async function startDeviceCookieStack(
  opts: DeviceCookieStackOptions = {},
): Promise<DeviceCookieStack> {
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
  let fixture: TargetFixture | undefined;
  let daemon: DeviceCookieDaemon | undefined;
  let mcp: McpSession | undefined;
  try {
    fixture = await startTargetFixture({
      username: canaries.username,
      password: canaries.password,
    });
    daemon = await startDeviceCookieDaemon({
      ...opts,
      entries: deviceCookieEntries(canaries, fixture),
      apiProxies: opts.oauth ? [deviceCookieOAuthProxy(fixture)] : [],
    });
    mcp = await connectMcp(daemon.socketPath, observe);
    return { guard, canaries, daemon, fixture, mcp, agentDir, observe };
  } catch (error) {
    await mcp?.close().catch(() => {});
    await daemon?.stop().catch(() => {});
    await fixture?.stop().catch(() => {});
    await guard.dispose().catch(() => {});
    fs.rmSync(agentDir, { recursive: true, force: true });
    throw error;
  }
}

/** Tear down and enforce the leak check, mirroring `stopCookieStack`. */
export async function stopDeviceCookieStack(
  stack: DeviceCookieStack,
): Promise<void> {
  await stack.mcp.close().catch(() => {});
  await stack.daemon.stop().catch(() => {});
  await stack.fixture.stop().catch(() => {});
  try {
    await stack.guard.assertNoLeaks();
  } finally {
    await stack.guard.dispose();
    fs.rmSync(stack.agentDir, { recursive: true, force: true });
  }
}

/** Read the `/device-cookies/` pages' record. */
export async function deviceCookieFixtureState(
  fixture: TargetFixture,
): Promise<DeviceCookieFixtureState> {
  const res = await fetch(`${fixture.url}/device-cookies/state`);
  if (!res.ok) throw new Error(`fixture state failed: ${res.status}`);
  return (await res.json()) as DeviceCookieFixtureState;
}

/** Void every `device` cookie and `sid` session the fixture has issued. */
export async function invalidateDeviceSessions(
  fixture: TargetFixture,
): Promise<void> {
  const res = await fetch(`${fixture.url}/device-cookies/invalidate`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`fixture invalidate failed: ${res.status}`);
}

/** Issue a device code through the fixture's `POST /device/issue`. */
export async function issueDeviceCode(fixture: TargetFixture): Promise<string> {
  const res = await fetch(`${fixture.url}/device/issue`, { method: "POST" });
  if (!res.ok) throw new Error(`POST /device/issue failed: ${res.status}`);
  const body = (await res.json()) as { user_code?: unknown };
  if (typeof body.user_code !== "string")
    throw new Error("POST /device/issue returned no user_code");
  return body.user_code;
}

/** Whether the fixture has approved a device code. */
export async function deviceApproved(
  fixture: TargetFixture,
  userCode: string,
): Promise<boolean> {
  const res = await fetch(
    `${fixture.url}/device/status?user_code=${encodeURIComponent(userCode)}`,
  );
  if (!res.ok) throw new Error(`GET /device/status failed: ${res.status}`);
  return ((await res.json()) as { approved: boolean }).approved;
}
