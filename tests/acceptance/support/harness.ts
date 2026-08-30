/**
 * Acceptance-test harness. Owned by the acceptance suite (gauntlet); do not
 * modify during implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - binary/entry resolution (env vars and default paths)
 *   - the daemon's TOML config shape and CLI (`tegatad --config <path>`)
 *   - the target-fixture process protocol (stdin JSON config, stdout ready line)
 *   - the MCP server process contract (env TEGATA_SOCKET, stdio transport)
 *   - the JSON-RPC-over-UDS wire format
 *   - error classification codes and MCP error surface
 */
import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

/** Error classification codes. The full closed set; nothing else may appear.
 * APPROVAL_DENIED / APPROVAL_TIMEOUT were added by the Phase 3 contract
 * (docs/secret/briefs/tegata-phase3.md, 変更内容 4).
 * Keep in sync with ErrorCode in crates/tegatad/src/main.rs and
 * ERROR_CODES in packages/tegata-mcp/src/index.ts. */
export const ERROR_CODES = [
  "INVALID_CREDENTIAL",
  "MFA_REQUIRED",
  "SELECTOR_NOT_FOUND",
  "VAULT_LOCKED",
  "RATE_LIMITED",
  "TOTP_NOT_EXPOSABLE",
  "APPROVAL_DENIED",
  "APPROVAL_TIMEOUT",
  "INTERNAL",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

/** Binary / entrypoint resolution. Overridable via env for CI wiring. */
export function bins() {
  return {
    tegatad:
      process.env.TEGATAD_BIN ?? path.join(REPO_ROOT, "target/debug/tegatad"),
    leakscan:
      process.env.LEAKSCAN_BIN ?? path.join(REPO_ROOT, "target/debug/leakscan"),
    mcpEntry:
      process.env.TEGATA_MCP_ENTRY ??
      path.join(REPO_ROOT, "packages/tegata-mcp/dist/index.js"),
    fixtureEntry:
      process.env.TARGET_FIXTURE_ENTRY ??
      path.join(REPO_ROOT, "packages/target-fixture/dist/index.js"),
  };
}

export interface MockEntry {
  id: string;
  name: string;
  uri: string;
  kind: string;
  username: string;
  password: string;
  totpSeed?: string;
  totpExposable?: boolean;
}

export interface CanarySet {
  username: string;
  password: string;
  totpSeed: string;
  wrongPassword: string;
}

/** The default mock catalog used by most tests. */
export function defaultEntries(c: CanarySet): MockEntry[] {
  return [
    {
      id: "site",
      name: "Acceptance Test Site",
      uri: "http://127.0.0.1",
      kind: "login",
      username: c.username,
      password: c.password,
      totpSeed: c.totpSeed,
      totpExposable: true,
    },
    {
      id: "site-badpass",
      name: "Acceptance Test Site (bad password)",
      uri: "http://127.0.0.1",
      kind: "login",
      username: c.username,
      password: c.wrongPassword,
    },
    {
      id: "site-no-totp",
      name: "Acceptance Test Site (TOTP not exposable)",
      uri: "http://127.0.0.1",
      kind: "login",
      username: c.username,
      password: c.password,
      totpSeed: c.totpSeed,
      totpExposable: false,
    },
  ];
}

function tomlString(s: string): string {
  return JSON.stringify(s); // TOML basic strings share JSON's escape rules here
}

/** Render the daemon TOML config. This shape is the pinned config contract. */
export function renderDaemonConfig(opts: {
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  allowedUids: number[];
  entries: MockEntry[];
}): string {
  const lines = [
    `socket_path = ${tomlString(opts.socketPath)}`,
    `state_dir = ${tomlString(opts.stateDir)}`,
    `audit_log_path = ${tomlString(opts.auditLogPath)}`,
    `allowed_uids = [${opts.allowedUids.join(", ")}]`,
    "",
    "[[providers]]",
    `namespace = "mock"`,
    `type = "mock"`,
  ];
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

async function waitFor(
  what: string,
  probe: () => Promise<boolean> | boolean,
  timeoutMs = 15_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probe()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function stopProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 3_000);
  await once(child, "exit").catch(() => {});
  clearTimeout(timer);
}

/** Raw JSON-RPC 2.0 over UDS: one request line, one response line. */
export async function rawRpc(
  socketPath: string,
  method: string,
  params: unknown,
): Promise<{ result?: unknown; error?: { code: number; message?: string } }> {
  const sock = net.connect(socketPath);
  await once(sock, "connect");
  sock.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })}\n`);
  const rl = readline.createInterface({ input: sock });
  try {
    for await (const line of rl) {
      return JSON.parse(line);
    }
    throw new Error("connection closed without a response");
  } finally {
    rl.close();
    sock.destroy();
  }
}

export interface TargetFixture {
  port: number;
  url: string;
  stop(): Promise<void>;
}

/**
 * Start the dummy login site. Credentials go in via stdin as one JSON line
 * (never argv/env, to keep ps/environ scan surfaces clean); the fixture
 * prints `{"port": N}` on stdout once listening.
 *
 * `totp_seed` (optional, Phase 3) switches the fixture into TOTP mode: the
 * login form gains an `input#totp` field and the server validates the posted
 * code against the seed (±1 time step). Without it, behaviour is unchanged.
 */
export async function startTargetFixture(creds: {
  username: string;
  password: string;
  totp_seed?: string;
}): Promise<TargetFixture> {
  const child = spawn("node", [bins().fixtureEntry, "--port", "0"], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  child.stdin.write(`${JSON.stringify(creds)}\n`);
  child.stdin.end();
  const rl = readline.createInterface({ input: child.stdout });
  const ready = new Promise<number>((resolve, reject) => {
    rl.once("line", (line) => {
      try {
        resolve(JSON.parse(line).port as number);
      } catch (err) {
        reject(err);
      }
    });
    child.once("exit", (code) =>
      reject(new Error(`target-fixture exited early (code ${code})`)),
    );
  });
  const timeout = setTimeout(() => child.kill("SIGKILL"), 15_000);
  const port = await ready;
  clearTimeout(timeout);
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    stop: () => stopProcess(child),
  };
}

export interface Daemon {
  socketPath: string;
  stateDir: string;
  /** Daemon-private directory. Excluded from agent-visible scan roots. */
  daemonDir: string;
  stop(): Promise<void>;
}

/** Start tegatad with a mock-provider config in a private temp directory. */
export async function startDaemon(entries: MockEntry[]): Promise<Daemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-"));
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir);
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    renderDaemonConfig({
      socketPath,
      stateDir,
      auditLogPath: path.join(stateDir, "audit.log"),
      allowedUids: [os.userInfo().uid],
      entries,
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
  await Promise.race([
    waitFor("tegatad socket", async () => {
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
  child.removeAllListeners("exit");
  return {
    socketPath,
    stateDir,
    daemonDir,
    stop: async () => {
      await stopProcess(child);
      fs.rmSync(daemonDir, { recursive: true, force: true });
    },
  };
}

export interface McpResult {
  isError: boolean;
  /** Concatenated text content. On error this is exactly the error code. */
  text: string;
  /** `JSON.parse(text)` when it parses, otherwise undefined. */
  json: unknown;
}

export interface McpSession {
  callTool(name: string, args: Record<string, unknown>): Promise<McpResult>;
  close(): Promise<void>;
}

/**
 * Connect an MCP client to the tegata-mcp server (stdio transport). The
 * server finds the daemon through env TEGATA_SOCKET. Every result is passed
 * to `observe` so the guard scans the complete agent-visible surface.
 */
export async function connectMcp(
  socketPath: string,
  observe?: (label: string, value: unknown) => void,
  extraEnv?: Record<string, string>,
): Promise<McpSession> {
  const transport = new StdioClientTransport({
    command: "node",
    args: [bins().mcpEntry],
    env: { ...process.env, TEGATA_SOCKET: socketPath, ...extraEnv } as Record<
      string,
      string
    >,
  });
  const client = new Client({ name: "acceptance", version: "0.0.0" });
  await client.connect(transport);
  return {
    async callTool(name, args) {
      const res = await client.callTool({ name, arguments: args });
      observe?.(`mcp:${name}`, res);
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
    close: () => client.close(),
  };
}

/** The standard placeholder login steps for the target fixture's form. */
export function fixtureSteps() {
  return {
    steps: [
      { action: "fill", selector: "#username", value: "{{username}}" },
      { action: "fill", selector: "#password", value: "{{password}}" },
      { action: "click", selector: "#submit" },
    ],
    success_selector: "#welcome",
    failure_selector: "#login-error",
  };
}

/** Recursively list files under a root (missing root: empty). */
export function listFiles(root: string): string[] {
  if (!fs.existsSync(root)) return [];
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.isFile()) out.push(p);
    }
  };
  walk(root);
  return out;
}

/** Browser artifact patterns that must never exist after a login. */
export const FORBIDDEN_ARTIFACTS =
  /(\.har|\.webm)$|trace.*\.zip$|screenshot.*\.png$/i;
