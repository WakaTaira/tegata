/**
 * Phase 3 acceptance-test support. Owned by the acceptance suite (gauntlet);
 * do not modify during implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - the Phase 3 daemon TOML config keys: top-level `session_ttl_secs`,
 *     `approve_cmd`, `approve_timeout_secs`, `audit_log_max_bytes`
 *   - the `age-file` provider shape: `type = "age-file"`, `entries_path`
 *     (age-encrypted TOML of [[entries]] in the mock-entry field shape),
 *     `identity_path` (X25519 identity file, mode 0600), optional
 *     `session_ttl_secs`
 *   - the `pass` provider shape: `type = "pass"`, `store_dir`, optional
 *     `gnupghome`, optional `pass_bin`, `totp_exposable` (list of entry
 *     names), optional `session_ttl_secs`
 *   - the pass entry text format: first line is the password; `username:` or
 *     `login:` lines carry the username; `url:` carries the uri; a line
 *     containing an otpauth:// URI carries the TOTP seed in its `secret`
 *     query parameter
 *   - the audit rotation contract: when `audit_log_max_bytes` is exceeded the
 *     current file is renamed to `<path>.1` (single generation)
 *   - the audit record fields added in Phase 3: `session_id`, `namespace`,
 *     the daemon-originated events `session_expired` / `vault_autolocked` /
 *     `session_terminated`, and the `"peer_system":true` peer marker
 *   - the HITL approval env contract: `TEGATA_CRED_ID`, `TEGATA_TARGET_URL`,
 *     `TEGATA_PEER` (unix: decimal uid) — and never any secret value
 */
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard, type LeakGuard } from "@tegata/leak-guard";
import {
  bins,
  type CanarySet,
  connectMcp,
  type Daemon,
  type McpSession,
  type MockEntry,
  rawRpc,
  startTargetFixture,
  type TargetFixture,
} from "./harness.js";

function tomlString(s: string): string {
  return JSON.stringify(s);
}

export interface MockProviderSpec {
  type: "mock";
  namespace: string;
  entries: MockEntry[];
}

export interface AgeProviderSpec {
  type: "age-file";
  namespace: string;
  entriesPath: string;
  identityPath: string;
  sessionTtlSecs?: number;
}

export interface PassProviderSpec {
  type: "pass";
  namespace: string;
  storeDir: string;
  gnupgHome?: string;
  totpExposable?: string[];
  sessionTtlSecs?: number;
}

export type ProviderSpec =
  | MockProviderSpec
  | AgeProviderSpec
  | PassProviderSpec;

export interface Phase3ConfigOptions {
  socketPath: string;
  stateDir: string;
  auditLogPath: string;
  allowedUids: number[];
  sessionTtlSecs?: number;
  approveCmd?: string;
  approveTimeoutSecs?: number;
  auditLogMaxBytes?: number;
  providers: ProviderSpec[];
}

/** Render the Phase 3 daemon TOML config. This shape is a pinned contract. */
export function renderPhase3Config(opts: Phase3ConfigOptions): string {
  const lines = [
    `socket_path = ${tomlString(opts.socketPath)}`,
    `state_dir = ${tomlString(opts.stateDir)}`,
    `audit_log_path = ${tomlString(opts.auditLogPath)}`,
    `allowed_uids = [${opts.allowedUids.join(", ")}]`,
  ];
  if (opts.sessionTtlSecs !== undefined)
    lines.push(`session_ttl_secs = ${opts.sessionTtlSecs}`);
  if (opts.approveCmd !== undefined)
    lines.push(`approve_cmd = ${tomlString(opts.approveCmd)}`);
  if (opts.approveTimeoutSecs !== undefined)
    lines.push(`approve_timeout_secs = ${opts.approveTimeoutSecs}`);
  if (opts.auditLogMaxBytes !== undefined)
    lines.push(`audit_log_max_bytes = ${opts.auditLogMaxBytes}`);
  for (const p of opts.providers) {
    lines.push("", "[[providers]]", `namespace = ${tomlString(p.namespace)}`);
    if (p.type === "mock") {
      lines.push(`type = "mock"`);
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
    } else if (p.type === "age-file") {
      lines.push(
        `type = "age-file"`,
        `entries_path = ${tomlString(p.entriesPath)}`,
        `identity_path = ${tomlString(p.identityPath)}`,
      );
      if (p.sessionTtlSecs !== undefined)
        lines.push(`session_ttl_secs = ${p.sessionTtlSecs}`);
    } else {
      lines.push(`type = "pass"`, `store_dir = ${tomlString(p.storeDir)}`);
      if (p.gnupgHome !== undefined)
        lines.push(`gnupghome = ${tomlString(p.gnupgHome)}`);
      if (p.totpExposable !== undefined)
        lines.push(
          `totp_exposable = [${p.totpExposable.map(tomlString).join(", ")}]`,
        );
      if (p.sessionTtlSecs !== undefined)
        lines.push(`session_ttl_secs = ${p.sessionTtlSecs}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

export interface Phase3Daemon extends Daemon {
  auditLogPath: string;
}

/** Start tegatad with a Phase 3 config in a private temp directory. */
export async function startPhase3Daemon(
  opts: Omit<
    Phase3ConfigOptions,
    "socketPath" | "stateDir" | "auditLogPath" | "allowedUids"
  >,
): Promise<Phase3Daemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-p3-"));
  const socketPath = path.join(daemonDir, "tegatad.sock");
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const auditLogPath = path.join(stateDir, "audit.log");
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    renderPhase3Config({
      socketPath,
      stateDir,
      auditLogPath,
      allowedUids: [os.userInfo().uid],
      ...opts,
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
  return {
    socketPath,
    stateDir,
    daemonDir,
    auditLogPath,
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

export interface AuditRecord {
  ts: string;
  method: string;
  outcome: string;
  cred_id: string | null;
  target_url: string | null;
  session_id?: string | null;
  namespace?: string | null;
  peer_uid?: number;
  peer_system?: boolean;
  [key: string]: unknown;
}

/**
 * Read every audit record for a daemon, oldest first, including the single
 * rotated generation `<path>.1` when it exists.
 */
export function readAuditRecords(auditLogPath: string): {
  records: AuditRecord[];
  rotatedExists: boolean;
} {
  const records: AuditRecord[] = [];
  const rotated = `${auditLogPath}.1`;
  const rotatedExists = fs.existsSync(rotated);
  for (const file of [rotated, auditLogPath]) {
    if (!fs.existsSync(file)) continue;
    for (const line of fs.readFileSync(file, "utf8").split("\n")) {
      if (line.trim() === "") continue;
      records.push(JSON.parse(line) as AuditRecord);
    }
  }
  return { records, rotatedExists };
}

/** Poll until the probe passes; throw on timeout. */
export async function waitUntil(
  what: string,
  probe: () => Promise<boolean> | boolean,
  timeoutMs = 15_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probe()) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`timed out waiting for ${what}`);
}

function run(
  cmd: string,
  args: string[],
  opts?: { input?: string; env?: Record<string, string> },
): string {
  const res = spawnSync(cmd, args, {
    input: opts?.input,
    env: { ...process.env, ...opts?.env },
    encoding: "utf8",
  });
  if (res.error) throw res.error;
  if (res.status !== 0)
    throw new Error(
      `${cmd} ${args.join(" ")} failed (${res.status}): ${res.stderr}`,
    );
  return res.stdout;
}

export interface AgeKeypair {
  identityPath: string;
  recipient: string;
}

/** Generate an age X25519 identity file (mode 0600) and its recipient. */
export function ageKeygen(dir: string): AgeKeypair {
  const identityPath = path.join(dir, "identity.txt");
  const out = run("age-keygen", ["-o", identityPath]);
  fs.chmodSync(identityPath, 0o600);
  const fileText = fs.readFileSync(identityPath, "utf8");
  const m =
    /public key: (age1[a-z0-9]+)/.exec(fileText) ?? /(age1[a-z0-9]+)/.exec(out);
  if (!m) throw new Error("age-keygen output carried no public key");
  return { identityPath, recipient: m[1] };
}

/** Render the age-file provider's plaintext entries TOML. */
export function renderAgeEntriesToml(entries: MockEntry[]): string {
  const lines: string[] = [];
  for (const e of entries) {
    lines.push(
      "[[entries]]",
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
    lines.push("");
  }
  return lines.join("\n");
}

/** Encrypt plaintext to a recipient with the age CLI. */
export function ageEncrypt(
  recipient: string,
  plaintext: string,
  outPath: string,
): void {
  run("age", ["-r", recipient, "-o", outPath], { input: plaintext });
}

/** Create a throwaway GNUPGHOME with one passphrase-less key; return it. */
export function makeGpgHome(dir: string): {
  gnupgHome: string;
  fingerprint: string;
} {
  const gnupgHome = path.join(dir, "gnupg");
  fs.mkdirSync(gnupgHome, { mode: 0o700 });
  const env = { GNUPGHOME: gnupgHome };
  run(
    "gpg",
    [
      "--batch",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      "",
      "--quick-generate-key",
      "Tegata Acceptance <acceptance@test.local>",
      "default",
      "default",
      "never",
    ],
    { env },
  );
  const colons = run("gpg", ["--list-secret-keys", "--with-colons"], { env });
  const fpr = colons
    .split("\n")
    .find((l) => l.startsWith("fpr:"))
    ?.split(":")[9];
  if (!fpr) throw new Error("gpg reported no secret key fingerprint");
  return { gnupgHome, fingerprint: fpr };
}

export interface PassEntry {
  name: string;
  password: string;
  username?: string;
  url?: string;
  /** TOTP seed; provisioned as an otpauth:// line in the entry body. */
  totpSeed?: string;
}

export interface Phase3Stack {
  guard: LeakGuard;
  canaries: CanarySet;
  daemon: Phase3Daemon;
  fixture: TargetFixture;
  mcp: McpSession;
  /** Agent-visible scratch dir; part of the guard's scan roots. */
  agentDir: string;
  /** Daemon-side provider material (age files, pass store). Not scanned. */
  materialsDir: string;
}

/**
 * Full-stack composition for the Phase 3 suite: leak guard + a daemon built
 * from caller-supplied provider specs + target fixture + MCP session, torn
 * down (and leak-checked) in reverse order via `stopPhase3Stack`.
 *
 * `makeProviders` runs after the canaries exist and receives a private
 * materials directory for provider fixtures (encrypted entry files, pass
 * stores). That directory lives on the daemon side of the boundary and is
 * excluded from the guard's scan roots.
 */
export async function startPhase3Stack(opts: {
  top?: {
    sessionTtlSecs?: number;
    approveCmd?: string;
    approveTimeoutSecs?: number;
    auditLogMaxBytes?: number;
  };
  makeProviders: (
    canaries: CanarySet,
    materialsDir: string,
  ) => ProviderSpec[] | Promise<ProviderSpec[]>;
  withFixture?: boolean;
}): Promise<Phase3Stack> {
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
  let daemon: Phase3Daemon | undefined;
  let fixture: TargetFixture | undefined;
  let mcp: McpSession | undefined;
  try {
    const providers = await opts.makeProviders(canaries, materialsDir);
    daemon = await startPhase3Daemon({
      providers,
      sessionTtlSecs: opts.top?.sessionTtlSecs,
      approveCmd: opts.top?.approveCmd,
      approveTimeoutSecs: opts.top?.approveTimeoutSecs,
      auditLogMaxBytes: opts.top?.auditLogMaxBytes,
    });
    fixture =
      opts.withFixture === false
        ? ({
            port: 0,
            url: "http://127.0.0.1:0",
            stop: async () => {},
          } as TargetFixture)
        : await startTargetFixture({
            username: canaries.username,
            password: canaries.password,
          });
    mcp = await connectMcp(daemon.socketPath, (label, value) =>
      guard.observe(label, value),
    );
    return { guard, canaries, daemon, fixture, mcp, agentDir, materialsDir };
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
export async function stopPhase3Stack(stack: Phase3Stack): Promise<void> {
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

/** Initialize a pass store and provision entries via the pass CLI. */
export function makePassStore(
  dir: string,
  gnupgHome: string,
  fingerprint: string,
  entries: PassEntry[],
): string {
  const storeDir = path.join(dir, "password-store");
  const env = { PASSWORD_STORE_DIR: storeDir, GNUPGHOME: gnupgHome };
  run("pass", ["init", fingerprint], { env });
  for (const e of entries) {
    const body = [e.password];
    if (e.username !== undefined) body.push(`username: ${e.username}`);
    if (e.url !== undefined) body.push(`url: ${e.url}`);
    if (e.totpSeed !== undefined)
      body.push(`otpauth://totp/acceptance?secret=${e.totpSeed}&issuer=tegata`);
    run("pass", ["insert", "-m", e.name], {
      env,
      input: `${body.join("\n")}\n`,
    });
  }
  return storeDir;
}
