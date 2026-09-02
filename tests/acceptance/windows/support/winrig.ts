/**
 * Windows/WSL rig harness for the Phase 2 acceptance suite. Owned by the
 * acceptance suite (gauntlet); do not modify during implementation.
 *
 * These tests run INSIDE WSL on the test rig, against a tegatad Windows service
 * installed on the Windows host. The rig is set up
 * once by hand; see RIG.md next to this suite for prerequisites.
 *
 * Everything in this file is a pinned implementation contract:
 *
 *   - env vars and their defaults (rig layout, binaries, ports)
 *   - the transport: loopback TCP across the WSL boundary. (vsock was ruled
 *     out on the rig on 2026-08-28: Windows editions without the Hyper-V
 *     VMMS never consult GuestCommunicationServices, so a guest->host
 *     AF_HYPERV listener is unreachable from WSL.) The daemon listens on the
 *     Windows side of the WSL NAT — the vEthernet (WSL) gateway address —
 *     on `tcp_port`, firewalled to the WSL subnet at install time; in
 *     mirrored networking mode the listener binds 127.0.0.1 instead. From
 *     WSL the daemon is reached at the default-gateway IP (winHostAddr())
 *   - the preamble protocol on that TCP connection (line-delimited JSON):
 *       client first line  {"v":1,"auth":"<token>"}
 *                       or {"v":1,"auth":"<token>","tunnel":{"session_id":"...","port":N}}
 *       server on auth success (RPC mode): nothing; JSON-RPC lines follow,
 *         same wire format as the Phase 1 UDS transport
 *       server on tunnel success: one line {"ok":true}, then a raw byte splice
 *         to 127.0.0.1:N on the Windows side
 *       server on failure: one line {"ok":false,"error":"UNAUTHORIZED"} (bad or
 *         missing token) or {"ok":false,"error":"FORBIDDEN"} (tunnel target is
 *         not the CDP port of the named active session), then close
 *   - the tegata-bridge CLI:
 *       tegata-bridge --socket <path> --token-file <path> --daemon-addr <host:port>
 *     (--daemon-addr defaults to "<WSL default gateway>:21575" when omitted).
 *     It serves the daemon's JSON-RPC on the UNIX socket, plus one local
 *     method `bridge_open_tunnel {session_id, port}` -> {local_port}; preamble
 *     failures surface as a JSON-RPC error whose `message` is the preamble
 *     error code; an unreachable daemon surfaces as a JSON-RPC error whose
 *     `message` is one of the Phase 1 classification codes (nothing else)
 *   - the tegatad.exe Windows CLI:
 *       tegatad.exe status [--pipe <name>]   (exit 0, one-line JSON on stdout)
 *       tegatad.exe token issue              (admin RPC; non-elevated: exit != 0)
 *       tegatad.exe seal                     (reads the master password from
 *                                             stdin when stdin is not a TTY;
 *                                             non-elevated: exit != 0)
 *       tegatad.exe --config <win path> --foreground
 *                                            (no service context; prints one
 *                                             line {"ready":true} when listening)
 *   - the Windows config TOML shape (see renderWinDaemonConfig): `pipe_name`,
 *     `tcp_port` (0 disables the TCP listener), `allowed_sids`,
 *     `state_dir`, `audit_log_path`, and the Phase 1 `[[providers]]` shape
 *   - the on-disk layout under C:\ProgramData\tegata (PROTECTED_FILES)
 *   - MCP bridge mode: env TEGATA_BRIDGE=1 makes tegata-mcp rewrite the login
 *     endpoint through `bridge_open_tunnel` (TEGATA_SOCKET points at the
 *     bridge socket)
 */
import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { REPO_ROOT, rawRpc } from "../../support/harness.js";

/** Default daemon TCP port ("TG" in ASCII; TCP ports are 16-bit). */
export const DEFAULT_DAEMON_PORT = 0x5447;

/** Preamble-level error codes (transport layer, distinct from ERROR_CODES). */
export const PREAMBLE_ERRORS = ["UNAUTHORIZED", "FORBIDDEN"] as const;

/**
 * Files under the daemon's ProgramData directory that must be unreadable from
 * the agent side, expressed relative to TEGATA_WIN_PROGRAMDATA. This is the
 * pinned on-disk layout of the Windows service.
 */
export const PROTECTED_FILES = [
  "config.toml",
  "state/sealed.blob",
  "state/token_hash",
];

export interface RigEnv {
  bridgeBin: string;
  daemonPort: number;
  tokenFile: string;
  powershell: string;
  tegatadExe: string;
  /** WSL view of C:\ProgramData\tegata (via /mnt/c). */
  programData: string;
  serviceName: string;
  vaultPort: number;
  vaultEmail: string;
  masterPasswordFile: string;
  /** The throwaway vault's certificate (PEM); the service trusts it too. */
  vaultCert: string;
  /** The private key matching vaultCert (PEM, 0600). */
  vaultKey: string;
  provisionEntry: string;
}

export function rigEnv(): RigEnv {
  const home = os.homedir();
  const vaultTlsDir =
    process.env.TEGATA_TEST_VAULT_TLS_DIR ??
    path.join(home, ".config/tegata/test-vault-tls");
  return {
    bridgeBin:
      process.env.TEGATA_BRIDGE_BIN ??
      path.join(REPO_ROOT, "target/debug/tegata-bridge"),
    daemonPort: Number(process.env.TEGATA_DAEMON_PORT ?? DEFAULT_DAEMON_PORT),
    tokenFile:
      process.env.TEGATA_TOKEN_FILE ?? path.join(home, ".config/tegata/token"),
    powershell:
      process.env.TEGATA_POWERSHELL ??
      "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    tegatadExe:
      process.env.TEGATA_WIN_TEGATAD_EXE ??
      "/mnt/c/Program Files/tegata/tegatad.exe",
    programData:
      process.env.TEGATA_WIN_PROGRAMDATA ?? "/mnt/c/ProgramData/tegata",
    serviceName: process.env.TEGATA_WIN_SERVICE ?? "tegatad",
    vaultPort: Number(process.env.TEGATA_TEST_VAULT_PORT ?? 8087),
    vaultEmail: process.env.TEGATA_TEST_VAULT_EMAIL ?? "acceptance@test.local",
    masterPasswordFile:
      process.env.TEGATA_TEST_MASTER_PASSWORD_FILE ??
      path.join(home, ".config/tegata/test-master-password"),
    vaultCert: path.join(vaultTlsDir, "cert.pem"),
    vaultKey: path.join(vaultTlsDir, "key.pem"),
    provisionEntry:
      process.env.PROVISION_TEST_VAULT_ENTRY ??
      path.join(REPO_ROOT, "packages/provision-test-vault/dist/index.js"),
  };
}

/**
 * Fail fast (and descriptively) when this is not a configured rig. The suite
 * never skips: running it anywhere but the rig is an error, not a pass.
 */
export function requireRig(): RigEnv {
  const rig = rigEnv();
  const missing: string[] = [];
  if (!fs.existsSync("/mnt/c/Windows"))
    missing.push("/mnt/c/Windows (WSL automount towards the Windows host)");
  if (!fs.existsSync(rig.powershell))
    missing.push(`${rig.powershell} (TEGATA_POWERSHELL)`);
  if (!fs.existsSync(rig.tegatadExe))
    missing.push(`${rig.tegatadExe} (TEGATA_WIN_TEGATAD_EXE)`);
  if (!fs.existsSync(rig.tokenFile))
    missing.push(`${rig.tokenFile} (TEGATA_TOKEN_FILE)`);
  if (!fs.existsSync(rig.masterPasswordFile))
    missing.push(
      `${rig.masterPasswordFile} (TEGATA_TEST_MASTER_PASSWORD_FILE)`,
    );
  if (!fs.existsSync(rig.vaultCert))
    missing.push(`${rig.vaultCert} (TEGATA_TEST_VAULT_TLS_DIR)`);
  if (!fs.existsSync(rig.vaultKey))
    missing.push(`${rig.vaultKey} (TEGATA_TEST_VAULT_TLS_DIR)`);
  if (!fs.existsSync(rig.bridgeBin))
    missing.push(`${rig.bridgeBin} (TEGATA_BRIDGE_BIN)`);
  if (missing.length > 0) {
    throw new Error(
      `Windows rig not configured; see tests/acceptance/windows/RIG.md.\nMissing:\n  - ${missing.join("\n  - ")}`,
    );
  }
  return rig;
}

/**
 * The Windows-host address as seen from this WSL distro. In NAT mode that is
 * the default-gateway IP (the host side of the vEthernet (WSL) switch), which
 * is where the daemon's TCP listener is reachable. Override with
 * TEGATA_DAEMON_HOST (e.g. 127.0.0.1 on a mirrored-networking rig).
 */
export function winHostAddr(): string {
  const override = process.env.TEGATA_DAEMON_HOST;
  if (override) return override;
  const route = fs.readFileSync("/proc/net/route", "utf8");
  for (const line of route.split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    // Destination 00000000 marks the default route; the gateway field is
    // little-endian hex.
    if (cols.length >= 3 && cols[1] === "00000000" && cols[2] !== "00000000") {
      return [6, 4, 2, 0]
        .map((i) => Number.parseInt(cols[2].slice(i, i + 2), 16))
        .join(".");
    }
  }
  throw new Error(
    "no default route in /proc/net/route (NAT-mode WSL expected); set TEGATA_DAEMON_HOST",
  );
}

/** Convert a Windows path (C:\...) to its WSL /mnt view. */
export function winToWsl(winPath: string): string {
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(winPath.trim());
  if (!m) throw new Error(`not an absolute Windows path: ${winPath}`);
  return `/mnt/${m[1].toLowerCase()}/${m[2].replaceAll("\\", "/")}`;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function collect(
  child: ChildProcess,
  stdin?: string,
): Promise<ExecResult> {
  let stdout = "";
  let stderr = "";
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (d: string) => {
    stdout += d;
  });
  child.stderr?.on("data", (d: string) => {
    stderr += d;
  });
  if (child.stdin) {
    if (stdin !== undefined) child.stdin.write(stdin);
    child.stdin.end();
  }
  const [code] = (await once(child, "exit")) as [number | null];
  return { code: code ?? -1, stdout, stderr };
}

/** Run a PowerShell command on the Windows host through WSL interop. */
export async function psRun(
  command: string,
  stdin?: string,
): Promise<ExecResult> {
  const rig = rigEnv();
  const child = spawn(
    rig.powershell,
    ["-NoProfile", "-NonInteractive", "-Command", command],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  return collect(child, stdin);
}

/** Run a Windows executable directly through WSL interop. */
export async function winExec(
  exe: string,
  args: string[],
  stdin?: string,
): Promise<ExecResult> {
  const child = spawn(exe, args, { stdio: ["pipe", "pipe", "pipe"] });
  return collect(child, stdin);
}

/** The interop user's %TEMP%, as a WSL path. */
export async function winAgentTempWsl(): Promise<string> {
  const res = await psRun("$env:TEMP");
  if (res.code !== 0 || res.stdout.trim() === "")
    throw new Error(`cannot resolve %TEMP% via interop: ${res.stderr}`);
  return winToWsl(res.stdout.trim());
}

/** The interop user's SID (the SID every WSL interop process runs under). */
export async function currentWindowsSid(): Promise<string> {
  const res = await psRun(
    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
  );
  if (res.code !== 0 || !/^S-1-/.test(res.stdout.trim()))
    throw new Error(`cannot resolve the current Windows SID: ${res.stderr}`);
  return res.stdout.trim();
}

async function serviceStatus(): Promise<string> {
  const rig = rigEnv();
  const res = await psRun(`(Get-Service -Name '${rig.serviceName}').Status`);
  if (res.code !== 0)
    throw new Error(`Get-Service failed: ${res.stderr || res.stdout}`);
  return res.stdout.trim();
}

async function waitFor(
  what: string,
  probe: () => Promise<boolean>,
  timeoutMs = 30_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probe()) return;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`timed out waiting for ${what}`);
}

/**
 * Service start/stop go through the operator grant made at install time
 * (`operator_sid`); they must not require elevation.
 */
export async function stopService(): Promise<void> {
  const rig = rigEnv();
  const res = await psRun(`Stop-Service -Name '${rig.serviceName}'`);
  if (res.code !== 0) throw new Error(`Stop-Service failed: ${res.stderr}`);
  await waitFor(
    "service to stop",
    async () => (await serviceStatus()) === "Stopped",
  );
}

export async function startService(): Promise<void> {
  const rig = rigEnv();
  const res = await psRun(`Start-Service -Name '${rig.serviceName}'`);
  if (res.code !== 0) throw new Error(`Start-Service failed: ${res.stderr}`);
  await waitFor(
    "service to start",
    async () => (await serviceStatus()) === "Running",
  );
}

export async function restartService(): Promise<void> {
  const rig = rigEnv();
  const res = await psRun(`Restart-Service -Name '${rig.serviceName}'`);
  if (res.code !== 0) throw new Error(`Restart-Service failed: ${res.stderr}`);
  await waitFor(
    "service to restart",
    async () => (await serviceStatus()) === "Running",
  );
}

export async function ensureServiceRunning(): Promise<void> {
  if ((await serviceStatus()) !== "Running") await startService();
}

export interface Bridge {
  socketPath: string;
  stop(): Promise<void>;
}

async function stopProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 3_000);
  await once(child, "exit").catch(() => {});
  clearTimeout(timer);
}

/** Start tegata-bridge on a fresh UNIX socket in a private temp directory. */
export async function startBridge(opts?: {
  tokenFile?: string;
}): Promise<Bridge> {
  const rig = rigEnv();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-bridge-"));
  const socketPath = path.join(dir, "bridge.sock");
  const child = spawn(
    rig.bridgeBin,
    [
      "--socket",
      socketPath,
      "--token-file",
      opts?.tokenFile ?? rig.tokenFile,
      "--daemon-addr",
      `${winHostAddr()}:${rig.daemonPort}`,
    ],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  const exited = new Promise<never>((_, reject) => {
    child.once("exit", (code) =>
      reject(new Error(`tegata-bridge exited early (code ${code})`)),
    );
  });
  await Promise.race([
    waitFor("bridge socket", async () => {
      if (!fs.existsSync(socketPath)) return false;
      return new Promise<boolean>((resolve) => {
        const sock = net.connect(socketPath);
        sock.once("connect", () => {
          sock.destroy();
          resolve(true);
        });
        sock.once("error", () => resolve(false));
      });
    }),
    exited,
  ]);
  child.removeAllListeners("exit");
  return {
    socketPath,
    stop: async () => {
      await stopProcess(child);
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

export interface DaemonExchange {
  /** Every line the server sent before closing, in order. */
  lines: string[];
  /** True when the server closed the connection. */
  closed: boolean;
}

/**
 * Talk to the daemon's TCP listener directly (bypassing the bridge), sending
 * raw preamble/RPC lines. Used to probe the preamble protocol itself.
 */
export async function daemonExchange(
  inputLines: string[],
  timeoutMs = 10_000,
): Promise<DaemonExchange> {
  const rig = rigEnv();
  const sock = net.connect(rig.daemonPort, winHostAddr());
  const rl = readline.createInterface({ input: sock });
  const lines: string[] = [];
  rl.on("line", (l) => lines.push(l));
  const timer = setTimeout(
    () => sock.destroy(new Error("daemonExchange timed out")),
    timeoutMs,
  );
  try {
    await once(sock, "connect");
    sock.write(`${inputLines.join("\n")}\n`);
    await once(sock, "close");
  } finally {
    clearTimeout(timer);
  }
  return { lines, closed: true };
}

export interface TestVault {
  port: number;
  stop(): Promise<void>;
}

/** Probe the throwaway vault over TLS, trusting only the rig certificate. */
function vaultAlive(rig: RigEnv): Promise<boolean> {
  return new Promise((resolve) => {
    const req = https.request(
      {
        host: "127.0.0.1",
        port: rig.vaultPort,
        path: "/alive",
        ca: fs.readFileSync(rig.vaultCert),
      },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.once("error", () => resolve(false));
    req.end();
  });
}

/**
 * Start a throwaway vaultwarden inside WSL on the FIXED rig port, serving TLS
 * with the rig certificate (bw refuses plain-http servers since 2025.10). The
 * Windows service's provider config points at https://localhost:<port>, which
 * reaches this instance through WSL localhost forwarding; the service trusts
 * the same certificate through NODE_EXTRA_CA_CERTS.
 */
export async function startVaultwarden(): Promise<TestVault> {
  const rig = rigEnv();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-vw-"));
  const child = spawn("vaultwarden", [], {
    env: {
      ...process.env,
      ROCKET_ADDRESS: "127.0.0.1",
      ROCKET_PORT: String(rig.vaultPort),
      ROCKET_TLS: `{certs="${rig.vaultCert}",key="${rig.vaultKey}"}`,
      SIGNUPS_ALLOWED: "true",
      WEB_VAULT_ENABLED: "false",
      DATA_FOLDER: dataDir,
      DOMAIN: `https://localhost:${rig.vaultPort}`,
    },
    stdio: ["ignore", "ignore", "inherit"],
  });
  const exited = new Promise<never>((_, reject) => {
    child.once("exit", (code) =>
      reject(new Error(`vaultwarden exited early (code ${code})`)),
    );
  });
  await Promise.race([waitFor("vaultwarden", () => vaultAlive(rig)), exited]);
  child.removeAllListeners("exit");
  return {
    port: rig.vaultPort,
    stop: async () => {
      await stopProcess(child);
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export interface VaultItem {
  name: string;
  uri: string;
  username: string;
  password: string;
  totp_seed?: string;
}

/**
 * Provision the rig account (fixed email + the sealed master password) and
 * the given items into the running vaultwarden.
 */
export async function provisionVault(items: VaultItem[]): Promise<void> {
  const rig = rigEnv();
  const masterPassword = fs.readFileSync(rig.masterPasswordFile, "utf8").trim();
  const child = spawn(
    "node",
    [
      rig.provisionEntry,
      "--server",
      `https://127.0.0.1:${rig.vaultPort}`,
      "--email",
      rig.vaultEmail,
      "--password",
      masterPassword,
    ],
    {
      // The provisioning tool is a node program; it trusts the rig
      // certificate the same way the service's bw does.
      env: { ...process.env, NODE_EXTRA_CA_CERTS: rig.vaultCert },
      stdio: ["pipe", "inherit", "inherit"],
    },
  );
  child.stdin.write(JSON.stringify(items));
  child.stdin.end();
  const [code] = (await once(child, "exit")) as [number | null];
  if (code !== 0) throw new Error(`provision-test-vault failed (code ${code})`);
}

function tomlString(s: string): string {
  return JSON.stringify(s);
}

/**
 * Render a Windows daemon config for a throwaway foreground instance. This
 * shape is the pinned Windows config contract (`tcp_port = 0` disables the
 * TCP listener; `allowed_sids` gates the named pipe's normal RPC surface).
 */
export function renderWinDaemonConfig(opts: {
  pipeName: string;
  stateDirWin: string;
  auditLogPathWin: string;
  allowedSids: string[];
}): string {
  return `${[
    `pipe_name = ${tomlString(opts.pipeName)}`,
    "tcp_port = 0",
    `state_dir = ${tomlString(opts.stateDirWin)}`,
    `audit_log_path = ${tomlString(opts.auditLogPathWin)}`,
    `allowed_sids = [${opts.allowedSids.map(tomlString).join(", ")}]`,
  ].join("\n")}\n`;
}

export interface ForegroundDaemon {
  pipeName: string;
  stop(): Promise<void>;
}

/**
 * Run tegatad.exe as a plain foreground process (no service context) with a
 * throwaway config, for pipe-gate tests. The process and its config live in
 * the interop user's %TEMP%, which the harness can write through /mnt/c.
 */
export async function startForegroundDaemon(opts: {
  allowedSids: string[];
}): Promise<ForegroundDaemon> {
  const rig = rigEnv();
  const tempWsl = await winAgentTempWsl();
  const id = Math.random().toString(16).slice(2, 10);
  const dirWsl = path.join(tempWsl, `tegata-ac-${id}`);
  fs.mkdirSync(path.join(dirWsl, "state"), { recursive: true });
  const tempWinRes = await psRun("$env:TEMP");
  const dirWin = `${tempWinRes.stdout.trim()}\\tegata-ac-${id}`;
  const pipeName = `tegata-ac-${id}`;
  fs.writeFileSync(
    path.join(dirWsl, "config.toml"),
    renderWinDaemonConfig({
      pipeName,
      stateDirWin: `${dirWin}\\state`,
      auditLogPathWin: `${dirWin}\\state\\audit.log`,
      allowedSids: opts.allowedSids,
    }),
  );
  const child = spawn(
    rig.tegatadExe,
    ["--config", `${dirWin}\\config.toml`, "--foreground"],
    { stdio: ["ignore", "pipe", "inherit"] },
  );
  const rl = readline.createInterface({ input: child.stdout });
  const ready = new Promise<void>((resolve, reject) => {
    rl.on("line", (line) => {
      try {
        if (JSON.parse(line).ready === true) resolve();
      } catch {
        // ignore non-JSON noise
      }
    });
    child.once("exit", (code) =>
      reject(new Error(`foreground tegatad exited early (code ${code})`)),
    );
  });
  const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
  await ready;
  clearTimeout(timer);
  child.removeAllListeners("exit");
  return {
    pipeName,
    stop: async () => {
      await stopProcess(child);
      fs.rmSync(dirWsl, { recursive: true, force: true });
    },
  };
}

/** JSON-RPC to the daemon through a bridge socket (same wire as Phase 1). */
export function bridgeRpc(
  socketPath: string,
  method: string,
  params: unknown,
): ReturnType<typeof rawRpc> {
  return rawRpc(socketPath, method, params);
}

/** The WMI process command-line sampler used as an extra leak-guard surface. */
export function wmiPsSampleCommand(): string[] {
  const rig = rigEnv();
  return [
    rig.powershell,
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-CimInstance Win32_Process | Select-Object -ExpandProperty CommandLine",
  ];
}
