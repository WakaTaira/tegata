/**
 * Phase 4a Windows/WSL rig support. Owned by the acceptance suite (gauntlet);
 * do not modify during implementation.
 *
 * Everything in this file is a pinned implementation contract:
 *   - the Windows config keeps accepting the legacy transport keys
 *     (`pipe_name`, `tcp_port`, `tcp_bind`, `allowed_sids`,
 *     `token_hash_path`); `tcp_bind = "127.0.0.1"` binds plain loopback
 *   - legacy token import: an existing `token_hash_path` file (sha256 hex of
 *     the token followed by a newline) is imported at start-up into
 *     `<state_dir>\peers.json` — a JSON array of
 *     `{peer_id, label, token_sha256, issued_at, revoked_at}` — as
 *     `peer_id = "legacy"`, `label = "legacy"`, and the old file is renamed
 *     `<name>.imported`
 *   - the named pipe speaks the same line-delimited JSON-RPC as the UNIX
 *     socket, and a pipe caller is the principal `sid:<SID>`
 *   - env TEGATA_WIN_PIPE names the service's pipe (default: the service name)
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { psRun, rigEnv, winAgentTempWsl } from "./winrig.js";

function tomlString(s: string): string {
  return JSON.stringify(s);
}

/** Single-quote a string for PowerShell (doubling embedded quotes). */
function psQuote(s: string): string {
  return `'${s.replaceAll("'", "''")}'`;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** The rig service's pipe name (TEGATA_WIN_PIPE, default = service name). */
export function rigPipeName(): string {
  return process.env.TEGATA_WIN_PIPE ?? rigEnv().serviceName;
}

/**
 * Render a Windows daemon config for a throwaway foreground instance with a
 * loopback TCP listener and an explicit legacy token hash file. Legacy key
 * shape on purpose: this is the upgrade path the import contract covers.
 */
export function renderWinPhase4Config(opts: {
  pipeName: string;
  tcpPort: number;
  stateDirWin: string;
  auditLogPathWin: string;
  tokenHashPathWin: string;
  allowedSids: string[];
}): string {
  return `${[
    `pipe_name = ${tomlString(opts.pipeName)}`,
    `tcp_port = ${opts.tcpPort}`,
    `tcp_bind = "127.0.0.1"`,
    `token_hash_path = ${tomlString(opts.tokenHashPathWin)}`,
    `state_dir = ${tomlString(opts.stateDirWin)}`,
    `audit_log_path = ${tomlString(opts.auditLogPathWin)}`,
    `allowed_sids = [${opts.allowedSids.map(tomlString).join(", ")}]`,
  ].join("\n")}\n`;
}

export interface ForegroundPhase4Daemon {
  pipeName: string;
  tcpPort: number;
  /** WSL view of the daemon directory (config + state). */
  dirWsl: string;
  /** WSL view of the state directory (peers.json, audit.log, token files). */
  stateDirWsl: string;
  stop(): Promise<void>;
}

/**
 * Run tegatad.exe in the foreground with a legacy `token_hash` file already
 * in place, a loopback TCP listener on a random high port, and the pipe
 * gated to `allowedSids`. Files live in the interop user's %TEMP%, which the
 * harness can read and write through /mnt/c.
 */
export async function startForegroundPhase4Daemon(opts: {
  allowedSids: string[];
  legacyToken: string;
}): Promise<ForegroundPhase4Daemon> {
  const rig = rigEnv();
  const tempWsl = await winAgentTempWsl();
  const id = Math.random().toString(16).slice(2, 10);
  const dirWsl = path.join(tempWsl, `tegata-p4-${id}`);
  const stateDirWsl = path.join(dirWsl, "state");
  fs.mkdirSync(stateDirWsl, { recursive: true });
  const tempWinRes = await psRun("$env:TEMP");
  const dirWin = `${tempWinRes.stdout.trim()}\\tegata-p4-${id}`;
  const pipeName = `tegata-p4-${id}`;
  const tcpPort = 20_000 + Math.floor(Math.random() * 20_000);
  fs.writeFileSync(
    path.join(stateDirWsl, "token_hash"),
    `${sha256Hex(opts.legacyToken)}\n`,
  );
  fs.writeFileSync(
    path.join(dirWsl, "config.toml"),
    renderWinPhase4Config({
      pipeName,
      tcpPort,
      stateDirWin: `${dirWin}\\state`,
      auditLogPathWin: `${dirWin}\\state\\audit.log`,
      tokenHashPathWin: `${dirWin}\\state\\token_hash`,
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
    tcpPort,
    dirWsl,
    stateDirWsl,
    stop: async () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGTERM");
        const killTimer = setTimeout(() => child.kill("SIGKILL"), 3_000);
        await new Promise<void>((resolve) =>
          child.once("exit", () => resolve()),
        );
        clearTimeout(killTimer);
      }
      fs.rmSync(dirWsl, { recursive: true, force: true });
    },
  };
}

/**
 * Send raw lines to a Windows-side loopback TCP port and collect every line
 * the server writes back, using a PowerShell TcpClient on the Windows host
 * (WSL cannot reach the host's 127.0.0.1 directly). Reading stops when the
 * server closes the connection or stays quiet for `readTimeoutMs`.
 */
export async function winLoopbackExchange(
  port: number,
  lines: string[],
  readTimeoutMs = 5_000,
): Promise<string[]> {
  const script = [
    `$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', ${port})`,
    "$s = $c.GetStream()",
    `$s.ReadTimeout = ${readTimeoutMs}`,
    "$w = New-Object System.IO.StreamWriter($s)",
    "$w.NewLine = [string][char]10",
    "$w.AutoFlush = $true",
    ...lines.map((l) => `$w.WriteLine(${psQuote(l)})`),
    "$r = New-Object System.IO.StreamReader($s)",
    "try { while ($true) { $line = $r.ReadLine(); if ($null -eq $line) { break }; Write-Output $line } } catch { }",
    "$c.Dispose()",
  ].join("; ");
  const res = await psRun(script);
  if (res.code !== 0)
    throw new Error(`loopback exchange failed: ${res.stderr || res.stdout}`);
  return res.stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

/**
 * One JSON-RPC call over the daemon's named pipe from the interop user's
 * SID, via a PowerShell NamedPipeClientStream. Blocks until the daemon
 * answers (a login can take a minute on the rig).
 */
export async function pipeRpc(
  pipeName: string,
  method: string,
  params: unknown,
): Promise<{ result?: unknown; error?: { code: number; message?: string } }> {
  const request = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const script = [
    `$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', ${psQuote(pipeName)}, [System.IO.Pipes.PipeDirection]::InOut)`,
    "$c.Connect(5000)",
    "$w = New-Object System.IO.StreamWriter($c)",
    "$w.NewLine = [string][char]10",
    "$w.AutoFlush = $true",
    `$w.WriteLine(${psQuote(request)})`,
    "$r = New-Object System.IO.StreamReader($c)",
    "$line = $r.ReadLine()",
    "$c.Dispose()",
    "Write-Output $line",
  ].join("; ");
  const res = await psRun(script);
  if (res.code !== 0)
    throw new Error(`pipe rpc failed: ${res.stderr || res.stdout}`);
  const line = res.stdout
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l.startsWith("{"));
  if (line === undefined) throw new Error("pipe rpc: no JSON response line");
  return JSON.parse(line);
}

/** Parse the foreground daemon's audit log (readable: it lives in %TEMP%). */
export function readForegroundAudit(
  stateDirWsl: string,
): Array<Record<string, unknown>> {
  const file = path.join(stateDirWsl, "audit.log");
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}
