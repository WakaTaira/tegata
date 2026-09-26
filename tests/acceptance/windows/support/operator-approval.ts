import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import {
  startTargetFixture,
  type TargetFixture,
} from "../../support/harness.js";
import { pipeRpc, sha256Hex } from "./phase4.js";
import {
  provisionVault,
  psRun,
  rigEnv,
  startVaultwarden,
  type TestVault,
  winAgentTempWsl,
} from "./winrig.js";

/** The item provisioned into the throwaway vault for the approval tests. */
export const APPROVAL_ITEM_NAME = "Acceptance Approval Site";

/**
 * Namespace of the foreground daemon's provider. Independent of the rig
 * service's config: these tests never go through the service.
 */
const APPROVAL_NAMESPACE = "vw";

export interface ApprovalVault {
  fixture: TargetFixture;
  stop(): Promise<void>;
}

/**
 * The throwaway vaultwarden (rig port, rig TLS certificate, rig account) with
 * one login item for the target fixture. Throwaway values only: a login in
 * these tests never gets past the approval gate, so nothing is filled.
 */
export async function startApprovalVault(): Promise<ApprovalVault> {
  const creds = { username: "approval-user", password: "approval-pass" };
  let vault: TestVault | undefined;
  let fixture: TargetFixture | undefined;
  try {
    vault = await startVaultwarden();
    fixture = await startTargetFixture(creds);
    await provisionVault([
      { name: APPROVAL_ITEM_NAME, uri: fixture.url, ...creds },
    ]);
  } catch (error) {
    await fixture?.stop().catch(() => {});
    await vault?.stop().catch(() => {});
    throw error;
  }
  const started = { vault, fixture };
  return {
    fixture: started.fixture,
    stop: async () => {
      await started.fixture.stop().catch(() => {});
      await started.vault.stop();
    },
  };
}

export interface ApprovalDaemon {
  pipeName: string;
  stateDirWsl: string;
  stderr(): string;
  /**
   * The namespaced id of the provisioned item, via `list_credentials` over the
   * pipe. The first call pays the provider's cold start (bw login and sync).
   */
  credId(): Promise<string>;
  /** Resolve with the first stderr match of `pattern`, or reject on timeout. */
  waitForStderr(pattern: RegExp, timeoutMs: number): Promise<RegExpExecArray>;
  stop(): Promise<void>;
}

/** Single-quote a string for PowerShell (doubling embedded quotes). */
function psQuote(s: string): string {
  return `'${s.replaceAll("'", "''")}'`;
}

/**
 * The directory of the rig service's installed binary. The rig installs its
 * bw.exe next to tegatad.exe there; the foreground daemon borrows that bw.exe
 * (read-only), whichever tegatad.exe is under test.
 */
async function rigServiceDirWin(): Promise<string> {
  const rig = rigEnv();
  const res = await psRun(
    `(Get-CimInstance Win32_Service | Where-Object Name -eq ${psQuote(rig.serviceName)}).PathName`,
  );
  const imagePath = /^\s*"([^"]+)"|^\s*(\S+)/.exec(res.stdout);
  const exe = imagePath?.[1] ?? imagePath?.[2];
  if (res.code !== 0 || exe === undefined)
    throw new Error(
      `cannot resolve the image path of service ${rig.serviceName}: ${res.stderr || res.stdout}`,
    );
  return exe.slice(0, exe.lastIndexOf("\\"));
}

/**
 * Seal the rig's throwaway master password with DPAPI under the interop
 * user's own scope, in the blob format `tegatad seal` writes (no entropy,
 * CurrentUser scope), so the foreground daemon — which runs as that user —
 * unseals it the way the service unseals its own blob. The password crosses
 * interop on stdin, never on a command line.
 */
async function sealForInteropUser(sealedBlobWin: string): Promise<void> {
  const rig = rigEnv();
  const masterPassword = fs.readFileSync(rig.masterPasswordFile, "utf8").trim();
  const res = await psRun(
    [
      "Add-Type -AssemblyName System.Security",
      "$p = [Console]::In.ReadLine()",
      "$b = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($p), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
      `[System.IO.File]::WriteAllBytes(${psQuote(sealedBlobWin)}, $b)`,
    ].join("; "),
    `${masterPassword}\n`,
  );
  if (res.code !== 0)
    throw new Error(`DPAPI seal for the interop user failed: ${res.stderr}`);
}

/** Wait for the `{"ready":true}` line; reject with the daemon's stderr. */
function waitReady(child: ChildProcess, stderr: () => string): Promise<void> {
  const stdout = child.stdout;
  if (stdout === null)
    return Promise.reject(new Error("foreground daemon has no stdout pipe"));
  const rl = readline.createInterface({ input: stdout });
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        new Error(
          `foreground daemon did not become ready within 30 s; stderr:\n${stderr()}`,
        ),
      );
    }, 30_000);
    rl.on("line", (line) => {
      try {
        if (JSON.parse(line).ready === true) {
          clearTimeout(timer);
          resolve();
        }
      } catch {}
    });
    // stderr の末尾は exit より後に届きうるため、パイプが閉じる close で読む。
    child.once("close", (code) => {
      clearTimeout(timer);
      reject(
        new Error(`foreground daemon exited (${code}); stderr:\n${stderr()}`),
      );
    });
  });
}

/**
 * Run tegatad.exe in the foreground with operator approval enabled and a
 * bitwarden-cli provider pointed at the rig's throwaway vaultwarden (see
 * startApprovalVault), so that `login` reaches the approval gate for a
 * credential that exists.
 */
export async function startApprovalDaemon(opts: {
  allowedSids: string[];
  approveTimeoutSecs: number;
}): Promise<ApprovalDaemon> {
  const rig = rigEnv();
  const tempWsl = await winAgentTempWsl();
  const tempWin = (await psRun("$env:TEMP")).stdout.trim();
  const bwExeWin = `${await rigServiceDirWin()}\\bw.exe`;
  const id = Math.random().toString(16).slice(2, 10);
  const dirWsl = path.join(tempWsl, `tegata-approval-${id}`);
  const stateDirWsl = path.join(dirWsl, "state");
  fs.mkdirSync(stateDirWsl, { recursive: true });
  const dirWin = `${tempWin}\\tegata-approval-${id}`;
  const pipeName = `tegata-approval-${id}`;
  let child: ChildProcess | undefined;
  let stderr = "";
  try {
    fs.writeFileSync(
      path.join(stateDirWsl, "token_hash"),
      `${sha256Hex("acceptance-token")}\n`,
    );
    // WSL 側のパスは Windows プロセスから読めないため、リグ証明書を %TEMP%
    // 配下へ複製し、bw には Windows パスで渡す。
    fs.copyFileSync(rig.vaultCert, path.join(dirWsl, "vault-ca.pem"));
    await sealForInteropUser(`${dirWin}\\state\\sealed.blob`);
    fs.writeFileSync(
      path.join(dirWsl, "config.toml"),
      `${[
        `pipe_name = ${JSON.stringify(pipeName)}`,
        "tcp_port = 0",
        `state_dir = ${JSON.stringify(`${dirWin}\\state`)}`,
        `audit_log_path = ${JSON.stringify(`${dirWin}\\state\\audit.log`)}`,
        `token_hash_path = ${JSON.stringify(`${dirWin}\\state\\token_hash`)}`,
        `allowed_sids = [${opts.allowedSids.map((sid) => JSON.stringify(sid)).join(", ")}]`,
        `bw_path = ${JSON.stringify(bwExeWin)}`,
        'unlock_mode = "sealed"',
        "approve_operator = true",
        `approve_timeout_secs = ${opts.approveTimeoutSecs}`,
        "[[providers]]",
        `namespace = ${JSON.stringify(APPROVAL_NAMESPACE)}`,
        'type = "bitwarden-cli"',
        // localhost は Windows 側で ::1 に解決され、WSL の localhost 転送は
        // IPv4 だけを運ぶため、127.0.0.1 を明示する（RIG.md 参照）。
        `server_url = ${JSON.stringify(`https://127.0.0.1:${rig.vaultPort}`)}`,
        `email = ${JSON.stringify(rig.vaultEmail)}`,
        'askpass_cmd = ""',
      ].join("\n")}\n`,
    );
    child = spawn(
      rig.tegatadExe,
      ["--config", `${dirWin}\\config.toml`, "--foreground"],
      {
        env: {
          ...process.env,
          NODE_EXTRA_CA_CERTS: `${dirWin}\\vault-ca.pem`,
          // interop が Windows 側へ引き継ぐ環境変数は WSLENV に列挙したものに限られる。
          WSLENV: [process.env.WSLENV, "NODE_EXTRA_CA_CERTS"]
            .filter((v) => v !== undefined && v !== "")
            .join(":"),
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (data: string) => {
      stderr += data;
    });
    await waitReady(child, () => stderr);
    child.removeAllListeners("close");
  } catch (error) {
    if (child && child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
    fs.rmSync(dirWsl, { recursive: true, force: true });
    throw error;
  }
  const running = child;
  return {
    pipeName,
    stateDirWsl,
    stderr: () => stderr,
    credId: async () => {
      const res = await pipeRpc(pipeName, "list_credentials", {});
      const items = (res.result ?? []) as Array<{ id: string; name: string }>;
      const item = Array.isArray(items)
        ? items.find((i) => i.name === APPROVAL_ITEM_NAME)
        : undefined;
      if (item === undefined)
        throw new Error(
          `"${APPROVAL_ITEM_NAME}" not listed by the foreground daemon: ${JSON.stringify(res)}\nstderr:\n${stderr}`,
        );
      return item.id;
    },
    waitForStderr: async (pattern, timeoutMs) => {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const match = pattern.exec(stderr);
        if (match) return match;
        if (Date.now() >= deadline)
          throw new Error(
            `daemon stderr did not match ${pattern} within ${timeoutMs} ms; stderr:\n${stderr}`,
          );
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    },
    stop: async () => {
      if (running.exitCode === null && running.signalCode === null) {
        running.kill("SIGTERM");
        const killTimer = setTimeout(() => running.kill("SIGKILL"), 3_000);
        await new Promise<void>((resolve) =>
          running.once("exit", () => resolve()),
        );
        clearTimeout(killTimer);
      }
      fs.rmSync(dirWsl, { recursive: true, force: true });
    },
  };
}
