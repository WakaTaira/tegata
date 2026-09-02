// AC-54 — the age-file provider is refused on the Windows service, because
// the browser worker shares the service account and could read the identity
// file directly (no per-user isolation exists on Windows, unlike the
// `executor_user` split added for Unix).
// Traceability: docs/secret/briefs/tegata-v042-browser-worker.md acceptance
// condition AC-54.

import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { beforeAll, expect, test } from "vitest";
import {
  currentWindowsSid,
  psRun,
  renderWinDaemonConfig,
  requireRig,
  rigEnv,
  winAgentTempWsl,
} from "./support/winrig.js";

let mySid: string;

beforeAll(async () => {
  requireRig();
  mySid = await currentWindowsSid();
});

function tomlString(s: string): string {
  return JSON.stringify(s); // TOML basic strings share JSON's escape rules here
}

/**
 * `renderWinDaemonConfig` only emits the pinned Phase 1 fields; it has no
 * notion of `[[providers]]`. This appends a single age-file provider block
 * rather than extending the pinned helper for one test.
 */
function withAgeFileProvider(
  base: string,
  entriesPathWin: string,
  identityPathWin: string,
): string {
  return `${base}\n[[providers]]\nnamespace = "age"\ntype = "age-file"\nentries_path = ${tomlString(entriesPathWin)}\nidentity_path = ${tomlString(identityPathWin)}\n`;
}

interface ForegroundResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * `startForegroundDaemon` in winrig.ts only covers the success path: it
 * waits for the `{"ready":true}` line and treats an early exit as an error.
 * AC-54 needs the opposite outcome (rejection before that line), so this
 * spawns tegatad.exe directly and races its exit against a timeout, killing
 * the process on timeout — the red behaviour before the fix is that the
 * daemon accepts the age-file provider and keeps running forever.
 */
async function runForegroundDaemonExpectingRejection(
  configPathWin: string,
  timeoutMs = 15_000,
): Promise<ForegroundResult> {
  const rig = rigEnv();
  const child: ChildProcess = spawn(
    rig.tegatadExe,
    ["--config", configPathWin, "--foreground"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
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
  try {
    const [code] = (await Promise.race([
      once(child, "exit"),
      new Promise<never>((_, reject) => {
        setTimeout(
          () =>
            reject(
              new Error(
                `tegatad.exe did not exit within ${timeoutMs}ms (it accepted the age-file provider); stdout: ${stdout}`,
              ),
            ),
          timeoutMs,
        );
      }),
    ])) as [number | null];
    return { code: code ?? -1, stdout, stderr };
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  }
}

test("AC-54: age-file provider is refused on the Windows service", async () => {
  // Given: a config with an age-file provider, pointing at dummy (but
  // non-empty) entries/identity files on the rig
  const tempWsl = await winAgentTempWsl();
  const id = Math.random().toString(16).slice(2, 10);
  const dirWsl = path.join(tempWsl, `tegata-ac-agefile-${id}`);
  fs.mkdirSync(path.join(dirWsl, "state"), { recursive: true });
  fs.writeFileSync(
    path.join(dirWsl, "entries.age"),
    "not a real age-encrypted file; only startup validation is under test\n",
  );
  fs.writeFileSync(
    path.join(dirWsl, "identity.txt"),
    "AGE-SECRET-KEY-DUMMY0000000000000000000000000000000000000000000\n",
  );
  const tempWinRes = await psRun("$env:TEMP");
  const dirWin = `${tempWinRes.stdout.trim()}\\tegata-ac-agefile-${id}`;
  const configPathWin = `${dirWin}\\config.toml`;
  fs.writeFileSync(
    path.join(dirWsl, "config.toml"),
    withAgeFileProvider(
      renderWinDaemonConfig({
        pipeName: `tegata-ac-agefile-${id}`,
        stateDirWin: `${dirWin}\\state`,
        auditLogPathWin: `${dirWin}\\state\\audit.log`,
        allowedSids: [mySid],
      }),
      `${dirWin}\\entries.age`,
      `${dirWin}\\identity.txt`,
    ),
  );

  try {
    // When: tegatad.exe is started in the foreground against that config
    const res = await runForegroundDaemonExpectingRejection(configPathWin);

    // Then: it exits non-zero and reports the age-file rejection
    expect(res.code).not.toBe(0);
    expect(res.stderr).toContain(
      "age-file provider is not supported on Windows",
    );
  } finally {
    fs.rmSync(dirWsl, { recursive: true, force: true });
  }
});
