/**
 * Support for the Issue #60 acceptance tests (AC-202..AC-204): reading the
 * target fixture's /fingerprint/ records, and starting a daemon against a
 * Playwright browsers directory that holds only the headless shell.
 * Owned by the acceptance suite (gauntlet); do not modify during
 * implementation.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import {
  bins,
  type CanarySet,
  defaultEntries,
  renderDaemonConfig,
} from "./harness.js";

/** One document request for /fingerprint/ as the fixture server saw it. */
export interface FingerprintRequest {
  seq: number;
  nonce: string;
  logged_in: boolean;
  user_agent: string | null;
  sec_ch_ua: string | null;
  sec_fetch_dest: string | null;
}

/** The values the /fingerprint/ page's own JS reported after loading. */
export interface FingerprintObservation {
  nonce: string;
  logged_in: boolean;
  webdriver: unknown;
  plugins_length: number;
  chrome_type: string;
  user_agent: string;
  brands: Array<{ brand: string; version: string }> | null;
  screen_width: number;
  screen_height: number;
  outer_width: number;
  outer_height: number;
  inner_width: number;
  inner_height: number;
}

export interface FingerprintState {
  requests: FingerprintRequest[];
  observations: FingerprintObservation[];
}

export async function fingerprintState(
  fixtureUrl: string,
): Promise<FingerprintState> {
  const response = await fetch(`${fixtureUrl}/fingerprint/state`);
  if (!response.ok)
    throw new Error(`/fingerprint/state answered HTTP ${response.status}`);
  return (await response.json()) as FingerprintState;
}

/**
 * Poll the fixture until `pick` returns a value (the page's JS reports
 * asynchronously after its load event).
 */
export async function waitForFingerprint<T>(
  fixtureUrl: string,
  what: string,
  pick: (state: FingerprintState) => T | undefined,
  timeoutMs = 15_000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: FingerprintState | undefined;
  while (Date.now() < deadline) {
    last = await fingerprintState(fixtureUrl);
    const value = pick(last);
    if (value !== undefined) return value;
    await sleep(100);
  }
  throw new Error(
    `timed out waiting for ${what}; fixture state: ${JSON.stringify(last)}`,
  );
}

/**
 * A copy of the dev shell's PLAYWRIGHT_BROWSERS_PATH that keeps only the
 * `chromium_headless_shell-*` entries (as symlinks), i.e. what
 * `playwright install --only-shell chromium` would leave behind.
 */
export function headlessShellOnlyBrowsersPath(): {
  dir: string;
  entries: string[];
  cleanup(): void;
} {
  const source = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (source === undefined || source === "")
    throw new Error("PLAYWRIGHT_BROWSERS_PATH is not set in the dev shell");
  const shells = fs
    .readdirSync(source)
    .filter((name) => name.startsWith("chromium_headless_shell-"));
  if (shells.length === 0)
    throw new Error(`no chromium_headless_shell-* entry under ${source}`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-shell-only-"));
  for (const name of shells) {
    fs.symlinkSync(
      fs.realpathSync(path.join(source, name)),
      path.join(dir, name),
    );
  }
  return {
    dir,
    entries: fs.readdirSync(dir),
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

/** Throwaway secrets for a daemon that must never get as far as serving. */
function throwawayCanaries(): CanarySet {
  const random = () => randomBytes(12).toString("hex");
  return {
    username: `user_${random()}`,
    password: `pass_${random()}`,
    totpSeed: `seed_${random()}`,
    wrongPassword: `wrong_${random()}`,
  };
}

export interface SpawnModeDaemonLayout {
  daemonDir: string;
  configPath: string;
  cleanup(): void;
}

/**
 * Lay out a spawn-mode daemon (no `executor_socket`: the daemon launches the
 * executor itself, as in the rest of the Linux suite).
 */
export function layOutSpawnModeDaemon(): SpawnModeDaemonLayout {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-shell-"));
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    renderDaemonConfig({
      socketPath: path.join(daemonDir, "tegatad.sock"),
      stateDir,
      auditLogPath: path.join(stateDir, "audit.log"),
      allowedUids: [os.userInfo().uid],
      entries: defaultEntries(throwawayCanaries()),
    }),
    { mode: 0o600 },
  );
  return {
    daemonDir,
    configPath,
    cleanup: () => fs.rmSync(daemonDir, { recursive: true, force: true }),
  };
}

export interface DaemonExit {
  /** null when the daemon was still running at the deadline (then killed). */
  code: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}

/**
 * Start the daemon with extra environment variables and wait for it to exit.
 * The executor inherits the daemon's environment in spawn mode.
 */
export async function runDaemonWithEnvUntilExit(
  layout: SpawnModeDaemonLayout,
  env: Record<string, string>,
  timeoutMs = 20_000,
): Promise<DaemonExit> {
  const child = spawn(bins().tegatad, ["--config", layout.configPath], {
    stdio: ["ignore", "ignore", "pipe"],
    cwd: layout.daemonDir,
    env: { ...process.env, ...env },
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
