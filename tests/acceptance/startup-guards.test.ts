// AC-74, AC-75 — the daemon refuses to start on an unsafe `state_dir` or on
// an unspecified TCP bind address, and says why on stderr.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance conditions
// AC-74 and AC-75 (Phase 4b). These guards need no container, so they live in
// the Linux suite and run in every CI `check` job rather than only where a
// docker daemon is available.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { type CanarySet, defaultEntries } from "./support/harness.js";
import {
  freeTcpPort,
  renderPhase4Config,
  runDaemonUntilExit,
} from "./support/phase4.js";

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

interface GuardDaemon {
  daemonDir: string;
  stateDir: string;
  configPath: string;
}

/** Lay out a daemon directory with a 0700 state dir and a rendered config. */
async function layOutDaemon(opts: { tcpBind?: string }): Promise<GuardDaemon> {
  const daemonDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegatad-guard-"));
  const stateDir = path.join(daemonDir, "state");
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const configPath = path.join(daemonDir, "config.toml");
  fs.writeFileSync(
    configPath,
    renderPhase4Config({
      socketPath: path.join(daemonDir, "tegatad.sock"),
      stateDir,
      auditLogPath: path.join(stateDir, "audit.log"),
      allowedUids: [os.userInfo().uid],
      tcpPort: opts.tcpBind === undefined ? undefined : await freeTcpPort(),
      tcpBind: opts.tcpBind,
      entries: defaultEntries(throwawayCanaries()),
    }),
    { mode: 0o600 },
  );
  return { daemonDir, stateDir, configPath };
}

test("AC-74: a state_dir that is not 0700 refuses startup", async () => {
  // Given: state_dir を 0755 にしたデーモン
  const layout = await layOutDaemon({});
  try {
    fs.chmodSync(layout.stateDir, 0o755);

    // When: 起動
    const exit = await runDaemonUntilExit(layout.configPath, layout.daemonDir);

    // Then: exit code 非ゼロ、stderr に state_dir の権限違反の理由
    expect(
      exit.code,
      `daemon kept running with a 0755 state_dir; stderr: ${exit.stderr}`,
    ).not.toBeNull();
    expect(exit.code).not.toBe(0);
    expect(exit.stderr).toMatch(/state_dir/);
    expect(exit.stderr).toMatch(/0700|mode|permission/i);
  } finally {
    fs.rmSync(layout.daemonDir, { recursive: true, force: true });
  }
});

test("AC-75: listen.tcp.bind = 0.0.0.0 refuses startup", async () => {
  // Given: listen.tcp.bind = "0.0.0.0" の config
  const layout = await layOutDaemon({ tcpBind: "0.0.0.0" });
  try {
    // When: 起動
    const exit = await runDaemonUntilExit(layout.configPath, layout.daemonDir);

    // Then: exit code 非ゼロ、stderr に bind 拒否の理由
    expect(
      exit.code,
      `daemon kept running bound to 0.0.0.0; stderr: ${exit.stderr}`,
    ).not.toBeNull();
    expect(exit.code).not.toBe(0);
    expect(exit.stderr).toMatch(/bind/i);
    expect(exit.stderr).toMatch(/unspecified|0\.0\.0\.0/);
  } finally {
    fs.rmSync(layout.daemonDir, { recursive: true, force: true });
  }
});
