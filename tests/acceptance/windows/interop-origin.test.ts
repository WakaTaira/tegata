// AC-93 / AC-94 — WSL interop の pipe caller を監査し、管理 RPC を拒否する。
// Traceability: docs/secret/briefs/tegata-issue13-interop-admin.md.

import { randomBytes } from "node:crypto";
import { beforeAll, expect, test } from "vitest";
import {
  pipeRpc,
  readForegroundAudit,
  startForegroundPhase4Daemon,
} from "./support/phase4.js";
import { currentWindowsSid, requireRig } from "./support/winrig.js";

let mySid: string;

beforeAll(async () => {
  requireRig();
  mySid = await currentWindowsSid();
});

test("AC-93: interop status audit records peer_pid and wsl_interop origin", async () => {
  // Given: foreground デーモン
  const daemon = await startForegroundPhase4Daemon({
    allowedSids: [mySid],
    legacyToken: randomBytes(32).toString("base64url"),
  });
  try {
    // When: WSL interop の pipe client（`pipeRpc`）から `status`
    const response = await pipeRpc(daemon.pipeName, "status", {});
    expect(response.error, JSON.stringify(response.error)).toBeUndefined();

    // Then: 監査行に `peer_pid`（正の整数）と `peer_origin: "wsl_interop"` がある
    const audit = readForegroundAudit(daemon.stateDirWsl);
    const record = audit.find((entry) => entry.method === "status");
    expect(record, JSON.stringify(audit)).toBeDefined();
    expect(record?.peer_pid).toEqual(expect.any(Number));
    expect(record?.peer_pid).toBeGreaterThan(0);
    expect(record?.peer_origin).toBe("wsl_interop");
  } finally {
    await daemon.stop();
  }
});

test("AC-94: interop admin_peer_list is rejected and audited as wsl_interop", async () => {
  // Given: 同じデーモン
  const daemon = await startForegroundPhase4Daemon({
    allowedSids: [mySid],
    legacyToken: randomBytes(32).toString("base64url"),
  });
  try {
    // When: interop の pipe client から `admin_peer_list`
    const response = await pipeRpc(daemon.pipeName, "admin_peer_list", {});

    // Then: `ADMIN_REQUIRED`（非昇格でも interop でも拒否され、回帰しない）、監査行の `peer_origin` は `"wsl_interop"`
    expect(response.error?.message).toBe("ADMIN_REQUIRED");
    const audit = readForegroundAudit(daemon.stateDirWsl);
    const record = audit.find((entry) => entry.method === "admin_peer_list");
    expect(record, JSON.stringify(audit)).toBeDefined();
    expect(record?.peer_origin).toBe("wsl_interop");
  } finally {
    await daemon.stop();
  }
});
