// AC-28, AC-29 — the named pipe gates normal RPC on the caller's SID, not on
// the pipe DACL alone.
// Traceability: docs/secret/briefs/tegata-phase2.md 受け入れ条件 #10, #11.
//
// Each test starts a throwaway foreground tegatad.exe (no service context)
// with a specific allowed_sids set, then calls it back over the named pipe
// through interop. The interop client runs under the current Windows SID.

import { beforeAll, expect, test } from "vitest";
import {
  currentWindowsSid,
  type ForegroundDaemon,
  requireRig,
  rigEnv,
  startForegroundDaemon,
  winExec,
} from "./support/winrig.js";

let mySid: string;

beforeAll(async () => {
  requireRig();
  mySid = await currentWindowsSid();
});

test("AC-28: an empty allowed_sids rejects normal RPC over the pipe", async () => {
  // Given: a daemon whose allowed_sids is empty
  const daemon: ForegroundDaemon = await startForegroundDaemon({
    allowedSids: [],
  });
  try {
    // When: status is called over the named pipe from the current SID
    const res = await winExec(rigEnv().tegatadExe, [
      "status",
      "--pipe",
      daemon.pipeName,
    ]);

    // Then: the call is refused
    expect(res.code).not.toBe(0);
    expect(res.stdout).not.toContain('"ok"');
  } finally {
    await daemon.stop();
  }
});

test("AC-29: an allowed SID gets a normal response over the pipe", async () => {
  // Given: a daemon whose allowed_sids includes the current Windows SID
  const daemon: ForegroundDaemon = await startForegroundDaemon({
    allowedSids: [mySid],
  });
  try {
    // When: status is called over the named pipe
    const res = await winExec(rigEnv().tegatadExe, [
      "status",
      "--pipe",
      daemon.pipeName,
    ]);

    // Then: a normal response is returned
    expect(res.code, `status failed: ${res.stderr}`).toBe(0);
    const parsed = JSON.parse(res.stdout.trim());
    expect(parsed).toBeTypeOf("object");
  } finally {
    await daemon.stop();
  }
});
