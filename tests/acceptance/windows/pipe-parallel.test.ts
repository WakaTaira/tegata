// AC-47 — the named pipe accepts connections concurrently: a silent client
// that never sends its first byte must not stall other clients for the
// duration of the identity-read timeout (5 seconds).
// Traceability: docs/secret/briefs/tegata-phase3.md 受け入れ条件 #16.

import { beforeAll, expect, test } from "vitest";
import {
  currentWindowsSid,
  type ForegroundDaemon,
  psRun,
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

test("AC-47: a silent pipe client does not stall other clients", async () => {
  // Given: a foreground daemon and a silent client that connects to the
  // pipe and sends nothing for eight seconds
  const daemon: ForegroundDaemon = await startForegroundDaemon({
    allowedSids: [mySid],
  });
  try {
    const silent = psRun(
      `$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', '${daemon.pipeName}', [System.IO.Pipes.PipeDirection]::InOut); ` +
        "$c.Connect(5000); Start-Sleep -Seconds 8; $c.Dispose()",
    );
    // Give the silent client time to reach the daemon before probing.
    await new Promise((r) => setTimeout(r, 2_000));

    // When: another client calls status over the same pipe
    const started = Date.now();
    const res = await winExec(rigEnv().tegatadExe, [
      "status",
      "--pipe",
      daemon.pipeName,
    ]);
    const elapsed = Date.now() - started;

    // Then: the status call succeeds promptly instead of waiting out the
    // silent client's identity-read timeout
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toContain('"ok"');
    expect(elapsed).toBeLessThan(4_000);

    await silent;
  } finally {
    await daemon.stop();
  }
});
