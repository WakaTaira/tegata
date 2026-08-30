// AC-31 — control test for the injected WMI command-line sampler: a canary
// deliberately exposed in a Windows-side process command line MUST be
// detected. The decoy process is started detached via Start-Process and the
// canary reaches it through a file, so the WSL-visible outer process never
// carries it: the WSL `ps` surface cannot see the canary, and only a working
// WMI sampler can. This guards against a leak-guard implementation that
// accepts `psSampleCommands` but never samples it, which would let AC-26 pass
// with the WMI surface unmonitored.
// Traceability: docs/secret/briefs/tegata-phase2.md acceptance condition #13.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard } from "@tegata/leak-guard";
import { expect, test } from "vitest";
import { bins } from "../support/harness.js";
import {
  psRun,
  requireRig,
  winAgentTempWsl,
  wmiPsSampleCommand,
} from "./support/winrig.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("AC-31: a canary exposed only in a Windows command line is caught by the WMI sampler", async () => {
  // Given: a leak guard with the same sampler set the win-stack uses
  // (WSL ps table + interop WMI command-line sampler)
  requireRig();
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-ac31-"));
  const guard = await createLeakGuard({
    leakscanBin: bins().leakscan,
    agentVisibleRoots: [agentDir],
    psSampleIntervalMs: 200,
    psSampleCommands: [["ps", "-eo", "args"], wmiPsSampleCommand()],
  });
  const tempWsl = await winAgentTempWsl();
  const canaryFileWsl = path.join(tempWsl, `tegata-ac31-${guard.runId}.txt`);
  try {
    const canary = guard.canary("control");
    // The canary travels to the Windows side through this file, not through
    // any argv visible from WSL.
    fs.writeFileSync(canaryFileWsl, canary);
    const winTempRes = await psRun("$env:TEMP");
    expect(winTempRes.code).toBe(0);
    const canaryFileWin = `${winTempRes.stdout.trim()}\\tegata-ac31-${guard.runId}.txt`;

    // When: a detached Windows-only decoy process runs with the canary in its
    // command line for several sampler intervals ('#' turns the canary into a
    // PowerShell comment, so the decoy just sleeps)
    const start = await psRun(
      [
        `$c = (Get-Content -Raw '${canaryFileWin}').Trim()`,
        "Start-Process -WindowStyle Hidden -FilePath powershell.exe " +
          "-ArgumentList ('-NoProfile -NonInteractive -Command Start-Sleep -Seconds 12 #' + $c)",
      ].join("; "),
    );
    expect(start.code, `failed to start the decoy: ${start.stderr}`).toBe(0);
    await sleep(8_000);

    // Then: the guard reports a ps-surface hit for the planted canary
    const hits = await guard.collectLeaks();
    expect(
      hits.some((h) => h.surface === "ps" && h.canaryLabel === "control"),
      `expected a ps-surface hit for the planted canary, got: ${JSON.stringify(hits)}`,
    ).toBe(true);
  } finally {
    fs.rmSync(canaryFileWsl, { force: true });
    await guard.dispose();
    fs.rmSync(agentDir, { recursive: true, force: true });
  }
});
