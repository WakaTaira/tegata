// AC-22 — the daemon's ProgramData directory is unreadable from the agent
// side even with WSL interop and automount enabled.
// Traceability: docs/secret/briefs/tegata-phase2.md acceptance condition #4.

import fs from "node:fs";
import path from "node:path";
import { beforeAll, expect, test } from "vitest";
import {
  PROTECTED_FILES,
  psRun,
  requireRig,
  rigEnv,
} from "./support/winrig.js";

let programData: string;

beforeAll(() => {
  requireRig();
  programData = rigEnv().programData;
});

test("AC-22: agent-side reads of the daemon's protected files are denied", async () => {
  // Given: WSL with interop + automount enabled, and the daemon's protected
  // files present under C:\ProgramData\tegata
  for (const rel of PROTECTED_FILES) {
    const wslPath = path.join(programData, rel);

    // When: the agent reads the file directly through /mnt/c ...
    let directDenied = false;
    try {
      fs.readFileSync(wslPath);
    } catch (err) {
      directDenied = (err as NodeJS.ErrnoException).code === "EACCES";
    }

    // ... and again via powershell.exe over interop
    const winPath = `C:\\ProgramData\\tegata\\${rel.replaceAll("/", "\\")}`;
    const ps = await psRun(
      `try { Get-Content -Raw -LiteralPath '${winPath}' -ErrorAction Stop; 'READABLE' } ` +
        `catch { if ($_.CategoryInfo.Category -eq 'PermissionDenied') { 'DENIED' } else { 'ERR:' + $_.CategoryInfo.Category } }`,
    );

    // Then: both access paths are refused (never readable)
    expect(directDenied, `direct /mnt/c read of ${rel} was not EACCES`).toBe(
      true,
    );
    expect(ps.stdout.trim(), `powershell read of ${rel}`).toBe("DENIED");
  }
});
