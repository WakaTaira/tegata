// AC-24 — administrative RPCs require elevation.
// Traceability: docs/secret/briefs/tegata-phase2.md acceptance condition #6.
//
// The acceptance suite runs from a non-elevated WSL shell, so the interop
// pipe client here is inherently non-elevated. Both admin CLIs must refuse.

import { beforeAll, expect, test } from "vitest";
import {
  ensureServiceRunning,
  requireRig,
  rigEnv,
  winExec,
} from "./support/winrig.js";

beforeAll(async () => {
  requireRig();
  await ensureServiceRunning();
});

test("AC-24: token issue is rejected without elevation", async () => {
  // Given: a non-elevated interop context
  // When: `tegatad.exe token issue` is invoked
  const res = await winExec(rigEnv().tegatadExe, ["token", "issue"]);

  // Then: it is refused (non-zero exit) and prints no token material
  expect(res.code).not.toBe(0);
  expect(res.stdout).not.toMatch(/[A-Za-z0-9]{32,}/);
});

test("AC-24: seal is rejected without elevation", async () => {
  // Given: a non-elevated interop context and a password on stdin
  // When: `tegatad.exe seal` is invoked
  const res = await winExec(
    rigEnv().tegatadExe,
    ["seal"],
    "irrelevant-master-password\n",
  );

  // Then: it is refused before touching the sealed blob
  expect(res.code).not.toBe(0);
});
