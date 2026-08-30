// AC-15 — negative control: a deliberate leak MUST be caught. This guards
// against a broken detector turning the whole suite green.
// Traceability: docs/secret/briefs/tegata-phase1.md acceptance condition #15.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createLeakGuard } from "@tegata/leak-guard";
import { expect, test } from "vitest";
import { bins } from "./support/harness.js";

test("AC-15: leak_guard fails when a canary is deliberately leaked", async () => {
  // Given: a leak guard watching an agent-visible directory
  const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-nc-"));
  const guard = await createLeakGuard({
    leakscanBin: bins().leakscan,
    agentVisibleRoots: [agentDir],
  });
  try {
    const canary = guard.canary("negative_control");

    // When: the canary is intentionally leaked (base64-obfuscated, to prove
    // encoded variants are covered) into the watched surface
    fs.writeFileSync(
      path.join(agentDir, "innocent-looking.log"),
      `debug: ${Buffer.from(canary, "utf8").toString("base64")}\n`,
    );

    // Then: the inspection reports the hit and the assertion throws
    const hits = await guard.collectLeaks();
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.some((h) => h.canaryLabel === "negative_control")).toBe(true);
    await expect(guard.assertNoLeaks()).rejects.toThrow();
  } finally {
    await guard.dispose();
    fs.rmSync(agentDir, { recursive: true, force: true });
  }
});
