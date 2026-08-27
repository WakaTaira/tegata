// AC-13, AC-14 — the leakscan CLI detects encoded canaries and stays quiet
// on clean input.
// Traceability: docs/secret/briefs/tegata-phase1.md 受け入れ条件 #13-#14.
//
// Pinned CLI contract:
//   leakscan --canaries <canaries.json> --json <target>...
//   canaries.json: {"canaries": ["..."]}
//   stdout (--json): {"hits": [{"path", "canary_index", "encoding",
//                               "byte_offset"}]} — never the canary value
//   exit code: 1 when any hit, 0 when clean
// Encoding variants generated per canary: raw, base64 (standard, of the UTF-8
// bytes), url (full percent-encoding of every byte), hex (lowercase, UTF-8
// bytes), json (JSON string escape). For alphanumeric canaries the url and
// json variants of *partial* encodings coincide with raw — the scanner must
// still catch the fully-encoded forms exercised here.
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { bins } from "./support/harness.js";

function makeWorkdir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "leakscan-ac-"));
}

function writeCanariesFile(dir: string, canaries: string[]): string {
  const p = path.join(dir, "canaries.json");
  fs.writeFileSync(p, JSON.stringify({ canaries }));
  return p;
}

function percentEncodeAll(s: string): string {
  return [...Buffer.from(s, "utf8")]
    .map((b) => `%${b.toString(16).toUpperCase().padStart(2, "0")}`)
    .join("");
}

function runLeakscan(canariesFile: string, target: string) {
  const res = spawnSync(
    bins().leakscan,
    ["--canaries", canariesFile, "--json", target],
    { encoding: "utf8" },
  );
  if (res.error) throw res.error;
  return res;
}

test("AC-13: every encoded variant of a canary is detected (exit 1)", async () => {
  // Given: five files, each hiding the canary under a different encoding
  const dir = makeWorkdir();
  try {
    const canary = `LEAK_CANARY_selftest_${crypto.randomBytes(16).toString("hex")}`;
    const canariesFile = writeCanariesFile(dir, [canary]);
    const targets = path.join(dir, "targets");
    fs.mkdirSync(targets);
    const variants: Record<string, string> = {
      raw: canary,
      base64: Buffer.from(canary, "utf8").toString("base64"),
      url: percentEncodeAll(canary),
      hex: Buffer.from(canary, "utf8").toString("hex"),
      json: JSON.stringify(canary),
    };
    for (const [name, payload] of Object.entries(variants)) {
      fs.writeFileSync(
        path.join(targets, `${name}.txt`),
        `some harmless prefix ${payload} some harmless suffix\n`,
      );
    }

    // When: leakscan scans the directory
    const res = runLeakscan(canariesFile, targets);

    // Then: all five files are flagged, exit code is 1, and the report never
    // echoes the canary value itself
    expect(res.status).toBe(1);
    const report = JSON.parse(res.stdout) as {
      hits: Array<{
        path: string;
        canary_index: number;
        encoding: string;
        byte_offset: number;
      }>;
    };
    const flagged = new Set(report.hits.map((h) => path.basename(h.path)));
    expect([...flagged].sort()).toEqual(
      ["base64.txt", "hex.txt", "json.txt", "raw.txt", "url.txt"].sort(),
    );
    expect(res.stdout).not.toContain(canary);
    expect(res.stderr).not.toContain(canary);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("AC-14: a clean file produces zero hits and exit 0", async () => {
  // Given: a file that does not contain the canary in any form
  const dir = makeWorkdir();
  try {
    const canary = `LEAK_CANARY_selftest_${crypto.randomBytes(16).toString("hex")}`;
    const canariesFile = writeCanariesFile(dir, [canary]);
    const clean = path.join(dir, "clean.txt");
    fs.writeFileSync(clean, "nothing to see here, just regular log output\n");

    // When: leakscan scans it
    const res = runLeakscan(canariesFile, clean);

    // Then: zero hits, exit code 0
    expect(res.status).toBe(0);
    const report = JSON.parse(res.stdout) as { hits: unknown[] };
    expect(report.hits).toEqual([]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
