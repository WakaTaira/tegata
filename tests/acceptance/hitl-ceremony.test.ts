// AC-50, AC-51 — the approval gate must not turn a ceremony provider's
// locked state into a refusal: the pre-approval existence check defers
// lockedness to the resolve path, where the unlock ceremony reopens the
// provider. AC-50 covers an explicitly relocked age provider; AC-51 covers
// a cold-started pass provider whose catalog scan never runs the ceremony.
// Traceability: docs/secret/briefs/tegata-phase3.md 受け入れ条件 #19.

import path from "node:path";
import { expect, test } from "vitest";
import { fixtureSteps, type MockEntry } from "./support/harness.js";
import {
  ageEncrypt,
  ageKeygen,
  makeGpgHome,
  makePassStore,
  renderAgeEntriesToml,
  startPhase3Stack,
  stopPhase3Stack,
} from "./support/phase3.js";

test("AC-50: with approve_cmd set, a locked age provider still logs in", async () => {
  // Given: an approving approve_cmd and an age-file provider
  const stack = await startPhase3Stack({
    top: { approveCmd: "exit 0" },
    makeProviders: (canaries, materialsDir) => {
      const { identityPath, recipient } = ageKeygen(materialsDir);
      const entries: MockEntry[] = [
        {
          id: "site",
          name: "Age Test Site",
          uri: "http://127.0.0.1",
          kind: "login",
          username: canaries.username,
          password: canaries.password,
        },
      ];
      const entriesPath = path.join(materialsDir, "entries.toml.age");
      ageEncrypt(recipient, renderAgeEntriesToml(entries), entriesPath);
      return [
        { type: "age-file", namespace: "age", entriesPath, identityPath },
      ];
    },
  });
  try {
    // When: the namespace is locked and login is called right away
    const locked = await stack.mcp.callTool("lock_vault", {
      namespace: "age",
    });
    expect(locked.isError, locked.text).toBe(false);
    const login = await stack.mcp.callTool("login", {
      cred_id: "age:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: the login succeeds through approval and the re-decryption
    // ceremony, instead of being refused with VAULT_LOCKED
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-51: with approve_cmd set, a cold pass provider logs in first try", async () => {
  // Given: an approving approve_cmd and a freshly started daemon whose pass
  // provider has never run its gpg ceremony
  const stack = await startPhase3Stack({
    top: { approveCmd: "exit 0" },
    makeProviders: (canaries, materialsDir) => {
      const { gnupgHome, fingerprint } = makeGpgHome(materialsDir);
      const storeDir = makePassStore(materialsDir, gnupgHome, fingerprint, [
        {
          name: "site",
          password: canaries.password,
          username: canaries.username,
        },
      ]);
      return [{ type: "pass", namespace: "pass", storeDir, gnupgHome }];
    },
  });
  try {
    // When: the very first RPC is a login for a store entry
    const login = await stack.mcp.callTool("login", {
      cred_id: "pass:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: the login succeeds (the existence check must not report the
    // never-unlocked provider as VAULT_LOCKED)
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
  } finally {
    await stopPhase3Stack(stack);
  }
});
