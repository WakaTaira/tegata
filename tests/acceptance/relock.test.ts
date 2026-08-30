// AC-34, AC-35 — unlock is a per-provider ceremony that runs implicitly on
// the next operation: TTL expiry is not sticky, and an explicit lock of a
// provider with a ceremony (age re-decryption) reopens on demand. AC-11
// (a ceremony-less static provider stays VAULT_LOCKED) pins the other half.
// Traceability: docs/secret/briefs/tegata-phase3.md 受け入れ条件 #3, #4.

import path from "node:path";
import { expect, test } from "vitest";
import { fixtureSteps, type MockEntry } from "./support/harness.js";
import {
  ageEncrypt,
  ageKeygen,
  type Phase3Stack,
  renderAgeEntriesToml,
  startPhase3Stack,
  stopPhase3Stack,
} from "./support/phase3.js";

function ageStack(opts: { sessionTtlSecs?: number }): Promise<Phase3Stack> {
  return startPhase3Stack({
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
        {
          type: "age-file",
          namespace: "age",
          entriesPath,
          identityPath,
          sessionTtlSecs: opts.sessionTtlSecs,
        },
      ];
    },
  });
}

test("AC-34: provider TTL expiry is soft — a later login succeeds", async () => {
  // Given: an age-file provider with a one-second unlock TTL
  const stack = await ageStack({ sessionTtlSecs: 1 });
  try {
    const first = await stack.mcp.callTool("login", {
      cred_id: "age:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    expect(first.isError, `first login failed: ${first.text}`).toBe(false);

    // When: the TTL has expired and login is called again
    await new Promise((r) => setTimeout(r, 2_500));
    const second = await stack.mcp.callTool("login", {
      cred_id: "age:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });

    // Then: the login succeeds (the unlock ceremony ran again implicitly)
    expect(second.isError, `second login failed: ${second.text}`).toBe(false);
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-35: an explicit lock of a ceremony provider reopens on demand", async () => {
  // Given: an unlocked age-file provider
  const stack = await ageStack({});
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

    // Then: the login succeeds through the re-decryption ceremony
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
  } finally {
    await stopPhase3Stack(stack);
  }
});
