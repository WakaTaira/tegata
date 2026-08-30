// AC-41, AC-42 — the age-file provider: an end-to-end leak-guarded login
// from an age-encrypted entries file, and a classified-only failure when the
// identity cannot decrypt it.
// Traceability: docs/secret/briefs/tegata-phase3.md acceptance condition #10, #11.

import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import {
  ERROR_CODES,
  fixtureSteps,
  type MockEntry,
} from "./support/harness.js";
import {
  ageEncrypt,
  ageKeygen,
  renderAgeEntriesToml,
  startPhase3Stack,
  stopPhase3Stack,
} from "./support/phase3.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

test("AC-41: an age-file credential logs in end to end without leaking", async () => {
  // Given: canary credentials sealed in an age-encrypted entries file and
  // the target fixture running
  const stack = await startPhase3Stack({
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
    // When: the credential is listed and MCP login is called
    const list = await stack.mcp.callTool("list_credentials", {});
    expect(list.isError, list.text).toBe(false);
    const items = list.json as Array<{ id: string; name: string }>;
    expect(items.some((i) => i.id === "age:site")).toBe(true);

    const login = await stack.mcp.callTool("login", {
      cred_id: "age:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
    const result = login.json as LoginResult;

    // Then: CDP reaches the logged-in page, and the teardown leak check
    // (stopPhase3Stack) finds no canary on any agent-observable surface
    const browser = await chromium.connectOverCDP(result.channel.endpoint);
    try {
      const page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().startsWith(stack.fixture.url));
      expect(page, "no page on the fixture origin").toBeDefined();
      const hasWelcome = await page?.evaluate(
        () => document.querySelector("#welcome") !== null,
      );
      expect(hasWelcome).toBe(true);
    } finally {
      await browser.close();
    }
    const logout = await stack.mcp.callTool("logout", {
      session_id: result.session_id,
    });
    expect(logout.isError, logout.text).toBe(false);
  } finally {
    await stopPhase3Stack(stack);
  }
});

test("AC-42: a wrong identity fails with a bare classification code", async () => {
  // Given: an entries file encrypted to one key and a provider configured
  // with a different identity
  const stack = await startPhase3Stack({
    makeProviders: (canaries, materialsDir) => {
      const ownDir = path.join(materialsDir, "own");
      const otherDir = path.join(materialsDir, "other");
      fs.mkdirSync(ownDir, { recursive: true });
      fs.mkdirSync(otherDir, { recursive: true });
      const own = ageKeygen(ownDir);
      const other = ageKeygen(otherDir);
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
      ageEncrypt(other.recipient, renderAgeEntriesToml(entries), entriesPath);
      return [
        {
          type: "age-file",
          namespace: "age",
          entriesPath,
          identityPath: own.identityPath,
        },
      ];
    },
    withFixture: false,
  });
  try {
    // When: login is attempted
    const login = await stack.mcp.callTool("login", {
      cred_id: "age:site",
      target_url: "http://127.0.0.1:1/login",
      ...fixtureSteps(),
    });

    // Then: the error is one bare classification code — no detail, no path
    expect(login.isError).toBe(true);
    expect(ERROR_CODES).toContain(login.text);
    expect(login.text).toMatch(/^[A-Z_]+$/);
  } finally {
    await stopPhase3Stack(stack);
  }
});
