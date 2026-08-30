// AC-43, AC-44 — the pass provider: list/login/get_totp end to end against a
// throwaway GNU pass store (passphrase-less GPG key), leak-guarded, and the
// totp_exposable opt-in enforced by entry name.
// Traceability: docs/secret/briefs/tegata-phase3.md acceptance condition #12, #13.

import { chromium } from "playwright-core";
import { expect, test } from "vitest";
import { fixtureSteps } from "./support/harness.js";
import {
  makeGpgHome,
  makePassStore,
  type Phase3Stack,
  startPhase3Stack,
  stopPhase3Stack,
} from "./support/phase3.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

function passStack(): Promise<Phase3Stack> {
  return startPhase3Stack({
    makeProviders: (canaries, materialsDir) => {
      const { gnupgHome, fingerprint } = makeGpgHome(materialsDir);
      const storeDir = makePassStore(materialsDir, gnupgHome, fingerprint, [
        {
          name: "site",
          password: canaries.password,
          username: canaries.username,
          url: "http://127.0.0.1",
          totpSeed: canaries.totpSeed,
        },
        {
          name: "site-no-totp",
          password: canaries.password,
          username: canaries.username,
          totpSeed: canaries.totpSeed,
        },
      ]);
      return [
        {
          type: "pass",
          namespace: "pass",
          storeDir,
          gnupgHome,
          totpExposable: ["site"],
        },
      ];
    },
  });
}

test("AC-43: a pass entry lists, logs in, and serves a TOTP code", async () => {
  // Given: a throwaway pass store holding canary credentials with an
  // otpauth line, and the target fixture running
  const stack = await passStack();
  try {
    // When: the catalog is listed
    const list = await stack.mcp.callTool("list_credentials", {});
    expect(list.isError, list.text).toBe(false);
    const items = list.json as Array<{ id: string; name: string }>;
    expect(items.some((i) => i.id === "pass:site")).toBe(true);

    // And: MCP login is called for the pass entry
    const login = await stack.mcp.callTool("login", {
      cred_id: "pass:site",
      target_url: stack.fixture.url,
      ...fixtureSteps(),
    });
    expect(login.isError, `login failed: ${login.text}`).toBe(false);
    const result = login.json as LoginResult;

    // Then: CDP reaches the logged-in page
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

    // And: get_totp returns a six-digit code for the opted-in entry
    const totp = await stack.mcp.callTool("get_totp", {
      cred_id: "pass:site",
    });
    expect(totp.isError, totp.text).toBe(false);
    const code = (totp.json as { code: string; expires_in: number }).code;
    expect(code).toMatch(/^\d{6}$/);

    const logout = await stack.mcp.callTool("logout", {
      session_id: result.session_id,
    });
    expect(logout.isError, logout.text).toBe(false);
  } finally {
    // The teardown leak check asserts no canary reached any agent surface
    await stopPhase3Stack(stack);
  }
});

test("AC-44: get_totp refuses a pass entry not opted in by name", async () => {
  // Given: a pass entry with a seed but absent from totp_exposable
  const stack = await passStack();
  try {
    // When: get_totp is called for it
    const totp = await stack.mcp.callTool("get_totp", {
      cred_id: "pass:site-no-totp",
    });

    // Then: the call is refused with TOTP_NOT_EXPOSABLE
    expect(totp.isError).toBe(true);
    expect(totp.text).toBe("TOTP_NOT_EXPOSABLE");
  } finally {
    await stopPhase3Stack(stack);
  }
});
