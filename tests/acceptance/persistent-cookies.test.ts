// AC-147 .. AC-158 — persistent cookies per credential: opt-in per provider
// with `persist_cookies`, keyed by (principal, namespace, cred_id), only
// unexpired persistent cookies survive, restored cookies may skip the login
// steps, and the store is private, cleaned on startup, and forgettable.
// Traceability: docs/secret/briefs/tegata-issue45-persistent-cookies.md
// acceptance condition AC-147 .. AC-158.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { type CanarySet, type MockEntry, rawRpc } from "./support/harness.js";
import {
  browserCount,
  type CookieProviderSpec,
  type CookieStack,
  cookieEntries,
  cookieFixtureState,
  cookieLoginParams,
  cookieStoreDir,
  cookieStoreFiles,
  cookiesForgetCli,
  invalidateDeviceCookies,
  loginRecord,
  sessionEndRecords,
  startCookieStack,
  stopCookieStack,
  waitForBrowserCount,
} from "./support/persistent-cookies.js";
import {
  ageEncrypt,
  ageKeygen,
  readAuditRecords,
  renderAgeEntriesToml,
  waitUntil,
} from "./support/phase3.js";
import { issuePeer, type LoginResult, tcpRpc } from "./support/phase4.js";

const UID_PRINCIPAL = `uid:${os.userInfo().uid}`;

/** A mock provider over the suite's credentials A (site) and B (site-b). */
function mockProvider(
  persistCookies?: string[],
): (canaries: CanarySet) => CookieProviderSpec[] {
  return (canaries) => [
    {
      type: "mock",
      namespace: "mock",
      entries: cookieEntries(canaries),
      persistCookies,
    },
  ];
}

/** Login through the MCP tool (the agent-facing surface); asserts success. */
async function login(
  stack: CookieStack,
  credId = "mock:site",
): Promise<LoginResult> {
  const res = await stack.mcp.callTool(
    "login",
    cookieLoginParams(stack.fixture, credId),
  );
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

/**
 * Logout of a session that holds its own browser, over the UNIX socket, and
 * wait until that browser is gone (the session end has completed).
 */
async function logout(
  stack: CookieStack,
  sessionId: string,
): Promise<Awaited<ReturnType<typeof rawRpc>>> {
  const browsers = browserCount(stack);
  const res = await rawRpc(stack.daemon.socketPath, "logout", {
    session_id: sessionId,
  });
  stack.observe("rpc:logout", res);
  expect(
    res.error,
    `logout failed: ${JSON.stringify(res.error)}`,
  ).toBeUndefined();
  await waitForBrowserCount(stack, browsers - 1);
  return res;
}

interface Cycle {
  first: LoginResult;
  second: LoginResult;
  /** Form POSTs made by the first and by the second login. */
  firstPosts: number;
  secondPosts: number;
  /** Cookie names of the fixture requests made by the second login. */
  secondRequestCookies: string[][];
}

/** login -> logout -> login on one credential, measured at the fixture. */
async function loginLogoutLogin(
  stack: CookieStack,
  credId = "mock:site",
): Promise<Cycle> {
  const start = await cookieFixtureState(stack.fixture);
  const first = await login(stack, credId);
  await logout(stack, first.session_id);
  const middle = await cookieFixtureState(stack.fixture);
  const second = await login(stack, credId);
  const end = await cookieFixtureState(stack.fixture);
  return {
    first,
    second,
    firstPosts: middle.login_posts - start.login_posts,
    secondPosts: end.login_posts - middle.login_posts,
    secondRequestCookies: end.requests
      .slice(middle.requests.length)
      .map((r) => r.cookies),
  };
}

/** Form POSTs made while `action` runs. */
async function postsDuring<T>(
  stack: CookieStack,
  action: () => Promise<T>,
): Promise<{ value: T; posts: number; requestCookies: string[][] }> {
  const before = await cookieFixtureState(stack.fixture);
  const value = await action();
  const after = await cookieFixtureState(stack.fixture);
  return {
    value,
    posts: after.login_posts - before.login_posts,
    requestCookies: after.requests
      .slice(before.requests.length)
      .map((r) => r.cookies),
  };
}

test("AC-147: without persist_cookies nothing is stored or restored", async () => {
  // Given: persist_cookies is not set
  const stack = await startCookieStack({ providers: mockProvider() });
  try {
    // When: login -> logout -> login on the same credential
    const cycle = await loginLogoutLogin(stack);

    // Then: the second login posts the form too (two in total), the cookie
    // store holds no file, and no login record carries cookies/steps_skipped
    expect(cycle.firstPosts + cycle.secondPosts).toBe(2);
    expect(cookieStoreFiles(stack.daemon.stateDir)).toEqual([]);
    for (const sessionId of [cycle.first.session_id, cycle.second.session_id]) {
      const record = loginRecord(stack, sessionId);
      expect(record).toBeDefined();
      expect(record).not.toHaveProperty("cookies");
      expect(record).not.toHaveProperty("steps_skipped");
    }
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-148: a persisted credential's second login skips the form", async () => {
  // Given: persist_cookies = ["site"]
  const stack = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    // When: login -> logout -> login
    const cycle = await loginLogoutLogin(stack);

    // Then: the second login succeeds with no further form POST (one in
    // total) and its first request carries `device`
    expect(cycle.firstPosts).toBe(1);
    expect(cycle.secondPosts).toBe(0);
    expect(cycle.secondRequestCookies[0]).toContain("device");

    // Then: the login records are none/false, then restored/true
    const first = loginRecord(stack, cycle.first.session_id);
    expect(first?.cookies).toBe("none");
    expect(first?.steps_skipped).toBe(false);
    const second = loginRecord(stack, cycle.second.session_id);
    expect(second?.cookies).toBe("restored");
    expect(second?.steps_skipped).toBe(true);

    // Then: the first session's end record carries cookies_saved: true
    await waitUntil(
      "a session-end record with cookies_saved",
      () => sessionEndRecords(stack, cycle.first.session_id).length > 0,
      10_000,
    );
    const ends = sessionEndRecords(stack, cycle.first.session_id);
    expect(ends.map((r) => r.cookies_saved)).toContain(true);
    expect(ends.map((r) => r.cookies_saved)).not.toContain(false);
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-149: session cookies are not carried over", async () => {
  // Given: the AC-148 configuration (persist_cookies = ["site"])
  const stack = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    // When: login -> logout -> login
    const cycle = await loginLogoutLogin(stack);

    // Then: the second login's first request does not carry `sid` (the
    // `device` check confirms the Given: cookies are carried at all)
    const firstRequest = cycle.secondRequestCookies[0];
    expect(firstRequest).toContain("device");
    expect(firstRequest).not.toContain("sid");
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-150: '*' persists every credential, a list only the listed ones", async () => {
  // Given: credentials A and B of one provider, persist_cookies = ["*"]
  const all = await startCookieStack({ providers: mockProvider(["*"]) });
  try {
    // When: login -> logout -> login on each credential
    const a = await loginLogoutLogin(all, "mock:site");
    const b = await loginLogoutLogin(all, "mock:site-b");

    // Then: both second logins are restored
    expect(loginRecord(all, a.second.session_id)?.cookies).toBe("restored");
    expect(loginRecord(all, b.second.session_id)?.cookies).toBe("restored");
  } finally {
    await stopCookieStack(all);
  }

  // Given: the same credentials, persist_cookies = ["site"] (A only)
  const listed = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    // When: login -> logout -> login on each credential
    const a = await loginLogoutLogin(listed, "mock:site");
    const b = await loginLogoutLogin(listed, "mock:site-b");

    // Then: only A is restored; B posts the form twice
    expect(loginRecord(listed, a.second.session_id)?.cookies).toBe("restored");
    expect(loginRecord(listed, b.second.session_id)?.cookies).not.toBe(
      "restored",
    );
    expect(b.firstPosts + b.secondPosts).toBe(2);
  } finally {
    await stopCookieStack(listed);
  }
}, 240_000);

test("AC-151: cookies are not shared across principals", async () => {
  // Given: persist_cookies = ["*"], principal P1 (UNIX socket uid) has
  // logged in and out of A
  const stack = await startCookieStack({
    providers: mockProvider(["*"]),
    tcp: true,
  });
  try {
    const p1 = await login(stack, "mock:site");
    await logout(stack, p1.session_id);
    expect(cookieStoreFiles(stack.daemon.stateDir).length).toBe(1);
    const p2 = await issuePeer(stack.daemon.socketPath, "p2");

    // When: another principal P2 (peer token) logs in to A
    const { value: res, ...seen } = await postsDuring(stack, () =>
      tcpRpc(
        stack.daemon.tcpPort as number,
        p2.token,
        "login",
        cookieLoginParams(stack.fixture, "mock:site"),
      ),
    );
    stack.observe("tcp:login", res);
    expect(res.preamble).toBeUndefined();
    expect(res.error, JSON.stringify(res.error)).toBeUndefined();

    // Then: P2's login posts the form and its first request has no `device`
    expect(seen.posts).toBe(1);
    expect(seen.requestCookies[0]).not.toContain("device");
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-152: the cookie store is private and holds no credential secret", async () => {
  // Given: the AC-148 run (persist_cookies = ["site"], login -> logout -> login)
  const stack = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    await loginLogoutLogin(stack);

    // When: <state_dir>/cookies/ is inspected
    const dir = cookieStoreDir(stack.daemon.stateDir);
    const files = cookieStoreFiles(stack.daemon.stateDir);

    // Then: the directory is 0700, each file is 0600 and owned by the daemon
    // uid, file names reveal neither cred_id nor principal, and no file
    // holds the credential's username, password, or TOTP seed canary
    expect(fs.lstatSync(dir).mode & 0o777).toBe(0o700);
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const stat = fs.lstatSync(file);
      expect(stat.mode & 0o777).toBe(0o600);
      expect(stat.uid).toBe(os.userInfo().uid);
      const name = path.basename(file);
      expect(name).toMatch(/^[0-9a-f]{64}\.[a-z]+$/);
      expect(name).not.toContain("mock:site");
      expect(name).not.toContain(UID_PRINCIPAL);
      const content = fs.readFileSync(file, "utf8");
      const { username, password, totpSeed } = stack.canaries;
      for (const canary of [username, password, totpSeed])
        expect(content.includes(canary)).toBe(false);
    }
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-153: lock_vault keeps the store; the next login restores", async () => {
  // Given: an age-file provider (unlocked again by its ceremony) with
  // persist_cookies = ["site"], after the first login and logout
  const stack = await startCookieStack({
    providers: (canaries, materialsDir) => {
      const { identityPath, recipient } = ageKeygen(materialsDir);
      const entries: MockEntry[] = [
        {
          id: "site",
          name: "Age Persistent Cookie Site",
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
          persistCookies: ["site"],
        },
      ];
    },
  });
  try {
    const first = await login(stack, "age:site");
    await logout(stack, first.session_id);

    // When: lock_vault -> the implicit unlock ceremony -> login
    const locked = await stack.mcp.callTool("lock_vault", {
      namespace: "age",
    });
    expect(locked.isError, locked.text).toBe(false);
    const { value: second, posts } = await postsDuring(stack, () =>
      login(stack, "age:site"),
    );

    // Then: the login is restored and succeeds without a form POST
    expect(loginRecord(stack, second.session_id)?.cookies).toBe("restored");
    expect(posts).toBe(0);
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-154: an operator forgets one credential or all; others are refused", async () => {
  // Given: stored cookies for A and B
  const stack = await startCookieStack({
    providers: mockProvider(["*"]),
    tcp: true,
  });
  try {
    const a0 = await login(stack, "mock:site");
    await logout(stack, a0.session_id);
    const b0 = await login(stack, "mock:site-b");
    await logout(stack, b0.session_id);
    expect(cookieStoreFiles(stack.daemon.stateDir).length).toBe(2);

    // When: the operator forgets A, then A and B log in
    const forgetA = await rawRpc(
      stack.daemon.socketPath,
      "admin_cookies_forget",
      { cred_id: "mock:site" },
    );
    stack.observe("rpc:admin_cookies_forget", forgetA);
    expect(forgetA.error, JSON.stringify(forgetA.error)).toBeUndefined();
    const a1 = await postsDuring(stack, () => login(stack, "mock:site"));
    const b1 = await postsDuring(stack, () => login(stack, "mock:site-b"));

    // Then: removed >= 1; A posts the form and is "none", B is restored
    expect(
      (forgetA.result as { removed: number }).removed,
    ).toBeGreaterThanOrEqual(1);
    expect(a1.posts).toBe(1);
    expect(loginRecord(stack, a1.value.session_id)?.cookies).toBe("none");
    expect(b1.posts).toBe(0);
    expect(loginRecord(stack, b1.value.session_id)?.cookies).toBe("restored");

    // When: both sessions end, then `tegatad cookies forget --all`, then B
    await logout(stack, a1.value.session_id);
    await logout(stack, b1.value.session_id);
    const forgetAll = cookiesForgetCli(stack.daemon.socketPath, { all: true });
    expect(forgetAll.status, forgetAll.stderr).toBe(0);
    const b2 = await postsDuring(stack, () => login(stack, "mock:site-b"));

    // Then: B is "none" as well
    expect(b2.posts).toBe(1);
    expect(loginRecord(stack, b2.value.session_id)?.cookies).toBe("none");

    // When: a non-operator peer calls admin_cookies_forget
    await waitUntil(
      "B's cookies to be stored again",
      () => cookieStoreFiles(stack.daemon.stateDir).length > 0,
      10_000,
    );
    const kept = cookieStoreFiles(stack.daemon.stateDir).sort();
    const peer = await issuePeer(stack.daemon.socketPath, "non-operator");
    const refused = await tcpRpc(
      stack.daemon.tcpPort as number,
      peer.token,
      "admin_cookies_forget",
      { all: true },
      10_000,
    );
    stack.observe("tcp:admin_cookies_forget", refused);

    // Then: it is refused and the files remain
    expect(refused.preamble).toBeUndefined();
    expect(refused.error?.message).toBe("ADMIN_REQUIRED");
    expect(cookieStoreFiles(stack.daemon.stateDir).sort()).toEqual(kept);
  } finally {
    await stopCookieStack(stack);
  }
}, 240_000);

test("AC-155: dropping a credential from the list deletes its file at startup", async () => {
  // Given: a stored file for A (persist_cookies = ["site"])
  const stack = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    const first = await login(stack, "mock:site");
    await logout(stack, first.session_id);
    expect(cookieStoreFiles(stack.daemon.stateDir).length).toBe(1);

    // When: A is removed from persist_cookies and the daemon restarts
    await stack.daemon.restart(mockProvider(["site-b"])(stack.canaries));
    await stack.reconnectMcp();

    // Then: A's file is gone, A's login posts the form, and its login
    // record has no `cookies` field
    expect(cookieStoreFiles(stack.daemon.stateDir)).toEqual([]);
    const { value: again, posts } = await postsDuring(stack, () =>
      login(stack, "mock:site"),
    );
    expect(posts).toBe(1);
    const record = loginRecord(stack, again.session_id);
    expect(record).toBeDefined();
    expect(record).not.toHaveProperty("cookies");
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-156: a rejected restored cookie falls back to the login steps", async () => {
  // Given: stored cookies for A, and the fixture has voided `device`
  const stack = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    const first = await login(stack, "mock:site");
    await logout(stack, first.session_id);
    expect(cookieStoreFiles(stack.daemon.stateDir).length).toBe(1);
    await invalidateDeviceCookies(stack.fixture);

    // When: A logs in
    const { value: second, posts } = await postsDuring(stack, () =>
      login(stack, "mock:site"),
    );

    // Then: the steps run and the login succeeds, audited as
    // restored / steps_skipped: false
    expect(posts).toBe(1);
    const record = loginRecord(stack, second.session_id);
    expect(record?.cookies).toBe("restored");
    expect(record?.steps_skipped).toBe(false);
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-157: cookie values never reach responses, audit, or stderr", async () => {
  // Given: the whole AC-148 run (persist_cookies = ["site"])
  const stack = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    const surfaces: Array<{ label: string; text: string }> = [];
    const firstRes = await stack.mcp.callTool(
      "login",
      cookieLoginParams(stack.fixture, "mock:site"),
    );
    surfaces.push({ label: "mcp:login", text: JSON.stringify(firstRes) });
    expect(firstRes.isError, firstRes.text).toBe(false);
    const first = firstRes.json as LoginResult;
    const logoutRes = await logout(stack, first.session_id);
    surfaces.push({ label: "rpc:logout", text: JSON.stringify(logoutRes) });
    const secondRes = await stack.mcp.callTool(
      "login",
      cookieLoginParams(stack.fixture, "mock:site"),
    );
    surfaces.push({ label: "mcp:login", text: JSON.stringify(secondRes) });
    expect(secondRes.isError, secondRes.text).toBe(false);
    const second = secondRes.json as LoginResult;
    expect(loginRecord(stack, second.session_id)?.cookies).toBe("restored");

    // When: the responses, the audit log, and the daemon stderr are scanned
    const audit = readAuditRecords(stack.daemon.auditLogPath).records;
    surfaces.push({ label: "audit", text: JSON.stringify(audit) });
    surfaces.push({ label: "stderr", text: stack.daemon.stderr() });
    const state = await cookieFixtureState(stack.fixture);
    const values = [...state.device_values, ...state.sid_values];

    // Then: no `device` or `sid` canary value appears anywhere
    expect(state.device_values.length).toBeGreaterThan(0);
    expect(state.sid_values.length).toBeGreaterThan(0);
    const hits = surfaces.flatMap(({ label, text }) =>
      values.filter((v) => text.includes(v)).map((v) => `${label}: ${v}`),
    );
    expect(hits).toEqual([]);
  } finally {
    await stopCookieStack(stack);
  }
});

test("AC-158: a corrupt store file is replaced after a normal login", async () => {
  // Given: the stored file is overwritten with invalid JSON
  const stack = await startCookieStack({ providers: mockProvider(["site"]) });
  try {
    const first = await login(stack, "mock:site");
    await logout(stack, first.session_id);
    const files = cookieStoreFiles(stack.daemon.stateDir);
    expect(files.length).toBe(1);
    const garbage = "{ this is not json";
    fs.writeFileSync(files[0], garbage);

    // When: the credential logs in
    const { value: second, posts } = await postsDuring(stack, () =>
      login(stack, "mock:site"),
    );

    // Then: the steps run and the login succeeds, audited as "none", and
    // the corrupt file is replaced by new content
    expect(posts).toBe(1);
    expect(loginRecord(stack, second.session_id)?.cookies).toBe("none");
    await waitUntil(
      "the corrupt file to be replaced",
      () => {
        const now = cookieStoreFiles(stack.daemon.stateDir);
        if (!now.includes(files[0])) return false;
        const text = fs.readFileSync(files[0], "utf8");
        if (text === garbage) return false;
        try {
          JSON.parse(text);
          return true;
        } catch {
          return false;
        }
      },
      10_000,
    );
  } finally {
    await stopCookieStack(stack);
  }
});
