// AC-173 .. AC-182 — persistent cookies for authorize_device and the OAuth
// proxy login: the #45 store is shared with `login` (same key, same
// `persist_cookies`), a restored cookie skips the login steps only when the
// device approval page actually appears, a rejected or ineffective cookie
// falls back to the login steps, and approval is never skipped.
// Traceability: docs/secret/briefs/tegata-issue49-device-oauth-cookies.md
// acceptance condition AC-173 .. AC-182.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import {
  type DeviceCookieFixtureState,
  type DeviceCookieStack,
  deviceApproved,
  deviceCookieFixtureState,
  gatedVerificationUrl,
  invalidateDeviceSessions,
  issueDeviceCode,
  OAUTH_PROXY_NAME,
  openVerificationUrl,
  startDeviceCookieStack,
  stopDeviceCookieStack,
} from "./support/device-oauth-cookies.js";
import { type McpResult, rawRpc } from "./support/harness.js";
import {
  cookieFixtureState,
  cookieLoginParams,
  cookieStoreFiles,
} from "./support/persistent-cookies.js";
import {
  type AuditRecord,
  readAuditRecords,
  waitUntil,
} from "./support/phase3.js";
import { issuePeer, type LoginResult, tcpRpc } from "./support/phase4.js";

type RpcResponse = Awaited<ReturnType<typeof rawRpc>>;
type RecordedRequest = DeviceCookieFixtureState["requests"][number];

interface DeviceCall {
  credId?: string;
  verificationUrl?: string;
  userCode?: string;
  failureSelector?: string;
}

interface OpenProxy {
  session_id: string;
  base_url: string;
}

interface OAuthState {
  grants: { device_code: number; refresh_token: number };
  issued: number;
}

/** authorize_device parameters on the fixture's gated approval page. */
function deviceParams(
  stack: DeviceCookieStack,
  call: DeviceCall & { userCode: string },
): Record<string, unknown> {
  return {
    cred_id: call.credId ?? "mock:site",
    verification_url:
      call.verificationUrl ?? gatedVerificationUrl(stack.fixture),
    user_code: call.userCode,
    success_selector: "#device-ok",
    ...(call.failureSelector === undefined
      ? {}
      : { failure_selector: call.failureSelector }),
  };
}

/** authorize_device over the UNIX socket with a freshly issued code. */
async function authorizeDevice(
  stack: DeviceCookieStack,
  call: DeviceCall = {},
): Promise<{ response: RpcResponse; userCode: string }> {
  const userCode = call.userCode ?? (await issueDeviceCode(stack.fixture));
  const response = await rawRpc(
    stack.daemon.socketPath,
    "authorize_device",
    deviceParams(stack, { ...call, userCode }),
  );
  stack.observe("rpc:authorize_device", response);
  return { response, userCode };
}

/** authorize_device that must succeed and approve its code at the fixture. */
async function authorizeDeviceOk(
  stack: DeviceCookieStack,
  call: DeviceCall = {},
): Promise<RpcResponse> {
  const { response, userCode } = await authorizeDevice(stack, call);
  expect(
    response.error,
    `authorize_device failed: ${JSON.stringify(response.error)}`,
  ).toBeUndefined();
  expect(response.result).toEqual({ ok: true });
  expect(await deviceApproved(stack.fixture, userCode)).toBe(true);
  return response;
}

/** Login through the MCP tool on the #45 login site; asserts success. */
async function login(
  stack: DeviceCookieStack,
  credId: string,
): Promise<LoginResult> {
  const res = await stack.mcp.callTool(
    "login",
    cookieLoginParams(stack.fixture, credId),
  );
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

/** Open the OAuth proxy through the MCP tool; asserts success. */
async function openProxy(
  stack: DeviceCookieStack,
): Promise<{ mcp: McpResult; session: OpenProxy }> {
  const mcp = await stack.mcp.callTool("open_api_proxy", {
    name: OAUTH_PROXY_NAME,
  });
  expect(mcp.isError, `open_api_proxy failed: ${mcp.text}`).toBe(false);
  const session = mcp.json as OpenProxy;
  expect(typeof session.session_id).toBe("string");
  expect(typeof session.base_url).toBe("string");
  return { mcp, session };
}

/** Close a proxy session with logout and wait until its lease is gone. */
async function closeProxy(
  stack: DeviceCookieStack,
  sessionId: string,
): Promise<McpResult> {
  const res = await stack.mcp.callTool("logout", { session_id: sessionId });
  expect(res.isError, `logout failed: ${res.text}`).toBe(false);
  await waitUntil(
    "the proxy lease to be released",
    async () => {
      const status = await rawRpc(stack.daemon.socketPath, "status", {});
      return (status.result as { leases?: number } | undefined)?.leases === 0;
    },
    15_000,
  );
  return res;
}

/** The fixture user through an open proxy (the issued token works). */
async function proxiedUser(session: OpenProxy): Promise<unknown> {
  const res = await fetch(`${session.base_url}/api/me`);
  expect(res.status).toBe(200);
  return res.json();
}

async function oauthState(stack: DeviceCookieStack): Promise<OAuthState> {
  const res = await fetch(`${stack.fixture.url}/oauth/state`);
  expect(res.status).toBe(200);
  return (await res.json()) as OAuthState;
}

/** Logout of a login session over the UNIX socket. */
async function logout(
  stack: DeviceCookieStack,
  sessionId: string,
): Promise<RpcResponse> {
  const res = await rawRpc(stack.daemon.socketPath, "logout", {
    session_id: sessionId,
  });
  stack.observe("rpc:logout", res);
  expect(
    res.error,
    `logout failed: ${JSON.stringify(res.error)}`,
  ).toBeUndefined();
  return res;
}

/** Wait until the cookie store holds at least `count` files. */
async function waitForStoredFiles(
  stack: DeviceCookieStack,
  count: number,
): Promise<string[]> {
  await waitUntil(
    `the cookie store to hold ${count} file(s)`,
    () => cookieStoreFiles(stack.daemon.stateDir).length >= count,
    15_000,
  );
  return cookieStoreFiles(stack.daemon.stateDir);
}

/** Successful audit records of a method, oldest first, once `count` exist. */
async function okRecords(
  stack: DeviceCookieStack,
  method: string,
  count: number,
): Promise<AuditRecord[]> {
  const read = () =>
    readAuditRecords(stack.daemon.auditLogPath).records.filter(
      (r) => r.method === method && r.outcome === "ok",
    );
  await waitUntil(
    `${count} successful ${method} audit record(s)`,
    () => read().length >= count,
    10_000,
  );
  return read();
}

/** The successful login audit record of a session. */
function loginRecord(
  stack: DeviceCookieStack,
  sessionId: string,
): AuditRecord | undefined {
  return readAuditRecords(stack.daemon.auditLogPath).records.find(
    (r) =>
      r.method === "login" && r.outcome === "ok" && r.session_id === sessionId,
  );
}

interface Measured<T> {
  value: T;
  /** Login form POSTs at the fixture while the action ran. */
  posts: number;
  /** Device approvals at the `/device-cookies/` pages while the action ran. */
  approvals: number;
  /** `/device-cookies/` requests made while the action ran, in order. */
  requests: RecordedRequest[];
}

/** Run `action` and measure what the fixture saw meanwhile. */
async function during<T>(
  stack: DeviceCookieStack,
  action: () => Promise<T>,
): Promise<Measured<T>> {
  const before = await deviceCookieFixtureState(stack.fixture);
  const value = await action();
  const after = await deviceCookieFixtureState(stack.fixture);
  return {
    value,
    posts: after.login_posts - before.login_posts,
    approvals: after.approvals - before.approvals,
    requests: after.requests.slice(before.requests.length),
  };
}

function routes(requests: RecordedRequest[]): string[] {
  return requests.map((r) => `${r.method} ${r.path}`);
}

test("AC-173: without persist_cookies authorize_device stores and restores nothing", async () => {
  // Given: persist_cookies is not set
  const stack = await startDeviceCookieStack();
  try {
    // When: authorize_device twice with the same credential
    const run = await during(stack, async () => {
      await authorizeDeviceOk(stack);
      await authorizeDeviceOk(stack);
    });

    // Then: both succeed, the login form is posted twice in total, the
    // cookie store holds no file, and no authorize_device record carries
    // cookies/steps_skipped
    expect(run.posts).toBe(2);
    expect(run.approvals).toBe(2);
    expect(cookieStoreFiles(stack.daemon.stateDir)).toEqual([]);
    const records = await okRecords(stack, "authorize_device", 2);
    expect(records).toHaveLength(2);
    for (const record of records) {
      expect(record).not.toHaveProperty("cookies");
      expect(record).not.toHaveProperty("steps_skipped");
    }
  } finally {
    await stopDeviceCookieStack(stack);
  }
});

test("AC-174: a persisted credential's second authorize_device skips the login", async () => {
  // Given: persist_cookies = ["site"]
  const stack = await startDeviceCookieStack({ persistCookies: ["site"] });
  try {
    // When: authorize_device twice
    const first = await during(stack, () => authorizeDeviceOk(stack));
    const second = await during(stack, () => authorizeDeviceOk(stack));

    // Then: both succeed with one login POST and two approvals in total
    expect(first.posts + second.posts).toBe(1);
    expect(first.approvals + second.approvals).toBe(2);

    // Then: the records are none/false, then restored/true
    const records = await okRecords(stack, "authorize_device", 2);
    expect(records).toHaveLength(2);
    expect(records[0].cookies).toBe("none");
    expect(records[0].steps_skipped).toBe(false);
    expect(records[1].cookies).toBe("restored");
    expect(records[1].steps_skipped).toBe(true);

    // Then: each RPC response is exactly { ok: true }
    for (const run of [first, second]) {
      expect(run.value.result).toEqual({ ok: true });
      expect(Object.keys(run.value.result as object)).toEqual(["ok"]);
    }
  } finally {
    await stopDeviceCookieStack(stack);
  }
});

test("AC-175: login and authorize_device share the stored cookies", async () => {
  // Given: persist_cookies = ["*"]
  const stack = await startDeviceCookieStack({ persistCookies: ["*"] });
  try {
    // When: login -> logout -> authorize_device on credential A
    const aLogin = await login(stack, "mock:site");
    await logout(stack, aLogin.session_id);
    await waitForStoredFiles(stack, 1);
    const aDevice = await during(stack, () =>
      authorizeDeviceOk(stack, { credId: "mock:site" }),
    );

    // When: authorize_device -> login on another credential B
    await authorizeDeviceOk(stack, { credId: "mock:site-b" });
    await waitForStoredFiles(stack, 2);
    const bLogin = await during(stack, () => login(stack, "mock:site-b"));

    // Then: A's authorize_device is restored/true without a login POST
    expect(aDevice.posts).toBe(0);
    const aRecords = (await okRecords(stack, "authorize_device", 2)).filter(
      (r) => r.cred_id === "mock:site",
    );
    expect(aRecords).toHaveLength(1);
    expect(aRecords[0].cookies).toBe("restored");
    expect(aRecords[0].steps_skipped).toBe(true);

    // Then: B's login is restored/true without a login POST
    expect(bLogin.posts).toBe(0);
    const bRecord = loginRecord(stack, bLogin.value.session_id);
    expect(bRecord?.cookies).toBe("restored");
    expect(bRecord?.steps_skipped).toBe(true);
  } finally {
    await stopDeviceCookieStack(stack);
  }
}, 240_000);

test("AC-176: the OAuth proxy login restores the stored cookies", async () => {
  // Given: persist_cookies = ["*"] and the OAuth [[api_proxy]]
  const stack = await startDeviceCookieStack({
    persistCookies: ["*"],
    oauth: true,
  });
  let openSession: string | undefined;
  try {
    // When: open_api_proxy -> close -> open_api_proxy
    const first = await during(stack, () => openProxy(stack));
    openSession = first.value.session.session_id;
    expect(await proxiedUser(first.value.session)).toEqual({ user: "fixture" });
    await closeProxy(stack, first.value.session.session_id);
    openSession = undefined;
    const second = await during(stack, () => openProxy(stack));
    openSession = second.value.session.session_id;

    // Then: both succeed and each is issued a working token
    expect(await proxiedUser(second.value.session)).toEqual({
      user: "fixture",
    });
    expect((await oauthState(stack)).grants.device_code).toBe(2);

    // Then: one login POST in total; the second open_api_proxy record is
    // restored/true
    expect(first.posts + second.posts).toBe(1);
    const records = await okRecords(stack, "open_api_proxy", 2);
    expect(records).toHaveLength(2);
    expect(records[1].cookies).toBe("restored");
    expect(records[1].steps_skipped).toBe(true);
  } finally {
    if (openSession !== undefined)
      await stack.mcp
        .callTool("logout", { session_id: openSession })
        .catch(() => {});
    await stopDeviceCookieStack(stack);
  }
}, 240_000);

test("AC-177: a voided restored cookie falls back to the login steps", async () => {
  // Given: stored cookies (from authorize_device) and the fixture has voided
  // `device`
  const stack = await startDeviceCookieStack({ persistCookies: ["site"] });
  try {
    await authorizeDeviceOk(stack);
    await waitForStoredFiles(stack, 1);
    await invalidateDeviceSessions(stack.fixture);

    // When: authorize_device
    const run = await during(stack, () => authorizeDeviceOk(stack));

    // Then: the login steps run and it succeeds, audited as
    // restored / steps_skipped: false
    expect(run.posts).toBe(1);
    expect(run.approvals).toBe(1);
    const records = await okRecords(stack, "authorize_device", 2);
    expect(records[1].cookies).toBe("restored");
    expect(records[1].steps_skipped).toBe(false);
  } finally {
    await stopDeviceCookieStack(stack);
  }
});

test("AC-178: an approval form shown without a login falls back to the login steps", async () => {
  // Given: stored cookies that the fixture no longer honours, and the
  // fixture variant whose approval form is shown empty without a login and
  // redirects its submission to the login page
  const stack = await startDeviceCookieStack({ persistCookies: ["site"] });
  try {
    await authorizeDeviceOk(stack);
    await waitForStoredFiles(stack, 1);
    await invalidateDeviceSessions(stack.fixture);

    // When: authorize_device on that variant
    const run = await during(stack, () =>
      authorizeDeviceOk(stack, {
        verificationUrl: openVerificationUrl(stack.fixture),
      }),
    );

    // Then: the approval page was tried first (steps skipped), its
    // submission was sent to the login page, the login steps then ran as a
    // fallback, and it succeeded with steps_skipped: false
    const seen = routes(run.requests);
    expect(seen[0]).toBe("GET /device-cookies/open");
    const firstSubmit = seen.indexOf("POST /device-cookies/device");
    const firstLogin = seen.indexOf("GET /device-cookies/login");
    expect(firstSubmit).toBeGreaterThanOrEqual(0);
    expect(firstLogin).toBeGreaterThan(firstSubmit);
    expect(run.posts).toBe(1);
    expect(run.approvals).toBe(1);
    const records = await okRecords(stack, "authorize_device", 2);
    expect(records[1].cookies).toBe("restored");
    expect(records[1].steps_skipped).toBe(false);
  } finally {
    await stopDeviceCookieStack(stack);
  }
});

test("AC-179: cookies stored by authorize_device are not shared across principals", async () => {
  // Given: principal P1 (UNIX socket uid) has stored cookies through
  // authorize_device
  const stack = await startDeviceCookieStack({
    persistCookies: ["*"],
    tcp: true,
  });
  try {
    await authorizeDeviceOk(stack, { credId: "mock:site" });
    await waitForStoredFiles(stack, 1);
    const p2 = await issuePeer(stack.daemon.socketPath, "p2");

    // When: another principal P2 (peer token) runs authorize_device on the
    // same credential
    const userCode = await issueDeviceCode(stack.fixture);
    const run = await during(stack, () =>
      tcpRpc(
        stack.daemon.tcpPort as number,
        p2.token,
        "authorize_device",
        deviceParams(stack, { credId: "mock:site", userCode }),
      ),
    );
    stack.observe("tcp:authorize_device", run.value);
    expect(run.value.preamble).toBeUndefined();
    expect(run.value.error, JSON.stringify(run.value.error)).toBeUndefined();
    expect(run.value.result).toEqual({ ok: true });

    // Then: P2 posts the login form and its first request has no `device`
    expect(run.posts).toBe(1);
    expect(run.requests.length).toBeGreaterThan(0);
    expect(run.requests[0].cookies).not.toContain("device");
  } finally {
    await stopDeviceCookieStack(stack);
  }
});

test("AC-180: a rejected device code leaves the stored cookies untouched", async () => {
  // Given: stored cookies (from authorize_device)
  const stack = await startDeviceCookieStack({ persistCookies: ["site"] });
  try {
    await authorizeDeviceOk(stack);
    const files = await waitForStoredFiles(stack, 1);
    const bytes = files.map((file) => fs.readFileSync(file));

    // When: authorize_device fails on a device code the fixture rejects
    const { response } = await authorizeDevice(stack, {
      userCode: "UNISSUED-DEVICE-CODE",
      failureSelector: "#device-error",
    });

    // Then: DEVICE_CODE_REJECTED, and the stored file bytes are unchanged
    expect(response.result).toBeUndefined();
    expect(response.error?.message).toBe("DEVICE_CODE_REJECTED");
    expect(cookieStoreFiles(stack.daemon.stateDir).sort()).toEqual(
      [...files].sort(),
    );
    files.forEach((file, i) => {
      expect(fs.readFileSync(file).equals(bytes[i])).toBe(true);
    });
  } finally {
    await stopDeviceCookieStack(stack);
  }
});

test("AC-181: stored cookies never skip approve_cmd", async () => {
  // Given: stored cookies (from an approved authorize_device), then an
  // approve_cmd that refuses every request
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-dck-hook-"));
  const control = path.join(scratch, "control");
  fs.writeFileSync(control, "allow");
  const stack = await startDeviceCookieStack({
    persistCookies: ["*"],
    oauth: true,
    approveCmd: `test "$(cat ${JSON.stringify(control)})" = allow`,
  });
  try {
    await authorizeDeviceOk(stack);
    await waitForStoredFiles(stack, 1);
    fs.writeFileSync(control, "deny");
    const loginSiteBefore = await cookieFixtureState(stack.fixture);
    const oauthBefore = await oauthState(stack);

    // When: authorize_device and open_api_proxy
    const run = await during(stack, async () => {
      const device = await authorizeDevice(stack);
      const proxy = await stack.mcp.callTool("open_api_proxy", {
        name: OAUTH_PROXY_NAME,
      });
      return { device: device.response, proxy };
    });

    // Then: both are APPROVAL_DENIED
    expect(run.value.device.result).toBeUndefined();
    expect(run.value.device.error?.message).toBe("APPROVAL_DENIED");
    expect(run.value.proxy.isError).toBe(true);
    expect(run.value.proxy.text).toBe("APPROVAL_DENIED");

    // Then: the fixture saw no request (cookies do not skip approval)
    const loginSiteAfter = await cookieFixtureState(stack.fixture);
    expect(run.requests).toEqual([]);
    expect(run.posts).toBe(0);
    expect(loginSiteAfter.requests.length).toBe(
      loginSiteBefore.requests.length,
    );
    expect(await oauthState(stack)).toEqual(oauthBefore);
  } finally {
    await stopDeviceCookieStack(stack);
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}, 240_000);

/** Every `device` and `sid` value the fixture issued found on the surfaces. */
async function cookieValueHits(
  stack: DeviceCookieStack,
  surfaces: Array<{ label: string; text: string }>,
): Promise<string[]> {
  const all = [
    ...surfaces,
    {
      label: "audit",
      text: JSON.stringify(readAuditRecords(stack.daemon.auditLogPath).records),
    },
    { label: "stderr", text: stack.daemon.stderr() },
  ];
  const state = await cookieFixtureState(stack.fixture);
  expect(state.device_values.length).toBeGreaterThan(0);
  expect(state.sid_values.length).toBeGreaterThan(0);
  const values = [...state.device_values, ...state.sid_values];
  return all.flatMap(({ label, text }) =>
    values.filter((v) => text.includes(v)).map((v) => `${label}: ${v}`),
  );
}

test("AC-182: cookie values never reach responses, audit, or stderr", async () => {
  // Given: the whole AC-174 run (persist_cookies = ["site"], authorize_device
  // twice over RPC)
  const device = await startDeviceCookieStack({ persistCookies: ["site"] });
  let deviceHits: string[];
  try {
    const surfaces: Array<{ label: string; text: string }> = [];
    for (let i = 0; i < 2; i += 1) {
      const { response } = await authorizeDevice(device);
      surfaces.push({
        label: "rpc:authorize_device",
        text: JSON.stringify(response),
      });
      expect(response.result).toEqual({ ok: true });
    }
    const records = await okRecords(device, "authorize_device", 2);
    expect(records[1].cookies).toBe("restored");

    // When: the responses, the audit log, and the daemon stderr are scanned
    deviceHits = await cookieValueHits(device, surfaces);
  } finally {
    await stopDeviceCookieStack(device);
  }

  // Given: the whole AC-176 run (persist_cookies = ["*"], OAuth proxy
  // open -> close -> open over MCP)
  const proxy = await startDeviceCookieStack({
    persistCookies: ["*"],
    oauth: true,
  });
  let proxyHits: string[];
  try {
    const surfaces: Array<{ label: string; text: string }> = [];
    const first = await openProxy(proxy);
    surfaces.push({ label: "mcp:open_api_proxy", text: JSON.stringify(first) });
    const closed = await closeProxy(proxy, first.session.session_id);
    surfaces.push({ label: "mcp:logout", text: JSON.stringify(closed) });
    const second = await openProxy(proxy);
    surfaces.push({
      label: "mcp:open_api_proxy",
      text: JSON.stringify(second),
    });
    const records = await okRecords(proxy, "open_api_proxy", 2);
    expect(records[1].cookies).toBe("restored");
    const last = await closeProxy(proxy, second.session.session_id);
    surfaces.push({ label: "mcp:logout", text: JSON.stringify(last) });

    // When: the responses, the audit log, and the daemon stderr are scanned
    proxyHits = await cookieValueHits(proxy, surfaces);
  } finally {
    await stopDeviceCookieStack(proxy);
  }

  // Then: no `device` or `sid` canary value appears anywhere
  expect(deviceHits).toEqual([]);
  expect(proxyHits).toEqual([]);
}, 240_000);
