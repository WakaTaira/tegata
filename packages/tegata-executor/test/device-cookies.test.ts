import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
  vi,
} from "vitest";
import {
  type Cookie,
  cleanupResources,
  DeviceCodeRejectedError,
  firstDeviceStepSelector,
  formatDeviceAuthorizationFields,
  formatExecutorErrorLine,
  handleApiProxyStart,
  handleApiProxyStop,
  handleAuthorizeDevice,
  isLoginFallbackError,
  parseRequest,
  SelectorNotFoundError,
} from "../src/index.js";

const DEVICE_VALUE = "device-canary-5d21";
const SID_VALUE = "sid-canary-a8e0";
const USER_CODE = "WDJB-MJHT";
const DEVICE_CODE = "device-code-canary-3b7c";

const secret = {
  username: "alice@example.test",
  password: "correct-horse-battery",
  totp: null,
};

type RecordedRequest = { method: string; path: string; cookieNames: string[] };

// device cookie または sid セッションでログイン状態を判定する、承認ページ付きの最小のサイト。
const site = {
  posts: 0,
  approvals: 0,
  deviceValid: true,
  sidValid: false,
  approved: false,
  requests: [] as RecordedRequest[],
};

const loginForm = `
  <form method="post" action="/login">
    <input name="username" type="text">
    <input name="password" type="password">
    <button type="submit">Log in</button>
  </form>
`;

const entryForm = `
  <form method="post" action="/device">
    <input name="user_code" type="text">
    <button type="submit">Continue</button>
  </form>
`;

const authorizationForm = `
  <form method="post" action="/approve">
    <button type="submit">Authorize</button>
  </form>
`;

function html(body: string): string {
  return `<!doctype html><html><body>${body}</body></html>`;
}

function requestCookies(request: IncomingMessage): Map<string, string> {
  const pairs = (request.headers.cookie ?? "")
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part !== "")
    .map((part): [string, string] => {
      const separator = part.indexOf("=");
      return [part.slice(0, separator), part.slice(separator + 1)];
    });
  return new Map(pairs);
}

function isAuthenticated(request: IncomingMessage): boolean {
  const cookies = requestCookies(request);
  return (
    (site.deviceValid && cookies.get("device") === DEVICE_VALUE) ||
    (site.sidValid && cookies.get("sid") === SID_VALUE)
  );
}

async function readBody(request: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

let server: Server;
let origin: string;

beforeAll(async () => {
  server = createServer(async (request, response) => {
    const route = `${request.method} ${request.url}`;
    const body = await readBody(request);
    const page = (content: string, headers: Record<string, unknown> = {}) => {
      response.writeHead(200, { "content-type": "text/html", ...headers });
      response.end(html(content));
    };
    const json = (status: number, value: unknown) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(value));
    };
    if (route === "POST /oauth/device_authorization") {
      json(200, {
        device_code: DEVICE_CODE,
        user_code: USER_CODE,
        verification_uri: `${origin}/device`,
        expires_in: 300,
        interval: 1,
      });
      return;
    }
    if (route === "POST /oauth/token") {
      if (site.approved) {
        json(200, { access_token: "access-token-canary", expires_in: 3600 });
      } else {
        json(400, { error: "authorization_pending" });
      }
      return;
    }
    site.requests.push({
      method: request.method ?? "",
      path: request.url ?? "",
      cookieNames: [...requestCookies(request).keys()].sort(),
    });
    if (route === "GET /login") {
      page(loginForm);
      return;
    }
    if (route === "POST /login") {
      site.posts += 1;
      site.sidValid = true;
      page(`<p id="welcome">Welcome</p>`, {
        "set-cookie": [
          `device=${DEVICE_VALUE}; Max-Age=86400; Path=/; HttpOnly`,
          `sid=${SID_VALUE}; Path=/`,
        ],
      });
      return;
    }
    if (route === "GET /open") {
      page(entryForm);
      return;
    }
    if (!isAuthenticated(request)) {
      response.writeHead(302, { location: "/login" }).end();
      return;
    }
    if (route === "GET /device") {
      page(entryForm);
    } else if (route === "POST /device") {
      page(
        body.get("user_code") === USER_CODE
          ? authorizationForm
          : `<p id="device-error">unknown device code</p>`,
      );
    } else if (route === "POST /approve") {
      site.approvals += 1;
      site.approved = true;
      page(`<p id="device-ok">approved</p>`);
    } else {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  site.posts = 0;
  site.approvals = 0;
  site.deviceValid = true;
  site.sidValid = false;
  site.approved = false;
  site.requests = [];
});

afterEach(async () => {
  await stopApiProxy();
  await cleanupResources();
});

/** 1 回の処理が標準出力へ書く応答行（イベント行を除く）を読み取る。 */
async function captureResponse(
  action: () => Promise<void>,
): Promise<Record<string, unknown>> {
  const lines: string[] = [];
  const spy = vi.spyOn(process.stdout, "write").mockImplementation(((
    chunk: string | Uint8Array,
  ) => {
    lines.push(String(chunk));
    return true;
  }) as typeof process.stdout.write);
  try {
    await action();
  } finally {
    spy.mockRestore();
  }
  const responses = lines
    .join("")
    .split("\n")
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((line) => !("event" in line));
  expect(responses).toHaveLength(1);
  return responses[0];
}

function deviceCookie(overrides: Partial<Cookie> = {}): Cookie {
  return {
    name: "device",
    value: DEVICE_VALUE,
    domain: "127.0.0.1",
    path: "/",
    expires: Math.floor(Date.now() / 1000) + 86_400,
    httpOnly: true,
    secure: false,
    sameSite: "Lax",
    ...overrides,
  };
}

function cookieNames(response: Record<string, unknown>): string[] {
  return (response.cookies as Cookie[]).map(({ name }) => name).sort();
}

function persistentCookies(response: Record<string, unknown>): Cookie[] {
  // デーモンと同じく、セッション cookie を除いたものを次回へ渡す。
  return (response.cookies as Cookie[]).filter(({ expires }) => expires !== -1);
}

function authorizeDevice(fields: Record<string, unknown>) {
  const request = parseRequest(
    JSON.stringify({
      op: "authorize_device",
      id: 5,
      login_url: `${origin}/login`,
      verification_url: `${origin}/device`,
      user_code: USER_CODE,
      steps: null,
      success_selector: "#device-ok",
      failure_selector: "#device-error",
      secret,
      ...fields,
    }),
  );
  if (request.op !== "authorize_device") throw new Error("not authorize");
  return captureResponse(() => handleAuthorizeDevice(request));
}

function oauthConfig(fields: Record<string, unknown> = {}) {
  return {
    client_id: "tegata-client",
    device_authorization_url: `${origin}/oauth/device_authorization`,
    token_url: `${origin}/oauth/token`,
    revocation_url: null,
    scope: null,
    login_url: `${origin}/login`,
    steps: null,
    success_selector: "#device-ok",
    failure_selector: "#device-error",
    secret,
    ...fields,
  };
}

function startOAuthProxy(fields: Record<string, unknown>) {
  const request = parseRequest(
    JSON.stringify({
      op: "api_proxy_start",
      id: 8,
      upstream: origin,
      header: "Authorization",
      value_template: "Bearer {{secret}}",
      oauth: oauthConfig(fields),
    }),
  );
  if (request.op !== "api_proxy_start") throw new Error("not a proxy start");
  return captureResponse(() => handleApiProxyStart(request));
}

async function stopApiProxy(): Promise<void> {
  const request = parseRequest('{"op":"api_proxy_stop","id":9}');
  if (request.op !== "api_proxy_stop") throw new Error("not a proxy stop");
  await captureResponse(() => handleApiProxyStop(request));
}

describe("authorize_device with persistent cookies", {
  timeout: 60_000,
}, () => {
  test("runs the login stage without cookies and returns the context cookies", async () => {
    const response = await authorizeDevice({ cookies: null });

    expect(response).toMatchObject({ ok: true, id: 5, steps_skipped: false });
    expect(cookieNames(response)).toEqual(["device", "sid"]);
    expect(site.posts).toBe(1);
    expect(site.approvals).toBe(1);
  });

  test("skips the login stage on the approval page reached by restored cookies", async () => {
    const first = await authorizeDevice({ cookies: null });
    await cleanupResources();
    site.requests = [];
    site.sidValid = false;

    const second = await authorizeDevice({ cookies: persistentCookies(first) });

    expect(second).toMatchObject({ ok: true, id: 5, steps_skipped: true });
    expect(site.posts).toBe(1);
    expect(site.approvals).toBe(2);
    expect(site.requests[0]).toEqual({
      method: "GET",
      path: "/device",
      cookieNames: ["device"],
    });
    expect(site.requests.some(({ path }) => path === "/login")).toBe(false);
    expect(cookieNames(second)).toEqual(["device"]);
  });

  test("runs the login stage when the restored cookies no longer reach the approval page", async () => {
    site.deviceValid = false;

    const response = await authorizeDevice({ cookies: [deviceCookie()] });

    expect(response).toMatchObject({ ok: true, steps_skipped: false });
    expect(site.posts).toBe(1);
    expect(site.approvals).toBe(1);
    expect(site.requests[0]).toMatchObject({
      method: "GET",
      path: "/device",
      cookieNames: ["device"],
    });
  });

  test("falls back to the login stage once when the reached form needs a login", async () => {
    site.deviceValid = false;

    const response = await authorizeDevice({
      cookies: [deviceCookie()],
      verification_url: `${origin}/open`,
    });

    expect(response).toMatchObject({ ok: true, steps_skipped: false });
    expect(site.posts).toBe(1);
    expect(site.approvals).toBe(1);
    expect(site.requests[0]).toMatchObject({ method: "GET", path: "/open" });
    // 省略した承認ページと、ログイン段の後のやり直しで 2 回開く。
    expect(
      site.requests.filter(
        ({ method, path }) => method === "GET" && path === "/open",
      ),
    ).toHaveLength(2);
  });

  test("does not fall back and returns no cookies on a rejected device code", async () => {
    const response = await authorizeDevice({
      cookies: [deviceCookie()],
      user_code: "NOPE-NOPE",
    });

    expect(response).toEqual({
      ok: false,
      error: "DEVICE_CODE_REJECTED",
      id: 5,
    });
    expect(site.posts).toBe(0);
    expect(site.approvals).toBe(0);
  });

  test("keeps the previous behavior when the cookies field is absent", async () => {
    const response = await authorizeDevice({});

    expect(response).toMatchObject({ ok: true, steps_skipped: false });
    expect(site.posts).toBe(1);
    expect(site.requests[0]).toEqual({
      method: "GET",
      path: "/login",
      cookieNames: [],
    });
  });
});

describe("OAuth api_proxy_start with persistent cookies", {
  timeout: 60_000,
}, () => {
  test("returns the cookies and steps_skipped of the browser login", async () => {
    const first = await startOAuthProxy({ cookies: null });

    expect(first).toMatchObject({ ok: true, id: 8, steps_skipped: false });
    expect(typeof first.port).toBe("number");
    expect(typeof first.secret).toBe("string");
    expect(cookieNames(first)).toEqual(["device", "sid"]);
    await stopApiProxy();
    site.approved = false;
    site.sidValid = false;

    const second = await startOAuthProxy({ cookies: persistentCookies(first) });

    expect(second).toMatchObject({ ok: true, id: 8, steps_skipped: true });
    expect(cookieNames(second)).toEqual(["device"]);
    expect(site.posts).toBe(1);
    expect(site.approvals).toBe(2);
  });

  test("does not add cookies to a static token proxy response", async () => {
    const request = parseRequest(
      JSON.stringify({
        op: "api_proxy_start",
        id: 10,
        upstream: origin,
        header: "Authorization",
        header_value: "Bearer static",
      }),
    );
    if (request.op !== "api_proxy_start") throw new Error("not a proxy start");

    const response = await captureResponse(() => handleApiProxyStart(request));

    expect(Object.keys(response).sort()).toEqual([
      "id",
      "ok",
      "port",
      "secret",
    ]);
  });
});

describe("device cookie parsing", () => {
  function parsedDeviceCookies(cookies: unknown) {
    const request = parseRequest(
      JSON.stringify({
        op: "authorize_device",
        login_url: "https://example.test/login",
        verification_url: "https://example.test/device",
        user_code: USER_CODE,
        steps: null,
        success_selector: "#device-ok",
        secret,
        ...(cookies === undefined ? {} : { cookies }),
      }),
    );
    if (request.op !== "authorize_device") throw new Error("not authorize");
    return request.cookies;
  }

  function parsedOAuthCookies(cookies: unknown) {
    const request = parseRequest(
      JSON.stringify({
        op: "api_proxy_start",
        upstream: "https://api.example.test",
        header: "Authorization",
        value_template: "Bearer {{secret}}",
        oauth: {
          ...oauthConfig(),
          ...(cookies === undefined ? {} : { cookies }),
        },
      }),
    );
    if (request.op !== "api_proxy_start" || !("oauth" in request)) {
      throw new Error("not an oauth proxy start");
    }
    return request.oauth.cookies;
  }

  test.each([
    ["authorize_device", parsedDeviceCookies],
    ["api_proxy_start oauth", parsedOAuthCookies],
  ])("treats a missing or null field in %s as no cookies", (_name, parse) => {
    expect(parse(undefined)).toBeNull();
    expect(parse(null)).toBeNull();
    expect(parse([])).toEqual([]);
  });

  test.each([
    ["authorize_device", parsedDeviceCookies],
    ["api_proxy_start oauth", parsedOAuthCookies],
  ])("keeps well-formed cookies in %s and drops the rest", (_name, parse) => {
    const valid = deviceCookie();
    expect(
      parse([{ ...valid, extra: true }, { ...valid, sameSite: "lax" }, null]),
    ).toEqual([valid]);
  });

  test.each([
    ["authorize_device", parsedDeviceCookies],
    ["api_proxy_start oauth", parsedOAuthCookies],
  ])("rejects a cookies field in %s that is not a list", (_name, parse) => {
    expect(() => parse({ name: "device" })).toThrow();
  });
});

describe("device cookie redaction", () => {
  test("redacts restored cookie values of authorize_device", () => {
    const request = parseRequest(
      JSON.stringify({
        op: "authorize_device",
        login_url: "https://example.test/login",
        verification_url: "https://example.test/device",
        user_code: USER_CODE,
        steps: null,
        success_selector: "#device-ok",
        secret,
        cookies: [deviceCookie()],
      }),
    );
    if (request.op !== "authorize_device") throw new Error("not authorize");

    const line = formatExecutorErrorLine(
      request,
      "device",
      "INTERNAL",
      new Error(`page threw for cookie ${DEVICE_VALUE}`),
    );

    expect(line).not.toContain(DEVICE_VALUE);
    expect(line).toContain("[REDACTED]");
  });

  test("redacts restored cookie values of the OAuth proxy login", () => {
    const request = parseRequest(
      JSON.stringify({
        op: "api_proxy_start",
        upstream: "https://api.example.test",
        header: "Authorization",
        value_template: "Bearer {{secret}}",
        oauth: { ...oauthConfig(), cookies: [deviceCookie()] },
      }),
    );
    if (request.op !== "api_proxy_start") throw new Error("not a proxy");

    const line = formatExecutorErrorLine(
      request,
      "login",
      "INTERNAL",
      new Error(`page threw for cookie ${DEVICE_VALUE}`),
    );

    expect(line).not.toContain(DEVICE_VALUE);
    expect(line).toContain("[REDACTED]");
  });
});

describe("login stage skip decision", () => {
  test("races the default device input without custom steps", () => {
    expect(firstDeviceStepSelector(null)).toBe(
      'input[name="user_code"], input[autocomplete="one-time-code"]',
    );
  });

  test("races the first custom device step and nothing for empty steps", () => {
    expect(
      firstDeviceStepSelector([
        { action: "wait_for", selector: "#code-form" },
        { action: "fill", selector: "#code", value: "{{user_code}}" },
      ]),
    ).toBe("#code-form");
    expect(firstDeviceStepSelector([])).toBeUndefined();
  });

  test("falls back to the login stage only for a missing selector", () => {
    expect(isLoginFallbackError(new SelectorNotFoundError(0))).toBe(true);
    expect(isLoginFallbackError(new SelectorNotFoundError())).toBe(true);
    expect(isLoginFallbackError(new DeviceCodeRejectedError())).toBe(false);
    expect(isLoginFallbackError(new Error("timed out"))).toBe(false);
  });

  test("formats the cookies and steps_skipped response fields", () => {
    const cookies = [deviceCookie()];
    expect(
      formatDeviceAuthorizationFields({ cookies, stepsSkipped: true }),
    ).toEqual({ cookies, steps_skipped: true });
  });
});
