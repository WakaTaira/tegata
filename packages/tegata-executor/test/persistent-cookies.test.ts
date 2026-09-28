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
  handleExportCookies,
  handleLogin,
  parseRequest,
} from "../src/index.js";

const DEVICE_VALUE = "device-canary-7f3a";
const SID_VALUE = "sid-canary-91c4";

const secret = {
  username: "alice@example.test",
  password: "correct-horse-battery",
  totp: null,
};

const explicitSteps = [
  { action: "fill", selector: "#user", value: "{{username}}" },
  { action: "fill", selector: "#pass", value: "{{password}}" },
  { action: "click", selector: "button[type=submit]" },
];

type RecordedRequest = { method: string; cookieNames: string[] };

// ログイン状態を device cookie で判定する最小のサイト。
const site = {
  posts: 0,
  deviceValid: true,
  formWithWelcome: false,
  requests: [] as RecordedRequest[],
};

const loginForm = `
  <form method="post" action="/login">
    <input id="user" name="user" type="text">
    <input id="pass" name="pass" type="password">
    <button type="submit">Log in</button>
  </form>
`;

const welcome = `<p id="welcome">Welcome</p>`;

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

function html(body: string): string {
  return `<!doctype html><html><body>${body}</body></html>`;
}

let server: Server;
let origin: string;

beforeAll(async () => {
  server = createServer((request, response) => {
    if (request.url !== "/login") {
      response.writeHead(404).end();
      return;
    }
    const cookies = requestCookies(request);
    site.requests.push({
      method: request.method ?? "",
      cookieNames: [...cookies.keys()].sort(),
    });
    if (request.method === "POST") {
      site.posts += 1;
      request.resume();
      response.writeHead(200, {
        "content-type": "text/html",
        "set-cookie": [
          `device=${DEVICE_VALUE}; Max-Age=86400; Path=/; HttpOnly`,
          `sid=${SID_VALUE}; Path=/`,
        ],
      });
      response.end(html(welcome));
      return;
    }
    const loggedIn = site.deviceValid && cookies.get("device") === DEVICE_VALUE;
    const body = loggedIn
      ? site.formWithWelcome
        ? `${welcome}${loginForm}`
        : welcome
      : loginForm;
    response.writeHead(200, { "content-type": "text/html" });
    response.end(html(body));
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
  site.deviceValid = true;
  site.formWithWelcome = false;
  site.requests = [];
});

afterEach(async () => {
  await cleanupResources();
});

/** 1 回の処理が標準出力へ書く応答行を読み取る。 */
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
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  expect(responses).toHaveLength(1);
  return responses[0];
}

function login(fields: Record<string, unknown>) {
  const request = parseRequest(
    JSON.stringify({
      op: "login",
      id: 1,
      target_url: `${origin}/login`,
      steps: explicitSteps,
      success_selector: "#welcome",
      failure_selector: null,
      secret,
      ...fields,
    }),
  );
  if (request.op !== "login") throw new Error("not a login request");
  return captureResponse(() => handleLogin(request));
}

function exportCookies() {
  const request = parseRequest(JSON.stringify({ op: "export_cookies", id: 7 }));
  if (request.op !== "export_cookies") throw new Error("not an export");
  return captureResponse(() => handleExportCookies(request));
}

function cookieNames(response: Record<string, unknown>): string[] {
  return (response.cookies as Cookie[]).map(({ name }) => name).sort();
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

describe("login with persistent cookies", { timeout: 60_000 }, () => {
  test("restores cookies before navigation and skips the steps on a logged-in page", async () => {
    const first = await login({ cookies: null });
    expect(first).toMatchObject({ ok: true, id: 1, steps_skipped: false });
    expect(cookieNames(first)).toEqual(["device", "sid"]);
    expect(site.posts).toBe(1);
    await cleanupResources();

    // デーモンと同じく、セッション cookie を除いたものを次回へ渡す。
    const persistent = (first.cookies as Cookie[]).filter(
      ({ expires }) => expires !== -1,
    );
    expect(persistent.map(({ name }) => name)).toEqual(["device"]);
    site.requests = [];

    const second = await login({ cookies: persistent });
    expect(second).toMatchObject({ ok: true, id: 1, steps_skipped: true });
    expect(typeof second.endpoint).toBe("string");
    expect(typeof second.target_id).toBe("string");
    expect(site.posts).toBe(1);
    expect(site.requests[0]).toEqual({
      method: "GET",
      cookieNames: ["device"],
    });
    expect(cookieNames(second)).toEqual(["device"]);
  });

  test("runs the steps when the restored cookies no longer log in", async () => {
    site.deviceValid = false;

    const response = await login({ cookies: [deviceCookie()], steps: null });

    expect(response).toMatchObject({ ok: true, steps_skipped: false });
    expect(site.posts).toBe(1);
    expect(site.requests[0]).toEqual({
      method: "GET",
      cookieNames: ["device"],
    });
    expect(cookieNames(response)).toEqual(["device", "sid"]);
  });

  test("does not race for a logged-in page when success_selector is null", async () => {
    site.formWithWelcome = true;

    const response = await login({
      cookies: [deviceCookie()],
      success_selector: null,
    });

    expect(response).toMatchObject({ ok: true, steps_skipped: false });
    expect(site.posts).toBe(1);
  });

  test("keeps the previous behavior when the cookies field is absent", async () => {
    const response = await login({});

    expect(response).toMatchObject({ ok: true, steps_skipped: false });
    expect(site.posts).toBe(1);
    expect(site.requests[0]).toEqual({ method: "GET", cookieNames: [] });
  });

  test("drops a cookie the browser rejects and restores the others", async () => {
    const rejected = deviceCookie({ name: "broken", value: "a;b" });

    const response = await login({ cookies: [rejected, deviceCookie()] });

    expect(response).toMatchObject({ ok: true, steps_skipped: true });
    expect(site.posts).toBe(0);
    expect(site.requests[0]).toEqual({
      method: "GET",
      cookieNames: ["device"],
    });
  });
});

describe("export_cookies", { timeout: 60_000 }, () => {
  test("returns an empty list without a browser", async () => {
    expect(await exportCookies()).toEqual({ ok: true, id: 7, cookies: [] });
  });

  test("returns every cookie of the login context and nothing after cleanup", async () => {
    await login({ cookies: null });

    const exported = await exportCookies();
    expect(exported).toMatchObject({ ok: true, id: 7 });
    expect(cookieNames(exported)).toEqual(["device", "sid"]);
    const device = (exported.cookies as Cookie[]).find(
      ({ name }) => name === "device",
    );
    expect(Object.keys(device ?? {}).sort()).toEqual([
      "domain",
      "expires",
      "httpOnly",
      "name",
      "path",
      "sameSite",
      "secure",
      "value",
    ]);
    expect(device).toMatchObject({ value: DEVICE_VALUE, httpOnly: true });

    await cleanupResources();
    expect(await exportCookies()).toEqual({ ok: true, id: 7, cookies: [] });
  });
});

describe("login cookie parsing", () => {
  function parsedCookies(cookies: unknown): Cookie[] | null | undefined {
    const request = parseRequest(
      JSON.stringify({
        op: "login",
        target_url: "https://example.test/login",
        steps: null,
        secret,
        ...(cookies === undefined ? {} : { cookies }),
      }),
    );
    if (request.op !== "login") throw new Error("not a login request");
    return request.cookies;
  }

  test("treats a missing or null field as no cookies and keeps an empty list", () => {
    expect(parsedCookies(undefined)).toBeNull();
    expect(parsedCookies(null)).toBeNull();
    expect(parsedCookies([])).toEqual([]);
  });

  test("drops malformed elements and keeps only the known fields", () => {
    const valid = deviceCookie();
    const parsed = parsedCookies([
      { ...valid, partitionKey: "ignored", extra: true },
      { ...valid, value: undefined },
      { ...valid, sameSite: "strict" },
      { ...valid, expires: -5 },
      { ...valid, expires: 0 },
      { ...valid, expires: "1" },
      { ...valid, expires: 253_402_300_800 },
      { ...valid, domain: "" },
      { ...valid, path: "" },
      { ...valid, httpOnly: "true" },
      null,
      "device=value",
      { ...valid, name: "session", expires: -1 },
    ]);

    expect(parsed).toEqual([valid, { ...valid, name: "session", expires: -1 }]);
  });

  test("rejects a cookies field that is not a list", () => {
    expect(() => parsedCookies({ name: "device" })).toThrow();
  });

  test("parses export_cookies", () => {
    expect(parseRequest('{"op":"export_cookies","id":3}')).toEqual({
      op: "export_cookies",
      id: 3,
    });
  });
});
