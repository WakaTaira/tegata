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
  formatExecutorErrorLine,
  handleExportCookies,
  handleLoginBegin,
  handleLoginStep,
  parseRequest,
} from "../src/index.js";
import { parseSnapshotLine } from "../src/snapshot.js";

const USERNAME = "alice&co@example.test";
const PASSWORD = "correct horse/battery+staple";
const TOTP_CODE = "493817";
const SESSION_VALUE = "session-canary-5d1e";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function html(title: string, body: string): string {
  return `<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`;
}

// 段階ログインの最小のサイト。username → password → 成功ページの 3 画面と、password を返す悪性ページ、
// 誤った password を欄に残したまま再描画するページを持つ。
const site = {
  posts: [] as string[],
  stickyReports: [] as Array<{ when: string; length: number }>,
};

const usernamePage = html(
  "Sign in",
  `<form method="post" action="/username">
    <label for="username">Username</label>
    <input id="username" name="username" type="text" autocomplete="username">
    <button type="submit">Next</button>
  </form>`,
);

function passwordPage(error: boolean): string {
  return html(
    "Password",
    `${error ? '<p id="login-error">Incorrect password</p>' : ""}
    <form method="post" action="/password">
      <input name="password" type="password" autocomplete="current-password"
        aria-label="Password">
      <button type="submit">Sign in</button>
    </form>`,
  );
}

const homePage = html(
  "Home",
  `<div id="signed-in">Signed in as ${escapeHtml(USERNAME)}</div>
  <a href="/profile?user=${encodeURIComponent(USERNAME)}">Profile</a>`,
);

function echoForm(kind: string): string {
  return html(
    "Echo",
    `<form method="post" action="/echo-login?kind=${kind}">
      <input id="username" name="username" type="text" aria-label="Username">
      <input id="password" name="password" type="password" aria-label="Password">
      <input id="otp" name="otp" type="text" aria-label="Code">
      <button id="submit" type="submit">Sign in</button>
    </form>`,
  );
}

function echoPage(kind: string, form: URLSearchParams): string | undefined {
  const password = form.get("password") ?? "";
  if (kind === "text") return `<p>You entered: ${escapeHtml(password)}</p>`;
  if (kind === "attr") {
    return `<button aria-label="${escapeHtml(password)}">Continue</button>`;
  }
  if (kind === "base64") {
    return `<p>${Buffer.from(password).toString("base64")}</p>`;
  }
  if (kind === "totp")
    return `<p>Code ${escapeHtml(form.get("otp") ?? "")}</p>`;
  return undefined;
}

const stickyPage = html(
  "Sticky",
  `<form id="sticky-form">
    <input id="password" name="password" type="password" aria-label="Password">
    <button id="submit" type="submit">Sign in</button>
  </form>
  <button id="help" type="button">Help</button>
  <div id="status"></div>
  <script>
    const field = document.getElementById("password");
    const report = (when) => {
      const request = new XMLHttpRequest();
      request.open("POST", "/report", false);
      request.send(JSON.stringify({ when, length: field.value.length }));
    };
    document.getElementById("help").addEventListener("click", () => report("click"));
    document.getElementById("sticky-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      await fetch("/sticky-login", { method: "POST" });
      document.getElementById("status").innerHTML = '<p class="notice">Incorrect password</p>';
      report("rerender");
    });
  </script>`,
);

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => resolve(body));
  });
}

function hasSession(request: IncomingMessage): boolean {
  return (request.headers.cookie ?? "").includes(`session=${SESSION_VALUE}`);
}

let server: Server;
let origin: string;

beforeAll(async () => {
  server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const body = await readBody(request);
    const form = new URLSearchParams(body);
    const send = (page: string) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(page);
    };
    const route = `${request.method} ${url.pathname}`;
    if (route === "GET /login") {
      send(hasSession(request) ? homePage : usernamePage);
    } else if (route === "POST /username") {
      site.posts.push("username");
      send(passwordPage(false));
    } else if (route === "POST /password") {
      site.posts.push("password");
      if (form.get("password") !== PASSWORD) {
        send(passwordPage(true));
        return;
      }
      response.writeHead(303, {
        location: "/home",
        "set-cookie": `session=${SESSION_VALUE}; Max-Age=86400; Path=/; HttpOnly`,
      });
      response.end();
    } else if (route === "GET /home") {
      send(homePage);
    } else if (route === "GET /echo") {
      send(echoForm(url.searchParams.get("kind") ?? ""));
    } else if (route === "POST /echo-login") {
      const kind = url.searchParams.get("kind") ?? "";
      site.posts.push(`echo-${kind}`);
      const page = echoPage(kind, form);
      if (page !== undefined) {
        send(html("Welcome", page));
        return;
      }
      const password = encodeURIComponent(form.get("password") ?? "");
      response.writeHead(303, { location: `/echo-result?p=${password}` });
      response.end();
    } else if (route === "GET /echo-result") {
      send(html("Result", "<p>Done</p>"));
    } else if (route === "GET /sticky") {
      send(stickyPage);
    } else if (route === "POST /sticky-login") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":false}');
    } else if (route === "POST /report") {
      site.stickyReports.push(JSON.parse(body));
      response.writeHead(204).end();
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
  site.posts = [];
  site.stickyReports = [];
});

afterEach(async () => {
  await cleanupResources();
});

type Response = Record<string, unknown>;

/** 1 回の処理が標準出力へ書く応答行を読み取る。 */
async function captureResponse(action: () => Promise<void>): Promise<Response> {
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
    .map((line) => JSON.parse(line) as Response);
  expect(responses).toHaveLength(1);
  return responses[0];
}

function begin(path: string, fields: Record<string, unknown> = {}) {
  const request = parseRequest(
    JSON.stringify({
      op: "login_begin",
      id: 1,
      target_url: `${origin}${path}`,
      success_selector: "#signed-in",
      failure_selector: "#login-error",
      secret: { username: USERNAME, password: PASSWORD },
      cookies: null,
      ...fields,
    }),
  );
  if (request.op !== "login_begin") throw new Error("not a login_begin");
  return captureResponse(() => handleLoginBegin(request));
}

function step(action: Record<string, unknown>, totp: string | null = null) {
  const request = parseRequest(
    JSON.stringify({ op: "login_step", id: 2, ...action, totp }),
  );
  if (request.op !== "login_step") throw new Error("not a login_step");
  return captureResponse(() => handleLoginStep(request));
}

type Snapshot = {
  url: string;
  title: string;
  page: string;
  settled: boolean;
  truncated?: true;
};

function snapshotOf(response: Response): Snapshot {
  expect(response).toMatchObject({ ok: true, state: "pending" });
  return response.snapshot as Snapshot;
}

/** 応答のスナップショットから、役割と名前で 1 行を探してその ref を返す。 */
function refOf(response: Response, role: string, name?: string): string {
  const line = snapshotOf(response)
    .page.split("\n")
    .map((raw) => parseSnapshotLine(raw))
    .find((parsed) => parsed?.role === role && parsed.name === name);
  const ref = line?.attrs
    .find((attr) => attr.startsWith("ref="))
    ?.slice("ref=".length);
  expect(ref, `${role} ${name ?? ""}`).toMatch(/^(f\d+)?e\d+$/);
  return ref as string;
}

/** username 画面から password 画面まで進める。 */
async function advanceToPassword(
  fields: Record<string, unknown> = {},
): Promise<Response> {
  const begun = await begin("/login", fields);
  const filled = await step({
    action: "fill",
    ref: refOf(begun, "textbox", "Username"),
    value: "{{username}}",
  });
  const next = await step({
    action: "click",
    ref: refOf(filled, "button", "Next"),
  });
  expect(snapshotOf(next).url).toBe(`${origin}/username`);
  return next;
}

function submitPassword(page: Response) {
  return step({
    action: "fill_submit",
    fills: [{ ref: refOf(page, "textbox", "Password"), value: "{{password}}" }],
    submit: { click: { ref: refOf(page, "button", "Sign in") } },
  });
}

describe("login_step parsing", () => {
  function parseStep(action: Record<string, unknown>) {
    return () =>
      parseRequest(JSON.stringify({ op: "login_step", id: 5, ...action }));
  }

  test("refuses a lone fill of anything but {{username}}", () => {
    for (const value of ["{{password}}", "{{totp}}", "literal"]) {
      expect(parseStep({ action: "fill", selector: "#p", value })).toThrow();
    }
    expect(
      parseStep({ action: "fill", selector: "#u", value: "{{username}}" })(),
    ).toMatchObject({ op: "login_step", totp: null });
  });

  test("accepts only placeholders, 1 to 3 fills and one submit form", () => {
    const fill = { selector: "#p", value: "{{password}}" };
    const submit = { click: "#s" };
    const invalid = [
      { fills: [{ selector: "#p", value: "literal" }], submit },
      { fills: [], submit },
      { fills: [fill, fill, fill, fill], submit },
      { fills: [fill], submit: { click: "#s", press_enter: "#p" } },
      { fills: [fill], submit: {} },
    ];
    for (const fields of invalid) {
      expect(parseStep({ action: "fill_submit", ...fields })).toThrow();
    }
    expect(
      parseStep({
        action: "fill_submit",
        fills: [fill, { ref: "e7", value: "{{totp}}" }],
        submit: { press_enter: "#o" },
        totp: TOTP_CODE,
      })(),
    ).toMatchObject({
      action: {
        action: "fill_submit",
        fills: [fill, { ref: "e7", value: "{{totp}}" }],
        submit: { press_enter: { selector: "#o" } },
      },
      totp: TOTP_CODE,
    });
  });

  test("takes exactly one of ref and selector wherever an element is named", () => {
    const both = { ref: "e3", selector: "#a" };
    const invalid = [
      { action: "click", ...both },
      { action: "click" },
      { action: "wait_for", ...both },
      { action: "fill", ...both, value: "{{username}}" },
      { action: "fill", value: "{{username}}" },
      {
        action: "fill_submit",
        fills: [{ ...both, value: "{{password}}" }],
        submit: { click: "#s" },
      },
      {
        action: "fill_submit",
        fills: [{ value: "{{password}}" }],
        submit: { click: "#s" },
      },
      {
        action: "fill_submit",
        fills: [{ ref: "e1", value: "{{password}}" }],
        submit: { click: both },
      },
      {
        action: "fill_submit",
        fills: [{ ref: "e1", value: "{{password}}" }],
        submit: { press_enter: {} },
      },
    ];
    for (const action of invalid) expect(parseStep(action)).toThrow();

    expect(parseStep({ action: "click", ref: "f2e10" })()).toMatchObject({
      action: { action: "click", ref: "f2e10" },
    });
    expect(
      parseStep({ action: "wait_for", ref: null, selector: "#a" })(),
    ).toMatchObject({ action: { action: "wait_for", selector: "#a" } });
    for (const submit of [
      { click: { ref: "e9" } },
      { click: { selector: "#next" } },
      { press_enter: { ref: "f1e2" } },
      { press_enter: { selector: "#x" } },
    ]) {
      expect(
        parseStep({
          action: "fill_submit",
          fills: [{ ref: "e1", value: "{{password}}" }],
          submit,
        })(),
      ).toMatchObject({ action: { submit } });
    }
    expect(
      parseStep({
        action: "fill_submit",
        fills: [{ ref: "e1", value: "{{password}}" }],
        submit: { click: "#next" },
      })(),
    ).toMatchObject({ action: { submit: { click: { selector: "#next" } } } });
  });

  test("accepts only refs of the e<n> / f<n>e<n> form up to 32 characters", () => {
    for (const ref of ["e", "f1", "1e2", "e1 ", "E1", "e-1", "f1f2e3", 5]) {
      expect(parseStep({ action: "click", ref })).toThrow();
    }
    const long = `f${"1".repeat(29)}e1`;
    expect(long.length).toBe(32);
    expect(parseStep({ action: "click", ref: long })()).toMatchObject({
      action: { ref: long },
    });
    expect(parseStep({ action: "click", ref: `f${long}` })).toThrow();
  });

  test("requires a success_selector on login_begin", () => {
    expect(() =>
      parseRequest(
        JSON.stringify({
          op: "login_begin",
          target_url: "https://example.test",
          secret: { username: "u", password: "p" },
        }),
      ),
    ).toThrow();
  });

  test("redacts the stepwise secrets from diagnostic lines", () => {
    const request = parseRequest(
      JSON.stringify({
        op: "login_step",
        action: "snapshot",
        totp: TOTP_CODE,
      }),
    );
    if (request.op !== "login_step") throw new Error("not a login_step");
    const line = formatExecutorErrorLine(
      request,
      "login",
      "INTERNAL",
      new Error(`page threw ${TOTP_CODE} ${PASSWORD}`),
      [PASSWORD],
    );
    expect(line).not.toContain(TOTP_CODE);
    expect(line).not.toContain(PASSWORD);
  });
});

describe("stepwise login", { timeout: 90_000 }, () => {
  test("begins with a pending snapshot and no CDP endpoint", async () => {
    const begun = await begin("/login");

    expect(begun).toMatchObject({ ok: true, id: 1, state: "pending" });
    expect(JSON.stringify(begun)).not.toContain("ws://");
    expect(begun).not.toHaveProperty("endpoint");
    const snapshot = snapshotOf(begun);
    expect(snapshot.url).toBe(`${origin}/login`);
    expect(snapshot.settled).toBe(true);
    expect(snapshot).not.toHaveProperty("text");
    expect(snapshot).not.toHaveProperty("elements");
    refOf(begun, "textbox", "Username");
    refOf(begun, "button", "Next");
  });

  test("hands off with an endpoint once the success selector appears", async () => {
    const passwordStep = await advanceToPassword();
    expect(JSON.stringify(passwordStep)).not.toContain("ws://");

    const done = await submitPassword(passwordStep);

    expect(done).toMatchObject({
      ok: true,
      id: 2,
      state: "done",
      steps_skipped: false,
    });
    expect(done.endpoint).toMatch(/^ws:\/\//);
    expect(typeof done.target_id).toBe("string");
    expect((done.cookies as Cookie[]).map(({ name }) => name)).toEqual([
      "session",
    ]);
    expect(site.posts).toEqual(["username", "password"]);

    // ハンドオフ後は login の成功後と同じ要求を受け付け、段階ログインの操作は受け付けない。
    const exportRequest = parseRequest('{"op":"export_cookies","id":3}');
    if (exportRequest.op !== "export_cookies") throw new Error("not export");
    const exported = await captureResponse(() =>
      handleExportCookies(exportRequest),
    );
    expect((exported.cookies as Cookie[]).map(({ name }) => name)).toEqual([
      "session",
    ]);
    expect(await step({ action: "snapshot" })).toMatchObject({
      ok: false,
      error: "INTERNAL",
    });
  });

  test("keeps going after SELECTOR_NOT_FOUND", async () => {
    await begin("/login");

    const missing = await step({ action: "click", selector: "#missing" });
    const again = await step({ action: "snapshot" });

    expect(missing).toEqual({ ok: false, error: "SELECTOR_NOT_FOUND", id: 2 });
    refOf(again, "button", "Next");
  });

  test("answers SELECTOR_NOT_FOUND for a ref the latest snapshot does not carry", async () => {
    const begun = await begin("/login");

    const unknown = await step({ action: "click", ref: "e99999" });
    const next = await step({
      action: "click",
      ref: refOf(begun, "button", "Next"),
    });

    expect(unknown).toEqual({ ok: false, error: "SELECTOR_NOT_FOUND", id: 2 });
    expect(snapshotOf(next).url).toBe(`${origin}/username`);
  });

  test("keeps {{password}} out of a non-password field named by ref", async () => {
    const begun = await begin("/login");

    const refused = await step({
      action: "fill_submit",
      fills: [
        { ref: refOf(begun, "textbox", "Username"), value: "{{password}}" },
      ],
      submit: { click: { ref: refOf(begun, "button", "Next") } },
    });

    expect(refused).toEqual({
      ok: false,
      error: "FILL_MISMATCH",
      step: 0,
      id: 2,
    });
    expect(site.posts).toEqual([]);
  });

  test("marks the field the agent filled and leaves its value out", async () => {
    const begun = await begin("/login", { success_selector: "#never" });

    const filled = await step({
      action: "fill",
      ref: refOf(begun, "textbox", "Username"),
      value: "{{username}}",
    });

    const { page } = snapshotOf(filled);
    expect(page).toMatch(/^\s*- textbox "Username" \[ref=e\d+\] \[filled\]$/mu);
    expect(page).not.toContain("[username]");
    expect(JSON.stringify(filled)).not.toContain(USERNAME);
  });

  test("masks the username on a page that shows it", async () => {
    const passwordStep = await advanceToPassword({
      success_selector: "#never",
    });

    const home = await submitPassword(passwordStep);

    const snapshot = snapshotOf(home);
    expect(snapshot.url).toBe(`${origin}/home`);
    expect(snapshot.page).toContain("Signed in as [username]");
    expect(JSON.stringify(home)).not.toContain(USERNAME);
    expect(JSON.stringify(home)).not.toContain(encodeURIComponent(USERNAME));
  });

  test("ends with INVALID_CREDENTIAL when the failure selector appears", async () => {
    const passwordStep = await advanceToPassword({
      secret: { username: USERNAME, password: "wrong-password" },
    });

    const wrong = await submitPassword(passwordStep);

    expect(wrong).toEqual({ ok: false, error: "INVALID_CREDENTIAL", id: 2 });
    expect(await step({ action: "snapshot" })).toMatchObject({
      error: "INTERNAL",
    });
    // ブラウザは破棄済みであり、新しい段階ログインを始められる。
    expect(await begin("/login")).toMatchObject({ state: "pending" });
  });

  test.each(["text", "attr", "query", "base64"])(
    "rejects a page echoing the password (%s) and tears down",
    async (kind) => {
      const begun = await begin(`/echo?kind=${kind}`);

      const rejected = await step({
        action: "fill_submit",
        fills: [
          { selector: "#username", value: "{{username}}" },
          { selector: "#password", value: "{{password}}" },
        ],
        submit: { click: { ref: refOf(begun, "button", "Sign in") } },
      });

      expect(rejected).toEqual({
        ok: false,
        error: "SNAPSHOT_REJECTED",
        id: 2,
      });
      expect(JSON.stringify(rejected)).not.toContain(PASSWORD);
      expect(await step({ action: "snapshot" })).toMatchObject({
        error: "INTERNAL",
      });
      expect(await begin("/login")).toMatchObject({ state: "pending" });
    },
  );

  test("rejects a page echoing an entered TOTP code", async () => {
    await begin("/echo?kind=totp");

    const rejected = await step(
      {
        action: "fill_submit",
        fills: [{ selector: "#otp", value: "{{totp}}" }],
        submit: { press_enter: "#otp" },
      },
      TOTP_CODE,
    );

    expect(rejected).toEqual({ ok: false, error: "SNAPSHOT_REJECTED", id: 2 });
  });

  test("ends with MFA_REQUIRED before submitting when no TOTP is given", async () => {
    await begin("/echo?kind=totp");

    const missing = await step({
      action: "fill_submit",
      fills: [
        { selector: "#username", value: "{{username}}" },
        { selector: "#otp", value: "{{totp}}" },
      ],
      submit: { click: "#submit" },
    });

    expect(missing).toEqual({ ok: false, error: "MFA_REQUIRED", id: 2 });
    expect(site.posts).toEqual([]);
    expect(await step({ action: "snapshot" })).toMatchObject({
      error: "INTERNAL",
    });
  });

  test("clears the filled fields after fill_submit", async () => {
    await begin("/sticky", { success_selector: "#welcome" });

    const submitted = await step({
      action: "fill_submit",
      fills: [{ selector: "#password", value: "{{password}}" }],
      submit: { click: "#submit" },
    });
    snapshotOf(submitted);
    await step({ action: "click", selector: "#help" });

    const rerender = site.stickyReports.find((r) => r.when === "rerender");
    expect(rerender?.length).toBe(PASSWORD.length);
    const clicks = site.stickyReports.filter((r) => r.when === "click");
    expect(clicks.length).toBeGreaterThan(0);
    for (const click of clicks) expect(click.length).toBe(0);
  });

  test("clears the filled fields when the submit selector is missing", async () => {
    await begin("/sticky", { success_selector: "#welcome" });

    const missing = await step({
      action: "fill_submit",
      fills: [{ selector: "#password", value: "{{password}}" }],
      submit: { click: "#missing" },
    });
    expect(missing).toEqual({
      ok: false,
      error: "SELECTOR_NOT_FOUND",
      step: 1,
      id: 2,
    });
    await step({ action: "click", selector: "#help" });

    const clicks = site.stickyReports.filter((r) => r.when === "click");
    expect(clicks.length).toBeGreaterThan(0);
    for (const click of clicks) expect(click.length).toBe(0);
  });

  test("finishes login_begin at once when restored cookies log in", async () => {
    const cookie: Cookie = {
      name: "session",
      value: SESSION_VALUE,
      domain: "127.0.0.1",
      path: "/",
      expires: Math.floor(Date.now() / 1000) + 86_400,
      httpOnly: true,
      secure: false,
      sameSite: "Lax",
    };

    const done = await begin("/login", { cookies: [cookie] });

    expect(done).toMatchObject({
      ok: true,
      state: "done",
      steps_skipped: true,
    });
    expect(done).not.toHaveProperty("snapshot");
    expect(done.endpoint).toMatch(/^ws:\/\//);
    expect(site.posts).toEqual([]);
  });

  test("aborts and tears the browser down", async () => {
    await begin("/login");

    const aborted = await step({ action: "abort" });

    expect(aborted).toEqual({ ok: true, state: "aborted", id: 2 });
    expect(await step({ action: "snapshot" })).toMatchObject({
      error: "INTERNAL",
    });
    expect(await begin("/login")).toMatchObject({ state: "pending" });
  });
});
