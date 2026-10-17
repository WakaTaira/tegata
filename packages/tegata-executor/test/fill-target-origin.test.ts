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
  cleanupResources,
  handleLoginBegin,
  handleLoginStep,
  parseRequest,
} from "../src/index.js";
import { parseSnapshotLine } from "../src/snapshot.js";

const USERNAME = "alice@example.test";
const PASSWORD = "correct-horse-battery";

// 入力の報告。欄の input イベントごとに、frame の名前と値の長さを同期的に送る。
const reports: Array<{ frame: string; length: number }> = [];

const reportScript = `<script>
  function report(frame, value) {
    const request = new XMLHttpRequest();
    request.open("POST", "/report", false);
    request.send(JSON.stringify({ frame, length: value.length }));
  }
</script>`;

function framedForm(name: string): string {
  return `<!doctype html><html><body>${reportScript}
    <form>
      <label>${name} username <input type=text data-f=${name} oninput=report(this.dataset.f,this.value)></label>
      <label>${name} password <input type=password data-f=${name} oninput=report(this.dataset.f,this.value)></label>
      <button type=button>${name} go</button>
    </form></body></html>`;
}

// 同じ origin・別 origin（localhost）・srcdoc・about:blank の iframe と、後から取り除かれる iframe を持つページ。
function framesPage(port: number): string {
  return `<!doctype html><html><head><title>Frames</title></head><body>${reportScript}
    <h1>Frames</h1>
    <iframe src="/frame/form?name=Same"></iframe>
    <iframe src="http://localhost:${port}/frame/form?name=Cross"></iframe>
    <iframe srcdoc="<label>Srcdoc password <input type=password data-f=Srcdoc oninput=parent.report(this.dataset.f,this.value)></label>"></iframe>
    <iframe id="blank"></iframe>
    <iframe id="removable" src="/frame/button"></iframe>
    <button type="button" id="later">Remove frame later</button>
    <button type="button">Main go</button>
    <script>
      const blank = document.getElementById("blank").contentDocument;
      blank.body.innerHTML = '<label>Blank password <input type="password"></label>';
      const blankInput = blank.querySelector("input");
      blankInput.addEventListener("input", () => report("Blank", blankInput.value));
      document.getElementById("later").addEventListener("click", () => {
        setTimeout(() => document.getElementById("removable").remove(), 1500);
      });
    </script></body></html>`;
}

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

let server: Server;
let port: number;

beforeAll(async () => {
  server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const body = await readBody(request);
    const send = (page: string) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(page);
    };
    const route = `${request.method} ${url.pathname}`;
    if (route === "GET /frames") {
      send(framesPage(port));
    } else if (route === "GET /frame/form") {
      send(framedForm(url.searchParams.get("name") ?? ""));
    } else if (route === "GET /frame/button") {
      send("<!doctype html><button type=button>Framed button</button>");
    } else if (route === "POST /report") {
      reports.push(JSON.parse(body));
      response.writeHead(204).end();
    } else {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  reports.length = 0;
});

afterEach(async () => {
  await cleanupResources();
});

type Response = Record<string, unknown>;

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

async function begin(): Promise<Response> {
  const request = parseRequest(
    JSON.stringify({
      op: "login_begin",
      id: 1,
      target_url: `http://127.0.0.1:${port}/frames`,
      success_selector: "#signed-in",
      failure_selector: null,
      secret: { username: USERNAME, password: PASSWORD },
      cookies: null,
    }),
  );
  if (request.op !== "login_begin") throw new Error("not a login_begin");
  const response = await captureResponse(() => handleLoginBegin(request));
  expect(response).toMatchObject({ ok: true, state: "pending" });
  return response;
}

function step(action: Record<string, unknown>) {
  const request = parseRequest(
    JSON.stringify({ op: "login_step", id: 2, ...action, totp: null }),
  );
  if (request.op !== "login_step") throw new Error("not a login_step");
  return captureResponse(() => handleLoginStep(request));
}

function refOf(response: Response, role: string, name: string): string {
  const page = (response.snapshot as { page: string }).page;
  const line = page
    .split("\n")
    .map((raw) => parseSnapshotLine(raw))
    .find((parsed) => parsed?.role === role && parsed.name === name);
  const ref = line?.attrs
    .find((attr) => attr.startsWith("ref="))
    ?.slice("ref=".length);
  expect(ref, `${role} ${name} in\n${page}`).toMatch(/^(f\d+)?e\d+$/);
  return ref as string;
}

const refused = { ok: false, error: "FILL_TARGET_REFUSED", id: 2 };

/** 拒否の後は段階ログインが終わり、ブラウザは破棄されている。 */
async function expectEnded(): Promise<void> {
  expect(await step({ action: "snapshot" })).toMatchObject({
    ok: false,
    error: "INTERNAL",
  });
}

describe("fill target origin", { timeout: 90_000 }, () => {
  test("fills a same-origin iframe by f-refs", async () => {
    const begun = await begin();
    const username = refOf(begun, "textbox", "Same username");
    expect(username).toMatch(/^f\d+e\d+$/);

    const submitted = await step({
      action: "fill_submit",
      fills: [
        { ref: username, value: "{{username}}" },
        {
          ref: refOf(begun, "textbox", "Same password"),
          value: "{{password}}",
        },
      ],
      submit: { click: { ref: refOf(begun, "button", "Same go") } },
    });

    expect(submitted).toMatchObject({ ok: true, state: "pending" });
    expect(reports.slice(0, 2)).toEqual([
      { frame: "Same", length: USERNAME.length },
      { frame: "Same", length: PASSWORD.length },
    ]);
  });

  test("refuses a fill_submit with a cross-origin field before filling anything", async () => {
    const begun = await begin();

    const response = await step({
      action: "fill_submit",
      fills: [
        {
          ref: refOf(begun, "textbox", "Same username"),
          value: "{{username}}",
        },
        {
          ref: refOf(begun, "textbox", "Cross password"),
          value: "{{password}}",
        },
      ],
      submit: { click: { ref: refOf(begun, "button", "Main go") } },
    });

    expect(response).toEqual(refused);
    expect(reports).toEqual([]);
    await expectEnded();
  });

  test("refuses a lone username fill into a cross-origin frame", async () => {
    const begun = await begin();

    const response = await step({
      action: "fill",
      ref: refOf(begun, "textbox", "Cross username"),
      value: "{{username}}",
    });

    expect(response).toEqual(refused);
    expect(reports).toEqual([]);
    await expectEnded();
  });

  test.each([
    ["srcdoc", "Srcdoc password"],
    ["about:blank", "Blank password"],
  ])("refuses a %s frame", async (_kind, name) => {
    const begun = await begin();

    const response = await step({
      action: "fill_submit",
      fills: [{ ref: refOf(begun, "textbox", name), value: "{{password}}" }],
      submit: { click: { ref: refOf(begun, "button", "Main go") } },
    });

    expect(response).toEqual(refused);
    expect(reports).toEqual([]);
    await expectEnded();
  });

  test("lets click and wait_for reach a cross-origin frame", async () => {
    const begun = await begin();

    const waited = await step({
      action: "wait_for",
      ref: refOf(begun, "textbox", "Cross username"),
    });
    const clicked = await step({
      action: "click",
      ref: refOf(waited, "button", "Cross go"),
    });

    expect(waited).toMatchObject({ ok: true, state: "pending" });
    expect(clicked).toMatchObject({ ok: true, state: "pending" });
  });

  test("answers SELECTOR_NOT_FOUND for the f-ref of a removed iframe and goes on", async () => {
    const begun = await begin();

    const scheduled = await step({
      action: "click",
      ref: refOf(begun, "button", "Remove frame later"),
    });
    const framed = refOf(scheduled, "button", "Framed button");
    await new Promise((resolve) => setTimeout(resolve, 2_000));

    const stale = await step({ action: "click", ref: framed });
    const again = await step({ action: "snapshot" });

    expect(stale).toEqual({ ok: false, error: "SELECTOR_NOT_FOUND", id: 2 });
    expect(again).toMatchObject({ ok: true, state: "pending" });
    expect((again.snapshot as { page: string }).page).not.toContain(
      "Framed button",
    );
  });
});
