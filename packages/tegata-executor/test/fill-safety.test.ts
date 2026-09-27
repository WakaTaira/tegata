import { type Browser, chromium, type Page } from "playwright-core";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "vitest";
import {
  classifyError,
  FillMismatchError,
  parseRequest,
  runSteps,
  SelectorNotFoundError,
} from "../src/index.js";

const secret = {
  username: "alice@example.test",
  password: "correct-horse-battery",
  totp: null,
};

let browser: Browser;
let page: Page;

beforeAll(async () => {
  browser = await chromium.launch({ headless: true });
});

afterAll(async () => {
  await browser.close();
});

beforeEach(async () => {
  page = await browser.newPage();
});

afterEach(async () => {
  await page.close();
});

async function fieldValue(selector: string): Promise<string> {
  return page.locator(selector).inputValue();
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => undefined,
    (error: unknown) => error,
  );
}

// フォーカス奪取型のサイト（Issue #43）を模す。パスワード欄がフォーカスを得ると
// ユーザー名欄へフォーカスを戻すため、フォーカス経由の入力ではユーザー名欄へ秘密が追記される。
const focusStealingForm = `
  <form onsubmit="event.preventDefault(); window.submitted = true;">
    <input id="user" type="text">
    <input id="pass" type="password">
    <button type="submit">Log in</button>
  </form>
  <script>
    const user = document.getElementById("user");
    document.getElementById("pass").addEventListener("focus", () => user.focus());
  </script>
`;

describe("focus-independent fill", () => {
  test("keeps each explicit step value in its own field on a focus-stealing page", async () => {
    await page.setContent(focusStealingForm);

    await runSteps(
      page,
      [
        { action: "fill", selector: "#user", value: "{{username}}" },
        { action: "fill", selector: "#pass", value: "{{password}}" },
      ],
      secret,
    );

    expect(await fieldValue("#user")).toBe(secret.username);
    expect(await fieldValue("#pass")).toBe(secret.password);
  });

  test("keeps each automatic fill in its own field on a focus-stealing page", async () => {
    await page.setContent(focusStealingForm);

    await runSteps(page, null, secret);

    expect(await fieldValue("#user")).toBe(secret.username);
    expect(await fieldValue("#pass")).toBe(secret.password);
    expect(await page.evaluate(() => Reflect.get(window, "submitted"))).toBe(
      true,
    );
  });

  test("updates a React-like controlled input that tracks value assignments", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <script>
        // React は value の代入を追跡し、追跡値と一致する input イベントを無視する。
        const input = document.getElementById("user");
        const native = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
        let tracked = "";
        window.state = "";
        Object.defineProperty(input, "value", {
          configurable: true,
          get() { return native.get.call(this); },
          set(next) { tracked = next; native.set.call(this, next); },
        });
        input.addEventListener("input", () => {
          const current = native.get.call(input);
          if (current !== tracked) {
            tracked = current;
            window.state = current;
          }
        });
      </script>
    `);

    await runSteps(
      page,
      [{ action: "fill", selector: "#user", value: "{{username}}" }],
      secret,
    );

    expect(await page.evaluate(() => Reflect.get(window, "state"))).toBe(
      secret.username,
    );
  });
});

describe("FILL_MISMATCH", () => {
  test("refuses to fill the password into a field that is not a password input", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <input id="pass" type="text">
    `);

    const error = await caught(
      runSteps(
        page,
        [
          { action: "fill", selector: "#user", value: "{{username}}" },
          { action: "fill", selector: "#pass", value: "{{password}}" },
        ],
        secret,
      ),
    );

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(error).toMatchObject({ stepIndex: 1 });
    expect(classifyError(error, "login")).toBe("FILL_MISMATCH");
    expect(String(error)).not.toContain(secret.password);
    expect(await fieldValue("#pass")).toBe("");
  });

  test("clears every field changed by a page handler during the fill", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <input id="pass" type="password">
      <script>
        const user = document.getElementById("user");
        document.getElementById("pass").addEventListener("input", (event) => {
          user.value += event.target.value;
        });
      </script>
    `);

    const error = await caught(
      runSteps(
        page,
        [
          { action: "fill", selector: "#user", value: "{{username}}" },
          { action: "fill", selector: "#pass", value: "{{password}}" },
        ],
        secret,
      ),
    );

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(error).toMatchObject({ stepIndex: 1 });
    expect(await fieldValue("#user")).toBe("");
    expect(await fieldValue("#pass")).toBe("");
  });

  test("fails when the page rewrites the target value during the fill", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <script>
        const user = document.getElementById("user");
        user.addEventListener("input", () => {
          if (user.value !== "") user.value = user.value.slice(1);
        });
      </script>
    `);

    const error = await caught(
      runSteps(
        page,
        [{ action: "fill", selector: "#user", value: "{{username}}" }],
        secret,
      ),
    );

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(error).toMatchObject({ stepIndex: 0 });
    expect(await fieldValue("#user")).toBe("");
  });

  test("refuses to fill an element that is not an input or textarea", async () => {
    await page.setContent('<div id="user" contenteditable="true"></div>');

    const error = await caught(
      runSteps(
        page,
        [{ action: "fill", selector: "#user", value: "{{username}}" }],
        secret,
      ),
    );

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(error).toMatchObject({ stepIndex: 0 });
    expect(await page.locator("#user").textContent()).toBe("");
  });

  test("reports automatic mode mismatches without a step index", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <input id="pass" type="password">
      <script>
        const user = document.getElementById("user");
        document.getElementById("pass").addEventListener("input", (event) => {
          user.value += event.target.value;
        });
      </script>
    `);

    const error = await caught(runSteps(page, null, secret));

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(error).toMatchObject({ stepIndex: undefined });
    expect(await fieldValue("#user")).toBe("");
    expect(await fieldValue("#pass")).toBe("");
  });
});

describe("post-fill verification", () => {
  async function fillPasswordError(): Promise<unknown> {
    return caught(
      runSteps(
        page,
        [{ action: "fill", selector: "#pass", value: "{{password}}" }],
        secret,
      ),
    );
  }

  test("clears again when a clear-event handler writes a value back", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <input id="pass" type="password">
      <script>
        const user = document.getElementById("user");
        const pass = document.getElementById("pass");
        let restoredUser = false;
        let restoredPass = false;
        pass.addEventListener("input", () => {
          if (pass.value !== "") {
            user.value += pass.value;
          } else if (!restoredPass) {
            restoredPass = true;
            pass.value = "restored-pass";
          }
        });
        user.addEventListener("input", () => {
          if (user.value === "" && !restoredUser) {
            restoredUser = true;
            user.value = "restored-user";
          }
        });
      </script>
    `);

    const error = await fillPasswordError();

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(await fieldValue("#user")).toBe("");
    expect(await fieldValue("#pass")).toBe("");
  });

  test.each([
    ["queueMicrotask", "queueMicrotask(write)"],
    ["setTimeout(0)", "setTimeout(write, 0)"],
  ])("detects a change deferred with %s", async (_name, schedule) => {
    await page.setContent(`
      <input id="user" type="text">
      <input id="pass" type="password">
      <script>
        const user = document.getElementById("user");
        document.getElementById("pass").addEventListener("input", (event) => {
          const leaked = event.target.value;
          const write = () => { if (leaked !== "") user.value += leaked; };
          ${schedule};
        });
      </script>
    `);

    const error = await fillPasswordError();

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(await fieldValue("#user")).toBe("");
    expect(await fieldValue("#pass")).toBe("");
  });

  test("detects and clears a change inside an open shadow root", async () => {
    await page.setContent(`
      <div id="host"></div>
      <input id="pass" type="password">
      <script>
        const root = document.getElementById("host").attachShadow({ mode: "open" });
        const shadowUser = document.createElement("input");
        shadowUser.id = "shadow-user";
        root.append(shadowUser);
        document.getElementById("pass").addEventListener("input", (event) => {
          shadowUser.value += event.target.value;
        });
      </script>
    `);

    const error = await fillPasswordError();

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(await fieldValue("#shadow-user")).toBe("");
    expect(await fieldValue("#pass")).toBe("");
  });

  test("fills a target that lives inside a shadow root", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <div id="host"></div>
      <script>
        const root = document.getElementById("host").attachShadow({ mode: "open" });
        const pass = document.createElement("input");
        pass.id = "pass";
        pass.type = "password";
        root.append(pass);
      </script>
    `);

    await runSteps(
      page,
      [
        { action: "fill", selector: "#user", value: "{{username}}" },
        { action: "fill", selector: "#pass", value: "{{password}}" },
      ],
      secret,
    );

    expect(await fieldValue("#user")).toBe(secret.username);
    expect(await fieldValue("#pass")).toBe(secret.password);
  });

  test("converts a throwing value getter into FILL_MISMATCH and clears the target", async () => {
    await page.setContent(`
      <input id="pass" type="password">
      <script>
        const pass = document.getElementById("pass");
        const native = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
        Object.defineProperty(pass, "value", {
          configurable: true,
          get() {
            const current = native.get.call(this);
            if (current !== "") throw new Error("page-thrown:" + current);
            return current;
          },
          set(next) { native.set.call(this, next); },
        });
      </script>
    `);

    const error = await fillPasswordError();

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(error).toMatchObject({ stepIndex: 0 });
    expect(classifyError(error, "login")).toBe("FILL_MISMATCH");
    expect(String(error)).not.toContain("page-thrown");
    expect(String(error)).not.toContain(secret.password);
    expect((error as Error).message).not.toContain("page-thrown");
    expect(await fieldValue("#pass")).toBe("");
  });

  test("converts a tampered Map.prototype.get into FILL_MISMATCH and clears the target", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <input id="pass" type="password">
      <script>
        window.originalMapGet = Map.prototype.get;
        document.getElementById("pass").addEventListener("input", (event) => {
          const filled = event.target.value;
          if (filled === "") return;
          Map.prototype.get = function () {
            throw new Error("page-thrown:" + filled);
          };
        });
      </script>
    `);

    const error = await fillPasswordError();
    await page.evaluate(() => {
      Map.prototype.get = Reflect.get(window, "originalMapGet");
    });

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(error).toMatchObject({ stepIndex: 0 });
    expect(classifyError(error, "login")).toBe("FILL_MISMATCH");
    expect(String(error)).not.toContain("page-thrown");
    expect(String(error)).not.toContain(secret.password);
    expect((error as Error).message).not.toContain("page-thrown");
    expect(await fieldValue("#pass")).toBe("");
  });

  test("succeeds when an input handler throws but every value ends up correct", async () => {
    await page.setContent(`
      <input id="pass" type="password">
      <script>
        document.getElementById("pass").addEventListener("input", (event) => {
          if (event.target.value !== "") {
            throw new Error("page-thrown:" + event.target.value);
          }
        });
      </script>
    `);

    const error = await fillPasswordError();

    expect(error).toBeUndefined();
    expect(await fieldValue("#pass")).toBe(secret.password);
  });

  test("clears an input appended with a value during the fill", async () => {
    await page.setContent(`
      <input id="pass" type="password">
      <script>
        document.getElementById("pass").addEventListener("input", (event) => {
          if (event.target.value === "") return;
          const leak = document.createElement("input");
          leak.id = "leak";
          leak.value = event.target.value;
          document.body.append(leak);
        });
      </script>
    `);

    const error = await fillPasswordError();

    expect(error).toBeInstanceOf(FillMismatchError);
    expect(await fieldValue("#leak")).toBe("");
    expect(await fieldValue("#pass")).toBe("");
  });
});

describe("wait_for step", () => {
  test("parses a wait_for step in login and device requests", () => {
    const steps = [
      { action: "wait_for", selector: "#pass" },
      { action: "fill", selector: "#pass", value: "{{password}}" },
    ];
    const secretField = { username: "alice", password: "secret", totp: null };

    expect(
      parseRequest(
        JSON.stringify({
          op: "login",
          target_url: "https://example.test/login",
          steps,
          secret: secretField,
        }),
      ),
    ).toMatchObject({ steps });
    expect(
      parseRequest(
        JSON.stringify({
          op: "authorize_device",
          login_url: "https://example.test/login",
          verification_url: "https://example.test/device",
          user_code: "ABCD-EFGH",
          steps,
          success_selector: "#success",
          secret: secretField,
        }),
      ),
    ).toMatchObject({ steps });
  });

  test("waits until the selector becomes visible", async () => {
    await page.setContent(`
      <input id="user" type="text">
      <script>
        setTimeout(() => {
          const pass = document.createElement("input");
          pass.id = "pass";
          pass.type = "password";
          document.body.append(pass);
        }, 300);
      </script>
    `);

    await runSteps(
      page,
      [
        { action: "fill", selector: "#user", value: "{{username}}" },
        { action: "wait_for", selector: "#pass" },
        { action: "fill", selector: "#pass", value: "{{password}}" },
      ],
      secret,
    );

    expect(await fieldValue("#pass")).toBe(secret.password);
  });

  test("reports SELECTOR_NOT_FOUND with the step index on timeout", async () => {
    await page.setContent(
      '<input id="user" type="text"><input id="pass" type="password" hidden>',
    );

    const error = await caught(
      runSteps(
        page,
        [
          { action: "fill", selector: "#user", value: "{{username}}" },
          { action: "wait_for", selector: "#pass" },
        ],
        secret,
      ),
    );

    expect(error).toBeInstanceOf(SelectorNotFoundError);
    expect(error).toMatchObject({ stepIndex: 1 });
    expect(classifyError(error, "login")).toBe("SELECTOR_NOT_FOUND");
  }, 20_000);
});
