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
  collectRefs,
  displayForms,
  finalizeSnapshot,
  parseSnapshotLine,
  type RawAriaSnapshot,
  rejectionForms,
  SNAPSHOT_MAX_BYTES,
  SnapshotRejectedError,
  secretForms,
} from "../src/snapshot.js";
import { captureAriaSnapshot } from "../src/stepwise.js";

const USERNAME = "alice&co@example.test";
const PASSWORD = "correct horse/battery+staple";
const TOTP_CODE = "493817";
const URL = "https://example.test/login";

const secrets = { username: USERNAME, password: PASSWORD, totpCodes: [] };

function raw(
  aria: string,
  overrides: Partial<RawAriaSnapshot> = {},
): RawAriaSnapshot {
  return { url: URL, title: "Sign in", aria, roles: [], ...overrides };
}

function pageOf(aria: string, overrides: Partial<RawAriaSnapshot> = {}) {
  return finalizeSnapshot(raw(aria, overrides), true, secrets).snapshot.page;
}

function lines(...rows: string[]): string {
  return rows.join("\n");
}

describe("value removal", () => {
  test.each(["textbox", "searchbox", "spinbutton", "slider", "combobox"])(
    "drops the inline value of %s and marks it filled",
    (role) => {
      expect(pageOf(`- ${role} "Field" [ref=e3]: typed-value-marker`)).toBe(
        `- ${role} "Field" [ref=e3] [filled]`,
      );
    },
  );

  test("treats the collected explicit roles of input and textarea as value roles", () => {
    const aria = lines(
      '- note "Notey" [ref=e8]: note-value-marker',
      "- menuitem [ref=e9]: menu-value-marker",
      '- button "Keep" [ref=e10]: kept text',
    );

    const page = pageOf(aria, { roles: ["note", "bogus menuitem"] });

    expect(page).toBe(
      lines(
        '- note "Notey" [ref=e8] [filled]',
        "- menuitem [ref=e9] [filled]",
        '- button "Keep" [ref=e10]: kept text',
      ),
    );
  });

  test("drops a quoted value", () => {
    expect(pageOf('- textbox "User" [ref=e3]: "he said: \\"a: b\\" # x"')).toBe(
      '- textbox "User" [ref=e3] [filled]',
    );
  });

  test("does not mark an empty value filled", () => {
    expect(pageOf('- textbox "User" [ref=e3]: ""')).toBe(
      '- textbox "User" [ref=e3]',
    );
    expect(pageOf('- textbox "User" [ref=e3]')).toBe(
      '- textbox "User" [ref=e3]',
    );
  });

  test("puts the mark inside a single-quoted KEY", () => {
    expect(
      pageOf("- 'textbox \"it''s: here\" [ref=e3]': typed-value-marker"),
    ).toBe("- 'textbox \"it''s: here\" [ref=e3] [filled]'");
    expect(
      pageOf(
        lines(
          "- 'textbox \"a: b\" [ref=e4]':",
          "  - /placeholder: Enter it",
          "  - text: typed-value-marker",
        ),
      ),
    ).toBe(
      lines(
        "- 'textbox \"a: b\" [ref=e4] [filled]':",
        "  - /placeholder: Enter it",
      ),
    );
  });

  test("drops the direct text child of a field with a placeholder and keeps the placeholder", () => {
    const aria = lines(
      "- generic [ref=e4]:",
      "  - text: Ph",
      '  - textbox "Ph" [ref=e5]:',
      "    - /placeholder: Enter phone",
      "    - text: typed-value-marker",
      '  - textbox "Empty" [ref=e6]:',
      "    - /placeholder: Nothing yet",
    );

    expect(pageOf(aria)).toBe(
      lines(
        "- generic [ref=e4]:",
        "  - text: Ph",
        '  - textbox "Ph" [ref=e5] [filled]:',
        "    - /placeholder: Enter phone",
        '  - textbox "Empty" [ref=e6]:',
        "    - /placeholder: Nothing yet",
      ),
    );
  });

  test("touches neither deeper lines nor the descendants' own rules", () => {
    const aria = lines(
      "- generic [ref=e1]: generic-value-marker",
      '- note "Group" [ref=e2]:',
      "  - text: direct-text-marker",
      "  - generic [ref=e3]:",
      "    - text: deeper text",
      '    - textbox "Inner" [ref=e4]: inner-value-marker',
    );

    expect(pageOf(aria, { roles: ["note"] })).toBe(
      lines(
        "- generic [ref=e1]: generic-value-marker",
        '- note "Group" [ref=e2] [filled]:',
        "  - generic [ref=e3]:",
        "    - text: deeper text",
        '    - textbox "Inner" [ref=e4] [filled]',
      ),
    );
  });

  test("keeps the options of a select", () => {
    const aria = lines(
      '- combobox "Pick" [ref=e11]:',
      '  - option "One"',
      '  - option "Two" [selected]',
    );

    expect(pageOf(aria)).toBe(aria);
  });

  test("removes a password left in a field instead of rejecting the snapshot", () => {
    const page = pageOf(`- textbox "Password" [ref=e6]: ${PASSWORD}`);

    expect(page).toBe('- textbox "Password" [ref=e6] [filled]');
  });
});

describe("roles that could not be collected", () => {
  test("removes values from every role's heading line", () => {
    const aria = lines(
      "- generic [ref=e1]:",
      "  - text: label text",
      '  - button "Go" [ref=e2]: inline-value-marker',
      "  - paragraph [ref=e3]:",
      "    - text: direct-text-marker",
      '  - link "Help" [ref=e4]:',
      "    - /url: /help",
      '  - heading "Sign in" [level=1] [ref=e5]',
    );

    expect(pageOf(aria, { roles: "all" })).toBe(
      lines(
        "- generic [ref=e1] [filled]:",
        '  - button "Go" [ref=e2] [filled]',
        "  - paragraph [ref=e3] [filled]:",
        '  - link "Help" [ref=e4]:',
        "    - /url: /help",
        '  - heading "Sign in" [level=1] [ref=e5]',
      ),
    );
  });

  test("falls back to every role when a frame fails to answer", async () => {
    const working = {
      locator: () => ({
        all: async () => [{ getAttribute: async () => "note" }],
      }),
    };
    const failing = {
      locator: () => ({
        all: async () => {
          throw new Error("Frame was detached");
        },
      }),
    };
    const fake = (frames: unknown[]) =>
      ({
        frames: () => frames,
        ariaSnapshot: async () => '- button "Go" [ref=e1]: inline-value-marker',
        title: async () => "Sign in",
        url: () => URL,
      }) as unknown as Page;

    expect((await captureAriaSnapshot(fake([working]))).roles).toEqual([
      "note",
    ]);
    const captured = await captureAriaSnapshot(fake([working, failing]));

    expect(captured.roles).toBe("all");
    expect(finalizeSnapshot(captured, true, secrets).snapshot.page).toBe(
      '- button "Go" [ref=e1] [filled]',
    );
  });
});

describe("line grammar", () => {
  test("passes the known line kinds through unchanged", () => {
    const aria = lines(
      "- generic [active] [ref=e1]:",
      "  - 'heading \"Hello: world #x\" [level=1] [ref=e2]'",
      "  - text: Email",
      '  - link "Help" [ref=e3] [cursor=pointer]:',
      "    - /url: /help?q=1",
      '  - checkbox "Remember" [checked] [ref=e4]',
      "  - 'button \"it''s: odd\" [ref=e5]'",
      '  - text: "quoted: text"',
      "  - iframe [ref=e6]:",
      '    - button "Inner" [ref=f1e2]',
    );

    expect(pageOf(aria)).toBe(aria);
    expect(
      parseSnapshotLine("  - 'heading \"Hello: world #x\" [level=1] [ref=e2]'"),
    ).toMatchObject({
      indent: 2,
      role: "heading",
      name: "Hello: world #x",
      attrs: ["level=1", "ref=e2"],
      quoted: true,
    });
    expect(parseSnapshotLine("    - /url: /help?q=1")).toMatchObject({
      role: "/url",
      value: "/help?q=1",
    });
  });

  test.each([
    "garbage",
    "- link /root [ref=e1]",
    "- link root/ [ref=e1]",
    "- 'link /a/ [ref=e1]: b'",
    "- <changed> button [ref=e2]",
    "- ref=e3 [unchanged]",
    '- button "unterminated [ref=e4]',
    '- \'button "open" [ref=e5]',
    '- button "x" [ref=e6]:value',
    '- button "x" [ref=e6]: ',
    '- button "x" [Ref=e6]',
    "\t- button [ref=e7]",
  ])("refuses to return a snapshot with the line %j", (line) => {
    const aria = lines('- heading "Sign in" [level=1] [ref=e1]', line);

    expect(() => finalizeSnapshot(raw(aria), true, secrets)).toThrow(
      SnapshotRejectedError,
    );
  });

  test("refuses an empty line between lines", () => {
    expect(() =>
      finalizeSnapshot(
        raw(lines("- button [ref=e1]", "", "- button [ref=e2]")),
        true,
        secrets,
      ),
    ).toThrow(SnapshotRejectedError);
  });

  test("returns an empty page for an empty snapshot", () => {
    const { snapshot, refs } = finalizeSnapshot(raw(""), true, secrets);
    expect(snapshot.page).toBe("");
    expect(refs.size).toBe(0);
  });
});

describe("unquoted /…/ names", () => {
  test.each([
    ["- link / [ref=e17]", "/", ["ref=e17"]],
    [
      "- link /root/ [ref=e18] [cursor=pointer]:",
      "/root/",
      ["ref=e18", "cursor=pointer"],
    ],
    ['- link "/" [ref=e1]', "/", ["ref=e1"]],
    ['- link /a "b" [c]/ [ref=e2]', '/a "b" [c]/', ["ref=e2"]],
    ["- 'link /it''s: here/ [ref=e3]'", "/it's: here/", ["ref=e3"]],
  ])("reads %j", (raw, name, attrs) => {
    expect(parseSnapshotLine(raw)).toMatchObject({ name, attrs });
  });

  test("tells a JSON name from an unquoted one", () => {
    expect(parseSnapshotLine('- link "/" [ref=e1]')?.quoted).toBe(false);
    expect(parseSnapshotLine("- link / [ref=e1]")?.keyEnd).toBe(
      "- link / [ref=e1]".length,
    );
  });

  test("keeps a [ref=…] inside an unquoted name out of the ledger", () => {
    const aria = lines(
      "- link /a [ref=e99] b/ [ref=e3]",
      "- 'link /c: [ref=e98]/ [ref=e4]'",
    );

    const { snapshot, refs } = finalizeSnapshot(raw(aria), true, secrets);

    expect(snapshot.page).toBe(aria);
    expect([...refs].sort()).toEqual(["e3", "e4"]);
    expect(parseSnapshotLine("- link /a [ref=e99] b/ [ref=e3]")).toMatchObject({
      name: "/a [ref=e99] b/",
      attrs: ["ref=e3"],
    });
  });

  test("removes the value of a field with an unquoted name", () => {
    const aria = lines(
      "- textbox /user/ [ref=e3]: typed-value-marker",
      "- textbox /a/b/ [ref=e4]: a/ [ref=e9]",
      '- textbox /p/ [ref=e5]: "x/ [ref=e8]: y"',
      "- 'textbox /q: r/ [ref=e6]': quoted-key-marker",
      "- textbox /ph/ [ref=e7]:",
      "  - /placeholder: Enter it",
      "  - text: child-value-marker",
    );

    const { snapshot, refs } = finalizeSnapshot(raw(aria), true, secrets);

    expect(snapshot.page).toBe(
      lines(
        "- textbox /user/ [ref=e3] [filled]",
        "- textbox /a/b/ [ref=e4] [filled]",
        "- textbox /p/ [ref=e5] [filled]",
        "- 'textbox /q: r/ [ref=e6] [filled]'",
        "- textbox /ph/ [ref=e7] [filled]:",
        "  - /placeholder: Enter it",
      ),
    );
    expect([...refs].sort()).toEqual(["e3", "e4", "e5", "e6", "e7"]);
  });
});

describe("ref ledger", () => {
  test("takes refs only from the attribute part of each KEY", () => {
    const aria = lines(
      '- button "Click [ref=e90]" [ref=e1]',
      "- text: see [ref=e91]",
      '- generic [ref=e2]: "[ref=e92]"',
      "- 'heading \"a: [ref=e93]\" [level=2] [ref=f3e4]'",
      "- img",
    );

    const { refs } = finalizeSnapshot(raw(aria), true, secrets);

    expect([...refs].sort()).toEqual(["e1", "e2", "f3e4"]);
  });

  test("drops the refs of the lines a cut removes", () => {
    const rows = Array.from(
      { length: 3000 },
      (_, index) =>
        `- link "${"entry ".repeat(4)}${index}" [ref=e${index + 1}]`,
    );

    const { snapshot, refs } = finalizeSnapshot(
      raw(lines(...rows)),
      true,
      secrets,
    );

    expect(snapshot.truncated).toBe(true);
    expect(refs.has("e1")).toBe(true);
    expect(refs.has("e3000")).toBe(false);
    expect(refs).toEqual(collectRefs(snapshot.page));
    expect(refs.size).toBe(snapshot.page.split("\n").length);
  });
});

describe("limit", () => {
  test("cuts the page by whole lines from the end to stay within 64 KiB", () => {
    const rows = Array.from(
      { length: 2000 },
      (_, index) =>
        `- button "${"label ".repeat(10)}${index}" [ref=e${index + 1}]`,
    );

    const { snapshot } = finalizeSnapshot(raw(lines(...rows)), false, secrets);

    expect(snapshot.truncated).toBe(true);
    expect(snapshot.settled).toBe(false);
    expect(Buffer.byteLength(JSON.stringify(snapshot))).toBeLessThanOrEqual(
      SNAPSHOT_MAX_BYTES,
    );
    const kept = snapshot.page.split("\n");
    expect(kept.length).toBeLessThan(rows.length);
    expect(kept).toEqual(rows.slice(0, kept.length));
    // 1 行足すと上限を超える位置で切られている。
    const oneMore = {
      ...snapshot,
      page: rows.slice(0, kept.length + 1).join("\n"),
    };
    expect(Buffer.byteLength(JSON.stringify(oneMore))).toBeGreaterThan(
      SNAPSHOT_MAX_BYTES,
    );
  });

  test("leaves a page within the limit as it is", () => {
    const { snapshot } = finalizeSnapshot(
      raw('- button "Go" [ref=e1]'),
      true,
      secrets,
    );
    expect(snapshot).toEqual({
      url: URL,
      title: "Sign in",
      page: '- button "Go" [ref=e1]',
      settled: true,
    });
  });

  test("shortens title and url when the page alone cannot make room", () => {
    const { snapshot } = finalizeSnapshot(
      raw('- button "Go" [ref=e1]', {
        title: "t".repeat(70_000),
        url: `${URL}?q=${"u".repeat(5000)}`,
      }),
      true,
      secrets,
    );

    expect(snapshot.truncated).toBe(true);
    expect(snapshot.page).toBe("");
    expect(snapshot.title).toHaveLength(256);
    expect(snapshot.url).toHaveLength(2048);
  });
});

describe("secret inspection", () => {
  const TRICKY = 'a\'b "c" \\d: e  f​';

  test("builds the 6 display forms", () => {
    const n = 'a\'b "c" \\d: e f';
    const j = 'a\'b \\"c\\" \\\\d: e f';
    const y = 'a\'b \\"c\\" \\\\d: e f';
    const forms = displayForms(TRICKY);
    for (const form of [n, j, y]) {
      expect(forms).toContain(form);
      expect(forms).toContain(form.replaceAll("'", "''"));
    }
    expect(displayForms("tab\u0008bell")).toEqual(
      expect.arrayContaining(["tab\\bbell", "tab\\x08bell"]),
    );
  });

  test("checks the 8 encodings of both the raw and the normalised value", () => {
    const forms = rejectionForms(" two  spaces ");
    for (const form of [
      ...secretForms(" two  spaces "),
      ...secretForms("two spaces"),
    ]) {
      expect(forms).toContain(form);
    }
  });

  test.each(secretForms(PASSWORD).map((form) => [form]))(
    "rejects the password in the form %s wherever it appears",
    (form) => {
      const placements: RawAriaSnapshot[] = [
        raw(`- text: echo ${form} echo`),
        raw('- button "Go" [ref=e1]', { title: form }),
        raw(`- button ${JSON.stringify(form)} [ref=e1]`),
        raw('- button "Go" [ref=e1]', { url: `${URL}?p=${form}` }),
      ];
      for (const snapshot of placements) {
        expect(() => finalizeSnapshot(snapshot, true, secrets)).toThrow(
          SnapshotRejectedError,
        );
      }
    },
  );

  test("rejects a password shown as a name, a value or inside a single-quoted KEY", () => {
    const tricky = { ...secrets, password: TRICKY };
    const n = 'a\'b "c" \\d: e f';
    const name = JSON.stringify(n);
    const yaml = `"${n.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
    const placements = [
      `- button ${name} [ref=e1]`,
      `- '${`button ${name} [ref=e1]`.replaceAll("'", "''")}'`,
      `- text: ${yaml}`,
      `- paragraph [ref=e2]: ${yaml}`,
      `- link "Go" [ref=e3]:\n  - /url: ${yaml}`,
    ];
    for (const aria of placements) {
      expect(() => finalizeSnapshot(raw(aria), true, tricky), aria).toThrow(
        SnapshotRejectedError,
      );
    }
    expect(() =>
      finalizeSnapshot(
        raw('- button "Go" [ref=e1]', { title: n }),
        true,
        tricky,
      ),
    ).toThrow(SnapshotRejectedError);
  });

  test("checks before masking, so a password that contains the username is caught", () => {
    const overlapping = {
      username: "alice",
      password: "alice-wonder-42",
      totpCodes: [],
    };

    expect(() =>
      finalizeSnapshot(raw("- text: alice-wonder-42"), true, overlapping),
    ).toThrow(SnapshotRejectedError);
  });

  test("checks the whole page before the cut", () => {
    const rows = Array.from(
      { length: 3000 },
      (_, index) => `- link "entry ${index}" [ref=e${index + 1}]`,
    );
    const aria = lines(...rows, `- text: ${PASSWORD}`);

    expect(() => finalizeSnapshot(raw(aria), true, secrets)).toThrow(
      SnapshotRejectedError,
    );
    expect(
      finalizeSnapshot(raw(lines(...rows)), true, secrets).snapshot.truncated,
    ).toBe(true);
  });

  test("rejects an entered TOTP code", () => {
    expect(() =>
      finalizeSnapshot(raw(`- text: Code ${TOTP_CODE}`), true, {
        ...secrets,
        totpCodes: [TOTP_CODE],
      }),
    ).toThrow(SnapshotRejectedError);
  });

  test("does not reject a partial echo", () => {
    const partial = PASSWORD.slice(0, -1);
    const page = pageOf(`- text: ${partial} ••••${PASSWORD.slice(-4)}`);
    expect(page).toContain(partial);
  });
});

describe("username masking", () => {
  test("masks the raw, HTML-escaped, URL-encoded and displayed username", () => {
    const spaced = { ...secrets, username: "bob  o'neil" };
    const { snapshot } = finalizeSnapshot(
      raw(
        lines(
          `- text: Signed in as ${USERNAME}`,
          "- text: Continue as bob o'neil",
          "- 'button \"Not bob o''neil: switch\" [ref=e1]'",
        ),
        {
          title: `Hello ${USERNAME}`,
          url: `${URL}?u=${encodeURIComponent(USERNAME)}`,
        },
      ),
      true,
      secrets,
    );
    expect(snapshot.page.split("\n")[0]).toBe(
      "- text: Signed in as [username]",
    );
    expect(snapshot.title).toBe("Hello [username]");
    expect(snapshot.url).toBe(`${URL}?u=[username]`);

    const displayed = finalizeSnapshot(
      raw(
        lines(
          "- text: Continue as bob o'neil",
          "- 'button \"Not bob o''neil: switch\" [ref=e1]'",
        ),
      ),
      true,
      spaced,
    ).snapshot.page;
    expect(displayed).toBe(
      lines(
        "- text: Continue as [username]",
        "- 'button \"Not [username]: switch\" [ref=e1]'",
      ),
    );
  });
});

describe("capture from a page", { timeout: 60_000 }, () => {
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

  const canaries = [
    "value-attribute-marker",
    "typed-value-marker",
    "textarea-default-marker",
    "hidden-value-marker",
    "data-attribute-marker",
    "script-variable-marker",
    "explicit-role-marker",
    "shadow-role-marker",
    "framed-role-marker",
    "placeholder-field-marker",
  ];

  const form = `
    <h1>Sign in</h1>
    <form>
      <label for="user">User name</label>
      <input id="user" type="text" value="value-attribute-marker"
        data-secret="data-attribute-marker">
      <label>Typed <input id="typed" type="text"></label>
      <label>Note <textarea>textarea-default-marker</textarea></label>
      <input type="hidden" name="csrf" value="hidden-value-marker">
      <input role="note" aria-label="Explicit" value="explicit-role-marker">
      <label>Phone <input placeholder="Enter phone" value="placeholder-field-marker"></label>
      <select aria-label="Choice"><option>Visible option</option></select>
      <button type="submit">Continue</button>
    </form>
    <div id="host"></div>
    <iframe srcdoc="<input role='menuitem' aria-label='Framed' value='framed-role-marker'>"></iframe>
    <script>
      var leaked = "script-variable-marker";
      document.getElementById("host").attachShadow({ mode: "open" }).innerHTML =
        '<input role="status" aria-label="Shadow" value="shadow-role-marker">';
    </script>
  `;

  test("leaves every value out and keeps the structure", async () => {
    await page.setContent(form);
    await page.fill("#typed", "typed-value-marker");
    await page.waitForFunction(
      () =>
        (document
          .querySelector("iframe")
          ?.contentDocument?.querySelector("input") ?? null) !== null,
    );

    const captured = await captureAriaSnapshot(page);
    const { snapshot, refs } = finalizeSnapshot(captured, true, secrets);
    const serialized = JSON.stringify(snapshot);

    expect(captured.roles).toEqual(
      expect.arrayContaining(["note", "status", "menuitem"]),
    );
    for (const canary of canaries) expect(serialized).not.toContain(canary);
    expect(snapshot.page).toMatch(
      /textbox "User name" \[ref=e\d+\] \[filled\]$/mu,
    );
    expect(snapshot.page).toMatch(/note "Explicit" \[ref=e\d+\] \[filled\]$/mu);
    expect(snapshot.page).toMatch(/status "Shadow" \[ref=e\d+\] \[filled\]$/mu);
    expect(snapshot.page).toMatch(
      /menuitem "Framed" \[ref=f\d+e\d+\] \[filled\]$/mu,
    );
    expect(snapshot.page).toMatch(
      /textbox "Phone" \[ref=e\d+\] \[filled\]:\n\s+- \/placeholder: Enter phone$/mu,
    );
    expect(snapshot.page).toContain('option "Visible option"');
    expect(snapshot.page).toMatch(/button "Continue" \[ref=e\d+\]/u);
    for (const raw of snapshot.page.split("\n")) {
      expect(parseSnapshotLine(raw), raw).toBeDefined();
    }
    expect(refs.size).toBeGreaterThan(5);
    // 台帳の ref は、取得の直後に aria-ref で解決できる。
    for (const ref of refs) {
      expect(await page.locator(`aria-ref=${ref}`).count(), ref).toBe(1);
    }
  });

  test("collects explicit roles even when the page replaces the DOM built-ins", async () => {
    const tamper = `
      Element.prototype.querySelectorAll = function () { return []; };
      Document.prototype.querySelectorAll = function () { return []; };
      DocumentFragment.prototype.querySelectorAll = function () { return []; };
      Element.prototype.querySelector = function () { return null; };
      Element.prototype.getAttribute = function () { return null; };
      Element.prototype.matches = function () { return false; };
    `;
    await page.setContent(`
      <input role="note" aria-label="Explicit" value="explicit-role-marker">
      <div id="host"></div>
      <iframe srcdoc="<input role='menuitem' aria-label='Framed' value='framed-role-marker'><script>${tamper.replaceAll('"', "&quot;")}</script>"></iframe>
      <script>
        document.getElementById("host").attachShadow({ mode: "open" }).innerHTML =
          '<textarea role="status" aria-label="Shadow">shadow-role-marker</textarea>';
        ${tamper}
      </script>
    `);
    await page.waitForFunction(() => window.frames.length === 1);
    await page.frames()[1].waitForLoadState();

    const captured = await captureAriaSnapshot(page);
    const { snapshot } = finalizeSnapshot(captured, true, secrets);

    expect(captured.roles).toEqual(
      expect.arrayContaining(["note", "status", "menuitem"]),
    );
    for (const canary of [
      "explicit-role-marker",
      "framed-role-marker",
      "shadow-role-marker",
    ]) {
      expect(snapshot.page).not.toContain(canary);
    }
  });

  test("returns the unquoted /…/ names Playwright writes", async () => {
    // Playwright は / で始まり / で終わる名前を、JSON 文字列にせず引用なしで出力する。
    await page.setContent(
      '<a href="/x">/</a> <a href="/y">/root/</a> <input aria-label="/path/" value="typed-value-marker">',
    );

    const captured = await captureAriaSnapshot(page);
    const { snapshot, refs } = finalizeSnapshot(captured, true, secrets);

    expect(captured.aria).toMatch(/^\s*- link \/ \[ref=e\d+\]/mu);
    expect(snapshot.page).toMatch(/^\s*- link \/root\/ \[ref=e\d+\]/mu);
    expect(snapshot.page).toMatch(
      /^\s*- textbox \/path\/ \[ref=e\d+\] \[filled\]$/mu,
    );
    expect(snapshot.page).not.toContain("typed-value-marker");
    for (const ref of refs) {
      expect(await page.locator(`aria-ref=${ref}`).count(), ref).toBe(1);
    }
  });
});
