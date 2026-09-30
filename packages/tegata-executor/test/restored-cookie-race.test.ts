import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { type Browser, chromium, type Page } from "playwright-core";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "vitest";
import { raceSuccessAgainstFirstStep } from "../src/index.js";

const PASSWORD = 'input[type="password"]';
const SUCCESS = ".account-menu";

// The success element appears this long after load, so the race cannot be won by a timing accident.
const SUCCESS_DELAY_MS = 1500;

const pages: Record<string, string> = {
  // A hidden password field precedes the visible one; the success element appears late.
  "/hidden-first-step": `
    <input type="password" hidden>
    <input type="password">
    <script>
      setTimeout(() => {
        document.body.insertAdjacentHTML("beforeend", '<div class="account-menu">Account</div>');
      }, ${SUCCESS_DELAY_MS});
    </script>
  `,
  // A hidden success element precedes the visible one; there is no password field.
  "/hidden-first-success": `
    <div class="account-menu" hidden>Account</div>
    <div class="account-menu">Account</div>
  `,
};

describe("race between success and the first step", { timeout: 60_000 }, () => {
  let server: Server;
  let origin: string;
  let browser: Browser;
  let page: Page;

  beforeAll(async () => {
    server = createServer((request, response) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(`<!doctype html><body>${pages[request.url ?? ""] ?? ""}`);
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", () => resolve()),
    );
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    browser = await chromium.launch({ headless: true });
  });

  afterAll(async () => {
    await browser.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(async () => {
    page = await browser.newPage();
    return async () => {
      await page.close();
    };
  });

  test("a visible first-step match is found behind a hidden one", async () => {
    await page.goto(`${origin}/hidden-first-step`);
    expect(await raceSuccessAgainstFirstStep(page, SUCCESS, PASSWORD)).toBe(
      "steps",
    );
  });

  test("a visible success match is found behind a hidden one", async () => {
    await page.goto(`${origin}/hidden-first-success`);
    expect(await raceSuccessAgainstFirstStep(page, SUCCESS, PASSWORD)).toBe(
      "success",
    );
  });
});
