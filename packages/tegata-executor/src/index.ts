#!/usr/bin/env node

import { createServer } from "node:net";
import { createInterface } from "node:readline";
import { type Browser, chromium, type Page } from "playwright-core";

type FillStep = {
  action: "fill";
  selector: string;
  value: "{{username}}" | "{{password}}" | "{{totp}}";
};

type ClickStep = {
  action: "click";
  selector: string;
};

type LoginStep = FillStep | ClickStep;

type LoginRequest = {
  op: "login";
  target_url: string;
  steps: LoginStep[] | null;
  success_selector: string | null;
  failure_selector: string | null;
  secret: {
    username: string;
    password: string;
    totp: string | null;
  };
};

type Request = LoginRequest | { op: "shutdown" };

type ErrorCode =
  | "INVALID_CREDENTIAL"
  | "MFA_REQUIRED"
  | "SELECTOR_NOT_FOUND"
  | "VAULT_LOCKED"
  | "RATE_LIMITED"
  | "TOTP_NOT_EXPOSABLE"
  | "INTERNAL";

class SelectorNotFoundError extends Error {}

class InvalidCredentialError extends Error {}

class MfaRequiredError extends Error {}

let activeBrowser: Browser | undefined;
let shuttingDown = false;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isSecretPlaceholder(value: unknown): value is FillStep["value"] {
  return (
    value === "{{username}}" || value === "{{password}}" || value === "{{totp}}"
  );
}

function parseRequest(line: string): Request {
  const value: unknown = JSON.parse(line);
  if (!isRecord(value) || (value.op !== "login" && value.op !== "shutdown")) {
    throw new Error("invalid request");
  }
  if (value.op === "shutdown") return { op: "shutdown" };

  const secret = value.secret;
  if (
    typeof value.target_url !== "string" ||
    (value.success_selector !== undefined &&
      !isNullableString(value.success_selector)) ||
    (value.failure_selector !== undefined &&
      !isNullableString(value.failure_selector)) ||
    !isRecord(secret) ||
    typeof secret.username !== "string" ||
    typeof secret.password !== "string" ||
    (secret.totp !== undefined && !isNullableString(secret.totp))
  ) {
    throw new Error("invalid login request");
  }

  let steps: LoginStep[] | null = null;
  if (value.steps !== null) {
    if (!Array.isArray(value.steps)) throw new Error("invalid steps");
    steps = value.steps.map((step): LoginStep => {
      if (!isRecord(step) || typeof step.selector !== "string") {
        throw new Error("invalid step");
      }
      if (step.action === "click") {
        return { action: "click", selector: step.selector };
      }
      if (step.action === "fill" && isSecretPlaceholder(step.value)) {
        return {
          action: "fill",
          selector: step.selector,
          value: step.value,
        };
      }
      throw new Error("invalid step");
    });
  }

  return {
    op: "login",
    target_url: value.target_url,
    steps,
    success_selector: value.success_selector ?? null,
    failure_selector: value.failure_selector ?? null,
    secret: {
      username: secret.username,
      password: secret.password,
      totp: secret.totp ?? null,
    },
  };
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("could not reserve a port");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
  return port;
}

async function waitForEndpoint(port: number): Promise<string> {
  const response = await fetch(`http://127.0.0.1:${port}/json/version`);
  if (!response.ok) throw new Error("could not read CDP endpoint");
  const value: unknown = await response.json();
  if (!isRecord(value) || typeof value.webSocketDebuggerUrl !== "string") {
    throw new Error("CDP endpoint was not returned");
  }
  return value.webSocketDebuggerUrl;
}

function isTimeoutError(error: unknown): boolean {
  return error instanceof Error && error.name === "TimeoutError";
}

async function fill(
  page: Page,
  selector: string,
  value: string,
): Promise<void> {
  try {
    await page.fill(selector, value, { timeout: 10_000 });
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError();
    throw error;
  }
}

async function click(page: Page, selector: string): Promise<void> {
  try {
    await page.click(selector, { timeout: 10_000 });
  } catch (error) {
    if (isTimeoutError(error)) throw new SelectorNotFoundError();
    throw error;
  }
}

function substituteSecrets(
  value: string,
  secret: LoginRequest["secret"],
): string {
  const substitutions = {
    username: secret.username,
    password: secret.password,
    totp: secret.totp,
  };
  return value.replace(
    /\{\{(username|password|totp)\}\}/g,
    (_placeholder, key: keyof typeof substitutions) => {
      const substitution = substitutions[key];
      if (substitution === null) throw new MfaRequiredError();
      return substitution;
    },
  );
}

async function runSteps(
  page: Page,
  steps: LoginStep[] | null,
  secret: LoginRequest["secret"],
): Promise<void> {
  if (steps !== null) {
    if (
      secret.totp === null &&
      steps.some((step) => step.action === "fill" && step.value === "{{totp}}")
    ) {
      throw new MfaRequiredError();
    }
    for (const step of steps) {
      if (step.action === "fill") {
        await fill(page, step.selector, substituteSecrets(step.value, secret));
      } else {
        await click(page, step.selector);
      }
    }
    return;
  }

  const password = page.locator('input[type="password"]').first();
  const usernameIndex = await password.evaluate((element) => {
    const inputs = Array.from(
      document.querySelectorAll<HTMLInputElement>("input"),
    );
    return inputs.findIndex(
      (candidate) =>
        (candidate.type === "text" || candidate.type === "email") &&
        (candidate.compareDocumentPosition(element) &
          Node.DOCUMENT_POSITION_FOLLOWING) !==
          0,
    );
  });
  if (usernameIndex >= 0) {
    try {
      await page
        .locator("input")
        .nth(usernameIndex)
        .fill(secret.username, { timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
  }
  await fill(page, 'input[type="password"]', secret.password);

  const submit = page.locator('button[type="submit"], input[type="submit"]');
  if ((await submit.count()) > 0) {
    try {
      await submit.first().click({ timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
  } else {
    try {
      await password.press("Enter", { timeout: 10_000 });
    } catch (error) {
      if (isTimeoutError(error)) throw new SelectorNotFoundError();
      throw error;
    }
  }
}

async function waitForLoginResult(
  page: Page,
  successSelector: string | null,
  failureSelector: string | null,
): Promise<void> {
  const waitForSelector = async (selector: string | null): Promise<boolean> => {
    if (selector === null) return false;
    try {
      await page.waitForSelector(selector, {
        state: "attached",
        timeout: 15_000,
      });
      return true;
    } catch (error) {
      if (isTimeoutError(error)) return false;
      throw error;
    }
  };

  const waitForDefaultResult = async (): Promise<
    "success" | "failure" | undefined
  > => {
    const networkIdleSettled = await page
      .waitForLoadState("networkidle", { timeout: 15_000 })
      .then(() => true)
      .catch(() => false);
    const { hasPasswordInput } = await page.evaluate((loadStateSettled) => {
      const inputs = Array.from(
        document.querySelectorAll<HTMLInputElement>("input"),
      );
      const hasPasswordInput = inputs.some((input) => {
        const style = getComputedStyle(input);
        return (
          input.type === "password" &&
          !input.hidden &&
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          input.offsetWidth !== 0 &&
          input.offsetHeight !== 0
        );
      });
      return { hasPasswordInput, loadStateSettled };
    }, networkIdleSettled);
    if (!hasPasswordInput && successSelector === null) return "success";
    if (hasPasswordInput && failureSelector === null) return "failure";
    return undefined;
  };

  const waits: Array<Promise<"success" | "failure" | undefined>> = [];
  if (successSelector !== null) {
    waits.push(
      waitForSelector(successSelector).then((matched) =>
        matched ? "success" : undefined,
      ),
    );
  }
  if (failureSelector !== null) {
    waits.push(
      waitForSelector(failureSelector).then((matched) =>
        matched ? "failure" : undefined,
      ),
    );
  }
  if (successSelector === null || failureSelector === null) {
    waits.push(waitForDefaultResult());
  }
  const result = await Promise.race([
    ...waits,
    new Promise<undefined>((resolve) => setTimeout(resolve, 15_000)),
  ]);
  if (result === "failure") throw new InvalidCredentialError();
  if (result !== "success") throw new Error("login result timed out");
}

async function executeLogin(request: LoginRequest): Promise<string> {
  const port = await reservePort();
  const browser = await chromium.launch({
    headless: true,
    args: [`--remote-debugging-port=${port}`],
  });
  activeBrowser = browser;
  const page = await browser.newPage();
  await page.goto(request.target_url);
  await runSteps(page, request.steps, request.secret);
  await waitForLoginResult(
    page,
    request.success_selector,
    request.failure_selector,
  );
  return waitForEndpoint(port);
}

function writeResponse(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function handleLogin(request: LoginRequest): Promise<void> {
  if (activeBrowser !== undefined) {
    writeResponse({ ok: false, error: "INTERNAL" satisfies ErrorCode });
    return;
  }

  try {
    const endpoint = await executeLogin(request);
    writeResponse({ ok: true, endpoint });
  } catch (error) {
    const errorCode: ErrorCode =
      error instanceof SelectorNotFoundError
        ? "SELECTOR_NOT_FOUND"
        : error instanceof InvalidCredentialError
          ? "INVALID_CREDENTIAL"
          : error instanceof MfaRequiredError
            ? "MFA_REQUIRED"
            : "INTERNAL";
    const browser = activeBrowser as Browser | undefined;
    if (browser !== undefined) {
      await browser.close().catch(() => undefined);
      activeBrowser = undefined;
    }
    writeResponse({ ok: false, error: errorCode });
  }
}

async function shutdown(): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  if (activeBrowser !== undefined) {
    await activeBrowser.close().catch(() => undefined);
    activeBrowser = undefined;
  }
  process.exit(0);
}

process.once("SIGTERM", () => {
  void shutdown();
});

async function main(): Promise<void> {
  const input = createInterface({ input: process.stdin });
  for await (const line of input) {
    if (shuttingDown || line.trim() === "") continue;
    try {
      const request = parseRequest(line);
      if (request.op === "shutdown") {
        await shutdown();
        return;
      }
      await handleLogin(request);
    } catch {
      writeResponse({ ok: false, error: "INTERNAL" satisfies ErrorCode });
    }
  }
  // stdin has closed: the daemon is gone and no shutdown request can arrive.
  // Exit instead of idling forever with a live browser keeping the process up.
  await shutdown();
}

void main();
