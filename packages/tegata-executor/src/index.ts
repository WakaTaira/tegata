#!/usr/bin/env node

import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
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

type RequestId = number;

type LoginRequest = {
  op: "login";
  id?: RequestId;
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

type LeaseRequest = { op: "lease"; id?: RequestId };

type ReleaseRequest = { op: "release"; id?: RequestId; target_id: string };

type Request =
  | LoginRequest
  | LeaseRequest
  | ReleaseRequest
  | { op: "hello"; id?: RequestId }
  | { op: "shutdown"; id?: RequestId };

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
let activeGuard: CdpGuard | undefined;
let activeTempDir: string | undefined;
let activeBrowserContextId: string | undefined;
let shuttingDown = false;

type CdpMessage = {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  sessionId?: string;
  result?: Record<string, unknown>;
  error?: { message?: string };
};

type CdpGuard = {
  close: () => void;
  failure: Promise<never>;
  browserPid: number | undefined;
  assertOpen: () => void;
  waitForTargetReady: (targetId: string) => Promise<void>;
  send: (
    method: string,
    params: Record<string, unknown>,
  ) => Promise<Record<string, unknown> | undefined>;
};

type PendingCdpCommand = {
  resolve: (result: Record<string, unknown> | undefined) => void;
  reject: (error: unknown) => void;
  timeout: ReturnType<typeof setTimeout>;
};

type TargetReadiness = {
  promise: Promise<void>;
  resolve: () => void;
  reject: (error: unknown) => void;
};

const autoAttachParams = {
  autoAttach: true,
  waitForDebuggerOnStart: true,
  flatten: true,
};

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

class InvalidRequestError extends Error {
  constructor(readonly id?: RequestId) {
    super("invalid request");
  }
}

function parseRequest(line: string): Request {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new InvalidRequestError();
  }
  const id =
    isRecord(value) && typeof value.id === "number" ? value.id : undefined;
  if (!isRecord(value) || typeof value.op !== "string") {
    throw new InvalidRequestError(id);
  }
  if (value.op === "hello") return { op: "hello", id };
  if (value.op === "shutdown") return { op: "shutdown", id };
  if (value.op === "lease") return { op: "lease", id };
  if (value.op === "release") {
    if (typeof value.target_id !== "string") {
      throw new InvalidRequestError(id);
    }
    return { op: "release", id, target_id: value.target_id };
  }
  if (value.op !== "login") throw new InvalidRequestError(id);

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
    throw new InvalidRequestError(id);
  }

  let steps: LoginStep[] | null = null;
  if (value.steps !== null) {
    if (!Array.isArray(value.steps)) throw new InvalidRequestError(id);
    steps = value.steps.map((step): LoginStep => {
      if (!isRecord(step) || typeof step.selector !== "string") {
        throw new InvalidRequestError(id);
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
      throw new InvalidRequestError(id);
    });
  }

  return {
    op: "login",
    id,
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

async function openGuard(endpoint: string): Promise<CdpGuard> {
  const ws = new WebSocket(endpoint);
  let nextId = 1;
  let rejectOpen: (error: unknown) => void = () => undefined;
  let rejectFailure: (error: unknown) => void = () => undefined;
  let failureError: Error | undefined;
  let intentionallyClosed = false;
  let browserPid: number | undefined;
  const pending = new Map<number, PendingCdpCommand>();
  const targetReadiness = new Map<string, TargetReadiness>();
  const failure = new Promise<never>((_resolve, reject) => {
    rejectFailure = reject;
  });

  const getTargetReadiness = (targetId: string): TargetReadiness => {
    const existing = targetReadiness.get(targetId);
    if (existing !== undefined) return existing;
    let resolveReadiness: () => void = () => undefined;
    let rejectReadiness: (error: unknown) => void = () => undefined;
    const promise = new Promise<void>((resolve, reject) => {
      resolveReadiness = resolve;
      rejectReadiness = reject;
    });
    promise.catch(() => undefined);
    const readiness = {
      promise,
      resolve: resolveReadiness,
      reject: rejectReadiness,
    };
    targetReadiness.set(targetId, readiness);
    return readiness;
  };

  const fail = (error: unknown): void => {
    if (failureError !== undefined) return;
    failureError =
      error instanceof Error ? error : new Error("CDP guard failed");
    rejectOpen(failureError);
    rejectFailure(failureError);
    for (const { reject, timeout } of pending.values()) {
      clearTimeout(timeout);
      reject(failureError);
    }
    pending.clear();
  };

  const send = (
    method: string,
    params: Record<string, unknown>,
    sessionId?: string,
    failOnTimeout = true,
  ): Promise<Record<string, unknown> | undefined> =>
    new Promise((resolve, reject) => {
      if (ws.readyState !== WebSocket.OPEN) {
        reject(new Error("CDP guard websocket is not open"));
        return;
      }
      const id = nextId++;
      const timeout = setTimeout(() => {
        pending.delete(id);
        const error = new Error("CDP guard command timed out");
        reject(error);
        if (failOnTimeout) fail(error);
      }, 10_000);
      pending.set(id, { resolve, reject, timeout });
      try {
        ws.send(JSON.stringify({ id, method, params, sessionId }));
      } catch (error) {
        pending.delete(id);
        clearTimeout(timeout);
        reject(error);
      }
    });

  const handleEvent = (message: CdpMessage): void => {
    if (message.method === "Target.attachedToTarget") {
      const params = message.params;
      const targetInfo = params?.targetInfo;
      const sessionId = params?.sessionId;
      if (
        !isRecord(targetInfo) ||
        typeof targetInfo.type !== "string" ||
        typeof targetInfo.targetId !== "string" ||
        typeof sessionId !== "string"
      ) {
        fail(new Error("invalid Target.attachedToTarget event"));
        return;
      }
      const readiness = getTargetReadiness(targetInfo.targetId);
      void send(
        "Fetch.enable",
        {
          patterns: [{ urlPattern: "file://*", requestStage: "Request" }],
        },
        sessionId,
      )
        .then(async () => {
          if (targetInfo.type === "page") {
            await send("Target.setAutoAttach", autoAttachParams, sessionId);
          }
          await send("Runtime.runIfWaitingForDebugger", {}, sessionId);
        })
        .then(() => readiness.resolve())
        .catch((error) => {
          readiness.reject(error);
          fail(error);
        });
      return;
    }

    if (message.method === "Fetch.requestPaused") {
      const params = message.params;
      if (
        typeof message.sessionId !== "string" ||
        typeof params?.requestId !== "string"
      ) {
        fail(new Error("invalid Fetch.requestPaused event"));
        return;
      }
      void send(
        "Fetch.failRequest",
        { requestId: params.requestId, errorReason: "AccessDenied" },
        message.sessionId,
      ).catch(fail);
    }
  };

  ws.onmessage = (event) => {
    let message: CdpMessage;
    try {
      message = JSON.parse(event.data as string) as CdpMessage;
    } catch (error) {
      fail(error);
      return;
    }
    if (typeof message.id === "number") {
      const command = pending.get(message.id);
      if (command === undefined) return;
      pending.delete(message.id);
      clearTimeout(command.timeout);
      if (message.error !== undefined) {
        command.reject(
          new Error(message.error.message ?? "CDP command failed"),
        );
      } else {
        command.resolve(message.result);
      }
      return;
    }
    handleEvent(message);
  };
  ws.onerror = () => fail(new Error("CDP guard websocket failed"));
  ws.onclose = () => {
    if (!intentionallyClosed) fail(new Error("CDP guard websocket closed"));
  };

  const opened = new Promise<void>((resolve, reject) => {
    rejectOpen = reject;
    ws.onopen = () => {
      void send("Target.setAutoAttach", autoAttachParams)
        .then(() => resolve())
        .catch(fail);
    };
  });

  try {
    await Promise.race([opened, failure]);
  } catch (error) {
    intentionallyClosed = true;
    ws.close();
    throw error;
  }

  try {
    const result = await send(
      "SystemInfo.getProcessInfo",
      {},
      undefined,
      false,
    );
    const processInfo = result?.processInfo;
    if (Array.isArray(processInfo)) {
      const browserProcess = processInfo.find(
        (value) => isRecord(value) && value.type === "browser",
      );
      if (isRecord(browserProcess) && typeof browserProcess.id === "number") {
        browserPid = browserProcess.id;
      }
    }
  } catch {
    browserPid = undefined;
  }

  return {
    close: () => {
      intentionallyClosed = true;
      ws.close();
      for (const { timeout } of pending.values()) clearTimeout(timeout);
      pending.clear();
    },
    failure,
    browserPid,
    assertOpen: () => {
      if (failureError !== undefined) throw failureError;
    },
    waitForTargetReady: (targetId) => {
      const readiness = getTargetReadiness(targetId);
      return readiness.promise.finally(() => {
        if (targetReadiness.get(targetId) === readiness) {
          targetReadiness.delete(targetId);
        }
      });
    },
    send: (method, params) => send(method, params),
  };
}

async function withGuard<T>(
  guard: CdpGuard,
  operation: () => Promise<T>,
): Promise<T> {
  return Promise.race([operation(), guard.failure]);
}

async function waitForTargetReady(
  guard: CdpGuard,
  targetId: string,
): Promise<void> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await withGuard(guard, () =>
      Promise.race([
        guard.waitForTargetReady(targetId),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(() => {
            reject(new Error("CDP target readiness timed out"));
          }, 5_000);
        }),
      ]),
    );
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
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

async function executeLogin(
  request: LoginRequest,
): Promise<{ endpoint: string; targetId: string }> {
  const port = await reservePort();
  const dir = await mkdtemp(path.join(os.tmpdir(), "tegata-browser-"));
  activeTempDir = dir;
  // ブラウザが参照する設定・キャッシュを executor の作業領域から隔離します。
  const browser = await chromium.launch({
    headless: true,
    args: [`--remote-debugging-port=${port}`],
    env: {
      ...process.env,
      HOME: dir,
      XDG_CONFIG_HOME: dir,
      XDG_CACHE_HOME: dir,
    },
  });
  activeBrowser = browser;
  // ページ操作より先に CDP エンドポイントを取得し、全 target にガードを張ります。
  const endpoint = await waitForEndpoint(port);
  const guard = await openGuard(endpoint);
  activeGuard = guard;
  const page = await withGuard(guard, () => browser.newPage());
  const pageSession = await withGuard(guard, () =>
    page.context().newCDPSession(page),
  );
  const targetInfoResult = await withGuard(guard, () =>
    pageSession.send("Target.getTargetInfo"),
  );
  const targetInfo = targetInfoResult.targetInfo;
  if (
    !isRecord(targetInfo) ||
    typeof targetInfo.targetId !== "string" ||
    typeof targetInfo.browserContextId !== "string"
  ) {
    throw new Error("CDP target information was not returned");
  }
  await waitForTargetReady(guard, targetInfo.targetId);
  await withGuard(guard, () => page.goto(request.target_url));
  await withGuard(guard, () => runSteps(page, request.steps, request.secret));
  await withGuard(guard, () =>
    waitForLoginResult(
      page,
      request.success_selector,
      request.failure_selector,
    ),
  );
  await pageSession.detach().catch(() => undefined);
  activeBrowserContextId = targetInfo.browserContextId;
  monitorGuardFailure(guard);
  guard.assertOpen();
  return { endpoint, targetId: targetInfo.targetId };
}

function writeResponse(value: unknown, id?: RequestId): void {
  const response =
    id === undefined || !isRecord(value) ? value : { ...value, id };
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

function monitorGuardFailure(guard: CdpGuard): void {
  void guard.failure.then(undefined, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await cleanupResources();
    process.exit(1);
  });
}

function killBrowserProcess(browserPid: number | undefined): void {
  if (browserPid === undefined) {
    process.stderr.write(
      "ブラウザプロセスの PID を取得できないため、強制終了を実行できません。\n",
    );
    return;
  }
  try {
    process.kill(browserPid, "SIGKILL");
  } catch {
    return;
  }
}

async function cleanupResources(): Promise<void> {
  const guard = activeGuard;
  const browserPid = guard?.browserPid;
  activeGuard = undefined;
  if (guard !== undefined) {
    guard.close();
  }
  const browser = activeBrowser;
  activeBrowser = undefined;
  if (browser !== undefined) {
    let closeTimedOut = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      browser.close().catch(() => undefined),
      new Promise<void>((resolve) => {
        timeout = setTimeout(() => {
          closeTimedOut = true;
          resolve();
        }, 5_000);
      }),
    ]);
    if (timeout !== undefined) clearTimeout(timeout);
    if (closeTimedOut) killBrowserProcess(browserPid);
  }
  const dir = activeTempDir;
  activeTempDir = undefined;
  activeBrowserContextId = undefined;
  if (dir !== undefined) {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

async function handleLease(request: LeaseRequest): Promise<void> {
  const guard = activeGuard;
  const browserContextId = activeBrowserContextId;
  if (
    activeBrowser === undefined ||
    guard === undefined ||
    browserContextId === undefined
  ) {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
    return;
  }

  let targetId: string | undefined;
  try {
    const result = await withGuard(guard, () =>
      guard.send("Target.createTarget", {
        url: "about:blank",
        browserContextId,
      }),
    );
    const createdTargetId = result?.targetId;
    if (typeof createdTargetId !== "string") {
      throw new Error("CDP target was not created");
    }
    targetId = createdTargetId;
    await waitForTargetReady(guard, targetId);
    writeResponse({ ok: true, target_id: targetId }, request.id);
  } catch {
    if (targetId !== undefined) {
      await guard
        .send("Target.closeTarget", { targetId })
        .catch(() => undefined);
    }
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
  }
}

async function handleRelease(request: ReleaseRequest): Promise<void> {
  const guard = activeGuard;
  if (activeBrowser === undefined || guard === undefined) {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
    return;
  }

  try {
    await withGuard(guard, () =>
      guard.send("Target.closeTarget", { targetId: request.target_id }),
    );
    writeResponse({ ok: true }, request.id);
  } catch {
    try {
      guard.assertOpen();
    } catch {
      writeResponse(
        { ok: false, error: "INTERNAL" satisfies ErrorCode },
        request.id,
      );
      return;
    }
    writeResponse({ ok: true }, request.id);
  }
}

async function handleLogin(request: LoginRequest): Promise<void> {
  if (activeBrowser !== undefined) {
    writeResponse(
      { ok: false, error: "INTERNAL" satisfies ErrorCode },
      request.id,
    );
    return;
  }

  try {
    const { endpoint, targetId } = await executeLogin(request);
    writeResponse({ ok: true, endpoint, target_id: targetId }, request.id);
  } catch (error) {
    const errorCode: ErrorCode =
      error instanceof SelectorNotFoundError
        ? "SELECTOR_NOT_FOUND"
        : error instanceof InvalidCredentialError
          ? "INVALID_CREDENTIAL"
          : error instanceof MfaRequiredError
            ? "MFA_REQUIRED"
            : "INTERNAL";
    await cleanupResources();
    writeResponse({ ok: false, error: errorCode }, request.id);
  }
}

async function shutdown(request?: { id?: RequestId }): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  await cleanupResources();
  if (request !== undefined) writeResponse({ ok: true }, request.id);
  process.exit(0);
}

let stdinEofHandled = false;

function handleStdinEof(): void {
  if (stdinEofHandled || shuttingDown) return;
  stdinEofHandled = true;
  void shutdown();
}

process.stdin.once("end", handleStdinEof);
process.stdin.once("close", handleStdinEof);

process.once("SIGTERM", () => {
  void shutdown();
});

async function main(): Promise<void> {
  const input = createInterface({ input: process.stdin });
  for await (const line of input) {
    if (shuttingDown || line.trim() === "") continue;
    try {
      const request = parseRequest(line);
      if (request.op === "hello") {
        writeResponse(
          {
            ok: true,
            uid: process.getuid?.() ?? null,
            pid: process.pid,
          },
          request.id,
        );
        continue;
      }
      if (request.op === "shutdown") {
        await shutdown(request);
        return;
      }
      if (request.op === "lease") {
        await handleLease(request);
        continue;
      }
      if (request.op === "release") {
        await handleRelease(request);
        continue;
      }
      await handleLogin(request);
    } catch (error) {
      writeResponse(
        { ok: false, error: "INTERNAL" satisfies ErrorCode },
        error instanceof InvalidRequestError ? error.id : undefined,
      );
    }
  }
  await shutdown();
}

void main();
