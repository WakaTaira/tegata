import { describe, expect, test } from "vitest";
import {
  classifyDeviceResult,
  classifyError,
  DeviceCodeRejectedError,
  formatExecutorErrorLine,
  formatResponse,
  guardTargetCommands,
  headfulUserAgent,
  headfulUserAgentMetadata,
  InvalidCredentialError,
  LoginResultTimeoutError,
  MfaRequiredError,
  parseRequest,
  raceDecisive,
  runSteps,
  SelectorNotFoundError,
  substituteSecrets,
  withoutHeadlessBrands,
} from "../src/index.js";

describe("headfulUserAgent", () => {
  test("replaces HeadlessChrome without hardcoding the browser version", () => {
    expect(headfulUserAgent("HeadlessChrome/150.0.0.0")).toBe(
      "Chrome/150.0.0.0",
    );
  });

  test("keeps a user agent without HeadlessChrome unchanged", () => {
    const userAgent = "Mozilla/5.0 Chrome/150.0.0.0 Safari/537.36";
    expect(headfulUserAgent(userAgent)).toBe(userAgent);
  });
});

describe("executor error diagnostics", () => {
  test("redacts request secrets and keeps only the first message line", () => {
    const request = {
      op: "authorize_device" as const,
      login_url: "https://example.test/login",
      verification_url: "https://example.test/device",
      user_code: "ABCD-EFGH",
      steps: null,
      success_selector: "#success",
      failure_selector: null,
      secret: { username: "alice", password: "password", totp: "123456" },
    };

    const line = formatExecutorErrorLine(
      request,
      "login",
      "INTERNAL",
      new Error(
        "alice/password/123456/ABCD-EFGH\nthis second line must not appear",
      ),
    );

    expect(line).toBe(
      `tegata-executor: error ${JSON.stringify({
        op: "authorize_device",
        stage: "login",
        code: "INTERNAL",
        name: "Error",
        message: "[REDACTED]/[REDACTED]/[REDACTED]/[REDACTED]",
      })}\n`,
    );
  });

  test("truncates the message at 300 UTF-8 bytes on a character boundary", () => {
    const request = {
      op: "login" as const,
      target_url: "https://example.test/login",
      steps: null,
      success_selector: null,
      failure_selector: null,
      secret: { username: "", password: "", totp: null },
    };

    const line = formatExecutorErrorLine(
      request,
      "login",
      "LOGIN_RESULT_TIMEOUT",
      new Error(`${"あ".repeat(101)}\nthis second line must not appear`),
    );
    const payload = JSON.parse(
      line.slice("tegata-executor: error ".length).trimEnd(),
    );

    expect(payload.message).toBe("あ".repeat(100));
    expect(Buffer.byteLength(payload.message, "utf8")).toBe(300);
  });

  test("removes URL query and fragment details from the message", () => {
    const request = {
      op: "login" as const,
      target_url: "https://example.test/login",
      steps: null,
      success_selector: null,
      failure_selector: null,
      secret: { username: "", password: "", totp: null },
    };

    const line = formatExecutorErrorLine(
      request,
      "login",
      "INTERNAL",
      new Error(
        'request failed at https://example.test/path?token=secret#fragment and "https://example.test/other#fragment"',
      ),
    );

    const payload = JSON.parse(
      line.slice("tegata-executor: error ".length).trimEnd(),
    );
    expect(payload.message).toBe(
      'request failed at https://example.test/path and "https://example.test/other"',
    );
  });

  test("redacts multiline secrets from the name and message", () => {
    const password = "password\ncontinued";
    class SecretError extends Error {
      name = `SecretError:${password}:${"x".repeat(100)}`;
    }
    const request = {
      op: "login" as const,
      target_url: "https://example.test/login",
      steps: null,
      success_selector: null,
      failure_selector: null,
      secret: { username: "", password, totp: null },
    };

    const line = formatExecutorErrorLine(
      request,
      "login",
      "INTERNAL",
      new SecretError(`${password}\nthis second line must not appear`),
    );

    const payload = JSON.parse(
      line.slice("tegata-executor: error ".length).trimEnd(),
    );
    expect(payload.name).toBe(`SecretError:[REDACTED]:${"x".repeat(41)}`);
    expect(Buffer.byteLength(payload.name, "utf8")).toBeLessThanOrEqual(64);
    expect(payload.message).toBe("[REDACTED]");
    expect(line).not.toContain(password);
  });
});

describe("raceDecisive", () => {
  test("ignores an undefined result until a decisive result arrives", async () => {
    const result = await raceDecisive(
      [
        Promise.resolve(undefined),
        new Promise<"success">((resolve) =>
          setTimeout(() => resolve("success"), 10),
        ),
      ],
      new Promise<undefined>((resolve) =>
        setTimeout(() => resolve(undefined), 100),
      ),
    );

    expect(result).toBe("success");
  });

  test("returns undefined from the timer when every wait is undefined", async () => {
    const result = await raceDecisive(
      [Promise.resolve(undefined), Promise.resolve(undefined)],
      new Promise<undefined>((resolve) =>
        setTimeout(() => resolve(undefined), 0),
      ),
    );

    expect(result).toBeUndefined();
  });
});

describe("headful user agent metadata", () => {
  test("removes Headless brands from low and high entropy lists", () => {
    const metadata = {
      brands: [
        { brand: "HeadlessChrome", version: "150" },
        { brand: "Chromium", version: "150" },
      ],
      fullVersionList: [
        { brand: "HeadlessChrome", version: "150.0.0.0" },
        { brand: "Chromium", version: "150.0.0.0" },
      ],
      platform: "Linux",
      platformVersion: "6.0.0",
      architecture: "x86",
      bitness: "64",
      model: "",
      mobile: false,
    };

    expect(withoutHeadlessBrands(metadata.brands)).toEqual([
      { brand: "Chromium", version: "150" },
    ]);
    expect(headfulUserAgentMetadata(metadata)).toEqual({
      ...metadata,
      brands: [{ brand: "Chromium", version: "150" }],
      fullVersionList: [{ brand: "Chromium", version: "150.0.0.0" }],
    });
  });
});

describe("guardTargetCommands", () => {
  test("enables Fetch only for page and iframe targets", () => {
    expect(guardTargetCommands("page")).toEqual([
      "Fetch.enable",
      "Target.setAutoAttach",
      "Emulation.setUserAgentOverride",
      "Runtime.runIfWaitingForDebugger",
    ]);
    expect(guardTargetCommands("iframe")).toEqual([
      "Fetch.enable",
      "Emulation.setUserAgentOverride",
      "Runtime.runIfWaitingForDebugger",
    ]);
    expect(guardTargetCommands("worker")).toEqual([
      "Runtime.runIfWaitingForDebugger",
    ]);
    expect(guardTargetCommands("shared_worker")).toEqual([
      "Runtime.runIfWaitingForDebugger",
    ]);
    expect(guardTargetCommands("service_worker")).toEqual([
      "Runtime.runIfWaitingForDebugger",
    ]);
  });
});

describe("authorize_device protocol", () => {
  test("parses the request and formats the response without a browser channel", () => {
    const request = parseRequest(
      JSON.stringify({
        op: "authorize_device",
        id: 17,
        login_url: "https://example.test/login",
        verification_url: "https://example.test/device",
        user_code: "ABCD-EFGH",
        steps: null,
        success_selector: "#success",
        failure_selector: null,
        secret: { username: "alice", password: "password", totp: null },
      }),
    );

    expect(request).toEqual({
      op: "authorize_device",
      id: 17,
      login_url: "https://example.test/login",
      verification_url: "https://example.test/device",
      user_code: "ABCD-EFGH",
      steps: null,
      success_selector: "#success",
      failure_selector: null,
      secret: { username: "alice", password: "password", totp: null },
    });
    expect(formatResponse({ ok: true }, request.id)).toEqual({
      ok: true,
      id: 17,
    });
    expect(formatResponse({ ok: true }, request.id)).not.toHaveProperty(
      "endpoint",
    );
    expect(formatResponse({ ok: true }, request.id)).not.toHaveProperty(
      "target_id",
    );
    expect(
      formatResponse({ ok: false, error: "DEVICE_CODE_REJECTED" }, request.id),
    ).toEqual({ ok: false, error: "DEVICE_CODE_REJECTED", id: 17 });
  });

  test("expands the user code placeholder", () => {
    expect(
      substituteSecrets(
        "{{username}}/{{password}}/{{totp}}/{{user_code}}",
        { username: "alice", password: "secret", totp: "123456" },
        "ABCD-EFGH",
      ),
    ).toBe("alice/secret/123456/ABCD-EFGH");
  });

  test("stops custom device steps when the failure selector appears", async () => {
    const actions: string[] = [];
    const page = {
      click: async (selector: string) => {
        actions.push(`click:${selector}`);
      },
      locator: (selector: string) => ({
        count: async () => (selector === "#device-error" ? 1 : 0),
      }),
    } as unknown as Parameters<typeof runSteps>[0];

    await expect(
      runSteps(
        page,
        [
          { action: "click", selector: "#submit" },
          { action: "click", selector: "#approve" },
        ],
        { username: "alice", password: "secret", totp: null },
        { userCode: "ABCD-EFGH", failureSelector: "#device-error" },
      ),
    ).rejects.toBeInstanceOf(DeviceCodeRejectedError);
    expect(actions).toEqual(["click:#submit"]);
  });

  test("rechecks the failure selector when a device step times out", async () => {
    const actions: string[] = [];
    let rejectionRendered = false;
    const page = {
      click: async (selector: string) => {
        actions.push(`click:${selector}`);
        if (selector === "#approve") {
          // 拒否表示が遅れて描画され、次の操作のセレクタ待ちが先に timeout した状況を模す。
          rejectionRendered = true;
          const timeout = new Error("locator.click: Timeout 10000ms exceeded");
          timeout.name = "TimeoutError";
          throw timeout;
        }
      },
      locator: (selector: string) => ({
        count: async () =>
          selector === "#device-error" && rejectionRendered ? 1 : 0,
      }),
    } as unknown as Parameters<typeof runSteps>[0];

    const error = await runSteps(
      page,
      [
        { action: "click", selector: "#submit" },
        { action: "click", selector: "#approve" },
      ],
      { username: "alice", password: "secret", totp: null },
      { userCode: "ABCD-EFGH", failureSelector: "#device-error" },
    ).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(DeviceCodeRejectedError);
    expect(classifyError(error, "device")).toBe("DEVICE_CODE_REJECTED");
    expect(actions).toEqual(["click:#submit", "click:#approve"]);
  });

  test("keeps login steps independent from the device failure selector check", async () => {
    const actions: string[] = [];
    const page = {
      click: async (selector: string) => {
        actions.push(`click:${selector}`);
      },
      locator: (selector: string) => ({
        count: async () => (selector === "#login-error" ? 1 : 0),
      }),
    } as unknown as Parameters<typeof runSteps>[0];

    await runSteps(
      page,
      [
        { action: "click", selector: "#submit" },
        { action: "click", selector: "#approve" },
      ],
      { username: "alice", password: "secret", totp: null },
    );
    expect(actions).toEqual(["click:#submit", "click:#approve"]);
  });

  test("keeps the zero-based index of a timed-out explicit step", async () => {
    const page = {
      click: async (selector: string) => {
        if (selector !== "#missing") return;
        const timeout = new Error("locator.click: Timeout 10000ms exceeded");
        timeout.name = "TimeoutError";
        throw timeout;
      },
    } as unknown as Parameters<typeof runSteps>[0];

    const error = await runSteps(
      page,
      [
        { action: "click", selector: "#submit" },
        { action: "click", selector: "#missing" },
      ],
      { username: "alice", password: "secret", totp: null },
    ).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(SelectorNotFoundError);
    expect(error).toMatchObject({ stepIndex: 1 });
  });

  test("classifies errors according to the execution stage", () => {
    expect(classifyError(new SelectorNotFoundError(), "login")).toBe(
      "SELECTOR_NOT_FOUND",
    );
    expect(classifyError(new InvalidCredentialError(), "login")).toBe(
      "INVALID_CREDENTIAL",
    );
    expect(classifyError(new MfaRequiredError(), "login")).toBe("MFA_REQUIRED");
    expect(classifyError(new LoginResultTimeoutError(), "login")).toBe(
      "LOGIN_RESULT_TIMEOUT",
    );
    expect(classifyError(new LoginResultTimeoutError(), "device")).toBe(
      "INTERNAL",
    );
    expect(classifyError(new SelectorNotFoundError(), "device")).toBe(
      "INTERNAL",
    );
    expect(classifyError(new Error("timeout"), "device")).toBe("INTERNAL");
    expect(classifyError(new DeviceCodeRejectedError(), "device")).toBe(
      "DEVICE_CODE_REJECTED",
    );
  });

  test("classifies a matching failure selector as rejected", () => {
    expect(classifyDeviceResult("failure")).toBe("DEVICE_CODE_REJECTED");
    expect(classifyDeviceResult("success")).toBe("ok");
    expect(classifyDeviceResult(undefined)).toBe("INTERNAL");
  });
});
