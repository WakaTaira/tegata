import { describe, expect, test } from "vitest";
import {
  classifyDeviceResult,
  classifyError,
  DeviceCodeRejectedError,
  formatResponse,
  headfulUserAgent,
  InvalidCredentialError,
  MfaRequiredError,
  parseRequest,
  runSteps,
  SelectorNotFoundError,
  substituteSecrets,
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

  test("classifies errors according to the execution stage", () => {
    expect(classifyError(new SelectorNotFoundError(), "login")).toBe(
      "SELECTOR_NOT_FOUND",
    );
    expect(classifyError(new InvalidCredentialError(), "login")).toBe(
      "INVALID_CREDENTIAL",
    );
    expect(classifyError(new MfaRequiredError(), "login")).toBe("MFA_REQUIRED");
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
