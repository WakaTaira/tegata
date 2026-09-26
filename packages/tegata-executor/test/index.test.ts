import { describe, expect, test } from "vitest";
import {
  classifyDeviceResult,
  classifyError,
  DeviceCodeRejectedError,
  formatResponse,
  InvalidCredentialError,
  MfaRequiredError,
  parseRequest,
  runSteps,
  SelectorNotFoundError,
  substituteSecrets,
} from "../src/index.js";

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
        "ABCD-EFGH",
        false,
        "#device-error",
      ),
    ).rejects.toBeInstanceOf(DeviceCodeRejectedError);
    expect(actions).toEqual(["click:#submit"]);
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
