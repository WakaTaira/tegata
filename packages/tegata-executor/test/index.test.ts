import { describe, expect, test } from "vitest";
import {
  classifyDeviceResult,
  formatResponse,
  parseRequest,
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

  test("classifies a matching failure selector as rejected", () => {
    expect(classifyDeviceResult("failure")).toBe("DEVICE_CODE_REJECTED");
    expect(classifyDeviceResult("success")).toBe("ok");
    expect(classifyDeviceResult(undefined)).toBe("INTERNAL");
  });
});
