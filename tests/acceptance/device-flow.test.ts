import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import {
  type DeviceFlowStack,
  startDeviceFlowStack,
  stopDeviceFlowStack,
} from "./support/device-flow.js";
import { bins, fixtureSteps, rawRpc } from "./support/harness.js";
import { readAuditRecords, waitUntil } from "./support/phase3.js";
import { countExecutors } from "./support/phase4.js";

type RpcResponse = Awaited<ReturnType<typeof rawRpc>>;

async function issueDeviceCode(fixtureUrl: string): Promise<string> {
  const response = await fetch(`${fixtureUrl}/device/issue`, {
    method: "POST",
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`POST /device/issue failed (${response.status}): ${body}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("POST /device/issue returned invalid JSON");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as { user_code?: unknown }).user_code !== "string"
  ) {
    throw new Error("POST /device/issue returned no user_code");
  }
  return (parsed as { user_code: string }).user_code;
}

async function deviceStatus(
  fixtureUrl: string,
  userCode: string,
): Promise<{ approved: boolean }> {
  const response = await fetch(
    `${fixtureUrl}/device/status?user_code=${encodeURIComponent(userCode)}`,
  );
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`GET /device/status failed (${response.status}): ${body}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("GET /device/status returned invalid JSON");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as { approved?: unknown }).approved !== "boolean"
  ) {
    throw new Error("GET /device/status returned no approved flag");
  }
  return parsed as { approved: boolean };
}

async function authorizeDevice(
  stack: DeviceFlowStack,
  userCode: string,
  extra: Record<string, unknown> = {},
): Promise<RpcResponse> {
  const response = await rawRpc(stack.daemon.socketPath, "authorize_device", {
    cred_id: "mock:site",
    verification_url: `${stack.fixture.url}/device`,
    user_code: userCode,
    success_selector: "#device-ok",
    ...extra,
  });
  stack.observe("rpc:authorize_device", response);
  return response;
}

async function login(stack: DeviceFlowStack): Promise<RpcResponse> {
  const response = await rawRpc(stack.daemon.socketPath, "login", {
    cred_id: "mock:site",
    target_url: stack.fixture.url,
    ...fixtureSteps(),
  });
  stack.observe("rpc:login", response);
  return response;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function assertNoDeviceCodeLeak(userCode: string, surface: string): void {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegata-device-leak-"),
  );
  const canariesPath = path.join(directory, "canaries.json");
  const surfacePath = path.join(directory, "surface.txt");
  try {
    fs.writeFileSync(canariesPath, JSON.stringify({ canaries: [userCode] }));
    fs.writeFileSync(surfacePath, surface);
    const result = spawnSync(
      bins().leakscan,
      ["--canaries", canariesPath, "--json", surfacePath],
      { encoding: "utf8" },
    );
    if (result.error) throw result.error;
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ hits: [] });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("AC-82: authorize_device approves an issued device code", async () => {
  const stack = await startDeviceFlowStack();
  try {
    // Given: code C issued through the fixture's POST /device/issue
    const userCode = await issueDeviceCode(stack.fixture.url);

    // When: authorize_device {cred_id: X, verification_url: <fixture>/device, user_code: C,
    // success_selector: "#device-ok"} (steps omitted)
    const response = await authorizeDevice(stack, userCode);

    // Then: {ok: true}, and C is approved on the fixture side
    expect(response.error).toBeUndefined();
    expect(response.result).toEqual({ ok: true });
    await expect(deviceStatus(stack.fixture.url, userCode)).resolves.toEqual({
      approved: true,
    });
  } finally {
    await stopDeviceFlowStack(stack);
  }
});

test("AC-83: authorize_device returns no browser channel and closes its browser", async () => {
  const stack = await startDeviceFlowStack();
  try {
    // Given: right after AC-82
    const userCode = await issueDeviceCode(stack.fixture.url);
    const response = await authorizeDevice(stack, userCode);
    expect(response.error).toBeUndefined();
    expect(response.result).toEqual({ ok: true });
    await expect(deviceStatus(stack.fixture.url, userCode)).resolves.toEqual({
      approved: true,
    });

    // When: count the browsers
    const result = response.result as Record<string, unknown>;

    // Then: 0 within 5 s. The response does not contain channel / endpoint / target_id
    expect(Object.keys(result)).not.toContain("channel");
    expect(Object.keys(result)).not.toContain("endpoint");
    expect(Object.keys(result)).not.toContain("target_id");
    await waitUntil(
      "authorize_device browser to close",
      () => countExecutors(stack.daemon.pid) === 0,
      5_000,
    );
  } finally {
    await stopDeviceFlowStack(stack);
  }
});

test("AC-84: approve_cmd receives the device-flow and login method names", async () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-device-"));
  const authorizeEnvFile = path.join(scratch, "authorize-env.txt");
  const loginEnvFile = path.join(scratch, "login-env.txt");
  const writeEnv = (file: string) =>
    `printf 'TEGATA_TARGET_URL=%s\\nTEGATA_METHOD=%s\\n' "$TEGATA_TARGET_URL" "$TEGATA_METHOD" > ${shellQuote(file)}`;
  const approveCmd = `if [ "$TEGATA_METHOD" = authorize_device ]; then ${writeEnv(authorizeEnvFile)}; else ${writeEnv(loginEnvFile)}; fi`;
  const stack = await startDeviceFlowStack({ approveCmd });
  try {
    // Given: a script for approve_cmd that writes the environment variables to a file
    const userCode = await issueDeviceCode(stack.fixture.url);

    // When: authorize_device
    const authorization = await authorizeDevice(stack, userCode);

    // Then: the file contains TEGATA_TARGET_URL=<verification_url> and
    // TEGATA_METHOD=authorize_device
    expect(authorization.error).toBeUndefined();
    expect(authorization.result).toEqual({ ok: true });
    const authorizeEnv = fs.readFileSync(authorizeEnvFile, "utf8");
    expect(authorizeEnv).toContain(
      `TEGATA_TARGET_URL=${stack.fixture.url}/device`,
    );
    expect(authorizeEnv).toContain("TEGATA_METHOD=authorize_device");

    // When: login
    const loginResponse = await login(stack);

    // Then: the file contains TEGATA_METHOD=login
    expect(loginResponse.error).toBeUndefined();
    expect(loginResponse.result).toBeDefined();
    const loginEnv = fs.readFileSync(loginEnvFile, "utf8");
    expect(loginEnv).toContain("TEGATA_METHOD=login");
  } finally {
    await stopDeviceFlowStack(stack);
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});

test("AC-85: authorize_device audit and observation surfaces exclude the user code", async () => {
  const stack = await startDeviceFlowStack();
  try {
    // Given: AC-82
    const userCode = await issueDeviceCode(stack.fixture.url);
    const authorization = await authorizeDevice(stack, userCode);
    expect(authorization.error).toBeUndefined();
    expect(authorization.result).toEqual({ ok: true });
    await expect(deviceStatus(stack.fixture.url, userCode)).resolves.toEqual({
      approved: true,
    });

    // When: audit log and leak guard scan
    const verificationUrl = `${stack.fixture.url}/device`;
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const auditText = fs.readFileSync(stack.daemon.auditLogPath, "utf8");
    const stdout = stack.daemon.stdout();
    const observed = { authorization, auditText, stdout };
    stack.observe("authorize_device:observed", observed);
    const leaks = await stack.guard.collectLeaks();
    assertNoDeviceCodeLeak(userCode, JSON.stringify(observed));

    // Then: the audit line has method: "authorize_device" and target_url = verification_url, and
    // the user_code value appears 0 times in the audit log, stdout, and the surfaces the agent can
    // observe
    const auditRecord = records.find(
      (record) => record.method === "authorize_device",
    );
    expect(auditRecord).toEqual(
      expect.objectContaining({
        method: "authorize_device",
        target_url: verificationUrl,
      }),
    );
    expect(auditText).not.toContain(userCode);
    expect(stdout).not.toContain(userCode);
    expect(JSON.stringify(observed)).not.toContain(userCode);
    expect(leaks).toEqual([]);
  } finally {
    await stopDeviceFlowStack(stack);
  }
});

test("AC-86: an unissued device code is rejected and its browser closes", async () => {
  const stack = await startDeviceFlowStack();
  try {
    // Given: an unissued code
    const userCode = "UNISSUED-DEVICE-CODE";
    await expect(deviceStatus(stack.fixture.url, userCode)).resolves.toEqual({
      approved: false,
    });

    // When: authorize_device {…, failure_selector: "#device-error"}
    const response = await authorizeDevice(stack, userCode, {
      failure_selector: "#device-error",
    });

    // Then: DEVICE_CODE_REJECTED, and the browser count is 0 within 5 s
    expect(response.result).toBeUndefined();
    expect(response.error?.message).toBe("DEVICE_CODE_REJECTED");
    await waitUntil(
      "rejected authorize_device browser to close",
      () => countExecutors(stack.daemon.pid) === 0,
      5_000,
    );
  } finally {
    await stopDeviceFlowStack(stack);
  }
});
