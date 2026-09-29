import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import {
  loginHandler,
  loginStepParams,
  openApiProxyHandler,
  stepwiseHandler,
} from "./index.js";

const endpoint = "ws://127.0.0.1:9001/devtools/browser/abc";
const originalSocket = process.env.TEGATA_SOCKET;
const originalBridge = process.env.TEGATA_BRIDGE;

afterEach(() => {
  if (originalSocket === undefined) delete process.env.TEGATA_SOCKET;
  else process.env.TEGATA_SOCKET = originalSocket;
  if (originalBridge === undefined) delete process.env.TEGATA_BRIDGE;
  else process.env.TEGATA_BRIDGE = originalBridge;
});

async function startFakeServer(
  bridgeError = false,
  loginError?: { message: string; data?: unknown },
) {
  const socketPath = join(process.cwd(), `.tegata-mcp-${randomUUID()}.sock`);
  let loginCompleted = false;
  const server = createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      const lineEnd = data.indexOf("\n");
      if (lineEnd === -1) return;
      const request = JSON.parse(data.slice(0, lineEnd)) as {
        method: string;
        params?: unknown;
      };
      if (!loginCompleted) {
        expect(request.method).toBe("login");
        loginCompleted = true;
      } else {
        expect(request.method).toBe("bridge_open_tunnel");
        expect(request.params).toEqual({ session_id: "s1", port: 9001 });
      }
      const response =
        request.method === "login"
          ? loginError === undefined
            ? {
                jsonrpc: "2.0",
                id: 1,
                result: {
                  session_id: "s1",
                  channel: { kind: "cdp", endpoint },
                },
              }
            : {
                jsonrpc: "2.0",
                id: 1,
                error: { code: -32000, ...loginError },
              }
          : bridgeError
            ? {
                jsonrpc: "2.0",
                id: 1,
                error: { code: -32000, message: "FORBIDDEN" },
              }
            : { jsonrpc: "2.0", id: 1, result: { local_port: 4242 } };
      socket.write(`${JSON.stringify(response)}\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  process.env.TEGATA_SOCKET = socketPath;
  return { server, socketPath };
}

async function stopFakeServer(server: ReturnType<typeof createServer>) {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

describe.sequential("login bridge", () => {
  test("rewrites the endpoint through the bridge", async () => {
    const fake = await startFakeServer();
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              session_id: "s1",
              channel: {
                kind: "cdp",
                endpoint: "ws://127.0.0.1:4242/devtools/browser/abc",
              },
            }),
          },
        ],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("returns the bridge error code through existing error handling", async () => {
    const fake = await startFakeServer(true);
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "FORBIDDEN" }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("preserves an unknown daemon error code that matches the code format", async () => {
    const fake = await startFakeServer(false, { message: "NEW_DAEMON_CODE" });
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "NEW_DAEMON_CODE" }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("returns INTERNAL for an arbitrary daemon error message", async () => {
    const fake = await startFakeServer(false, { message: "not a code" });
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "INTERNAL" }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("returns the selector step in structured content", async () => {
    const fake = await startFakeServer(false, {
      message: "SELECTOR_NOT_FOUND",
      data: { step: 1 },
    });
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "SELECTOR_NOT_FOUND" }],
        structuredContent: { error: "SELECTOR_NOT_FOUND", step: 1 },
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("returns the fill mismatch step in structured content", async () => {
    const fake = await startFakeServer(false, {
      message: "FILL_MISMATCH",
      data: { step: 2 },
    });
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "FILL_MISMATCH" }],
        structuredContent: { error: "FILL_MISMATCH", step: 2 },
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("preserves the endpoint when bridge mode is disabled", async () => {
    const fake = await startFakeServer();
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await loginHandler({});
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              session_id: "s1",
              channel: { kind: "cdp", endpoint },
            }),
          },
        ],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });
});

const baseUrl = "http://127.0.0.1:9002/path-secret_1";

/** open_api_proxy と bridge_open_tunnel に順に応答する偽デーモンを起動する。 */
async function startFakeApiProxyServer() {
  const socketPath = join(process.cwd(), `.tegata-mcp-${randomUUID()}.sock`);
  const methods: unknown[] = [];
  const server = createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      const lineEnd = data.indexOf("\n");
      if (lineEnd === -1) return;
      const request = JSON.parse(data.slice(0, lineEnd)) as {
        method: string;
        params?: unknown;
      };
      methods.push({ method: request.method, params: request.params });
      const response =
        request.method === "open_api_proxy"
          ? {
              jsonrpc: "2.0",
              id: 1,
              result: { session_id: "p1", base_url: baseUrl },
            }
          : { jsonrpc: "2.0", id: 1, result: { local_port: 4343 } };
      socket.write(`${JSON.stringify(response)}\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  process.env.TEGATA_SOCKET = socketPath;
  return { server, methods };
}

describe.sequential("open_api_proxy bridge", () => {
  test("rewrites only the base_url port through the bridge", async () => {
    const fake = await startFakeApiProxyServer();
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await openApiProxyHandler({ name: "fx" });
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              session_id: "p1",
              base_url: "http://127.0.0.1:4343/path-secret_1",
            }),
          },
        ],
      });
      expect(fake.methods).toEqual([
        { method: "open_api_proxy", params: { name: "fx" } },
        {
          method: "bridge_open_tunnel",
          params: { session_id: "p1", port: 9002 },
        },
      ]);
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("preserves the base_url when bridge mode is disabled", async () => {
    const fake = await startFakeApiProxyServer();
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await openApiProxyHandler({ name: "fx" });
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({ session_id: "p1", base_url: baseUrl }),
          },
        ],
      });
      expect(fake.methods).toEqual([
        { method: "open_api_proxy", params: { name: "fx" } },
      ]);
    } finally {
      await stopFakeServer(fake.server);
    }
  });
});

/** Issue #46: どの method でも同じ結果を返す偽デーモン。呼ばれた method / params を記録する。 */
async function startFakeStepwiseServer(response: {
  result?: unknown;
  error?: { message: string; data?: unknown };
}) {
  const socketPath = join(process.cwd(), `.tegata-mcp-${randomUUID()}.sock`);
  const calls: Array<{ method: string; params: unknown }> = [];
  const server = createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      const lineEnd = data.indexOf("\n");
      if (lineEnd === -1) return;
      const request = JSON.parse(data.slice(0, lineEnd)) as {
        method: string;
        params?: unknown;
      };
      calls.push({ method: request.method, params: request.params });
      const wire =
        response.error === undefined
          ? { jsonrpc: "2.0", id: 1, result: response.result }
          : {
              jsonrpc: "2.0",
              id: 1,
              error: { code: -32000, ...response.error },
            };
      socket.write(`${JSON.stringify(wire)}\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  process.env.TEGATA_SOCKET = socketPath;
  return { server, calls };
}

/**
 * Issue #46: 段階ログインの bridge 経路を検証する偽デーモン。1 回目は
 * `firstMethod`（`login_begin` / `login_step`）に `doneResult` を返し、bridge
 * 有効時にのみ来る 2 回目の `bridge_open_tunnel` に応答する。
 */
async function startFakeStepwiseBridgeServer(
  firstMethod: "login_begin" | "login_step",
  doneResult: unknown,
  bridgeError = false,
) {
  const socketPath = join(process.cwd(), `.tegata-mcp-${randomUUID()}.sock`);
  const calls: Array<{ method: string; params: unknown }> = [];
  let first = true;
  const server = createServer((socket) => {
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      const lineEnd = data.indexOf("\n");
      if (lineEnd === -1) return;
      const request = JSON.parse(data.slice(0, lineEnd)) as {
        method: string;
        params?: unknown;
      };
      calls.push({ method: request.method, params: request.params });
      const response = first
        ? { jsonrpc: "2.0", id: 1, result: doneResult }
        : bridgeError
          ? {
              jsonrpc: "2.0",
              id: 1,
              error: { code: -32000, message: "FORBIDDEN" },
            }
          : { jsonrpc: "2.0", id: 1, result: { local_port: 4242 } };
      if (first) expect(request.method).toBe(firstMethod);
      else expect(request.method).toBe("bridge_open_tunnel");
      first = false;
      socket.write(`${JSON.stringify(response)}\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  process.env.TEGATA_SOCKET = socketPath;
  return { server, calls };
}

describe.sequential("login_begin / login_step forwarding", () => {
  test("forwards login_begin params and the pending result unchanged", async () => {
    const pending = {
      state: "pending",
      login_id: "l1",
      snapshot: { url: "https://example.test", elements: [] },
    };
    const fake = await startFakeStepwiseServer({ result: pending });
    try {
      const params = {
        cred_id: "mock:site",
        target_url: "https://example.test/login",
        success_selector: "#signed-in",
      };
      const result = await stepwiseHandler("login_begin", params);
      expect(fake.calls).toEqual([{ method: "login_begin", params }]);
      expect(result).toEqual({
        content: [{ type: "text", text: JSON.stringify(pending) }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("forwards login_step's done result unchanged when bridge mode is disabled", async () => {
    const done = {
      state: "done",
      session_id: "s1",
      channel: { kind: "cdp", endpoint },
    };
    const fake = await startFakeStepwiseServer({ result: done });
    delete process.env.TEGATA_BRIDGE;
    try {
      const params = {
        login_id: "l1",
        action: "fill_submit",
        fills: [{ selector: "#password", value: "{{password}}" }],
        submit: { click: "#submit" },
      };
      const result = await stepwiseHandler("login_step", params);
      expect(fake.calls).toEqual([{ method: "login_step", params }]);
      expect(result).toEqual({
        content: [{ type: "text", text: JSON.stringify(done) }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("rewrites the endpoint of a login_step done result through the bridge", async () => {
    const done = {
      state: "done",
      session_id: "s1",
      target_id: "t1",
      channel: { kind: "cdp", endpoint },
    };
    const fake = await startFakeStepwiseBridgeServer("login_step", done);
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await stepwiseHandler("login_step", {
        login_id: "l1",
        action: "fill_submit",
        fills: [{ selector: "#otp", value: "{{totp}}" }],
        submit: { click: "#verify" },
      });
      expect(fake.calls).toEqual([
        {
          method: "login_step",
          params: {
            login_id: "l1",
            action: "fill_submit",
            fills: [{ selector: "#otp", value: "{{totp}}" }],
            submit: { click: "#verify" },
          },
        },
        {
          method: "bridge_open_tunnel",
          params: { session_id: "s1", port: 9001 },
        },
      ]);
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              state: "done",
              session_id: "s1",
              target_id: "t1",
              channel: {
                kind: "cdp",
                endpoint: "ws://127.0.0.1:4242/devtools/browser/abc",
              },
            }),
          },
        ],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("rewrites the endpoint of a login_begin done result through the bridge", async () => {
    const done = {
      state: "done",
      session_id: "s2",
      channel: { kind: "cdp", endpoint },
    };
    const fake = await startFakeStepwiseBridgeServer("login_begin", done);
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await stepwiseHandler("login_begin", {
        cred_id: "mock:site",
        target_url: "https://example.test/login",
        success_selector: "#signed-in",
      });
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              state: "done",
              session_id: "s2",
              channel: {
                kind: "cdp",
                endpoint: "ws://127.0.0.1:4242/devtools/browser/abc",
              },
            }),
          },
        ],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("returns the bridge error code for a login_step done result", async () => {
    const done = {
      state: "done",
      session_id: "s1",
      channel: { kind: "cdp", endpoint },
    };
    const fake = await startFakeStepwiseBridgeServer("login_step", done, true);
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await stepwiseHandler("login_step", {
        login_id: "l1",
        action: "snapshot",
      });
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "FORBIDDEN" }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });

  test("does not open a bridge tunnel for a pending or aborted result", async () => {
    const pending = {
      state: "pending",
      login_id: "l1",
      snapshot: { url: "https://example.test", elements: [] },
    };
    const fake = await startFakeStepwiseServer({ result: pending });
    process.env.TEGATA_BRIDGE = "1";
    try {
      const result = await stepwiseHandler("login_step", {
        login_id: "l1",
        action: "snapshot",
      });
      expect(fake.calls).toHaveLength(1);
      expect(result).toEqual({
        content: [{ type: "text", text: JSON.stringify(pending) }],
      });

      const aborted = { state: "aborted" };
      const fake2 = await startFakeStepwiseServer({ result: aborted });
      try {
        const abortedResult = await stepwiseHandler("login_step", {
          login_id: "l1",
          action: "abort",
        });
        expect(fake2.calls).toHaveLength(1);
        expect(abortedResult).toEqual({
          content: [{ type: "text", text: JSON.stringify(aborted) }],
        });
      } finally {
        await stopFakeServer(fake2.server);
      }
    } finally {
      delete process.env.TEGATA_BRIDGE;
      await stopFakeServer(fake.server);
    }
  });

  test("relays SNAPSHOT_REJECTED from the daemon", async () => {
    const fake = await startFakeStepwiseServer({
      error: { message: "SNAPSHOT_REJECTED" },
    });
    delete process.env.TEGATA_BRIDGE;
    try {
      const result = await stepwiseHandler("login_step", {
        login_id: "l1",
        action: "snapshot",
      });
      expect(result).toEqual({
        isError: true,
        content: [{ type: "text", text: "SNAPSHOT_REJECTED" }],
      });
    } finally {
      await stopFakeServer(fake.server);
    }
  });
});

describe("login_step input schema", () => {
  test("accepts one instance of each action shape", () => {
    const valid = [
      { login_id: "l1", action: "click", selector: "#a" },
      { login_id: "l1", action: "wait_for", selector: "#a" },
      { login_id: "l1", action: "fill", selector: "#a", value: "{{username}}" },
      {
        login_id: "l1",
        action: "fill_submit",
        fills: [{ selector: "#p", value: "{{password}}" }],
        submit: { click: "#submit" },
      },
      {
        login_id: "l1",
        action: "fill_submit",
        fills: [{ selector: "#o", value: "{{totp}}" }],
        submit: { press_enter: "#o" },
      },
      { login_id: "l1", action: "snapshot" },
      { login_id: "l1", action: "abort" },
    ];
    for (const candidate of valid) {
      expect(
        loginStepParams.safeParse(candidate).success,
        JSON.stringify(candidate),
      ).toBe(true);
    }
  });

  test("rejects a lone fill of {{password}} or {{totp}}", () => {
    expect(
      loginStepParams.safeParse({
        login_id: "l1",
        action: "fill",
        selector: "#p",
        value: "{{password}}",
      }).success,
    ).toBe(false);
    expect(
      loginStepParams.safeParse({
        login_id: "l1",
        action: "fill",
        selector: "#o",
        value: "{{totp}}",
      }).success,
    ).toBe(false);
  });

  test("rejects a fill_submit fill with a non-placeholder value", () => {
    expect(
      loginStepParams.safeParse({
        login_id: "l1",
        action: "fill_submit",
        fills: [{ selector: "#p", value: "hunter2" }],
        submit: { click: "#submit" },
      }).success,
    ).toBe(false);
  });

  test("rejects fill_submit with more than three fills", () => {
    expect(
      loginStepParams.safeParse({
        login_id: "l1",
        action: "fill_submit",
        fills: [
          { selector: "#a", value: "{{username}}" },
          { selector: "#b", value: "{{password}}" },
          { selector: "#c", value: "{{totp}}" },
          { selector: "#d", value: "{{username}}" },
        ],
        submit: { click: "#submit" },
      }).success,
    ).toBe(false);
  });

  test("rejects an unknown action", () => {
    expect(
      loginStepParams.safeParse({ login_id: "l1", action: "type" }).success,
    ).toBe(false);
  });
});
