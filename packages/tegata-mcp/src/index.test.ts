import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { loginHandler, openApiProxyHandler } from "./index.js";

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
