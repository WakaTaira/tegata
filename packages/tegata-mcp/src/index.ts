import { connect } from "node:net";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type RpcResponse = {
  result?: unknown;
  error?: { message?: unknown; data?: unknown };
};

// Keep in sync with crates/tegatad/src/main.rs and tests/acceptance/support/harness.ts.
// Keep in sync with tests/acceptance/support/phase4.ts.
const ERROR_CODES = [
  "INVALID_CREDENTIAL",
  "MFA_REQUIRED",
  "SELECTOR_NOT_FOUND",
  "LOGIN_RESULT_TIMEOUT",
  "OAUTH_GRANT_FAILED",
  "DEVICE_CODE_REJECTED",
  "VAULT_LOCKED",
  "RATE_LIMITED",
  "NOT_FOUND",
  "TOTP_NOT_EXPOSABLE",
  "APPROVAL_DENIED",
  "APPROVAL_TIMEOUT",
  "PROVIDER_UNAVAILABLE",
  "INTERNAL",
  "UNAUTHORIZED",
  "FORBIDDEN",
  "ADMIN_REQUIRED",
  "ADMIN_SEAL_UNAVAILABLE",
] as const;
type ErrorCode = (typeof ERROR_CODES)[number];
const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;

const loginStep = z.union([
  z.object({
    action: z.literal("fill"),
    selector: z.string(),
    value: z.enum(["{{username}}", "{{password}}", "{{totp}}"]),
  }),
  z.object({
    action: z.literal("click"),
    selector: z.string(),
  }),
]);

const authorizeDeviceStep = z.union([
  z.object({
    action: z.literal("fill"),
    selector: z.string(),
    value: z.enum([
      "{{username}}",
      "{{password}}",
      "{{totp}}",
      "{{user_code}}",
    ]),
  }),
  z.object({
    action: z.literal("click"),
    selector: z.string(),
  }),
]);

function internalError(): {
  isError: true;
  content: [{ type: "text"; text: "INTERNAL" }];
} {
  return {
    isError: true,
    content: [{ type: "text", text: "INTERNAL" }],
  };
}

function errorResult(message: string, data?: unknown) {
  const errorCode =
    ERROR_CODES.includes(message as ErrorCode) ||
    ERROR_CODE_PATTERN.test(message)
      ? message
      : "INTERNAL";
  const step =
    typeof data === "object" &&
    data !== null &&
    typeof (data as { step?: unknown }).step === "number" &&
    Number.isInteger((data as { step: number }).step) &&
    (data as { step: number }).step >= 0
      ? (data as { step: number }).step
      : undefined;
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: errorCode }],
    ...(step === undefined
      ? {}
      : { structuredContent: { error: errorCode, step } }),
  };
}

// run.ts（tegata-mcp-run）が同じデーモン呼び出し規則を共用するために export する。
export async function callDaemon(
  method: string,
  params: unknown,
): Promise<RpcResponse> {
  const socketPath = process.env.TEGATA_SOCKET;
  if (socketPath === undefined || socketPath === "")
    throw new Error("socket unavailable");

  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const lines = createInterface({ input: socket });
    let settled = false;

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      lines.close();
      socket.destroy();
      reject(error);
    };

    socket.once("error", fail);
    socket.once("close", () => fail(new Error("connection closed")));
    socket.once("connect", () => {
      socket.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })}\n`,
      );
    });
    lines.once("line", (line) => {
      try {
        const response: unknown = JSON.parse(line);
        if (typeof response !== "object" || response === null) {
          throw new Error("invalid response");
        }
        settled = true;
        lines.close();
        socket.destroy();
        resolve(response as RpcResponse);
      } catch (error) {
        fail(error instanceof Error ? error : new Error("invalid response"));
      }
    });
  });
}

async function forward(method: string, params: unknown) {
  try {
    const response = await callDaemon(method, params);
    if (response.error !== undefined) {
      if (typeof response.error.message !== "string") return internalError();
      return errorResult(response.error.message, response.error.data);
    }
    if (!("result" in response)) return internalError();
    return {
      content: [
        { type: "text" as const, text: JSON.stringify(response.result) },
      ],
    };
  } catch {
    return internalError();
  }
}

function successResult(result: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result) }],
  };
}

/** デーモンが返す loopback の URL を検証する。bridge はこのポートへのトンネルのみを開く。 */
function parseLoopbackUrl(value: string, protocol: "ws:" | "http:"): URL {
  const url = new URL(value);
  if (
    url.protocol !== protocol ||
    url.hostname !== "127.0.0.1" ||
    url.port === ""
  ) {
    throw new Error("invalid loopback url");
  }
  return url;
}

type ParsedLoginResult = {
  result: Record<string, unknown>;
  sessionId: string;
  endpoint: URL;
};

function parseLoginResult(result: unknown): ParsedLoginResult {
  if (typeof result !== "object" || result === null)
    throw new Error("invalid login result");
  const loginResult = result as {
    session_id?: unknown;
    channel?: { endpoint?: unknown; [key: string]: unknown };
    [key: string]: unknown;
  };
  if (
    typeof loginResult.session_id !== "string" ||
    loginResult.channel === undefined ||
    typeof loginResult.channel.endpoint !== "string"
  ) {
    throw new Error("invalid login result");
  }

  const endpoint = parseLoopbackUrl(loginResult.channel.endpoint, "ws:");
  return {
    result: loginResult,
    sessionId: loginResult.session_id,
    endpoint,
  };
}

function rewriteEndpoint(login: ParsedLoginResult, localPort: number) {
  const endpoint = new URL(login.endpoint);
  endpoint.port = String(localPort);
  return {
    ...login.result,
    channel: {
      ...(login.result.channel as Record<string, unknown>),
      endpoint: endpoint.toString(),
    },
  };
}

type BridgeTunnel =
  | { localPort: number }
  | { failure: ReturnType<typeof internalError | typeof errorResult> };

/** bridge にセッションのポートへのトンネルを開かせ、bridge 側のローカルポートを得る。
 * run.ts（tegata-mcp-run）が MCP サーバー中継の bridge トンネルにも同じ手順を使うため export する。 */
export async function openBridgeTunnel(
  sessionId: string,
  port: number,
): Promise<BridgeTunnel> {
  const tunnelResponse = await callDaemon("bridge_open_tunnel", {
    session_id: sessionId,
    port,
  });
  if (tunnelResponse.error !== undefined) {
    if (typeof tunnelResponse.error.message !== "string")
      return { failure: internalError() };
    return {
      failure: errorResult(
        tunnelResponse.error.message,
        tunnelResponse.error.data,
      ),
    };
  }
  if (
    typeof tunnelResponse.result !== "object" ||
    tunnelResponse.result === null
  ) {
    return { failure: internalError() };
  }
  const localPort = (tunnelResponse.result as { local_port?: unknown })
    .local_port;
  if (typeof localPort !== "number" || !Number.isInteger(localPort))
    return { failure: internalError() };
  return { localPort };
}

export async function loginHandler(params: unknown) {
  try {
    const response = await callDaemon("login", params);
    if (response.error !== undefined) {
      if (typeof response.error.message !== "string") return internalError();
      return errorResult(response.error.message, response.error.data);
    }
    if (!("result" in response)) return internalError();
    if (process.env.TEGATA_BRIDGE !== "1")
      return successResult(response.result);

    const loginResult = parseLoginResult(response.result);

    const tunnel = await openBridgeTunnel(
      loginResult.sessionId,
      Number(loginResult.endpoint.port),
    );
    if ("failure" in tunnel) return tunnel.failure;
    return successResult(rewriteEndpoint(loginResult, tunnel.localPort));
  } catch {
    return internalError();
  }
}

type ParsedApiProxyResult = {
  result: Record<string, unknown>;
  sessionId: string;
  baseUrl: URL;
};

function parseApiProxyResult(result: unknown): ParsedApiProxyResult {
  if (typeof result !== "object" || result === null)
    throw new Error("invalid API proxy result");
  const proxyResult = result as {
    session_id?: unknown;
    base_url?: unknown;
    [key: string]: unknown;
  };
  if (
    typeof proxyResult.session_id !== "string" ||
    typeof proxyResult.base_url !== "string"
  ) {
    throw new Error("invalid API proxy result");
  }
  const baseUrl = parseLoopbackUrl(proxyResult.base_url, "http:");
  return { result: proxyResult, sessionId: proxyResult.session_id, baseUrl };
}

/** ポートだけを bridge のローカルポートへ差し替え、path secret はそのまま残す。 */
function rewriteBaseUrl(proxy: ParsedApiProxyResult, localPort: number) {
  const baseUrl = new URL(proxy.baseUrl);
  baseUrl.port = String(localPort);
  return { ...proxy.result, base_url: baseUrl.toString() };
}

export async function openApiProxyHandler(params: unknown) {
  try {
    const response = await callDaemon("open_api_proxy", params);
    if (response.error !== undefined) {
      if (typeof response.error.message !== "string") return internalError();
      return errorResult(response.error.message, response.error.data);
    }
    if (!("result" in response)) return internalError();
    if (process.env.TEGATA_BRIDGE !== "1")
      return successResult(response.result);

    const proxyResult = parseApiProxyResult(response.result);
    const tunnel = await openBridgeTunnel(
      proxyResult.sessionId,
      Number(proxyResult.baseUrl.port),
    );
    if ("failure" in tunnel) return tunnel.failure;
    return successResult(rewriteBaseUrl(proxyResult, tunnel.localPort));
  } catch {
    return internalError();
  }
}

const server = new McpServer({ name: "tegata-mcp", version: "0.0.0" });

server.registerTool(
  "list_credentials",
  { inputSchema: { namespace: z.string().optional() } },
  (args) => forward("list_credentials", args),
);

server.registerTool(
  "login",
  {
    inputSchema: {
      cred_id: z.string(),
      target_url: z.string(),
      steps: z.array(loginStep).optional(),
      success_selector: z.string().optional(),
      failure_selector: z.string().optional(),
      exclusive: z.boolean().optional(),
    },
  },
  (args) => loginHandler(args),
);

server.registerTool(
  "authorize_device",
  {
    description: "Authorize an OAuth device flow with a stored credential.",
    inputSchema: {
      cred_id: z.string(),
      verification_url: z.string(),
      user_code: z.string(),
      steps: z.array(authorizeDeviceStep).optional(),
      success_selector: z.string(),
      failure_selector: z.string().optional(),
    },
  },
  (args) => forward("authorize_device", args),
);

server.registerTool(
  "open_api_proxy",
  {
    description:
      "Open a configured API proxy that injects a stored credential into requests to its fixed upstream. Send requests to base_url followed by the upstream path; close it with logout.",
    inputSchema: { name: z.string() },
  },
  (args) => openApiProxyHandler(args),
);

server.registerTool(
  "logout",
  { inputSchema: { session_id: z.string() } },
  (args) => forward("logout", args),
);

server.registerTool(
  "get_totp",
  { inputSchema: { cred_id: z.string() } },
  (args) => forward("get_totp", args),
);

server.registerTool(
  "lock_vault",
  { inputSchema: { namespace: z.string().optional() } },
  (args) => forward("lock_vault", args),
);

if (
  process.argv[1] !== undefined &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  const transport = new StdioServerTransport();
  server.connect(transport).catch(() => {
    process.exitCode = 1;
  });
}
