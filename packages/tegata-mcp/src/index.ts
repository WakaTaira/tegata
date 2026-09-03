import { connect } from "node:net";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type RpcResponse = {
  result?: unknown;
  error?: { message?: unknown };
};

// Keep in sync with crates/tegatad/src/main.rs and tests/acceptance/support/harness.ts.
// Keep in sync with tests/acceptance/support/phase4.ts.
const ERROR_CODES = [
  "INVALID_CREDENTIAL",
  "MFA_REQUIRED",
  "SELECTOR_NOT_FOUND",
  "VAULT_LOCKED",
  "RATE_LIMITED",
  "NOT_FOUND",
  "TOTP_NOT_EXPOSABLE",
  "APPROVAL_DENIED",
  "APPROVAL_TIMEOUT",
  "INTERNAL",
] as const;
type ErrorCode = (typeof ERROR_CODES)[number];

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

function internalError(): {
  isError: true;
  content: [{ type: "text"; text: "INTERNAL" }];
} {
  return {
    isError: true,
    content: [{ type: "text", text: "INTERNAL" }],
  };
}

function errorResult(message: string) {
  const errorCode: ErrorCode = ERROR_CODES.includes(message as ErrorCode)
    ? (message as ErrorCode)
    : "INTERNAL";
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: errorCode }],
  };
}

async function callDaemon(
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
      return errorResult(response.error.message);
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

  const endpoint = new URL(loginResult.channel.endpoint);
  if (
    endpoint.protocol !== "ws:" ||
    endpoint.hostname !== "127.0.0.1" ||
    endpoint.port === ""
  ) {
    throw new Error("invalid login endpoint");
  }
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

export async function loginHandler(params: unknown) {
  try {
    const response = await callDaemon("login", params);
    if (response.error !== undefined) {
      if (typeof response.error.message !== "string") return internalError();
      return errorResult(response.error.message);
    }
    if (!("result" in response)) return internalError();
    if (process.env.TEGATA_BRIDGE !== "1")
      return successResult(response.result);

    const loginResult = parseLoginResult(response.result);

    const tunnelResponse = await callDaemon("bridge_open_tunnel", {
      session_id: loginResult.sessionId,
      port: Number(loginResult.endpoint.port),
    });
    if (tunnelResponse.error !== undefined) {
      if (typeof tunnelResponse.error.message !== "string")
        return internalError();
      return errorResult(tunnelResponse.error.message);
    }
    if (
      typeof tunnelResponse.result !== "object" ||
      tunnelResponse.result === null
    ) {
      return internalError();
    }
    const localPort = (tunnelResponse.result as { local_port?: unknown })
      .local_port;
    if (typeof localPort !== "number" || !Number.isInteger(localPort))
      return internalError();
    return successResult(rewriteEndpoint(loginResult, localPort));
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
