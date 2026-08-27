import { connect } from "node:net";
import { createInterface } from "node:readline";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type RpcResponse = {
  result?: unknown;
  error?: { message?: unknown };
};

const ERROR_CODES = [
  "INVALID_CREDENTIAL",
  "MFA_REQUIRED",
  "SELECTOR_NOT_FOUND",
  "VAULT_LOCKED",
  "RATE_LIMITED",
  "TOTP_NOT_EXPOSABLE",
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
    },
  },
  (args) => forward("login", args),
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

const transport = new StdioServerTransport();
server.connect(transport).catch(() => {
  process.exitCode = 1;
});
