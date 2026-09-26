import { describe, expect, test } from "vitest";
import type { McpResult } from "../support/harness.js";
import {
  type ApiProxyContainerStack,
  startApiProxyContainerStack,
  stopApiProxyContainerStack,
} from "./support/api-proxy-stack.js";
import { dockerAvailable } from "./support/docker.js";
import { NODE } from "./support/stack.js";

interface OpenApiProxy {
  session_id: string;
  base_url: string;
}

interface ContainerProbe {
  status?: number;
  body?: string;
  error?: string;
}

describe("AC-105 (docker)", () => {
  // Given: agent コンテナの tegata-bridge と MCP（TEGATA_BRIDGE=1）
  // When: MCP の open_api_proxy の base_url + "/api/whoami" へコンテナ内から GET
  // Then: HTTP 200 で、本文が {"user":"fixture"}
  test("AC-105: the agent container reaches the API proxy through bridge MCP", async () => {
    if (!dockerAvailable())
      throw new Error("Docker daemon is unavailable for AC-105");
    const stack: ApiProxyContainerStack = await startApiProxyContainerStack();
    let sessionId: string | undefined;
    try {
      const opened: McpResult = await stack.mcp.callTool("open_api_proxy", {
        name: "fx",
      });
      expect(opened.isError, opened.text).toBe(false);
      const session = opened.json as Partial<OpenApiProxy>;
      expect(typeof session.session_id).toBe("string");
      expect(typeof session.base_url).toBe("string");
      sessionId = session.session_id as string;

      const probe = await stack.agent.exec(
        [
          NODE,
          "-e",
          `let input = ""; for await (const chunk of process.stdin) input += chunk; const value = JSON.parse(input); try { const response = await fetch(value.base_url + "/api/whoami"); console.log(JSON.stringify({ status: response.status, body: await response.text() })); } catch (error) { console.log(JSON.stringify({ error: String(error) })); process.exitCode = 1; }`,
        ],
        { input: JSON.stringify({ base_url: session.base_url }) },
      );
      stack.observe("container:api-proxy", probe.stdout);
      const result = JSON.parse(probe.stdout.trim()) as ContainerProbe;
      expect(result.error, probe.stderr).toBeUndefined();
      expect(result.status).toBe(200);
      expect(JSON.parse(result.body ?? "")).toEqual({ user: "fixture" });
    } finally {
      if (sessionId !== undefined)
        await stack.mcp
          .callTool("logout", { session_id: sessionId })
          .catch(() => {});
      await stopApiProxyContainerStack(stack);
    }
  });
});
