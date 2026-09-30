// AC-183 — the tegata-mcp tool listing is self-describing: `login_step`
// advertises its parameters and action enum in its inputSchema, every tool
// has a non-empty object inputSchema, and the server instructions point
// agents at `login_begin`.
// Traceability: docs/secret/briefs/tegata-issue53-55-stepwise-default.md
// acceptance condition AC-183.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { expect, test } from "vitest";
import { bins } from "./support/harness.js";

type Schema = {
  type?: string;
  properties?: Record<string, { type?: string; enum?: string[] }>;
};

test("AC-183: listTools exposes full login_step schema, non-empty schemas for all tools, and instructions mention login_begin", async () => {
  // Given: the tegata-mcp server started like the harness does (stdio); the
  // daemon is not needed to list tools, so TEGATA_SOCKET is a dummy path.
  const transport = new StdioClientTransport({
    command: "node",
    args: [bins().mcpEntry],
    env: {
      ...process.env,
      TEGATA_SOCKET: "/nonexistent/tegata-ac183.sock",
    } as Record<string, string>,
  });
  const client = new Client({ name: "acceptance", version: "0.0.0" });
  try {
    await client.connect(transport);

    // When: listTools and getInstructions are called through the SDK client.
    const { tools } = await client.listTools();
    const instructions = client.getInstructions();

    // Then: login_step has type object with the documented properties.
    const loginStep = tools.find((t) => t.name === "login_step");
    expect(loginStep, "login_step must be listed").toBeDefined();
    const schema = loginStep?.inputSchema as Schema;
    expect(schema.type).toBe("object");
    const props = schema.properties ?? {};
    for (const key of [
      "login_id",
      "action",
      "selector",
      "value",
      "fills",
      "submit",
    ]) {
      expect(Object.keys(props), `login_step.properties.${key}`).toContain(key);
    }
    expect(props.fills?.type).toBe("array");
    expect(new Set(props.action?.enum ?? [])).toEqual(
      new Set([
        "click",
        "wait_for",
        "fill",
        "fill_submit",
        "snapshot",
        "abort",
      ]),
    );

    // Then: every tool's inputSchema is an object with non-empty properties.
    for (const tool of tools) {
      const s = tool.inputSchema as Schema;
      expect(s.type, `${tool.name} inputSchema.type`).toBe("object");
      expect(
        Object.keys(s.properties ?? {}).length,
        `${tool.name} inputSchema.properties must not be empty`,
      ).toBeGreaterThan(0);
    }

    // Then: instructions are non-empty and contain login_begin.
    expect(instructions, "server instructions").toBeTruthy();
    expect(instructions).toContain("login_begin");
  } finally {
    await client.close();
  }
});
