import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, test } from "vitest";
import { createServer as createMcpServer } from "./index.js";

// src と dist のどちらから実行されても packages/tegata-mcp/<dir>/ 直下なので、同じ深さで解決できる。
const agentPath = fileURLToPath(
  new URL(
    "../../../integrations/claude-code/agents/tegata-login.md",
    import.meta.url,
  ),
);

const toolPrefix = "mcp__tegata__";

// frontmatter の `key: value` 行のみを扱う簡易パーサ（YAML 依存を避けるため）。
function parseFrontmatter(text: string): Record<string, string> {
  const lines = text.split(/\r?\n/);
  if (lines[0]?.trim() !== "---") throw new Error("frontmatter not found");
  const end = lines.indexOf("---", 1);
  if (end === -1) throw new Error("frontmatter is not closed");
  const fields: Record<string, string> = {};
  for (const line of lines.slice(1, end)) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    fields[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  return fields;
}

// tools 行を解析し、mcp__tegata__ 接頭辞を外したツール名を返す。形式違反は例外とする。
function parseToolNames(tools: string | undefined): string[] {
  if (tools === undefined) throw new Error("tools is missing");
  return tools.split(",").map((entry) => {
    const item = entry.trim();
    if (!item.startsWith(toolPrefix) || item.length === toolPrefix.length) {
      throw new Error(`unexpected tool entry: ${item}`);
    }
    return item.slice(toolPrefix.length);
  });
}

function assertRegistered(tools: string | undefined, registered: string[]) {
  for (const name of parseToolNames(tools)) {
    if (!registered.includes(name)) {
      throw new Error(`tool is not registered in the broker: ${name}`);
    }
  }
}

async function listRegisteredTools(): Promise<string[]> {
  const server = createMcpServer();
  const client = new Client({ name: "agent-definition-test", version: "0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const { tools } = await client.listTools();
    return tools.map((tool) => tool.name);
  } finally {
    await client.close();
    await server.close();
  }
}

describe("tegata-login agent definition", () => {
  const fields = parseFrontmatter(readFileSync(agentPath, "utf8"));

  test("declares name and a non-empty model", () => {
    expect(fields.name).toBe("tegata-login");
    expect(fields.model).toBeTruthy();
  });

  test("lists only tools registered by the broker", async () => {
    const registered = await listRegisteredTools();
    expect(() => assertRegistered(fields.tools, registered)).not.toThrow();
  });

  test("grants exactly login_begin and login_step", () => {
    expect(parseToolNames(fields.tools).sort()).toEqual([
      "login_begin",
      "login_step",
    ]);
  });

  test("the check rejects a tool that the broker does not register", async () => {
    const registered = await listRegisteredTools();
    const broken = parseFrontmatter(
      "---\nname: x\ntools: mcp__tegata__login_begin, mcp__tegata__no_such_tool\nmodel: haiku\n---\n",
    );
    expect(() => assertRegistered(broken.tools, registered)).toThrow(
      /no_such_tool/,
    );
  });
});
