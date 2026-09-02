// AC-53a, AC-53b — the executor's file:// guard blocks navigation to the
// local filesystem even when the daemon and the browser share a uid (the
// ordinary acceptance harness has no executor_user isolation).
// Traceability: docs/secret/briefs/tegata-v042-browser-worker.md acceptance
// condition AC-53a, AC-53b.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import { fixtureSteps } from "./support/harness.js";
import { type Stack, startStack, stopStack } from "./support/stack.js";

interface LoginResult {
  session_id: string;
  channel: { kind: string; endpoint: string };
}

/**
 * 生の CDP クライアント。tests/acceptance/support/vm-e2e.mjs の
 * inspectSession と同じ send/pending 実装をここに持つ（harness.ts は
 * 触らない方針のため、ローカルに複製する）。
 */
class CdpClient {
  private ws: WebSocket;
  private nextId = 1;
  private pending = new Map<
    number,
    (msg: { result?: unknown; error?: { message: string } }) => void
  >();

  private constructor(ws: WebSocket) {
    this.ws = ws;
    this.ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data as string);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        this.pending.get(msg.id)?.(msg);
        this.pending.delete(msg.id);
      }
    };
  }

  static async connect(endpoint: string): Promise<CdpClient> {
    const ws = new WebSocket(endpoint);
    await new Promise<void>((resolve, reject) => {
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new Error("CDP websocket failed to open"));
    });
    return new CdpClient(ws);
  }

  send(
    method: string,
    params: unknown,
    sessionId?: string,
  ): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, (msg) =>
        msg.error
          ? reject(new Error(`${method}: ${msg.error.message}`))
          : resolve(msg.result as Record<string, unknown>),
      );
      this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }

  close(): void {
    this.ws.close();
  }
}

async function login(stack: Stack): Promise<LoginResult> {
  const res = await stack.mcp.callTool("login", {
    cred_id: "mock:site",
    target_url: stack.fixture.url,
    ...fixtureSteps(),
  });
  expect(res.isError, `login failed: ${res.text}`).toBe(false);
  return res.json as LoginResult;
}

/** 新規 browser context にページを作り、そのセッションへ attach する。 */
async function openPageSession(
  client: CdpClient,
): Promise<{ sessionId: string }> {
  const { browserContextId } = await client.send(
    "Target.createBrowserContext",
    {},
  );
  const { targetId } = await client.send("Target.createTarget", {
    url: "about:blank",
    browserContextId,
  });
  const { sessionId } = await client.send("Target.attachToTarget", {
    targetId,
    flatten: true,
  });
  await client.send("Page.enable", {}, sessionId as string);
  return { sessionId: sessionId as string };
}

async function navigateAndInspect(
  client: CdpClient,
  sessionId: string,
  url: string,
): Promise<{ errorText: unknown; innerText: unknown }> {
  const navResult = await client.send("Page.navigate", { url }, sessionId);
  // ガードによる遮断は非同期に効くことがあるため、少し待ってから DOM を読む。
  await new Promise((r) => setTimeout(r, 1_500));
  const evalResult = await client.send(
    "Runtime.evaluate",
    {
      expression: "document.body ? document.body.innerText : ''",
      returnByValue: true,
    },
    sessionId,
  );
  const result = evalResult.result as { value?: unknown };
  return { errorText: navResult.errorText, innerText: result?.value };
}

test("AC-53a: navigating to a local file:// URL is denied and yields no page content", async () => {
  // Given: 通常ハーネス（uid 分離なし）でログイン済みで、0644 で書いたカナリアファイルがある
  const stack = await startStack();
  const canaryDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "tegata-file-canary-"),
  );
  const canary = stack.guard.canary("file_url_guard");
  const canaryPath = path.join(canaryDir, "canary.txt");
  fs.writeFileSync(canaryPath, canary, { mode: 0o644 });
  let client: CdpClient | undefined;
  try {
    const result = await login(stack);
    client = await CdpClient.connect(result.channel.endpoint);
    const { sessionId } = await openPageSession(client);

    // When: そのファイルの file:// URL へ遷移する
    const { errorText, innerText } = await navigateAndInspect(
      client,
      sessionId,
      `file://${canaryPath}`,
    );

    // Then: 遷移結果は net::ERR_ACCESS_DENIED、ページ本文は空でカナリアを含まない
    expect(errorText).toBe("net::ERR_ACCESS_DENIED");
    expect(innerText).toBe("");
    expect(String(innerText)).not.toContain(canary);
  } finally {
    client?.close();
    fs.rmSync(canaryDir, { recursive: true, force: true });
    await stopStack(stack);
  }
});

test("AC-53b: navigating to file:///proc/ is denied and yields no directory listing", async () => {
  // Given: 通常ハーネス（uid 分離なし）でログイン済み
  const stack = await startStack();
  let client: CdpClient | undefined;
  try {
    const result = await login(stack);
    client = await CdpClient.connect(result.channel.endpoint);
    const { sessionId } = await openPageSession(client);

    // When: file:///proc/ へ遷移する
    const { errorText, innerText } = await navigateAndInspect(
      client,
      sessionId,
      "file:///proc/",
    );

    // Then: 遷移結果は net::ERR_ACCESS_DENIED、ページ本文は空
    expect(errorText).toBe("net::ERR_ACCESS_DENIED");
    expect(innerText).toBe("");
  } finally {
    client?.close();
    await stopStack(stack);
  }
});
