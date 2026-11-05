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
 * A raw CDP client. It carries its own copy of the send/pending implementation of
 * inspectSession in tests/acceptance/support/vm-e2e.mjs (copied locally because
 * harness.ts is left untouched).
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

/** Creates a page in a new browser context and attaches to that session. */
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
): Promise<{ errorText: unknown; innerText: unknown; href: unknown }> {
  const navResult = await client.send("Page.navigate", { url }, sessionId);
  // The guard's blocking can take effect asynchronously, so wait briefly before reading the DOM.
  await new Promise((r) => setTimeout(r, 1_500));
  const evalResult = await client.send(
    "Runtime.evaluate",
    {
      expression:
        "JSON.stringify({ href: location.href, text: document.body ? document.body.innerText : '' })",
      returnByValue: true,
    },
    sessionId,
  );
  const result = evalResult.result as { value?: string };
  const page = JSON.parse(result?.value ?? "{}") as {
    href?: unknown;
    text?: unknown;
  };
  return {
    errorText: navResult.errorText,
    innerText: page.text,
    href: page.href,
  };
}

test("AC-53a: navigating to a local file:// URL is denied and yields no page content", async () => {
  // Given: logged in under the regular harness (no uid separation), with a canary file written with
  // mode 0644
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

    // When: navigate to the file:// URL of that file
    const { errorText, innerText, href } = await navigateAndInspect(
      client,
      sessionId,
      `file://${canaryPath}`,
    );

    // Then: the navigation result is net::ERR_ACCESS_DENIED, the page is the browser error page,
    // and its body does not contain the canary
    expect(errorText).toBe("net::ERR_ACCESS_DENIED");
    expect(String(href).startsWith("chrome-error://")).toBe(true);
    expect(String(innerText)).not.toContain(canary);
  } finally {
    client?.close();
    fs.rmSync(canaryDir, { recursive: true, force: true });
    await stopStack(stack);
  }
});

test("AC-53b: navigating to file:///proc/ is denied and yields no directory listing", async () => {
  // Given: logged in under the regular harness (no uid separation)
  const stack = await startStack();
  let client: CdpClient | undefined;
  try {
    const result = await login(stack);
    client = await CdpClient.connect(result.channel.endpoint);
    const { sessionId } = await openPageSession(client);

    // When: navigate to file:///proc/
    const { errorText, innerText, href } = await navigateAndInspect(
      client,
      sessionId,
      "file:///proc/",
    );

    // Then: the navigation result is net::ERR_ACCESS_DENIED, the page is the browser error page,
    // and its body does not contain a directory listing (cpuinfo, meminfo, self)
    expect(errorText).toBe("net::ERR_ACCESS_DENIED");
    expect(String(href).startsWith("chrome-error://")).toBe(true);
    for (const entry of ["cpuinfo", "meminfo", "self"]) {
      expect(String(innerText)).not.toContain(entry);
    }
  } finally {
    client?.close();
    await stopStack(stack);
  }
});
