// AC-72, AC-73 — an agent container reaches the daemon only through
// `tegata-bridge` with its named token, drives the resulting session over CDP
// from inside the container, and never sees a credential canary.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance conditions
// AC-72 and AC-73.
//
// Needs a rootful docker (`${TEGATA_DOCKER} info` must succeed); otherwise
// the tests are skipped. AC-73 builds on the state AC-72 leaves behind
// (bridge, MCP server and lease alive), so the two run in order in one file.

import { afterAll, beforeAll, describe, expect, test } from "vitest";
import type { McpSession } from "../support/harness.js";
import {
  LOGGED_IN_PAGE_TITLE,
  type LoginResult,
  loginParams,
} from "../support/phase4.js";
import { type Container, dockerAvailable } from "./support/docker.js";
import {
  type ContainerStack,
  IN_CONTAINER,
  NODE,
  startContainerStack,
  stopContainerStack,
} from "./support/stack.js";

describe.skipIf(!dockerAvailable())("AC-72 / AC-73 (docker)", () => {
  let stack: ContainerStack | undefined;
  let login: LoginResult | undefined;

  beforeAll(async () => {
    stack = await startContainerStack({ agent: true });
  });

  afterAll(async () => {
    if (stack?.mcp !== undefined && login !== undefined) {
      await stack.mcp
        .callTool("logout", { session_id: login.session_id })
        .catch(() => {});
    }
    if (stack !== undefined) await stopContainerStack(stack);
  });

  test("AC-72: the agent container logs in through the bridge and drives the session over CDP", async () => {
    // Given: tegata-bridge (with the token of p1) and MCP (TEGATA_BRIDGE=1) in the agent container
    if (stack?.mcp === undefined || stack.agent === undefined)
      throw new Error("agent stack not started");
    const mcp: McpSession = stack.mcp;
    const agent: Container = stack.agent;

    // When: connectOverCDP with Playwright (from inside the container) to the endpoint of login(X)
    const res = await mcp.callTool(
      "login",
      loginParams(stack.fixture.url, "mock:site"),
    );
    expect(res.isError, res.text).toBe(false);
    login = res.json as LoginResult;
    expect(login.channel.endpoint).toMatch(/^ws:\/\/127\.0\.0\.1:\d+\//);
    const probe = await agent.exec([
      NODE,
      `${IN_CONTAINER.probe}/cdp-title.mjs`,
      login.channel.endpoint,
      stack.fixture.url,
    ]);
    stack.observe("container:cdp-title", probe.stdout);
    const page = JSON.parse(probe.stdout.trim()) as {
      title?: string;
      url?: string;
      error?: string;
    };

    // Then: the title of the fixture post-login page is retrievable
    expect(page.error, probe.stdout).toBeUndefined();
    expect(page.title).toBe(LOGGED_IN_PAGE_TITLE);
    expect(stack.fixture.loginPosts()).toBe(1);
  });

  test("AC-73: no canary reaches the agent container", async () => {
    // Given: the AC-72 state (the bridge, the MCP server, and the lease are alive)
    if (stack?.agent === undefined) throw new Error("agent stack not started");
    expect(login).toBeDefined();
    const agent: Container = stack.agent;

    // When: scan the FS, environment variables, and ps output inside the container with leakscan.
    //       The FS scan covers every top-level directory under /. /proc, /sys, and /dev are
    //       excluded because they are pseudo filesystems, and /nix and /app are excluded
    //       because they hold tooling mounted read-only from the host (the store closure /
    //       node_modules / MCP / probe), cannot be written from the container side, and are
    //       already covered by the host-side guard scan. The ps output and environment
    //       variables are dumped as a file of every process's cmdline / environ, placed in
    //       /tmp, and included in the same scan. The canaries are passed via stdin.
    const dumpPath = "/tmp/tegata-acceptance-proc.txt";
    await agent.exec([
      "sh",
      "-c",
      `for p in /proc/[0-9]*; do cat "$p/cmdline" "$p/environ" 2>/dev/null; echo; done > ${dumpPath}; env >> ${dumpPath}`,
    ]);
    const excluded = ["proc", "sys", "dev", "nix", "app"];
    const roots = (await agent.exec(["ls", "-1", "/"])).stdout
      .split("\n")
      .filter((name) => name !== "" && !excluded.includes(name))
      .map((name) => `/${name}`);
    const canaries = [
      stack.canaries.username,
      stack.canaries.password,
      stack.canaries.totpSeed,
      stack.canaries.wrongPassword,
    ];
    const scan = await agent.exec(
      [IN_CONTAINER.leakscan, "--canaries", "/dev/stdin", "--json", ...roots],
      {
        input: JSON.stringify({ canaries }),
        allowFailure: true,
        timeoutMs: 600_000,
      },
    );

    // Then: 0 canaries found (the password, the TOTP seed, and every other guard canary)
    expect(scan.status, `${scan.stdout}\n${scan.stderr}`).toBe(0);
    const report = JSON.parse(scan.stdout) as { hits: unknown[] };
    expect(report.hits).toEqual([]);
  });
});
