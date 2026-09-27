import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, test } from "vitest";
import {
  defaultEntries,
  fixtureSteps,
  type MockEntry,
} from "./support/harness.js";
import {
  ageEncrypt,
  ageKeygen,
  type Phase3Stack,
  readAuditRecords,
  renderAgeEntriesToml,
  startPhase3Stack,
  stopPhase3Stack,
} from "./support/phase3.js";
import {
  issuePeer,
  type Phase4Stack,
  peerLogin,
  startPhase4Stack,
  stopPhase4Stack,
} from "./support/phase4.js";

interface HookFiles {
  root: string;
  control: string;
  calls: string;
  env: string;
}

interface HookCall {
  code: string;
  ttl: string;
  credId: string;
}

type LoginStack =
  | Pick<Phase3Stack, "mcp" | "fixture">
  | Pick<Phase4Stack, "mcp" | "fixture">;

function hookFiles(): HookFiles {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tegata-approval-grant-"));
  return {
    root,
    control: path.join(root, "control"),
    calls: path.join(root, "calls"),
    env: path.join(root, "env"),
  };
}

function removeHookFiles(files: HookFiles): void {
  fs.rmSync(files.root, { recursive: true, force: true });
}

function approvalHook(files: HookFiles): string {
  return [
    `printf '%s %s %s\\n' "$TEGATA_APPROVAL_CODE" "$TEGATA_APPROVAL_GRANT_TTL_SECS" "$TEGATA_CRED_ID" >> ${JSON.stringify(files.calls)}`,
    `env >> ${JSON.stringify(files.env)}`,
    `if [ "$(cat ${JSON.stringify(files.control)} 2>/dev/null)" = allow ]; then exit 0; fi`,
    "exit 1",
  ].join("; ");
}

function readHookCalls(files: HookFiles): HookCall[] {
  if (!fs.existsSync(files.calls)) return [];
  return fs
    .readFileSync(files.calls, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => {
      const [code, ttl, credId] = line.trim().split(/\s+/);
      return { code, ttl, credId };
    });
}

function expectApprovalCodes(calls: HookCall[]): void {
  expect(
    calls.every(
      ({ code }) =>
        /^[0-9]{2}$/.test(code) && Number(code) >= 10 && Number(code) <= 99,
    ),
  ).toBe(true);
}

async function login(stack: LoginStack, credId = "mock:site") {
  const result = await stack.mcp.callTool("login", {
    cred_id: credId,
    target_url: stack.fixture.url,
    ...fixtureSteps(),
  });
  expect(result.isError, `login failed: ${result.text}`).toBe(false);
  return result;
}

test("AC-122: Given approve_cmd without approval_grant_ttl_secs / When the same credential logs in twice / Then the hook runs twice and no approval grant is audited", {
  timeout: 90_000,
}, async () => {
  const files = hookFiles();
  fs.writeFileSync(files.control, "allow\n");
  const stack = await startPhase3Stack({
    top: { approveCmd: approvalHook(files) },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    await login(stack);
    await login(stack);

    const calls = readHookCalls(files);
    expect(calls).toHaveLength(2);
    expect(calls.map(({ ttl }) => ttl)).toEqual(["0", "0"]);
    expect(calls.map(({ credId }) => credId)).toEqual([
      "mock:site",
      "mock:site",
    ]);
    expectApprovalCodes(calls);

    const loginRecords = readAuditRecords(
      stack.daemon.auditLogPath,
    ).records.filter((record) => record.method === "login");
    expect(loginRecords).toHaveLength(2);
    for (const record of loginRecords)
      expect(record).not.toHaveProperty("approval_grant");
  } finally {
    await stopPhase3Stack(stack);
    removeHookFiles(files);
  }
});

test("AC-123: Given approval_grant_ttl_secs is 60 / When the same principal logs in twice with one credential / Then the hook runs once and the grant is issued then reused", {
  timeout: 90_000,
}, async () => {
  const files = hookFiles();
  fs.writeFileSync(files.control, "allow\n");
  const stack = await startPhase3Stack({
    top: {
      approveCmd: approvalHook(files),
      approvalGrantTtlSecs: 60,
    },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    await login(stack);
    const second = await login(stack);
    expect(second.isError).toBe(false);

    const calls = readHookCalls(files);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ ttl: "60", credId: "mock:site" });
    expectApprovalCodes(calls);

    const loginRecords = readAuditRecords(
      stack.daemon.auditLogPath,
    ).records.filter((record) => record.method === "login");
    expect(loginRecords).toHaveLength(2);
    expect(loginRecords[0]).toHaveProperty("approval_grant", "issued");
    expect(loginRecords[1]).toHaveProperty("approval_grant", "reused");
  } finally {
    await stopPhase3Stack(stack);
    removeHookFiles(files);
  }
});

test("AC-124: Given approval_grant_ttl_secs is 2 / When login waits three seconds before logging in again / Then the hook runs twice", {
  timeout: 90_000,
}, async () => {
  const files = hookFiles();
  fs.writeFileSync(files.control, "allow\n");
  const stack = await startPhase3Stack({
    top: {
      approveCmd: approvalHook(files),
      approvalGrantTtlSecs: 2,
    },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    await login(stack);
    await new Promise((resolve) => setTimeout(resolve, 3_000));
    await login(stack);

    const calls = readHookCalls(files);
    expect(calls).toHaveLength(2);
    expect(
      calls.every(({ ttl, credId }) => ttl === "2" && credId === "mock:site"),
    ).toBe(true);
    expectApprovalCodes(calls);
  } finally {
    await stopPhase3Stack(stack);
    removeHookFiles(files);
  }
});

test("AC-125: Given credential A has a 60-second grant / When credential B and another principal log in / Then each ungranted request reaches the hook", {
  timeout: 90_000,
}, async () => {
  const files = hookFiles();
  fs.writeFileSync(files.control, "allow\n");
  const stack = await startPhase4Stack({
    tcp: true,
    approveCmd: approvalHook(files),
    approvalGrantTtlSecs: 60,
  });
  try {
    await login(stack, "mock:site");
    await login(stack, "mock:site-no-totp");
    const peer = await issuePeer(
      stack.daemon.socketPath,
      "approval-grant-peer",
    );
    await peerLogin(stack, peer, "mock:site");

    const calls = readHookCalls(files);
    expect(calls).toHaveLength(3);
    expect(calls.map(({ credId }) => credId)).toEqual([
      "mock:site",
      "mock:site-no-totp",
      "mock:site",
    ]);
    expectApprovalCodes(calls);
  } finally {
    await stopPhase4Stack(stack);
    removeHookFiles(files);
  }
});

test("AC-126: Given approval_grant_ttl_secs is 60 / When the hook denies then allows / Then denial creates no grant and every hook code is a fresh two-digit value", {
  timeout: 90_000,
}, async () => {
  const deniedFiles = hookFiles();
  const deniedStack = await startPhase3Stack({
    top: {
      approveCmd: approvalHook(deniedFiles),
      approvalGrantTtlSecs: 60,
    },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    const denied = await deniedStack.mcp.callTool("login", {
      cred_id: "mock:site",
      target_url: deniedStack.fixture.url,
      ...fixtureSteps(),
    });
    expect(denied.isError).toBe(true);
    expect(denied.text).toBe("APPROVAL_DENIED");

    fs.writeFileSync(deniedFiles.control, "allow\n");
    await login(deniedStack);

    const calls = readHookCalls(deniedFiles);
    expect(calls).toHaveLength(2);
    expect(calls.every(({ ttl }) => ttl === "60")).toBe(true);
    expectApprovalCodes(calls);
  } finally {
    await stopPhase3Stack(deniedStack);
    removeHookFiles(deniedFiles);
  }

  const repeatedFiles = hookFiles();
  fs.writeFileSync(repeatedFiles.control, "allow\n");
  const repeatedStack = await startPhase3Stack({
    top: { approveCmd: approvalHook(repeatedFiles) },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    for (let i = 0; i < 5; i += 1) await login(repeatedStack);

    const calls = readHookCalls(repeatedFiles);
    expect(calls).toHaveLength(5);
    expect(calls.every(({ ttl }) => ttl === "0")).toBe(true);
    expectApprovalCodes(calls);
    expect(new Set(calls.map(({ code }) => code)).size).toBeGreaterThan(1);
  } finally {
    await stopPhase3Stack(repeatedStack);
    removeHookFiles(repeatedFiles);
  }
});

test("AC-127: Given credential A has a 60-second grant / When the vault is locked and reopened before login / Then the hook runs again", {
  timeout: 90_000,
}, async () => {
  const files = hookFiles();
  fs.writeFileSync(files.control, "allow\n");
  const stack = await startPhase3Stack({
    top: {
      approveCmd: approvalHook(files),
      approvalGrantTtlSecs: 60,
    },
    makeProviders: (canaries, materialsDir) => {
      const { identityPath, recipient } = ageKeygen(materialsDir);
      const entries: MockEntry[] = [
        {
          id: "site",
          name: "Age Test Site",
          uri: "http://127.0.0.1",
          kind: "login",
          username: canaries.username,
          password: canaries.password,
        },
      ];
      const entriesPath = path.join(materialsDir, "entries.toml.age");
      ageEncrypt(recipient, renderAgeEntriesToml(entries), entriesPath);
      return [
        { type: "age-file", namespace: "age", entriesPath, identityPath },
      ];
    },
  });
  try {
    await login(stack, "age:site");
    const locked = await stack.mcp.callTool("lock_vault", { namespace: "age" });
    expect(locked.isError, locked.text).toBe(false);
    await login(stack, "age:site");

    const calls = readHookCalls(files);
    expect(calls).toHaveLength(2);
    expect(
      calls.every(({ ttl, credId }) => ttl === "60" && credId === "age:site"),
    ).toBe(true);
    expectApprovalCodes(calls);
  } finally {
    await stopPhase3Stack(stack);
    removeHookFiles(files);
  }
});

test("AC-128: Given an approval hook records its environment / When a credential is approved / Then no credential canary appears in the environment record", {
  timeout: 90_000,
}, async () => {
  const files = hookFiles();
  fs.writeFileSync(files.control, "allow\n");
  const stack = await startPhase3Stack({
    top: {
      approveCmd: approvalHook(files),
      approvalGrantTtlSecs: 60,
    },
    makeProviders: (canaries) => [
      { type: "mock", namespace: "mock", entries: defaultEntries(canaries) },
    ],
  });
  try {
    await login(stack);
    const env = fs.readFileSync(files.env, "utf8");
    stack.guard.observe("approval-grant-hook-env", env);
    expect(env).toContain("TEGATA_CRED_ID=mock:site");
    expect(env).not.toContain(stack.canaries.username);
    expect(env).not.toContain(stack.canaries.password);
    expect(env).not.toContain(stack.canaries.totpSeed);
  } finally {
    await stopPhase3Stack(stack);
    removeHookFiles(files);
  }
});
