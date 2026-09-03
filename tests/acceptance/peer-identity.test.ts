// AC-58, AC-63, AC-64, AC-65 — named peers on the Linux TCP front: sessions
// are owned by their principal, revoked tokens are refused, the admin surface
// is limited to operators, and the audit log names the principal.
// Traceability: docs/secret/briefs/tegata-phase4.md acceptance condition
// AC-58, AC-63, AC-64, AC-65.

import os from "node:os";
import { expect, test } from "vitest";
import { rawRpc } from "./support/harness.js";
import { readAuditRecords } from "./support/phase3.js";
import {
  endpointPort,
  issuePeer,
  peerLogin,
  startPhase4Stack,
  stopPhase4Stack,
  tcpRpc,
  tcpTunnel,
  unixLogin,
} from "./support/phase4.js";

test("AC-58: another principal can neither log out nor tunnel into a session", async () => {
  // Given: peer p1 が login(X) したリース s1、別の peer p2
  const stack = await startPhase4Stack({ tcp: true });
  try {
    const tcpPort = stack.daemon.tcpPort as number;
    const p1 = await issuePeer(stack.daemon.socketPath, "p1");
    const p2 = await issuePeer(stack.daemon.socketPath, "p2");
    const s1 = await peerLogin(stack, p1);
    const cdpPort = endpointPort(s1.channel.endpoint);

    // When: p2 が logout(s1) を呼ぶ
    const crossLogout = await tcpRpc(tcpPort, p2.token, "logout", {
      session_id: s1.session_id,
    });
    stack.observe("tcp:logout", crossLogout);

    // Then: 応答は NOT_FOUND、s1 のリースは残り、p1 の tunnel は通り、
    // p2 の同じ tunnel は NOT_FOUND
    expect(crossLogout.error?.message).toBe("NOT_FOUND");
    expect(await tcpTunnel(tcpPort, p1.token, s1.session_id, cdpPort)).toEqual({
      ok: true,
    });
    expect(await tcpTunnel(tcpPort, p2.token, s1.session_id, cdpPort)).toEqual({
      ok: false,
      error: "NOT_FOUND",
    });
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-63: a revoked token is refused at the preamble and listed as revoked", async () => {
  // Given: admin_peer_issue {label: "ci"} で発行した p1
  const stack = await startPhase4Stack({ tcp: true });
  try {
    const tcpPort = stack.daemon.tcpPort as number;
    const p1 = await issuePeer(stack.daemon.socketPath, "ci");

    // When: p1 を失効させた後、p1 のトークンで preamble を送る
    const revoke = await rawRpc(stack.daemon.socketPath, "admin_peer_revoke", {
      peer_id: p1.peer_id,
    });
    expect(revoke.error, JSON.stringify(revoke.error)).toBeUndefined();
    const refused = await tcpRpc(tcpPort, p1.token, "status", {}, 10_000);

    // Then: 応答は UNAUTHORIZED、admin_peer_list の p1 に revoked_at が入る
    expect(refused.preamble).toEqual({ ok: false, error: "UNAUTHORIZED" });
    const list = await rawRpc(stack.daemon.socketPath, "admin_peer_list", {});
    const peers = list.result as Array<{
      peer_id: string;
      label: string;
      issued_at: unknown;
      revoked_at: unknown;
    }>;
    const entry = peers.find((p) => p.peer_id === p1.peer_id);
    expect(entry).toBeDefined();
    expect(entry?.label).toBe("ci");
    expect(entry?.revoked_at).not.toBeNull();
    expect(entry?.revoked_at).toBeDefined();
  } finally {
    await stopPhase4Stack(stack);
  }
});

test("AC-64: the peer admin RPCs are refused to non-operators and to TCP peers", async () => {
  // Given: operator_uids にテスト uid を含まないデーモン
  const nonOperator = await startPhase4Stack({ operator: false });
  try {
    // When: UNIX socket から admin_peer_issue を呼ぶ
    const res = await rawRpc(
      nonOperator.daemon.socketPath,
      "admin_peer_issue",
      {
        label: "x",
      },
    );

    // Then: ADMIN_REQUIRED
    expect(res.error?.message).toBe("ADMIN_REQUIRED");
  } finally {
    await stopPhase4Stack(nonOperator);
  }

  // Given: operator が発行した peer p1
  const operator = await startPhase4Stack({ tcp: true });
  try {
    const p1 = await issuePeer(operator.daemon.socketPath, "p1");

    // When: TCP の peer から admin_peer_issue を呼ぶ
    const viaPeer = await tcpRpc(
      operator.daemon.tcpPort as number,
      p1.token,
      "admin_peer_issue",
      { label: "y" },
      10_000,
    );

    // Then: ADMIN_REQUIRED（TCP は常に非 admin）
    expect(viaPeer.preamble).toBeUndefined();
    expect(viaPeer.error?.message).toBe("ADMIN_REQUIRED");
  } finally {
    await stopPhase4Stack(operator);
  }
});

test("AC-65: audit login records carry principal, peer identity, and shared", async () => {
  // Given: peer p1（label agent-a）の login と、UNIX socket からの login 2 回
  const stack = await startPhase4Stack({ tcp: true });
  try {
    const p1 = await issuePeer(stack.daemon.socketPath, "agent-a");
    const peerSession = await peerLogin(stack, p1);
    const unixFirst = await unixLogin(stack);
    const unixSecond = await unixLogin(stack);

    // When: 監査ログを読む
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const logins = records.filter(
      (r) => r.method === "login" && r.outcome === "ok",
    );
    const bySession = (id: string) => logins.find((r) => r.session_id === id);

    // Then: p1 の行は principal "peer:<peer_id>"、peer_id、peer_label を持ち、
    // UNIX の行は principal "uid:<n>"、初回は shared: false、相乗りは shared: true
    const peerRecord = bySession(peerSession.session_id);
    expect(peerRecord?.principal).toBe(`peer:${p1.peer_id}`);
    expect(peerRecord?.peer_id).toBe(p1.peer_id);
    expect(peerRecord?.peer_label).toBe("agent-a");
    expect(peerRecord?.shared).toBe(false);
    const uidPrincipal = `uid:${os.userInfo().uid}`;
    const firstRecord = bySession(unixFirst.session_id);
    expect(firstRecord?.principal).toBe(uidPrincipal);
    expect(firstRecord?.shared).toBe(false);
    const secondRecord = bySession(unixSecond.session_id);
    expect(secondRecord?.principal).toBe(uidPrincipal);
    expect(secondRecord?.shared).toBe(true);
  } finally {
    await stopPhase4Stack(stack);
  }
});
