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
  // Given: lease s1 created by peer p1 through login(X), and another peer p2
  const stack = await startPhase4Stack({ tcp: true });
  try {
    const tcpPort = stack.daemon.tcpPort as number;
    const p1 = await issuePeer(stack.daemon.socketPath, "p1");
    const p2 = await issuePeer(stack.daemon.socketPath, "p2");
    const s1 = await peerLogin(stack, p1);
    const cdpPort = endpointPort(s1.channel.endpoint);

    // When: p2 calls logout(s1)
    const crossLogout = await tcpRpc(tcpPort, p2.token, "logout", {
      session_id: s1.session_id,
    });
    stack.observe("tcp:logout", crossLogout);

    // Then: the response is NOT_FOUND, the lease s1 remains, the tunnel of p1 works, and
    // the same tunnel from p2 is NOT_FOUND
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
  // Given: p1 issued with admin_peer_issue {label: "ci"}
  const stack = await startPhase4Stack({ tcp: true });
  try {
    const tcpPort = stack.daemon.tcpPort as number;
    const p1 = await issuePeer(stack.daemon.socketPath, "ci");

    // When: after revoking p1, send a preamble with the token of p1
    const revoke = await rawRpc(stack.daemon.socketPath, "admin_peer_revoke", {
      peer_id: p1.peer_id,
    });
    expect(revoke.error, JSON.stringify(revoke.error)).toBeUndefined();
    const refused = await tcpRpc(tcpPort, p1.token, "status", {}, 10_000);

    // Then: the response is UNAUTHORIZED, and revoked_at is set for p1 in admin_peer_list
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
  // Given: a daemon whose operator_uids does not include the test uid
  const nonOperator = await startPhase4Stack({ operator: false });
  try {
    // When: call admin_peer_issue from the UNIX socket
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

  // Given: peer p1 issued by an operator
  const operator = await startPhase4Stack({ tcp: true });
  try {
    const p1 = await issuePeer(operator.daemon.socketPath, "p1");

    // When: call admin_peer_issue from the TCP peer
    const viaPeer = await tcpRpc(
      operator.daemon.tcpPort as number,
      p1.token,
      "admin_peer_issue",
      { label: "y" },
      10_000,
    );

    // Then: ADMIN_REQUIRED (TCP is always non-admin)
    expect(viaPeer.preamble).toBeUndefined();
    expect(viaPeer.error?.message).toBe("ADMIN_REQUIRED");
  } finally {
    await stopPhase4Stack(operator);
  }
});

test("AC-65: audit login records carry principal, peer identity, and shared", async () => {
  // Given: a login by peer p1 (label agent-a), and two logins from the UNIX socket
  const stack = await startPhase4Stack({ tcp: true });
  try {
    const p1 = await issuePeer(stack.daemon.socketPath, "agent-a");
    const peerSession = await peerLogin(stack, p1);
    const unixFirst = await unixLogin(stack);
    const unixSecond = await unixLogin(stack);

    // When: read the audit log
    const { records } = readAuditRecords(stack.daemon.auditLogPath);
    const logins = records.filter(
      (r) => r.method === "login" && r.outcome === "ok",
    );
    const bySession = (id: string) => logins.find((r) => r.session_id === id);

    // Then: the lines of p1 have principal "peer:<peer_id>", peer_id, and peer_label,
    // and the UNIX lines have principal "uid:<n>", with shared: false for the first and
    // shared: true for the piggybacked one
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
