import { expect, test } from "vitest";

import {
  shouldForwardTargetEvent,
  shouldForwardUpstreamResponse,
  type TargetInfo,
} from "../src/shim.ts";

test("only forwards target events for the tegata context", () => {
  const targetInfos = new Map<string, TargetInfo>([
    ["known-target", { targetId: "known-target", browserContextId: "ctx" }],
  ]);
  const shimTargets = new Set(["shim-target"]);
  const attachedSessions = new Set(["attached-session"]);

  expect(
    shouldForwardTargetEvent(
      {
        method: "Target.targetCreated",
        params: {
          targetInfo: {
            targetId: "other-target",
            browserContextId: "other-context",
          },
        },
      },
      "ctx",
      "login-target",
      shimTargets,
      targetInfos,
      attachedSessions,
    ),
  ).toBe(false);
  expect(
    shouldForwardTargetEvent(
      {
        method: "Target.targetCrashed",
        params: { targetId: "other-target" },
      },
      "ctx",
      "login-target",
      shimTargets,
      targetInfos,
      attachedSessions,
    ),
  ).toBe(false);
  expect(
    shouldForwardTargetEvent(
      {
        method: "Target.targetCrashed",
        params: { targetId: "shim-target" },
      },
      "ctx",
      "login-target",
      shimTargets,
      targetInfos,
      attachedSessions,
    ),
  ).toBe(true);
  expect(
    shouldForwardTargetEvent(
      {
        method: "Target.attachedToTarget",
        params: { sessionId: "unknown-session" },
      },
      "ctx",
      "login-target",
      shimTargets,
      targetInfos,
      attachedSessions,
    ),
  ).toBe(false);
  expect(
    shouldForwardTargetEvent(
      {
        method: "Target.detachedFromTarget",
        params: { sessionId: "attached-session" },
      },
      "ctx",
      "login-target",
      shimTargets,
      targetInfos,
      attachedSessions,
    ),
  ).toBe(true);
  expect(
    shouldForwardTargetEvent(
      { method: "Target.receivedMessageFromTarget", params: {} },
      "ctx",
      "login-target",
      shimTargets,
      targetInfos,
      attachedSessions,
    ),
  ).toBe(false);
});

test("drops upstream responses whose proxy request is no longer pending", () => {
  const pending = new Map<number, unknown>([[7, {}]]);
  expect(shouldForwardUpstreamResponse({ id: 7 }, pending)).toBe(true);
  expect(shouldForwardUpstreamResponse({ id: 8 }, pending)).toBe(false);
  expect(shouldForwardUpstreamResponse({ id: "7" }, pending)).toBe(false);
  expect(
    shouldForwardUpstreamResponse({ method: "Target.targetCreated" }, pending),
  ).toBe(true);
});
