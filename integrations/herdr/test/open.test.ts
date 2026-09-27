import { expect, test } from "vitest";

import { isValidTargetId, parseArgs } from "../src/open.ts";

test("rejects target IDs that could escape the state directory", () => {
  expect(isValidTargetId("../escape")).toBe(false);
  expect(isValidTargetId("valid_target-17")).toBe(true);
  expect(isValidTargetId("a".repeat(129))).toBe(false);
  expect(() =>
    parseArgs([
      "--endpoint",
      "ws://127.0.0.1:1/devtools/browser/test",
      "--target-id",
      "../escape",
      "--url",
      "about:blank",
    ]),
  ).toThrow(
    "--target-id must contain 1-128 ASCII letters, digits, underscores, or hyphens",
  );
});
