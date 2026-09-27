import { expect, test } from "vitest";

import {
  encodeFrame,
  MAX_INCOMING_MESSAGE_BYTES,
  parseClosePayload,
  WebSocketFrameParser,
  WebSocketProtocolError,
} from "../src/ws.ts";

test("WebSocket frames encode extended lengths and server masking rules", () => {
  const short = encodeFrame("x");
  expect(short.subarray(0, 2)).toEqual(Buffer.from([0x81, 0x01]));

  const medium = encodeFrame(Buffer.alloc(126, 1));
  expect(medium.subarray(0, 4)).toEqual(Buffer.from([0x81, 0x7e, 0x00, 0x7e]));

  const long = encodeFrame(Buffer.alloc(65_536, 2));
  expect(long.subarray(0, 10)).toEqual(
    Buffer.from([0x81, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]),
  );
  expect(long.length).toBe(65_546);
});

test("WebSocketFrameParser decodes masked and fragmented text frames", () => {
  const parser = new WebSocketFrameParser();
  const first = encodeFrame("hel", {
    fin: false,
    mask: true,
    maskKey: Buffer.from([1, 2, 3, 4]),
  });
  const second = encodeFrame("lo", {
    opcode: 0x0,
    mask: true,
    maskKey: Buffer.from([5, 6, 7, 8]),
  });

  expect(parser.push(first.subarray(0, 3))).toEqual([]);
  expect(parser.push(Buffer.concat([first.subarray(3), second]))).toEqual([
    { type: "text", text: "hello" },
  ]);
});

test("WebSocketFrameParser keeps control frames available between fragments", () => {
  const parser = new WebSocketFrameParser();
  const fragmented = encodeFrame("part", {
    fin: false,
    mask: true,
    maskKey: Buffer.from([9, 8, 7, 6]),
  });
  const ping = encodeFrame("ping", {
    opcode: 0x9,
    mask: true,
    maskKey: Buffer.from([4, 3, 2, 1]),
  });
  const final = encodeFrame("ial", {
    opcode: 0x0,
    mask: true,
    maskKey: Buffer.from([0, 1, 2, 3]),
  });

  expect(parser.push(Buffer.concat([fragmented, ping, final]))).toEqual([
    { type: "ping", payload: Buffer.from("ping") },
    { type: "text", text: "partial" },
  ]);
});

test("WebSocketFrameParser rejects oversized frames and fragmented messages", () => {
  const single = new WebSocketFrameParser(4);
  expectProtocolError(
    () => single.push(encodeFrame("12345", { mask: true })),
    1009,
  );

  const fragmented = new WebSocketFrameParser(4);
  const first = encodeFrame("123", {
    fin: false,
    mask: true,
    maskKey: Buffer.from([1, 2, 3, 4]),
  });
  const second = encodeFrame("45", {
    opcode: 0x0,
    mask: true,
    maskKey: Buffer.from([5, 6, 7, 8]),
  });
  expect(fragmented.push(first)).toEqual([]);
  expectProtocolError(() => fragmented.push(second), 1009);
  expect(MAX_INCOMING_MESSAGE_BYTES).toBe(16 * 1024 * 1024);
});

test("WebSocket close payloads reject invalid status codes and UTF-8", () => {
  expect(parseClosePayload(Buffer.alloc(0))).toEqual({
    code: 1000,
    reason: "",
  });
  expect(parseClosePayload(Buffer.from([0x03, 0xe8, 0x6f, 0x6b]))).toEqual({
    code: 1000,
    reason: "ok",
  });

  for (const payload of [
    Buffer.from([0x01]),
    Buffer.from([0x03, 0xed]),
    Buffer.from([0x03, 0xee]),
    Buffer.from([0x03, 0xf7]),
    Buffer.from([0x00, 0x01]),
    Buffer.from([0x13, 0x88]),
    Buffer.from([0x03, 0xe8, 0xff]),
  ]) {
    expectProtocolError(() => parseClosePayload(payload), 1002);
  }
});

function expectProtocolError(action: () => void, code: number): void {
  try {
    action();
    throw new Error("expected a WebSocket protocol error");
  } catch (error) {
    expect(error).toBeInstanceOf(WebSocketProtocolError);
    expect((error as WebSocketProtocolError).code).toBe(code);
  }
}
