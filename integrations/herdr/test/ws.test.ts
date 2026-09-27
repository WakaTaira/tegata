import { expect, test } from "vitest";

import { encodeFrame, WebSocketFrameParser } from "../src/ws.ts";

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
