import { createHash, randomBytes } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Socket } from "node:net";

const WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export type WebSocketFrameOptions = {
  opcode?: number;
  fin?: boolean;
  mask?: boolean;
  maskKey?: Uint8Array;
};

export type WebSocketParsedEvent =
  | { type: "text"; text: string }
  | { type: "ping"; payload: Buffer }
  | { type: "pong"; payload: Buffer }
  | { type: "close"; payload: Buffer };

export class WebSocketProtocolError extends Error {
  readonly code: number;

  constructor(code: number, message: string) {
    super(message);
    this.name = "WebSocketProtocolError";
    this.code = code;
  }
}

export function encodeFrame(
  payload: string | Uint8Array,
  options: WebSocketFrameOptions = {},
): Buffer {
  const body =
    typeof payload === "string"
      ? Buffer.from(payload, "utf8")
      : Buffer.from(payload);
  const opcode = options.opcode ?? 0x1;
  const fin = options.fin ?? true;
  const mask = options.mask ?? false;
  const maskKey = mask ? Buffer.from(options.maskKey ?? randomBytes(4)) : null;

  if (maskKey && maskKey.length !== 4) {
    throw new RangeError("a WebSocket mask key must contain four bytes");
  }
  if (body.length > Number.MAX_SAFE_INTEGER) {
    throw new RangeError("a WebSocket frame is too large");
  }

  const extendedLength = body.length < 126 ? 0 : body.length <= 0xffff ? 2 : 8;
  const headerLength = 2 + extendedLength + (maskKey ? 4 : 0);
  const frame = Buffer.alloc(headerLength + body.length);
  frame[0] = (fin ? 0x80 : 0) | (opcode & 0x0f);
  frame[1] =
    (mask ? 0x80 : 0) |
    (extendedLength === 0 ? body.length : extendedLength === 2 ? 126 : 127);

  let offset = 2;
  if (extendedLength === 2) {
    frame.writeUInt16BE(body.length, offset);
    offset += 2;
  } else if (extendedLength === 8) {
    frame.writeBigUInt64BE(BigInt(body.length), offset);
    offset += 8;
  }

  if (maskKey) {
    maskKey.copy(frame, offset);
    offset += 4;
    for (let index = 0; index < body.length; index += 1) {
      frame[offset + index] = body[index] ^ maskKey[index % 4];
    }
  } else {
    body.copy(frame, offset);
  }

  return frame;
}

export class WebSocketFrameParser {
  private buffer = Buffer.alloc(0);
  private fragments: Buffer[] | null = null;

  push(chunk: Uint8Array): WebSocketParsedEvent[] {
    if (chunk.length > 0) {
      this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
    }

    const events: WebSocketParsedEvent[] = [];
    while (true) {
      const frame = this.readFrame();
      if (!frame) {
        break;
      }
      this.consumeFrame(frame, events);
    }
    return events;
  }

  private readFrame(): {
    fin: boolean;
    opcode: number;
    payload: Buffer;
  } | null {
    if (this.buffer.length < 2) {
      return null;
    }

    const first = this.buffer[0];
    const second = this.buffer[1];
    if ((first & 0x70) !== 0) {
      throw new WebSocketProtocolError(1002, "reserved WebSocket bits are set");
    }

    const fin = (first & 0x80) !== 0;
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    const lengthCode = second & 0x7f;
    if (!masked) {
      throw new WebSocketProtocolError(
        1002,
        "client WebSocket frames must be masked",
      );
    }
    if (![0x0, 0x1, 0x8, 0x9, 0xa].includes(opcode)) {
      throw new WebSocketProtocolError(1002, "unsupported WebSocket opcode");
    }

    let length = lengthCode;
    let extendedLength = 0;
    if (lengthCode === 126) {
      extendedLength = 2;
      if (this.buffer.length < 4) {
        return null;
      }
      length = this.buffer.readUInt16BE(2);
    } else if (lengthCode === 127) {
      extendedLength = 8;
      if (this.buffer.length < 10) {
        return null;
      }
      const wideLength = this.buffer.readBigUInt64BE(2);
      if (wideLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new WebSocketProtocolError(1009, "WebSocket frame is too large");
      }
      length = Number(wideLength);
    }

    const isControl = opcode >= 0x8;
    if (isControl && (!fin || length > 125)) {
      throw new WebSocketProtocolError(1002, "invalid WebSocket control frame");
    }

    const maskOffset = 2 + extendedLength;
    const payloadOffset = maskOffset + 4;
    const frameLength = payloadOffset + length;
    if (this.buffer.length < frameLength) {
      return null;
    }

    const maskKey = this.buffer.subarray(maskOffset, payloadOffset);
    const payload = Buffer.alloc(length);
    for (let index = 0; index < length; index += 1) {
      payload[index] = this.buffer[payloadOffset + index] ^ maskKey[index % 4];
    }
    this.buffer = this.buffer.subarray(frameLength);
    return { fin, opcode, payload };
  }

  private consumeFrame(
    frame: { fin: boolean; opcode: number; payload: Buffer },
    events: WebSocketParsedEvent[],
  ): void {
    if (frame.opcode === 0x8) {
      events.push({ type: "close", payload: frame.payload });
      return;
    }
    if (frame.opcode === 0x9) {
      events.push({ type: "ping", payload: frame.payload });
      return;
    }
    if (frame.opcode === 0xa) {
      events.push({ type: "pong", payload: frame.payload });
      return;
    }

    if (frame.opcode === 0x1) {
      if (this.fragments) {
        throw new WebSocketProtocolError(
          1002,
          "a fragmented WebSocket message is already active",
        );
      }
      if (frame.fin) {
        events.push({ type: "text", text: decodeText(frame.payload) });
      } else {
        this.fragments = [frame.payload];
      }
      return;
    }

    if (!this.fragments || frame.opcode !== 0x0) {
      throw new WebSocketProtocolError(
        1002,
        "invalid WebSocket continuation frame",
      );
    }
    this.fragments.push(frame.payload);
    if (frame.fin) {
      events.push({
        type: "text",
        text: decodeText(Buffer.concat(this.fragments)),
      });
      this.fragments = null;
    }
  }
}

function decodeText(payload: Buffer): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(payload);
  } catch {
    throw new WebSocketProtocolError(
      1007,
      "invalid UTF-8 in WebSocket text message",
    );
  }
}

export type ServerWebSocketState = "open" | "closing" | "closed";

export class ServerWebSocket {
  private readonly socket: Socket;
  private readonly parser = new WebSocketFrameParser();
  private state: ServerWebSocketState = "open";
  private closeNotified = false;
  private readonly messageHandlers: Array<(text: string) => void> = [];
  private readonly closeHandlers: Array<
    (code: number | null, reason: string) => void
  > = [];
  private readonly errorHandlers: Array<(error: Error) => void> = [];

  constructor(socket: Socket, head: Buffer) {
    this.socket = socket;
    socket.on("data", (chunk: Buffer) => this.receive(chunk));
    socket.on("error", (error: Error) => this.fail(error));
    socket.on("close", () => this.finishClose(null, ""));
    if (head.length > 0) {
      this.receive(head);
    }
  }

  get readyState(): ServerWebSocketState {
    return this.state;
  }

  onMessage(handler: (text: string) => void): void {
    this.messageHandlers.push(handler);
  }

  onClose(handler: (code: number | null, reason: string) => void): void {
    this.closeHandlers.push(handler);
  }

  onError(handler: (error: Error) => void): void {
    this.errorHandlers.push(handler);
  }

  sendText(text: string): void {
    if (this.state !== "open") {
      return;
    }
    this.socket.write(encodeFrame(text));
  }

  close(code = 1000, reason = ""): void {
    if (this.state === "closed") {
      return;
    }
    if (this.state === "closing") {
      this.socket.end();
      return;
    }

    const payload = encodeClosePayload(code, reason);
    this.state = "closing";
    this.socket.write(encodeFrame(payload, { opcode: 0x8 }), () =>
      this.socket.end(),
    );
  }

  terminate(): void {
    if (this.state !== "closed") {
      this.state = "closed";
      this.socket.destroy();
      this.finishClose(null, "");
    }
  }

  private receive(chunk: Buffer): void {
    if (this.state === "closed") {
      return;
    }
    try {
      for (const event of this.parser.push(chunk)) {
        if (event.type === "text") {
          for (const handler of this.messageHandlers) {
            handler(event.text);
          }
        } else if (event.type === "ping") {
          if (this.state === "open") {
            this.socket.write(encodeFrame(event.payload, { opcode: 0xa }));
          }
        } else if (event.type === "close") {
          this.respondToClose(event.payload);
        }
      }
    } catch (error) {
      const protocolError =
        error instanceof WebSocketProtocolError
          ? error
          : new WebSocketProtocolError(1002, "invalid WebSocket frame");
      this.reportError(protocolError);
      this.close(protocolError.code, protocolError.message);
    }
  }

  private respondToClose(payload: Buffer): void {
    if (this.state === "closed") {
      return;
    }
    if (this.state === "open") {
      this.state = "closing";
      this.socket.write(encodeFrame(payload, { opcode: 0x8 }), () =>
        this.socket.end(),
      );
    } else {
      this.socket.end();
    }
  }

  private fail(error: Error): void {
    this.reportError(error);
    this.finishClose(null, "");
  }

  private reportError(error: Error): void {
    for (const handler of this.errorHandlers) {
      handler(error);
    }
  }

  private finishClose(code: number | null, reason: string): void {
    if (this.closeNotified) {
      return;
    }
    this.closeNotified = true;
    this.state = "closed";
    for (const handler of this.closeHandlers) {
      handler(code, reason);
    }
  }
}

export function acceptWebSocketUpgrade(
  request: IncomingMessage,
  socket: Socket,
  head: Buffer,
): ServerWebSocket | null {
  const key = headerValue(request.headers["sec-websocket-key"]);
  const upgrade = headerValue(request.headers.upgrade);
  if (
    request.method !== "GET" ||
    upgrade?.toLowerCase() !== "websocket" ||
    !key
  ) {
    socket.destroy();
    return null;
  }

  const accept = createHash("sha1")
    .update(`${key}${WEBSOCKET_GUID}`)
    .digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\n` +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n` +
      "\r\n",
  );
  return new ServerWebSocket(socket, head);
}

export class WebSocketServer {
  private readonly onConnection: (connection: ServerWebSocket) => void;
  private readonly connections = new Set<ServerWebSocket>();

  constructor(onConnection: (connection: ServerWebSocket) => void) {
    this.onConnection = onConnection;
  }

  handleUpgrade(
    request: IncomingMessage,
    socket: Socket,
    head: Buffer,
  ): ServerWebSocket | null {
    const connection = acceptWebSocketUpgrade(request, socket, head);
    if (!connection) {
      return null;
    }
    this.connections.add(connection);
    connection.onClose(() => this.connections.delete(connection));
    try {
      this.onConnection(connection);
    } catch (error) {
      connection.terminate();
      throw error;
    }
    return connection;
  }

  close(code = 1001, reason = "server shutting down"): void {
    for (const connection of this.connections) {
      connection.close(code, reason);
    }
  }
}

function headerValue(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }
  return value ?? null;
}

function encodeClosePayload(code: number, reason: string): Buffer {
  const reasonBytes = Buffer.from(reason, "utf8");
  if (reasonBytes.length > 123) {
    throw new RangeError("a WebSocket close reason is too long");
  }
  const payload = Buffer.alloc(2 + reasonBytes.length);
  payload.writeUInt16BE(code, 0);
  reasonBytes.copy(payload, 2);
  return payload;
}
