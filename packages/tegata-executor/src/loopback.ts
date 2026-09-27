import { randomBytes } from "node:crypto";
import type { AddressInfo, Server } from "node:net";

/** loopback リスナーの利用者を識別する secret（128 bit、base64url）を生成する。 */
export function createLoopbackSecret(): string {
  return randomBytes(16).toString("base64url");
}

/** 127.0.0.1 の空きポートで待ち受け、割り当てられたポートを返す。 */
export function listenLoopback(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve((server.address() as AddressInfo).port);
    });
  });
}

/** 待ち受けを止め、既存の接続がすべて閉じた時点で解決する。 */
export function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}
