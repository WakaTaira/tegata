import { randomBytes } from "node:crypto";
import type { AddressInfo, Server } from "node:net";

/** Generates the secret (128 bit, base64url) that identifies the user of a loopback listener. */
export function createLoopbackSecret(): string {
  return randomBytes(16).toString("base64url");
}

/** Listens on a free port of 127.0.0.1 and returns the assigned port. */
export function listenLoopback(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve((server.address() as AddressInfo).port);
    });
  });
}

/** Stops listening and resolves once all existing connections have closed. */
export function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}
