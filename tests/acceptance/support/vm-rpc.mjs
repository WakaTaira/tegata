// Minimal JSON-RPC-over-UDS client for the NixOS VM boundary tests.
// Owned by the acceptance suite (gauntlet); do not modify during
// implementation.
//
// Usage: node vm-rpc.mjs --socket <path> --method <name> [--params <json>]
// Exit 0 only when the daemon returns a JSON-RPC *result*. A refused or
// closed connection, or an error response, exits non-zero — this is what
// AC-17 relies on.
import net from "node:net";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) {
    if (fallback !== undefined) return fallback;
    console.error(`missing --${name}`);
    process.exit(64);
  }
  return process.argv[i + 1];
}

const socketPath = arg("socket");
const method = arg("method");
const params = JSON.parse(arg("params", "{}"));

const sock = net.connect(socketPath);
let buffer = "";
const bail = (msg) => {
  console.error(msg);
  process.exit(1);
};

sock.on("error", (err) => bail(`connect/write failed: ${err.code ?? err.message}`));
sock.on("connect", () => {
  sock.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })}\n`);
});
sock.on("data", (chunk) => {
  buffer += chunk.toString("utf8");
  const nl = buffer.indexOf("\n");
  if (nl === -1) return;
  const response = JSON.parse(buffer.slice(0, nl));
  console.log(JSON.stringify(response));
  sock.destroy();
  process.exit(response.result !== undefined ? 0 : 1);
});
sock.on("close", () => bail("connection closed without a response"));
