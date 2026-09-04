// TCP probe run inside a container: connect to <host>:<port>, optionally
// send one line, and report what happened as one JSON line on stdout.
//   node tcp-probe.mjs <host> <port> [line] [timeoutMs]
// Report: {connected, error, lines, closed, ms}. `ms` runs from the connect
// attempt to the close (or to the timeout, whichever comes first); `lines`
// are the newline-delimited replies received before that.
import net from "node:net";

const [host, port, line, timeoutArg] = process.argv.slice(2);
const timeoutMs = Number(timeoutArg === undefined ? 15_000 : timeoutArg);
const started = Date.now();
const report = {
  connected: false,
  error: null,
  lines: [],
  closed: false,
  ms: 0,
};
let buffered = "";
let finished = false;

const socket = net.connect(Number(port), host);

const finish = () => {
  if (finished) return;
  finished = true;
  report.ms = Date.now() - started;
  process.stdout.write(`${JSON.stringify(report)}\n`);
  socket.destroy();
  process.exit(0);
};

setTimeout(() => {
  if (report.error === null) report.error = "timeout";
  finish();
}, timeoutMs);

socket.on("connect", () => {
  report.connected = true;
  if (line !== undefined && line !== "") socket.write(`${line}\n`);
});
socket.on("data", (chunk) => {
  buffered += chunk.toString("utf8");
  let index = buffered.indexOf("\n");
  while (index >= 0) {
    report.lines.push(buffered.slice(0, index));
    buffered = buffered.slice(index + 1);
    index = buffered.indexOf("\n");
  }
});
socket.on("error", (error) => {
  report.error = error.code ?? String(error);
});
socket.on("close", () => {
  report.closed = true;
  finish();
});
