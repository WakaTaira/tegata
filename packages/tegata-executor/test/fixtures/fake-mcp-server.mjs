// mcp-host の単体テスト用の偽サーバーである。stdin の各行をコマンドとして解釈する。
import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const mode = process.argv[2] ?? "serve";
const token = process.env.TOKEN ?? "";

if (mode === "early-exit") process.exit(2);
if (mode === "stubborn") process.on("SIGTERM", () => {});
if (mode === "exit-later") setTimeout(() => process.exit(4), 1_500);

function write(text) {
  process.stdout.write(text);
}

const commands = {
  echo: (rest) => write(`echo ${rest}\n`),
  leak: () => write(`${JSON.stringify({ value: token })}\n`),
  split: () => {
    write(`{"value":"${token.slice(0, 3)}`);
    setTimeout(() => write(`${token.slice(3)}"}\n`), 100);
  },
  big: () => write("a".repeat(16 * 1024 * 1024 + 1)),
  env: () =>
    write(
      `${JSON.stringify({
        keys: Object.keys(process.env).sort(),
        home: process.env.HOME,
        cwd: process.cwd(),
        path: process.env.PATH ?? null,
      })}\n`,
    ),
  pid: () => write(`${process.pid}\n`),
  "partial-exit": () =>
    process.stdout.write("partial-without-newline", () => process.exit(0)),
  exit: (rest) => process.exit(Number(rest)),
};

const input = createInterface({ input: process.stdin });
input.on("line", (line) => {
  if (process.env.LOG !== undefined)
    appendFileSync(process.env.LOG, `${line}\n`);
  const space = line.indexOf(" ");
  const name = space < 0 ? line : line.slice(0, space);
  const rest = space < 0 ? "" : line.slice(space + 1);
  commands[name]?.(rest);
});
if (mode === "stubborn") setInterval(() => {}, 1_000);
