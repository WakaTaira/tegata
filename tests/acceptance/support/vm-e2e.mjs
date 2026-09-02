// Full agent-side E2E for the NixOS VM boundary test (AC-18): catalog →
// login → raw-CDP DOM check, recording everything the agent observed.
// Also probes the file:// navigation guard and the download write path
// (AC-52a/AC-52b) over a second CDP connection to the same session.
// Owned by the acceptance suite (gauntlet); do not modify during
// implementation.
//
// Deliberately dependency-free (node builtins + global WebSocket only): the
// login channel must be a plain browser-level CDP endpoint usable without
// Playwright, and this script is the proof.
//
// Usage: node vm-e2e.mjs --socket <path> --target-url <url>
//                        --cred-name <name> --out <observations.json>
// Exit 0 only when the handed-off session shows the logged-in marker.
import fs from "node:fs";
import net from "node:net";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) {
    console.error(`missing --${name}`);
    process.exit(64);
  }
  return process.argv[i + 1];
}

const socketPath = arg("socket");
const targetUrl = arg("target-url");
const credName = arg("cred-name");
const outPath = arg("out");

function rpc(method, params) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(socketPath);
    let buffer = "";
    sock.on("error", reject);
    sock.on("connect", () =>
      sock.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })}\n`,
      ),
    );
    sock.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      const nl = buffer.indexOf("\n");
      if (nl === -1) return;
      sock.destroy();
      const response = JSON.parse(buffer.slice(0, nl));
      if (response.result === undefined)
        reject(
          new Error(`rpc ${method} failed: ${JSON.stringify(response.error)}`),
        );
      else resolve(response.result);
    });
  });
}

/**
 * Open a raw CDP websocket connection and return its send()/close() helpers.
 * Factored out of inspectSession() so AC-52's separate probe connection can
 * share the same request/response plumbing.
 */
function connectCdp(endpoint) {
  const ws = new WebSocket(endpoint);
  const opened = new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error("CDP websocket failed to open"));
  });
  let nextId = 1;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  };
  const send = (method, params, sessionId) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, (msg) =>
        msg.error
          ? reject(new Error(`${method}: ${msg.error.message}`))
          : resolve(msg.result),
      );
      ws.send(JSON.stringify({ id, method, params, sessionId }));
    });
  return { ws, opened, send };
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * AC-52a/AC-52b: opens a second, independent CDP connection to the same
 * browser-level endpoint the agent used to log in, and probes the file://
 * navigation guard and the download write path. Failures are recorded into
 * the returned observation rather than thrown, since ahead of the fix this
 * probe is expected to succeed at reading/writing state (red).
 */
async function probeFileGuard(endpoint) {
  const { ws, opened, send } = connectCdp(endpoint);
  await opened;
  const observation = { fileNavigate: {}, download: {} };
  try {
    const { browserContextId } = await send("Target.createBrowserContext", {});
    const { targetId } = await send("Target.createTarget", {
      url: "about:blank",
      browserContextId,
    });
    const { sessionId } = await send("Target.attachToTarget", {
      targetId,
      flatten: true,
    });
    await send("Page.enable", {}, sessionId);

    const navigate = await send(
      "Page.navigate",
      { url: "file:///var/lib/tegata/config.toml" },
      sessionId,
    );
    observation.fileNavigate.errorText = navigate.errorText ?? null;
    await wait(1500);
    const innerText = await send(
      "Runtime.evaluate",
      {
        expression: "document.body ? document.body.innerText : ''",
        returnByValue: true,
      },
      sessionId,
    );
    observation.fileNavigate.innerText = innerText.result.value;

    try {
      // Browser-level command: no sessionId.
      await send("Browser.setDownloadBehavior", {
        behavior: "allow",
        downloadPath: "/var/lib/tegata",
      });
    } catch (err) {
      observation.download.error = err.message;
    }

    // file:// left the page without a body in some Chromium builds; return
    // to about:blank and confirm document.body exists before clicking.
    await send("Page.navigate", { url: "about:blank" }, sessionId);
    for (let attempt = 0; attempt < 10; attempt++) {
      const bodyReady = await send(
        "Runtime.evaluate",
        { expression: "document.body !== null", returnByValue: true },
        sessionId,
      );
      if (bodyReady.result.value) break;
      await wait(100);
    }
    await send(
      "Runtime.evaluate",
      {
        expression:
          "const a = document.createElement('a'); a.download = 'ac52-write.txt'; a.href = 'data:text/plain,ac52'; document.body.appendChild(a); a.click();",
      },
      sessionId,
    );
    await wait(2000);
  } finally {
    ws.close();
  }
  return observation;
}

/** Attach to the fixture page over raw CDP and evaluate two expressions. */
async function inspectSession(endpoint) {
  const { ws, opened, send } = connectCdp(endpoint);
  await opened;

  const { targetInfos } = await send("Target.getTargets", {});
  const page = targetInfos.find(
    (t) => t.type === "page" && t.url.startsWith(targetUrl),
  );
  if (!page) throw new Error("no page target on the fixture origin");
  const { sessionId } = await send("Target.attachToTarget", {
    targetId: page.targetId,
    flatten: true,
  });
  const evaluate = async (expression) =>
    (
      await send(
        "Runtime.evaluate",
        { expression, returnByValue: true },
        sessionId,
      )
    ).result.value;

  const hasWelcome = await evaluate(
    "document.querySelector('#welcome') !== null",
  );
  const dom = await evaluate("document.documentElement.outerHTML");
  ws.close();
  return { hasWelcome, dom };
}

const observations = {};
const list = await rpc("list_credentials", {});
observations.list_credentials = list;
const cred = list.find((c) => c.name === credName);
if (!cred) {
  console.error(`credential named ${credName} not found in catalog`);
  process.exit(3);
}

const login = await rpc("login", {
  cred_id: cred.id,
  target_url: targetUrl,
  steps: [
    { action: "fill", selector: "#username", value: "{{username}}" },
    { action: "fill", selector: "#password", value: "{{password}}" },
    { action: "click", selector: "#submit" },
  ],
  success_selector: "#welcome",
  failure_selector: "#login-error",
});
observations.login = login;

const session = await inspectSession(login.channel.endpoint);
observations.dom = session.dom;
observations.hasWelcome = session.hasWelcome;

// AC-52a/AC-52b: probe the file:// guard and the download write path over a
// second connection to the same browser endpoint, while the session is
// still alive.
const guardProbe = await probeFileGuard(login.channel.endpoint);
observations.fileNavigate = guardProbe.fileNavigate;
observations.download = guardProbe.download;

fs.writeFileSync(outPath, JSON.stringify(observations, null, 2));
process.exit(session.hasWelcome ? 0 : 2);
