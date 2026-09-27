# tegata Herdr integration

This integration displays a tegata login session in Herdr's `official.browser`
pane. Herdr starts a browser executable and connects to its browser-level CDP
endpoint. `tegata-herdr-chrome` is a small executable shim that presents the
same CDP shape while forwarding the permitted operations to the endpoint
returned by `login`.

The integration is experimental and depends on the internal behavior of the
`official.browser` plugin. A plugin update can change its startup arguments,
CDP methods, or lifecycle and can therefore break this integration.

## Prerequisites

- A Linux-local Herdr installation with the `official.browser` plugin from
  `ogulcancelik/herdr-browser`.
- Herdr configured with `[experimental] kitty_graphics = true`.
- A Kitty graphics-capable terminal, Bun, and Node.js 24 or newer.
- A live tegata `login` result. Bridge and remote-browser connections are not
  supported.

The shim uses Node's built-in WebSocket implementation and Node's type
stripping for the TypeScript sources. No npm dependency is required.

## Usage

Pass the `channel.endpoint` and `target_id` from the `login` result to the
launcher:

```sh
integrations/herdr/bin/tegata-herdr-open \
  --endpoint 'ws://127.0.0.1:41263/devtools/browser/example' \
  --target-id 'login-target-id'
```

Use `--url URL` to choose the initial pane URL. Without it, the launcher reads
the current URL from the login target. The pane placement defaults to `split`;
`--placement tab|zoomed|overlay` and `--direction right|down` select other
layouts.

The launcher creates a private state path at
`${XDG_RUNTIME_DIR:-/tmp}/tegata-herdr/<target_id>.json` and starts a dedicated
Herdr browser daemon with the shim as its browser executable.

Closing the pane closes only the shim connection and any tabs created by the
pane. It does not close the tegata browser or the login tab. When tegata logs
out or the session reaches its TTL, the upstream CDP connection closes and the
pane ends with a `session ended` close reason.

## Security and operational risks

The shim forwards only the CDP methods required by the browser pane. It forces
new targets into the login browser context, rejects closing the login target,
rejects browser-wide close and context-disposal operations, and filters events
from other browser contexts.

The pane drives the same logged-in browser as the agent, so it has the same
reach: session cookies and storage are readable through CDP, as described in
[docs/security.md](../../docs/security.md). The shim narrows what the pane can
do; it is not a boundary around the session.

The endpoint is supplied to the Herdr daemon through environment variables.
Another process with the same Unix uid can read those variables through
`/proc`, just as it can for the agent process; this integration does not add a
new exposure beyond that existing uid-level access. Do not pass a live endpoint
to an untrusted user or process.
