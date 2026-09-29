# MCP tool contract

This is the complete surface tegata exposes to an agent. Nine tools, no generic
escape hatch. Anything not listed here does not cross the boundary.

## Connecting

The broker is an MCP server speaking stdio, published as a flake package. It is
started with the path to the daemon socket in the environment:

```sh
TEGATA_SOCKET=/run/tegata/tegatad.sock nix run github:WakaTaira/tegata#tegata-mcp
```

Registered with an MCP client, that looks like:

```json
{
  "mcpServers": {
    "tegata": {
      "command": "nix",
      "args": ["run", "github:WakaTaira/tegata#tegata-mcp"],
      "env": { "TEGATA_SOCKET": "/run/tegata/tegatad.sock" }
    }
  }
}
```

Without Nix, build the broker from a checkout — `npm ci && npm run build
--workspace @tegata/mcp` — and use `node packages/tegata-mcp/dist/index.js` as
the command instead. Both shapes, and the Claude Code registration, are in
[setup-linux.md](setup-linux.md#connecting-an-agent).

When the daemon is a Windows service and the agent is inside WSL, add
`TEGATA_BRIDGE=1` and point `TEGATA_SOCKET` at the bridge's socket instead. See
[setup-windows-wsl.md](setup-windows-wsl.md) and
[the bridge section](#the-bridge-and-cdp-endpoints) below.

The broker itself holds no secrets. It runs as the agent's own user, forwards each
call across the boundary, and returns what comes back.

## Result and error shape

Every tool returns its result as JSON in a single text content block. On failure,
the response has `isError: true` and the text is a bare classification code:

```
INVALID_CREDENTIAL
```

That is the whole text message. It contains no stack trace and no echo of the
input — see [security.md](security.md#how-secrets-move-on-the-isolated-side)
for why. A code the broker does not recognise is passed through when it matches
the public code format; arbitrary daemon text is normalised to `INTERNAL`.

### Classification codes

| Code | Meaning |
| --- | --- |
| `INVALID_CREDENTIAL` | The credential does not exist, or the site rejected the login |
| `MFA_REQUIRED` | The login needs a TOTP code and the credential has no seed |
| `SELECTOR_NOT_FOUND` | A login step's selector did not resolve within the step timeout |
| `FILL_MISMATCH` | A secret fill was refused or rolled back: `{{password}}` targeted a non-password input, or the page changed another field / the value did not stick; explicit steps include `step` |
| `LOGIN_RESULT_TIMEOUT` | All login steps ran, but the executor could not tell within the wait window whether the login worked; no browser is handed back. Also returned by `authorize_device` when its login stage cannot be judged. |
| `OAUTH_GRANT_FAILED` | The OAuth device-code grant behind an `open_api_proxy` failed: the device authorization or token endpoint refused, the grant was denied or expired, or polling ran out of time. |
| `DEVICE_CODE_REJECTED` | The device authorization page rejected the user code |
| `VAULT_LOCKED` | The provider holding this credential is locked |
| `RATE_LIMITED` | A second `get_totp` for the same credential within 30 seconds |
| `TOTP_NOT_EXPOSABLE` | The credential is not marked `totp_exposable`, or has no seed |
| `APPROVAL_DENIED` | A configured approval hook refused this login |
| `APPROVAL_TIMEOUT` | The approval hook did not answer within its timeout |
| `PROVIDER_UNAVAILABLE` | A transient failure of the credential provider (for example the Bitwarden CLI failing or timing out right after a daemon restart); the call may be retried. Returned by `list_credentials`, `login`, `get_totp`, and `lock_vault` when they call a provider |
| `NOT_FOUND` | The session does not exist or belongs to another principal; its existence is not disclosed. Also returned by `login_step` for an unknown, expired, or foreign `login_id` |
| `SNAPSHOT_REJECTED` | A `login_begin` or `login_step` snapshot would have echoed a secret it just filled; the stepwise login ended and its browser was discarded |
| `INTERNAL` | Anything else, including a refused response that failed the leak scan |

For an explicit `steps` array, `structuredContent.step` is the zero-based index
of the step whose selector failed. Automatic mode and selector failures outside
an explicit `steps` array omit this field.

`INVALID_CREDENTIAL` covers both "no such credential" and "the site said no" on
purpose: distinguishing them would tell an agent which identifiers are real.

Three further codes come from the transport level rather than from a tool:
`UNAUTHORIZED` (bad or missing token, or a SID not on the allowlist) and
`FORBIDDEN` (a tunnel request for a port that is not the named session's CDP
port) and `NOT_FOUND` (a CDP tunnel preamble whose session does not exist or does
not belong to the calling principal; the session's existence is not disclosed).
They normally stop at the broker's connection or the bridge's tunnel request;
when one does reach a tool call, the broker returns it as is rather than as
`INTERNAL`. The administrative RPCs add `ADMIN_REQUIRED` and
`ADMIN_SEAL_UNAVAILABLE`.

---

## `list_credentials`

Returns the catalog. Metadata only — there is no code path from a credential value
to this result.

**Input**

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `namespace` | string | no | Restrict to one provider namespace |

**Output** — an array of entries:

```json
[
  {
    "id": "vw:a1b2c3d4",
    "name": "Example Service",
    "uri": "https://example.com/login",
    "kind": "login",
    "source": "vw",
    "status": "unlocked"
  },
  {
    "id": "pw:9f8e7d6c",
    "name": "Staging Account",
    "source": "pw",
    "status": "locked"
  }
]
```

| Field | Meaning |
| --- | --- |
| `id` | The reference to pass to `login` and `get_totp` |
| `name` | Display name from the backend |
| `uri` | The entry's login URL. Omitted while locked |
| `kind` | Entry type, `login` for form credentials. Omitted while locked |
| `source` | The provider namespace this entry came from |
| `status` | `unlocked` or `locked` |

**Identifiers are namespaced.** An `id` is `<namespace>:<backend id>`. The
namespace is assigned when the provider is registered in the daemon's
configuration, so two vaults can both contain an entry called "GitHub" without
colliding, and the `source` field tells the agent which one it is looking at.

**Locked providers still appear.** A locked provider contributes its entries by
name with `status: "locked"` and without `uri` or `kind`. Locking one namespace
does not blank the catalog of the others; each provider has its own lock state and
its own TTL.

## `login`

Resolves the credential behind the boundary, performs the form login there, and
returns a connection to the resulting browser.

**Input**

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `cred_id` | string | yes | An `id` from `list_credentials` |
| `target_url` | string | yes | The login page to open |
| `steps` | array | no | Explicit login steps; omitted means auto-detect |
| `success_selector` | string | no | A selector that appears only when login succeeded |
| `failure_selector` | string | no | A selector that appears only when login failed |
| `exclusive` | boolean | no | Defaults to `false`; `true` creates a dedicated browser that other calls cannot share |

**Output**

```json
{
  "session_id": "3f2b1c9e-...",
  "channel": { "kind": "cdp", "endpoint": "ws://127.0.0.1:41263/devtools/browser/..." },
  "target_id": "page-target-id"
}
```

Connect a Playwright client to that raw endpoint with `chromium.connectOverCDP` and
drive the authenticated browser directly. CDP exposes the browser's post-login
session state, including HttpOnly cookies through `Network.getAllCookies`; the RPC
response leak scan does not inspect CDP traffic. Keep the `session_id`; it is what
`logout` takes. `target_id` is the CDP target id of the lease's tab and is advisory.

When a live, non-exclusive browser exists for the same principal (the UNIX socket
uid, named token, or Windows SID), namespace, and `cred_id`, `login` issues a new
lease with a new `session_id` and returns the same endpoint. `logout` returns only
the caller's lease; the browser closes when its last lease ends. TTL is fixed per
lease at issuance and a fresh `login` is required to extend it. A shared browser
also has an absolute lifetime controlled by `browser_max_lifetime_secs` (3600
seconds by default); each lease ends at the earlier of its TTL and that deadline,
and sharing never extends the browser deadline. At the deadline all leases are
audited as `session_expired`, the browser closes, and a later `login` starts a new
browser. `lock_vault` keeps its existing behavior and drops all browsers and leases
in the namespace.

### Steps and the placeholder contract

A step is a `fill`, `click`, or `wait_for`:

```json
{
  "steps": [
    { "action": "fill",  "selector": "#username", "value": "{{username}}" },
    { "action": "click", "selector": "#next" },
    { "action": "wait_for", "selector": "#password" },
    { "action": "fill",  "selector": "#password", "value": "{{password}}" },
    { "action": "click", "selector": "button[type=submit]" }
  ]
}
```

A `fill` step's `value` must be exactly one of `{{username}}`, `{{password}}`, or
`{{totp}}`. No other value is accepted — not a literal, not a partial string. The
schema rejects anything else before the call leaves the agent's machine, and the
executor rejects it again on the far side. The `{{password}}` placeholder may
only target `input[type=password]`; a mismatch returns `FILL_MISMATCH` without
filling the element.

Every fill, including automatic fills and `{{user_code}}`, waits for its element
to be visible and sets its value directly through the element's native setter,
then dispatches `input` and `change` events and verifies the result. It does not
focus the element or send keystrokes, so a page that moves focus cannot redirect
a secret into another field. Sites that rely on keystroke events may need a click
or another step afterwards if they validate on key events.

`wait_for` has no `value` and waits for its selector to become visible. It uses
the same 10-second per-step timeout as selector resolution and returns
`SELECTOR_NOT_FOUND` on timeout. It is available in `login`, `authorize_device`,
and OAuth-proxy device steps.

This is what makes the step list safe to accept from an agent. The agent describes
*where* each value goes; it can neither supply a value nor construct a step that
extracts one. Substitution happens inside the executor, after the boundary.

Referencing `{{totp}}` for a credential with no seed fails the login with
`MFA_REQUIRED` rather than filling something wrong. The `{{totp}}` path is
exercised end to end by the acceptance suite, against a fixture that verifies the
submitted code rather than merely accepting the field.

### Automatic detection

With `steps` omitted, the executor locates the first password input, fills the
nearest preceding text or email input with the username, fills the password, and
submits — clicking a submit control if the page has one, pressing Enter otherwise.

This is a convenience for simple forms. Multi-page logins, custom widgets, and
anything behind a "Next" button need explicit `steps`.

### Deciding whether the login worked

- With `success_selector`, the login succeeds when that selector attaches.
- With `failure_selector`, it fails with `INVALID_CREDENTIAL` when that selector
  attaches.
- With neither, the executor waits up to 10 seconds for the network to settle and
  then checks for a *visible* password input: still present means the form was
  re-rendered, which is read as a failed login; gone means success. If the network
  does not settle, as with sites that long-poll continuously, it makes that check
  against the state at that point; hidden password inputs do not count.

Provide at least one selector for any site where that heuristic is not obviously
right. A login whose outcome cannot be determined within the approximately 15-second
wait window fails with `LOGIN_RESULT_TIMEOUT` rather than handing back a
possibly-unauthenticated browser.

### Persistent cookies

When the operator has enabled `persist_cookies` for this credential (see
[security.md](security.md#persistent-cookies)) and a saved cookie is restored
into a new, non-shared browser, `login` races `success_selector` against the
first step's selector: if `success_selector` becomes visible first, the call
succeeds without running any step at all — no secret is ever placed into the
page for that call. If the step's selector becomes visible first, or the site
still wants to authenticate, `login` runs the steps exactly as it would have
otherwise. A credential with no `success_selector` set never takes this
shortcut and always runs its steps.

### Approval

A deployment may configure an approval hook, in which case every `login` is gated
on it before any credential value is resolved. The agent sees this only as two
extra outcomes: `APPROVAL_DENIED` if a human refuses, and `APPROVAL_TIMEOUT` if
nobody answers in time. Neither carries any detail about who was asked or why they
declined.

There is no way for the agent to detect whether a hook is configured other than
being refused by one, and no parameter that influences it. Approval is an operator
control, not part of the call. This holds the same way whether the operator
answers through `approve_cmd` (Linux) or the operator approval hook (Windows,
`approve_operator`) — the agent sees only `APPROVAL_DENIED` or
`APPROVAL_TIMEOUT` either way.

### Session lifetime

Each lease carries a TTL, 300 seconds by default, configurable with
`session_ttl_secs`, fixed when issued. Browser and API-proxy sessions also have an
absolute lifetime of 3600 seconds by default, configurable with
`browser_max_lifetime_secs` (an integer of at least 1), measured from browser or
proxy launch. The whole login must also complete within
90 seconds. If startup fails for the same key, subsequent `login` calls wait for
backoff periods of 2 seconds, 5 seconds, then 15 seconds; calls during backoff
return `RATE_LIMITED`. More than 3 reauthentication attempts for the same key in
10 minutes also returns `RATE_LIMITED`.

## `login_begin` and `login_step`

Walk a multi-screen login one action at a time instead of guessing the whole
`steps` array up front. `login_begin` opens the page; each `login_step` drives
one action and, unless it hands the login off, answers with a fresh snapshot
that tegata builds and checks before returning it — the agent never receives
raw CDP, and no field value ever leaves the boundary, until the login
succeeds.

Use `login` when the whole flow is known ahead of time or is a simple
single-page form. Use `login_begin` / `login_step` for logins with
intermediate screens the agent cannot predict — a "More options" choice
before a TOTP field, for example — where a wrong guess in a `login` `steps`
array only returns `SELECTOR_NOT_FOUND` with no view of the page that caused
it.

### `login_begin`

**Input**

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `cred_id` | string | yes | An `id` from `list_credentials` |
| `target_url` | string | yes | The login page to open |
| `success_selector` | string | yes | A selector that appears only when login succeeded; stepwise login has no automatic-detection fallback, so this is required |
| `failure_selector` | string | no | A selector that appears only when login failed |
| `exclusive` | boolean | no | Defaults to `false`; applies to the browser once it is handed off |

**Output** — one of:

```json
{ "state": "pending", "login_id": "5c9e...", "snapshot": { "...": "..." } }
```

```json
{
  "state": "done",
  "session_id": "3f2b1c9e-...",
  "target_id": "page-target-id",
  "channel": { "kind": "cdp", "endpoint": "ws://127.0.0.1:41263/devtools/browser/..." }
}
```

A non-`exclusive` `login_begin` first tries to join an existing shared browser
for the same principal, namespace, and `cred_id`, exactly like `login`; a
successful join returns `state: "done"` immediately, with no browser started
and no snapshot involved.

### `login_step`

**Input** is flat: `{ "login_id", "action", ...the fields of that action }`.

| Action | Fields | Meaning |
| --- | --- | --- |
| `click` | `selector` | Click the element |
| `wait_for` | `selector` | Wait for the element to become visible; same per-step timeout and `SELECTOR_NOT_FOUND` as `login` |
| `fill` | `selector`, `value` | Fill one element. `value` must be `{{username}}` — a lone `fill` may not place `{{password}}` or `{{totp}}` |
| `fill_submit` | `fills` (1–3 of `{selector, value}`), `submit` (`{"click": selector}` or `{"press_enter": selector}`) | Fill one to three elements and submit as one uninterruptible operation; `value` is `{{username}}`, `{{password}}`, or `{{totp}}` — this is the only action that may place a secret |
| `snapshot` | — | Take a fresh snapshot without acting on the page |
| `abort` | — | Discard the browser and end the stepwise login |

**Output** is one of the two `login_begin` shapes (`pending` or `done`), plus
`{ "state": "aborted" }` for `abort` — three shapes in all.

`fill_submit` fills its elements with the same native-setter, no-keystroke
mechanism as `login`, then submits, then waits to settle (below). It then tries to
clear whatever it filled from the DOM, regardless of outcome. Clearing is
best-effort; the guarantee is the snapshot check below, which refuses any
snapshot that still carries a secret. A
`SELECTOR_NOT_FOUND` during `fill_submit` leaves the stepwise login open for
another step; a `FILL_MISMATCH` ends it, the same way a suspected
secret-misroute ends a `login`. While one `fill_submit` runs, other
`login_step` calls on the same `login_id`, including `snapshot`, wait for it.

Other than inside `fill_submit`, `{{password}}` and `{{totp}}` are rejected —
by the tool's input schema when called through MCP, and again by the daemon
when called directly over the socket.

### The snapshot

Built on the isolated side after every settle, from the main frame and any
open shadow roots:

```json
{
  "url": "https://example.com/login/2fa",
  "title": "Verify it's you",
  "text": "...",
  "elements": [
    {
      "tag": "button", "role": "button", "disabled": false,
      "text": "More options", "selector": "#more-options"
    }
  ],
  "settled": true
}
```

`text` is `document.body.innerText`, truncated to 2000 characters. `elements`
lists visible `button`, `a[href]`, `input`, `select`, `textarea`, and
`[role=button]` / `[role=link]` elements, up to 200. Each entry carries `tag`,
`disabled` (always a boolean), `text`, and a `selector` tegata generates (an
`#id` if unique, else a `[name=...]` match, else a positional path) — the same
selector the agent passes back in the next step — plus whichever of `type`,
`id`, `name`, `role`, `placeholder`, `aria-label`, `autocomplete`, and `href`
the element actually has; an attribute the element lacks is omitted from the
entry rather than serialized as `null`. **No `value` property, `value`
attribute, or `data-*` attribute of any element is ever included**, regardless
of the element's type or visibility. The whole snapshot is capped at 64 KiB
serialized; over that, `elements` is trimmed from the end and `truncated:
true` is added.

`settled` reports whether the page reached a quiet DOM before the snapshot
was taken: up to 10 seconds for `domcontentloaded` if the action navigated,
then up to 5 seconds of no DOM mutation for 500 ms straight. Hitting either
limit still returns a snapshot, marked `settled: false`, rather than an
error; `networkidle` is not used, matching `login`'s own note about sites
that long-poll continuously.

The snapshot's username is always replaced with `[username]` — raw,
HTML-escaped, and URL-encoded forms — before anything else happens to it.
This is not an omission the agent can rely on for other values: it exists
because the daemon's own response leak scan would otherwise flag the
credential's username and turn the whole response into `INTERNAL`.

### `SNAPSHOT_REJECTED`

Before a snapshot is returned, its full serialization — text, attributes, and
URL — is checked for an exact match, in raw, HTML-escaped, URL-encoded (both
`encodeURIComponent` and full percent-encoding), base64, and hex form, of the
credential's password and of every TOTP code entered so far in that stepwise
login. A single match ends the stepwise login, discards its browser, and
returns `SNAPSHOT_REJECTED` instead of the snapshot; the same `login_id` then
answers `NOT_FOUND`. Only exact matches are checked — a masked echo such as
`••••` or a last-four-digits display is not a full disclosure and is not
flagged; see [security.md](security.md#stepwise-login) for why partial
matches are out of scope.

### Timeouts, step count, and rate limiting

A stepwise login ends, its browser is discarded, and a `stepwise_expired`
audit record is written if either deadline passes:

- `stepwise_idle_secs` (default 120) since the last `login_begin` /
  `login_step` answer, with no further `login_step`.
- `stepwise_max_secs` (default 600) since `login_begin`, regardless of
  activity.

A `login_id` accepts at most 40 `login_step` calls; the 41st returns
`RATE_LIMITED` and ends the stepwise login.

A stepwise login counts as a single `login` attempt for rate limiting and
approval: `login_begin` is gated on an approval hook exactly like `login`,
and counts once against the same-key attempt limit (3 per 10 minutes, with
the 2/5/15-second backoff). `login_step` calls are never gated and never
counted — the flow can take many steps without spending the whole budget on
one login. `abort` does not count as a failure.

### Persistent cookies

When the credential has restored cookies (see
[security.md](security.md#persistent-cookies)) into a new browser and
`success_selector` is already visible on the first check, `login_begin`
finishes as `state: "done"` without ever building or returning a snapshot,
the same shortcut `login` takes; its audit record carries `cookies:
"restored"` and `steps_skipped: true`.

## `logout`

**Input**

| Field | Type | Required |
| --- | --- | --- |
| `session_id` | string | yes |

**Output**: `{"ok": true}`

Returns the caller's lease and shuts down the browser when it was the last lease.
An absent session or a session held by another principal returns `NOT_FOUND`, so
the daemon does not disclose whether the session exists.

Call it when finished. The caller's lease ends; the CDP endpoint and browser close
only when that was the last lease. In either case, logout does not invalidate a
site-side session. Cookies or other session state extracted through CDP remain
usable until the site invalidates them.

## `authorize_device`

Acts as the human approval step for a device-code grant started by an agent tool
such as `gh auth login` or a cloud CLI. tegata opens a dedicated browser, logs in
with the credential, enters the user code at the verification URL, and approves
the grant. The agent's tool receives the token directly; tegata never holds it.

**Input**

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `cred_id` | string | yes | An `id` from `list_credentials` |
| `verification_url` | string | yes | The device authorization page to open |
| `user_code` | string | yes | The short-lived code to enter; it is not recorded in logs or audit |
| `steps` | array | no | Explicit steps; omitted means the default device-flow procedure |
| `success_selector` | string | yes | A selector that appears when authorization succeeds |
| `failure_selector` | string | no | A selector that appears when the device code is rejected |

When `steps` is omitted, tegata uses the credential's login heuristic, opens
`verification_url`, fills the first matching input among
`input[name=user_code]`, `input[autocomplete=one-time-code]`, and
`input[type=text]`, submits with `button[type=submit]`, clicks the first matching
`Authorize`, `Continue`, or `Approve` button, and waits for `success_selector`.
Explicit steps have the same placeholder restriction as `login`, with
`{{user_code}}` additionally allowed. `wait_for` is also accepted in these
steps.

**Output**: `{"ok": true}`

The browser is dedicated to this call, closes when it completes, and never
returns a CDP channel. Login-stage failures use `INVALID_CREDENTIAL`,
`MFA_REQUIRED`, `SELECTOR_NOT_FOUND`, or `FILL_MISMATCH`. After `verification_url`
is opened, selector, fill, and timeout failures return `INTERNAL`; a matching `failure_selector`
returns `DEVICE_CODE_REJECTED`, including when it renders while a step is still
waiting for its selector. Approval hooks can also return `APPROVAL_DENIED`
or `APPROVAL_TIMEOUT`.

## `open_api_proxy`

Opens a loopback HTTP relay that injects a credential's value into a fixed
upstream API. The agent gets a URL that already carries the token's authority
without ever seeing the token itself. See [api-proxy.md](api-proxy.md) for
configuration and the full residual-risk discussion.

The same call opens a proxy configured with an OAuth device-code grant.

**Input**

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | The name of a configured `[[api_proxy]]` entry |

**Output**

```json
{ "session_id": "3f2b1c9e-...", "base_url": "http://127.0.0.1:41263/Ax7f...q2" }
```

`base_url` already includes the path secret. A request to `<base_url>/<path>`
is relayed to the configured `upstream`'s `<path>` with the configured header
replaced by the injected value; a request missing the secret, or carrying a
different session's secret, gets a 404 and never reaches upstream, as does a
request whose path contains a dot segment, `%2e`, or a backslash. `session_id`
is what `logout` takes to close the relay.

The proxy session ends at the earlier of its `session_ttl_secs` deadline and the
`browser_max_lifetime_secs` deadline. The latter is measured from proxy launch.

An unknown `name` returns `NOT_FOUND`. Where an approval hook is configured, it
gates `open_api_proxy` the same way it gates `login`, with `TEGATA_METHOD` set
to `open_api_proxy` and `TEGATA_TARGET_URL` set to the proxy's upstream.
Starts are rate-limited like `login`, per caller and `name`: during the backoff
after a failed start, or after 3 starts in 10 minutes, the call returns
`RATE_LIMITED`.

The lease this opens behaves like any other session: it has a TTL, `logout`
ends it early, and `lock_vault` closes every proxy in the locked namespace.

## `get_totp`

Returns the *current code* for a credential explicitly marked as exposable. Never
the seed.

**Input**

| Field | Type | Required |
| --- | --- | --- |
| `cred_id` | string | yes |

**Output**

```json
{ "code": "492013", "expires_in": 17 }
```

`expires_in` is the remaining seconds in the current 30-second window.

Refused with `TOTP_NOT_EXPOSABLE` unless the credential is marked
`totp_exposable` in the daemon's configuration — the default is off, and the same
code is returned for a credential that has no seed at all. A second call for the
same credential inside 30 seconds is refused with `RATE_LIMITED`. Every call is
audited.

This tool exists for step-up prompts that appear *after* handoff. During a normal
`login`, the code is computed and filled on the isolated side and the agent never
handles one. See [security.md](security.md#totp) for the reasoning and the
accepted risk.

## `lock_vault`

**Input**

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `namespace` | string | no | Lock this provider only; omitted locks every provider |

**Output**: `{"ok": true}`

Locks the backend and discards the cached vault session. Subsequent `login` and
`get_totp` calls against a locked provider fail with `VAULT_LOCKED`, while
`list_credentials` keeps listing its entries by name with `status: "locked"`.

It also terminates the browser sessions belonging to that namespace, shutting each
one down gracefully. This closes tegata's browsers but does not invalidate any
site-side session state already extracted through CDP.

**There is no unlock RPC, and none is needed.** Unlocking is always implicit and
always goes through the provider's own unlock ceremony — the askpass or sealed
password for Bitwarden, and the equivalent for any other backend. What
`lock_vault` and TTL expiry do is discard the vault session material; the next call
that needs a *value* performs the ceremony again and the provider comes back
unlocked.

That leaves a useful asymmetry:

- `list_credentials` against a locked provider does **not** trigger the ceremony.
  It answers from the catalog cached before the lock, names only, with
  `status: "locked"`. Listing is therefore always cheap and never prompts.
- `login` and `get_totp` do need a value, so they run the ceremony. On an
  `askpass` deployment that means the prompt appears on the isolated side at that
  moment, not in the agent's terminal.

A provider with no unlock ceremony to run — a static one, such as the mock
provider used by the test suite — has no way back and stays locked for the
lifetime of the daemon.

---

## The bridge and CDP endpoints

When the daemon is a Windows service and the agent runs in WSL, the CDP endpoint
the daemon returns names a port on the *Windows* side, which a WSL client under
NAT networking cannot reach.

With `TEGATA_BRIDGE=1`, the broker handles this: after a successful `login` it
opens a tunnel for that session and rewrites the endpoint's port to the WSL-local
end before returning it. The agent receives an endpoint it can connect to directly
and does not need to know a tunnel exists. `login_begin` / `login_step` get the
same treatment for their `state: "done"` answer, the only one carrying a CDP
endpoint; a `pending` or `aborted` answer has no endpoint to rewrite and is
returned as is.

The tunnel is not general-purpose. The daemon accepts a tunnel request only for the
CDP port belonging to the named active session. A session belonging to another
principal or an absent session is refused with `NOT_FOUND`; a port that does not
match the caller's session is refused with `FORBIDDEN`. It is a session handoff
mechanism, not a port forwarder.

## `open_mcp_server`

Not a tool the agent calls — this RPC exists for `tegata-mcp-run`, the
runner an agent's MCP client registers as an ordinary stdio server, one per
configured `[[mcp_server]]` entry. See
[mcp-hosting.md](mcp-hosting.md) for configuration, registration, and the
leak-containment discussion; `open_mcp_server` shares its error codes with
`login` and `open_api_proxy`: `NOT_FOUND` for an unconfigured name,
`APPROVAL_DENIED` and `APPROVAL_TIMEOUT` from the same approval hook,
`RATE_LIMITED` for repeated starts, `VAULT_LOCKED` for a locked namespace,
`INVALID_CREDENTIAL`, and `INTERNAL`.

## Talking to the daemon without MCP

The daemon speaks newline-delimited JSON-RPC 2.0 — one request object per line, one
response object per line. The MCP broker is a thin adapter over exactly the calls
documented above, plus `status`, which returns `{"ok": true, "browsers": n,
"leases": n}` and is useful as a liveness check. `browsers` counts running
browsers only; `leases` counts every live session, API proxies included.

Method names and parameters are identical to the tool names and inputs. A method
outside the allowlist is answered with a standard JSON-RPC method-not-found error;
the acceptance suite drives one straight at the socket to prove it.
