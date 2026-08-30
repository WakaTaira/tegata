# MCP tool contract

This is the complete surface tegata exposes to an agent. Five tools, no generic
escape hatch. Anything not listed here does not cross the boundary.

## Connecting

The broker is an MCP server speaking stdio. It is started with the path to the
daemon socket in the environment:

```sh
TEGATA_SOCKET=/run/tegata/tegatad.sock node packages/tegata-mcp/dist/index.js
```

Registered with an MCP client, that looks like:

```json
{
  "mcpServers": {
    "tegata": {
      "command": "node",
      "args": ["/path/to/packages/tegata-mcp/dist/index.js"],
      "env": { "TEGATA_SOCKET": "/run/tegata/tegatad.sock" }
    }
  }
}
```

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

That is the whole message. There is no detail field, no stack trace, and no echo
of the input — see [security.md](security.md#how-secrets-move-on-the-isolated-side)
for why. A code the broker does not recognise is normalised to `INTERNAL`, so an
unexpected daemon response cannot smuggle text out through the error path.

### Classification codes

| Code | Meaning |
| --- | --- |
| `INVALID_CREDENTIAL` | The credential does not exist, or the site rejected the login |
| `MFA_REQUIRED` | The login needs a TOTP code and the credential has no seed |
| `SELECTOR_NOT_FOUND` | A step's selector did not resolve within the step timeout |
| `VAULT_LOCKED` | The provider holding this credential is locked |
| `RATE_LIMITED` | A second `get_totp` for the same credential within 30 seconds |
| `TOTP_NOT_EXPOSABLE` | The credential is not marked `totp_exposable`, or has no seed |
| `APPROVAL_DENIED` | A configured approval hook refused this login |
| `APPROVAL_TIMEOUT` | The approval hook did not answer within its timeout |
| `INTERNAL` | Anything else, including a refused response that failed the leak scan |

`INVALID_CREDENTIAL` covers both "no such credential" and "the site said no" on
purpose: distinguishing them would tell an agent which identifiers are real.

Two further codes exist at the transport level on Windows and never reach the MCP
layer: `UNAUTHORIZED` (bad or missing token, or a SID not on the allowlist) and
`FORBIDDEN` (a tunnel request for a port that is not the named session's CDP
port). The administrative RPCs add `ADMIN_REQUIRED` and `ADMIN_SEAL_UNAVAILABLE`.

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

**Output**

```json
{
  "session_id": "3f2b1c9e-...",
  "channel": { "kind": "cdp", "endpoint": "ws://127.0.0.1:41263/devtools/browser/..." }
}
```

Connect a Playwright client to that endpoint with `chromium.connectOverCDP` and
drive the authenticated browser directly. Keep the `session_id`; it is what
`logout` takes.

### Steps and the placeholder contract

A step is either a `fill` or a `click`:

```json
{
  "steps": [
    { "action": "fill",  "selector": "#username", "value": "{{username}}" },
    { "action": "fill",  "selector": "#password", "value": "{{password}}" },
    { "action": "click", "selector": "button[type=submit]" }
  ]
}
```

A `fill` step's `value` must be exactly one of `{{username}}`, `{{password}}`, or
`{{totp}}`. No other value is accepted — not a literal, not a partial string. The
schema rejects anything else before the call leaves the agent's machine, and the
executor rejects it again on the far side.

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
- With neither, the executor waits for the network to settle and then checks for a
  *visible* password input: still present means the form was re-rendered, which is
  read as a failed login; gone means success.

Provide at least one selector for any site where that heuristic is not obviously
right. A login whose outcome cannot be determined within the wait window fails with
`INTERNAL` rather than handing back a possibly-unauthenticated browser.

### Approval

A deployment may configure an approval hook, in which case every `login` is gated
on it before any credential value is resolved. The agent sees this only as two
extra outcomes: `APPROVAL_DENIED` if a human refuses, and `APPROVAL_TIMEOUT` if
nobody answers in time. Neither carries any detail about who was asked or why they
declined.

There is no way for the agent to detect whether a hook is configured other than
being refused by one, and no parameter that influences it. Approval is an operator
control, not part of the call.

### Session lifetime

Each session carries a TTL, 300 seconds by default, configurable with
`session_ttl_secs`. The whole login must also complete within 90 seconds.

## `logout`

**Input**

| Field | Type | Required |
| --- | --- | --- |
| `session_id` | string | yes |

**Output**: `{"ok": true}`

Destroys the session and shuts down its browser. `{"ok": true}` is also the answer
for a `session_id` that is already gone, so logout is safe to call twice.

Call it when finished. The CDP endpoint stops being connectable and the browser
takes its cookies with it.

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
one down gracefully. Locking the vault and leaving an authenticated browser open
would have defeated the point of locking it.

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
and does not need to know a tunnel exists.

The tunnel is not general-purpose. The daemon accepts a tunnel request only for the
CDP port belonging to the named active session; any other port is refused with
`FORBIDDEN`. It is a session handoff mechanism, not a port forwarder.

## Talking to the daemon without MCP

The daemon speaks newline-delimited JSON-RPC 2.0 — one request object per line, one
response object per line. The MCP broker is a thin adapter over exactly the calls
documented above, plus `status`, which returns `{"ok": true}` and is useful as a
liveness check.

Method names and parameters are identical to the tool names and inputs. A method
outside the allowlist is answered with a standard JSON-RPC method-not-found error;
the acceptance suite drives one straight at the socket to prove it.
