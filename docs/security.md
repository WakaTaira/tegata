# Security

This document states what tegata assumes about an attacker, what it guarantees
against those assumptions, what it deliberately does not guarantee, and what an
operator must do for the guarantees to hold.

## Threat model

### The adversary is the agent

tegata does not model the agent as trusted-but-careless. It models the agent as
an untrusted program running on the same machine as the person using it, with the
following capabilities:

- **Arbitrary command execution.** It can run `env`, `ps -eo args`, `cat`, walk
  the filesystem, read `/proc/*/environ`, and inspect anything its uid can reach.
- **Arbitrary code execution.** It writes and runs its own programs, so any
  protection expressed as "our client library does not expose that" is not a
  protection.
- **Prompt injection.** Content it reads from a web page may contain instructions,
  and it may follow them. It can therefore be induced to try to exfiltrate a
  secret without its operator intending anything of the kind.

Two consequences follow directly.

First, **concealment is not isolation**. Ignore files, redaction in a UI, "the
agent was not told the path" — all of these fail against a process that can read
the filesystem. They are excluded from the design.

Second, **an in-process convention is not a boundary**. If the secret is ever
present in a process the agent's uid can read or attach to, the boundary has
already failed, regardless of what the code around it does with the value.

### What must be behind the boundary

- The vault master password
- Every resolved username, password, and TOTP seed
- Session cookies and any serialized browser state
- The vault session token (`BW_SESSION` and equivalents)
- The daemon's own configuration, which names the vault and the accounts

## The four invariants

Everything in the implementation exists to hold these four properties.

### 1. The agent handles references, not credentials

What crosses to the agent is an opaque identifier: `vw:a1b2c3`, namespaced by the
provider it came from. Resolution to a value happens only on the isolated side.
The catalog projection is performed inside the daemon, so a value has no code path
that reaches the projection in the first place — `list_credentials` builds its
result from the metadata fields alone.

### 2. The boundary is enforced by the operating system, not by the program

The boundary is one of: a separate UNIX user, a Windows service account, or a
separate host. Never a module, a class, or a promise.

**Linux.** The daemon runs as a dedicated `tegata` user. Its state directory is
mode 0700 and its configuration is mode 0600, both owned by that user. The agent's
user has no escalation path to it — in particular, no sudoers entry. The listening
socket is mode 0666 *on purpose*: access is not decided by filesystem permissions,
which are advisory about intent, but by `SO_PEERCRED`, which reports the uid the
kernel itself observed on the connecting process. A uid absent from
`allowed_uids` is refused inside the transport and never reaches the RPC layer.

**Windows.** The daemon runs under the virtual service account
`NT SERVICE\tegatad`. Files that hold, or briefly hold, secrets get a protected
DACL naming only the daemon's own account and `SYSTEM`. The local administrators
group is deliberately *excluded*: the WSL file server that backs `/mnt/c` reads
with a token in which that group is enabled, so granting it would hand the agent
side of the machine exactly the read it must not have. Administrators retain
ownership of the paths they create during installation, which is enough to repair
the DACL without being enough to read through it.

**WSL.** A WSL process reaching Windows through interop or `/mnt/c` runs with the
privileges of the Windows user who started WSL. It therefore cannot read files
owned by a different local account. Putting the daemon on the Windows side and the
agent inside WSL inverts the trust direction — the standard `\\wsl.localhost\`
problem, where Windows can read the distro as root, works in tegata's favour
because the side that must be protected is the Windows side.

Running the daemon *inside* the same WSL distro as the agent is possible with the
systemd boundary, but only if interop is disabled or `.exe` execution is denied.
Otherwise the agent launches `powershell.exe` and reads back into the distro as
root, and the boundary is gone.

**Container.** This boundary assumes that the daemon and agent are on the same
Linux host and that installation is available to the host administrator. The
agent container receives only a named token and a CDP tunnel; credential values
remain with the host daemon. A peer that possesses a token can act as that peer
on the bridge network, because tokens are plaintext and the connection has no TLS
in this release. A container using `--network host`, rootless Docker, or Podman is not
covered. An agent with a host privilege-escalation path — including passwordless
sudo, membership in the `docker` group, or Windows administrator elevation — is
not covered; a `docker`-group user is effectively host root, so running the agent
with that membership is not a boundary. Phase 4a ownership restrictions apply
to container peers as well: sessions owned by another principal return
`NOT_FOUND`.

### 3. Only a thin, allowlisted RPC crosses the boundary

Six methods exist: `status`, `list_credentials`, `login`, `logout`, `get_totp`,
`lock_vault`, plus two administrative methods on Windows. Anything else is
answered with a JSON-RPC method-not-found error. There is no generic "run this on
the isolated side" call, because such a call would be the boundary's own bypass.

Every response is scanned before it is written. The daemon keeps a registry of the
secret values it has resolved during its lifetime and runs the outgoing response
bytes through `leakscan` against that registry. A hit does not get logged and
passed through — the entire response is replaced with an `INTERNAL` error and the
audit record for the call records `INTERNAL`. This is defense in depth: if it ever
fires, something above it is already broken, and the point is that the value still
does not leave.

### 4. What comes back is a session, not a credential

`login` returns a CDP endpoint. Not a cookie jar, not a `storageState` file, not a
bearer token. The agent connects to a browser that is already authenticated and
drives it from there.

The executor never writes a trace, a video, a HAR file, or a screenshot — those
would be a credential-bearing artifact on disk that the agent could read, and the
acceptance suite asserts that no such file appears anywhere after a login.

## How secrets move on the isolated side

Being on the right side of the boundary is not sufficient; a value can still leak
sideways into a place the agent can read.

**Never in `argv`.** Process arguments are world-readable through `ps`. The
credential reaches the executor as one JSON line on its stdin, and the Bitwarden
CLI receives the master password only in the `bw` child process's environment,
using `--passwordenv BW_PASSWORD`. The password value and session key are never
placed in `argv`; `ps` can show only the variable name `BW_PASSWORD`, not its
value.

**Never in an environment the agent can observe.** `BW_PASSWORD` and `BW_SESSION`
exist only in the environment of the specific `bw` child process that needs them;
they are not present in the daemon, executor, or agent process environments. On
Linux, another process's `/proc/<pid>/environ` is readable only by the same uid or
root. The agent uses a different uid, and the browser worker uses the separate
`tegata-browser` user, so neither can read those variables.

**Never in a log or a formatted string.** Secrets are held in a `Secret` type
whose `Debug` and `Display` implementations both render `***`, and which zeroes its
buffer on drop. The isolated process's stdout and stderr are not connected to the
agent.

**Never in an error message.** Executor failures are converted to classification
codes before they cross back. A wrong password produces `INVALID_CREDENTIAL` and
nothing else — no stack trace, no DOM fragment, no echo of what was typed into the
form. The acceptance suite drives both a wrong credential and a missing selector
specifically to check that the error path leaks nothing the success path would not.

**The browser worker is isolated too.** On Linux, socket activation starts the
browser (executor) as a separate service under the `tegata-browser` user. The
daemon is given no capability to change uid and does not switch users itself.
The executor also has a defense-in-depth guard using CDP `Fetch.enable` that
rejects navigation to `file://` URLs. On Windows, the browser continues to share
the daemon's service account; user separation is not implemented there.

## Unlock

Resolution happens behind the boundary, so the master password is the one value
that must be *entered*. The invariant is that the input channel terminates on the
isolated side. It is not about hiding the characters on screen; it is about which
process owns the channel. Typing the master password into a terminal that shares a
session with the agent is not acceptable, however the prompt is drawn.

Two modes are implemented:

<table>
<thead><tr><th>Mode</th><th>Where the password comes from</th><th>Available on</th></tr></thead>
<tbody>
<tr>
<td><code>askpass</code></td>
<td>A command configured as <code>askpass_cmd</code>, run by the daemon, whose
stdout the daemon reads. The daemon runs it with stdin closed and stderr
discarded, in its own process group, and kills the whole group if it does not
answer in time — a helper that spawns children cannot leave one orphaned holding
a prompt.</td>
<td>Linux (the only mode), Windows (opt-in)</td>
</tr>
<tr>
<td><code>sealed</code></td>
<td>A DPAPI blob unsealed by the daemon itself. Decryptable only by the same
account on the same machine.</td>
<td>Windows (the default)</td>
</tr>
</tbody>
</table>

Windows defaults to `sealed` because the service runs in session 0 and cannot draw
an interactive prompt. The password is sealed once by an elevated
`tegatad.exe seal`, and every subsequent service restart unseals it with no human
present.

Unlocked state carries a TTL, per provider namespace, after which the daemon locks
the vault again. Different backends have genuinely different session lifetimes,
which is why the TTL is per namespace rather than global.

Locking — whether by `lock_vault` or by the TTL expiring — discards the vault
session material rather than latching the provider off. There is no unlock RPC:
unlocking is always implicit, and always runs the provider's own ceremony. The
next call that needs a credential *value* performs that ceremony and the provider
comes back unlocked; `list_credentials` answers from its cached catalog without
triggering it.

The security property that matters here is that the ceremony is the only way back
in, and the ceremony terminates on the isolated side. A shorter
`session_ttl_secs` therefore buys real protection — the window in which unlocked
material sits in the daemon's memory — at the cost of more frequent prompting,
which is the trade an operator should be making deliberately.

`lock_vault` also terminates the browser sessions in that namespace. Leaving an
authenticated browser alive after locking the vault it came from would have
undone the lock.

## TOTP

The protected asset is the **seed**, not the code. A six-digit code is valid for at
most 30 seconds, is single-use at any site worth protecting, and cannot log anyone
in on its own — it is the second factor, not the first. The seed, in contrast, is a
permanent bypass of the second factor. tegata treats them differently.

**During login (the default).** The daemon computes the current code from the seed
on the isolated side and hands it to the executor along with the password. The
agent never sees a code at all. A login step may reference `{{totp}}`; if the
credential has no seed, the login fails with `MFA_REQUIRED` rather than proceeding.

**After handoff (opt-in).** A site may demand a code during a step-up
authentication while the agent is already driving the session. For that case only,
`get_totp` returns the current code — and nothing else. It is gated on three
things:

- The credential must be marked `totp_exposable`; the default is off. A request
  for an entry that is not marked is refused with `TOTP_NOT_EXPOSABLE`, which is
  also the answer for an entry with no seed, so the refusal does not disclose
  which of the two is the case.
- A second request for the same credential within 30 seconds is refused with
  `RATE_LIMITED`. The agent can obtain one code per code lifetime, not a stream.
- Every call is written to the audit log.

**This is an accepted risk, stated explicitly.** Exposing the code is a deliberate
trade: it costs about 30 seconds of secrecy on a value that is useless without the
password, and it buys the ability for the agent to survive a step-up prompt without
a human present. Exposing the seed is not on the table under any configuration.

## Human-in-the-loop approval

The boundary keeps credentials away from the agent, but it cannot tell a
legitimate `login` from one an injected instruction talked the agent into making —
both are the same call for a credential the agent is entitled to use. The answer to
that is not a better boundary; it is a human.

Setting `approve_cmd` gates every `login` on an external command. The daemon runs
it through `sh -c` on the isolated side and reads the exit status as the verdict:
zero approves, anything else denies with `APPROVAL_DENIED`. A command that has not
answered within `approve_timeout_secs` — 60 by default — has its whole process
group killed and the login fails with `APPROVAL_TIMEOUT`. The verdict is recorded
as the login's audit outcome.

**Where the gate sits is itself a security decision.** It runs after the request
is parsed and the credential is confirmed to exist and be reachable, and *before*
any value is resolved or the executor is started.

The second half of that is the obvious part: no secret is touched until after a
human says yes. The first half is the less obvious one. If approval came before
the existence check, an agent could raise a prompt with any string at all, turning
the operator's approval channel into something it can spam at will — and a human
interrupted often enough starts approving reflexively, which is the failure mode
this control exists to avoid. Gating on a credential that actually exists keeps the
prompt rare and meaningful, and preserves the quiet `INVALID_CREDENTIAL` refusal
for everything else.

**The hook is told references, never values.** It receives exactly three
environment variables:

| Variable | Contents |
| --- | --- |
| `TEGATA_CRED_ID` | The namespaced credential reference being requested |
| `TEGATA_TARGET_URL` | The login destination |
| `TEGATA_PEER` | The calling peer's uid, in decimal |

That is enough for a human to make a decision — *which* account, at *which* site,
for *which* caller — and contains nothing worth stealing. The acceptance suite
dumps the hook's environment and runs it through the leak guard to keep it that
way.

Approval is UNIX-only. A Windows configuration containing `approve_cmd` is
rejected at startup with an explicit error rather than silently ignored, because a
security control that quietly does nothing is worse than one that is absent.

Consider a hook mandatory for any credential whose misuse you could not undo. It
is the only mechanism in tegata that constrains *which* logins happen, as opposed
to what the agent learns from them.

## Audit log

Every RPC call appends one JSON line to the audit log, whether it succeeded or
failed:

```json
{
  "ts":"unix:1756512000","peer_uid":1000,"method":"login",
  "cred_id":"vw:a1b2c3","target_url":"https://example.com/login",
  "session_id":"3f2b1c9e-…","namespace":"vw","outcome":"ok"
}
```

`cred_id` is a reference, `target_url` is a destination, and `session_id` and
`namespace` tie the record to the session and the provider it concerned. Any field
that does not apply to a given call is `null`. The record says *who asked for what,
when, which session and vault it touched, and how it went* — and holds no
credential value by construction.

**The peer field names the caller in the vocabulary of the transport that
authenticated it.** On Linux that is `peer_uid`. On Windows a named pipe client
contributes `peer_sid` together with `elevated` and `administrator`, so the log
shows not just who called an administrative RPC but on what authority; a
token-authenticated TCP client contributes `peer_token`.

**The daemon audits its own actions too.** Not everything worth recording is
something an agent asked for, so three events carry `"peer_system": true` instead
of a caller:

<table>
<thead><tr><th>Event</th><th>When</th></tr></thead>
<tbody>
<tr>
<td><code>session_expired</code></td>
<td>A browser session passed its TTL and was reaped</td>
</tr>
<tr>
<td><code>vault_autolocked</code></td>
<td>A provider's unlock TTL lapsed and it locked itself</td>
</tr>
<tr>
<td><code>session_terminated</code></td>
<td><code>lock_vault</code> tore down a live session in that namespace, or the
daemon reaped one while shutting down</td>
</tr>
</tbody>
</table>

Without these, the log would show a session being created and never show it
ending, which is exactly the gap an investigation needs closed.

**The log is created mode 0600**, owned by the daemon's account, so the agent
cannot read the history of its own calls, let alone edit it.

**Rotation** is opt-in through `audit_log_max_bytes`. When the file would exceed
that size, it is renamed to `<path>.1` — replacing any previous `.1` — and a fresh
log is started. Each daemon process rotates at most once, so the mechanism keeps
an unattended deployment's log bounded without silently shredding history behind a
busy daemon's back. Leave it unset for an unbounded log, and collect the file
somewhere the agent cannot rewrite it.

## Residual risks

These are known, accepted, and out of scope for the boundary itself.

**The session can do whatever the account can do.** Once the agent holds a CDP
endpoint for an authenticated browser, it has the account's full authority on that
site. tegata isolates the credential, not the consequences of being logged in.
Mitigate with the privileges, not with tegata: a dedicated account for agent use, a
read-only role where the site offers one, and an allowlist of target sites.

**Prompt injection can misuse a legitimate tool.** Nothing stops an injected
instruction from calling `login` for a credential the agent is entitled to use.
tegata narrows the blast radius — no credential is exfiltrated — but the call
itself is indistinguishable from a legitimate one, so no amount of boundary
enforcement can reject it. Configure
[`approve_cmd`](#human-in-the-loop-approval) to put a human in front of it; the
audit log remains the detection mechanism for anything that gets through, or for
deployments that run without a hook.

**A `totp_exposable` code is disclosed to the agent.** See above. Opt-in,
rate-limited, logged, and short-lived.

**The agent can implement its own daemon.** If the agent is allowed to write or
modify the daemon's code or configuration, it can replace the boundary with
something that has none. The daemon's binary and configuration must live where the
agent's user cannot write.

**Windows retains a browser-worker risk.** During unlock, the master password is
present in the `bw` child process's `BW_PASSWORD` environment variable. On Windows,
another process's environment block can be read only through debugging APIs, and a
browser `file://` page cannot read it. The browser nevertheless shares the
daemon's service account and can read and write the state directory, including
configuration, token hashes, and appdata. This separation is planned for a later
release.

**The CDP port has a short connection window.** Between browser launch and the
executor's guard attaching to CDP, another uid on the same host can connect to
the loopback CDP port. This is a limitation of the port-based design; network
namespace isolation is planned for a later release.

## Operator checklist

The guarantees above assume the deployment is set up correctly. Verify each of
these.

- [ ] The daemon runs as an account distinct from the agent's, and the agent's
      user has no sudo, `runas`, or service-control path to it.
- [ ] The daemon's configuration, state directory, and binary are not writable by
      the agent's user.
- [ ] `allowed_uids` (Linux) or `allowed_sids` (Windows) names exactly the identity
      that should be permitted, and nothing broader.
- [ ] The agent's tool permissions deny direct access to the credential backend and
      to the daemon socket — for Claude Code, deny rules covering `Bash(bw:*)` and
      any socket client the agent might invoke.
- [ ] `kernel.yama.ptrace_scope` is 1 or higher on Linux, so the agent's user
      cannot attach to a process it does not own.
- [ ] `approve_cmd` is configured if any reachable credential could do damage that
      cannot be undone, and the prompt it raises is one the agent cannot answer.
- [ ] The Windows TCP front is firewalled to the WSL interface, or disabled by
      setting `tcp_port = 0` when only the named pipe is needed.
- [ ] No real credential exists in any development, test, or acceptance
      environment. Canaries only.
- [ ] The audit log is collected somewhere the agent cannot rewrite it.
- [ ] On Linux, `executor_socket` is configured. Non-Nix deployments install both
      `tegata-executor.socket` and `tegata-executor@.service`.

## Reporting a vulnerability

If you find a way across the boundary, please report it privately through GitHub's
security advisory workflow on this repository rather than opening a public issue.
[SECURITY.md](../SECURITY.md) has the details, including what to include and what
is considered in scope.
