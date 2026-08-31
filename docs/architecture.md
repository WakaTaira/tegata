# Architecture

tegata is built around three abstractions and one hard rule: platform-specific
code lives only in the boundary implementation. Everything above it — the broker,
the provider registry, the executor — is the same on every platform.

## The three abstractions

### SandboxBoundary — where isolation is enforced

The boundary owns the answer to "how does a caller reach the isolated side, and how
do we know who they are". It exposes exactly two things: run an allowlisted method
over there and return a sanitized result, and hand out a connection to an
authenticated session.

It is the only layer that touches operating system mechanisms — peer credentials,
service accounts, sealed storage, ACLs — and exactly one implementation is compiled
per target.

In this repository it is `crates/tegatad/src/transport/`. The `Transport` trait
yields authenticated peers; the RPC layer above it sees only a peer identity and a
byte stream and is identical on Linux and Windows.

| Implementation | Platform | Mechanism | Peer authentication | Sealed storage |
| --- | --- | --- | --- | --- |
| systemd | Linux, WSL | Dedicated user, hardened unit, socket activation | UNIX socket + `SO_PEERCRED` | askpass at unlock |
| Windows service | Windows | Virtual account `NT SERVICE\tegatad` | Named pipe + SID; loopback TCP + token | DPAPI |
| Container | *not implemented* | Separate container, no shared volume | Socket + token | Secret mount |
| Remote host | *not implemented* | Separate host or VM | mTLS / Tailscale identity | Server-side |

### CredentialProvider — where values come from

A provider lists references and resolves them, and is instantiated only on the
isolated side. Its `list_refs` returns metadata alone — the projection to
publishable fields happens inside the provider, so a value never travels to a
caller that then has to remember to strip it.

`CredentialProvider` is a Rust trait (`crates/tegatad/src/provider/mod.rs`) with
five methods: `list_refs`, `resolve`, `lock`, `expire`, and `locked`. The split
between `lock` and `expire` is what makes the two kinds of locking distinguishable
— a deliberate lock and a TTL lapse are not the same event, and the audit log
records them differently.

Three backends are implemented, and they demonstrate that the trait is carrying
real weight rather than wrapping one product:

| Backend | Unlock ceremony | Notes |
| --- | --- | --- |
| `bitwarden-cli` | askpass, or a sealed password on Windows | Bitwarden cloud, self-hosted Bitwarden, or Vaultwarden — the server is configuration, not an assumption |
| `age-file` | Re-decrypting an age file with an X25519 identity | Pure-Rust age crate, no CLI or agent; the only backend that unlocks without a human |
| `pass` | Whatever `gpg-agent` requires | UNIX only; reads the seed from an `otpauth://` line, so `pass-otp` is not needed |

A static provider backs the test suite; having one with no ceremony at all is what
makes the "a locked provider with no way to unlock stays locked" path testable.

### ProviderRegistry — several vaults at once

Providers are not an either/or. The registry holds several at once, each under a
namespace assigned in configuration, and presents them to the agent as one catalog.

That has four consequences worth stating:

- **The agent's view never changes.** Which backend an entry came from is visible
  in the `source` field and the `id` prefix, but `login` is called the same way
  regardless.
- **Identifiers cannot collide.** `id` is `<namespace>:<backend id>`, so two vaults
  can both hold an entry named "GitHub".
- **Lock state is per namespace.** A `bw` session TTL and a `gpg-agent` cache have
  nothing to do with each other, so each provider locks and expires on its own.
  Locking one leaves the others listing normally.
- **Configuration is owned by the isolated side.** Which providers exist is
  declared in the daemon's own configuration file. There is no RPC that registers a
  provider, so the agent cannot add one.

### AuthExecutor — where a secret becomes a session

The executor consumes a secret and produces an authenticated session, then hands
out a connection to it. It runs on the isolated side and returns a channel
reference, never the material it consumed.

`packages/tegata-executor` is the implemented executor: a Playwright form login.
The daemon spawns it as `node <entry>` per login and writes one JSON line to its
stdin — target URL, steps, and the resolved secret. Nothing goes through `argv` or
the environment. It launches its own headless Chromium with a remote debugging
port, runs the steps, verifies the outcome, and answers with either
`{"ok":true,"endpoint":"ws://..."}` or `{"ok":false,"error":"<code>"}`.

It never enables tracing, video, HAR recording, or screenshots. Those would put
credential-bearing artifacts on disk where the agent could read them, and the
acceptance suite asserts none appear.

## Layers

```
┌────────────────────────────────────────────────────────────────┐
│ Agent                                                          │
│   sees: a catalog of names, five tools, a CDP endpoint         │
└────────────────────────────┬───────────────────────────────────┘
                             │ MCP over stdio
┌────────────────────────────▼───────────────────────────────────┐
│ Broker — packages/tegata-mcp                                   │
│   runs as the agent's user · holds nothing · validates the     │
│   tool schema · normalises errors to classification codes      │
└────────────────────────────┬───────────────────────────────────┘
                             │ newline-delimited JSON-RPC 2.0
══════════════ SandboxBoundary ═══════════════════════════════════
                             │
┌────────────────────────────▼───────────────────────────────────┐
│ tegatad — crates/tegatad                                       │
│   transport: authenticates the peer                            │
│   RPC: allowlisted methods only                                │
│   leak scan: every outgoing response                           │
│   audit: one line per call                                     │
│                                                                │
│   ┌──────────────────────┐      ┌──────────────────────────┐   │
│   │ ProviderRegistry     │      │ Executor (per session)   │   │
│   │  ns "vw" → bitwarden │─────▶│  Playwright form login   │   │
│   │  ns "ci" → age-file  │      │  → headless Chromium     │   │
│   └──────────────────────┘      └──────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

## A login, end to end

```
Agent            Broker           tegatad          Provider        Executor
  │ list_credentials │                │                │               │
  │─────────────────▶│───────────────▶│  list_refs()   │               │
  │                  │                │───────────────▶│               │
  │ [{id,name,uri}]  │  (metadata)    │◀───────────────│               │
  │◀─────────────────│◀───────────────│                │               │
  │                  │                │                │               │
  │ login(id, url)   │                │                │               │
  │─────────────────▶│───────────────▶│  resolve(id)   │               │
  │                  │                │───────────────▶│               │
  │                  │                │◀── Secret ─────│               │
  │                  │                │   register in the leak registry│
  │                  │                │─── spawn, secret over stdin ──▶│
  │                  │                │                │   fill / click / verify
  │                  │                │◀── ws://127.0.0.1:PORT ────────│
  │                  │  leak scan of the response bytes│               │
  │ {session_id,     │                │                │               │
  │  cdp endpoint}   │                │                │               │
  │◀─────────────────│◀───────────────│                │               │
  │                                                                    │
  │ connectOverCDP(ws) ──── the agent drives the session directly ────▶│
```

The secret exists in three places and nowhere else: inside the provider, inside the
daemon's `Secret` wrapper for the duration of the call, and on the executor's
stdin. It is zeroed on drop, renders as `***` in any formatting, and never appears
in a process argument list or an environment block.

## The RPC layer

The daemon speaks newline-delimited JSON-RPC 2.0. Method dispatch is an explicit
allowlist — `status`, `list_credentials`, `login`, `logout`, `get_totp`,
`lock_vault`, plus `admin_seal` and `admin_token_issue` on Windows. Anything else
returns method-not-found. There is deliberately no method that executes something
arbitrary on the isolated side.

### The final scan

Before any response is written back, the daemon serializes it and runs it through
`leakscan` against a registry of every secret value resolved during this process's
lifetime. If anything matches, the response is discarded and replaced with an
`INTERNAL` error, and the audit record for that call says `INTERNAL`.

This should never fire. It exists because "should never" is not a guarantee, and
the cost of a redundant scan is far below the cost of a leak.

### The audit record

One line per call, appended under a lock so concurrent connections cannot interleave:

```json
{"ts":"unix:1756512000","peer_uid":1000,"method":"login","cred_id":"vw:a1b2c3","target_url":"https://example.com/login","session_id":"3f2b1c9e-…","namespace":"vw","outcome":"ok"}
```

The peer key is whatever the transport established — `peer_uid`, `peer_sid` (with
`elevated` and `administrator` alongside it), or `peer_token` — so the record is
written in the vocabulary of the boundary that actually authenticated the caller.
`session_id` and `namespace` are `null` on calls they do not apply to. `outcome`
is `ok` or the classification code. Only references are recorded; no value is.

Daemon-initiated events use `"peer_system": true` in place of a caller:
`session_expired` when a session reaches its TTL, `vault_autolocked` when a
provider's unlock TTL lapses, and `session_terminated` when `lock_vault` takes a
live session down with the vault or the exiting daemon reaps one on shutdown.
The file is created mode 0600, and
`audit_log_max_bytes` enables a single rotation to `<path>.1` per daemon process.

## The transport layer

Each target compiles exactly one transport, chosen at build time. Authentication
happens *inside* `accept`: a peer that fails it is refused there and reported as
consumed, so an unauthenticated connection has no path to the RPC layer at all.

**UNIX.** The socket is either inherited from a systemd socket unit or bound by the
daemon. The peer's uid comes from `SO_PEERCRED` — established by the kernel, not
claimable by the client — and is checked against `allowed_uids`. The socket file
itself is mode 0666 because access is decided by that allowlist, not by permission
bits.

**Windows.** Two fronts, one RPC layer behind them.

- The **named pipe** identifies its client by impersonating it and reading the SID
  of its token. `allowed_sids` gates the ordinary RPC surface. The administrative
  methods additionally require the peer to be both elevated and a member of the
  local administrators group, which is why `token issue` and `seal` must be run
  from an elevated shell.
- The **loopback TCP** front carries no operating system identity, so it
  authenticates with a token: the client's first line is a preamble carrying the
  token, which the daemon compares against a stored hash. This is the front the WSL
  client uses. Setting `tcp_port = 0` disables it entirely and leaves the pipe as
  the only way in.

A preamble may also request a **tunnel**, naming a session and a port. The daemon
accepts it only when that port is the CDP port of that active session, and refuses
anything else with `FORBIDDEN`. It is a session handoff, not a port forwarder.

## Sessions

Each login gets its own executor process and its own browser, tagged with the
namespace it came from. The daemon holds the child handle and an expiry, and a
sweeper stops any session past its TTL — 300 seconds by default — auditing a
`session_expired` event as it goes. `logout` does the same on demand and is
idempotent, and `lock_vault` takes down every session belonging to the namespaces
it locks. A daemon asked to stop — a service stop request, `SIGTERM`, or
`SIGINT` — reaps every live executor on its way out, and the executor treats its
stdin closing as that same order, so even a daemon that dies without cleaning up
does not leave browsers running.

Vault sessions are reaped on the same principle by a separate task: an unlocked
provider past its TTL locks itself, per namespace, and the reaper audits
`vault_autolocked` on the transition. Neither kind of lock latches the provider
off — both discard the vault session material, and the next call that needs a
credential value runs the provider's unlock ceremony again.

## The WSL bridge

`crates/tegata-bridge` runs as the agent's user inside WSL. It listens on a UNIX
socket restricted to mode 0600, reads a token file, and relays to the Windows
daemon's TCP front with that token in the preamble. The daemon address defaults to
the WSL default gateway, read from `/proc/net/route`, so a NAT-networked distro
needs no address configured.

This gives the agent-side broker an ordinary UNIX socket to talk to, identical in
shape to the Linux deployment, and keeps the token in a file the broker never
reads. With `TEGATA_BRIDGE=1` the broker additionally asks for a tunnel after each
login and rewrites the returned CDP endpoint to its WSL-local port, so the agent
connects to something reachable without knowing why.

## Where things live

| Path | Role |
| --- | --- |
| `crates/tegatad/src/main.rs` | RPC layer, sessions, audit, leak scan |
| `crates/tegatad/src/provider/` | The `CredentialProvider` trait and its backends |
| `crates/tegatad/src/transport/` | The boundary: `unix.rs`, `windows.rs`, `tcp.rs` |
| `crates/tegatad/src/secure_fs.rs` | Mode bits and protected DACLs for secret-bearing paths |
| `crates/tegatad/src/dpapi.rs` | Sealing and unsealing the master password on Windows |
| `crates/tegatad/src/windows_service.rs` | Service registration, ACLs, firewall rule |
| `crates/tegata-core/src/lib.rs` | The `Secret` type and RFC 6238 TOTP |
| `crates/tegata-core/src/wire.rs` | JSON wire types shared by daemon and clients |
| `crates/tegata-bridge/` | WSL-side socket-to-TCP bridge |
| `crates/leakscan/` | Canary scanner, library and CLI |
| `packages/tegata-mcp/` | The MCP broker |
| `packages/tegata-executor/` | Playwright login executor |
| `nix/module.nix` | `services.tegata` |
| `nix/bridge-module.nix` | `services.tegata-bridge` |
| `nix/vm-test.nix` | The two-user boundary VM test |
