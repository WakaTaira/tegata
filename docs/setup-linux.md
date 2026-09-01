# Linux setup

This is the systemd boundary: the daemon runs as a dedicated user, listens on a
UNIX socket, and authenticates callers with `SO_PEERCRED`. The agent runs as an
ordinary user with no path to the daemon's files.

For a WSL agent, prefer the Windows service boundary instead — see
[setup-windows-wsl.md](setup-windows-wsl.md) — unless interop is disabled in the
distro. With interop enabled, an agent inside WSL can launch `powershell.exe` and
read back into the distro as root, which defeats a boundary that lives in the same
distro.

## NixOS

The flake exposes `nixosModules.tegata`. A minimal deployment:

```nix
{
  imports = [ tegata.nixosModules.tegata ];

  services.tegata = {
    enable = true;
    allowedUsers = [ "alice" ];          # the user the agent runs as
    providers = [{
      namespace = "vw";
      type = "bitwarden-cli";
      server_url = "https://vault.example.com";
      email = "vault-account@example.com";
      askpass_cmd = "/run/current-system/sw/bin/tegata-askpass";
      totp_exposable = [ "Example Service" ];
    }];
  };
}
```

The module creates the `tegata` system user and group, lays out
`/var/lib/tegata` mode 0700 and `/run/tegata` for the socket, writes the
configuration file mode 0600 at activation, and runs the daemon under a hardened
unit with `ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`, an
empty capability bounding set, and write access limited to its own two
directories.

`allowedUsers` are resolved to uids in the unit's `preStart`, so the allowlist is
written in terms of user names and enforced in terms of uids.

### Module options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `services.tegata.enable` | bool | `false` | Enable the daemon |
| `services.tegata.package` | package | the flake's `tegatad` | Which build to run |
| `services.tegata.allowedUsers` | list of string | `[]` | Users permitted to connect to the socket |
| `services.tegata.providers` | list of submodule | `[]` | Providers written into the daemon's TOML |
| `services.tegata.executorEntry` | null or string | the flake's executor | Path to the executor entry point |
| `services.tegata.sessionTtlSecs` | null or unsigned | `null` (300s) | Default session lifetime |
| `services.tegata.auditLogMaxBytes` | null or unsigned | `null` | Rotate the audit log past this size |
| `services.tegata.approveCmd` | null or string | `null` | Approval command gating each login |
| `services.tegata.approveTimeoutSecs` | null or unsigned | `null` (60s) | Approval command timeout |

Provider submodule fields: `namespace`, `type`, `server_url`, `email`,
`askpass_cmd`, `totp_exposable`, `session_ttl_secs`, and `entries` (used only by
the mock provider in tests).

The module ships the Bitwarden CLI from the flake's nixpkgs, and the CLI only
talks to servers over HTTPS. For a vault whose certificate comes from a private
CA, set `systemd.services.tegata.environment.NODE_EXTRA_CA_CERTS` to that CA's
certificate; the daemon passes its environment on to bw. The boundary test in
`nix/vm-test.nix` does exactly this for its throwaway vault.

The bridge module `nixosModules.tegata-bridge` is documented in
[setup-windows-wsl.md](setup-windows-wsl.md#nixos-bridge-module); it is only useful
when the daemon is a Windows service.

### Playwright browsers

The module passes `PLAYWRIGHT_BROWSERS_PATH` from the flake's own nixpkgs rather
than the host's. The browser revision has to match the `playwright-core` bundled
with the executor; a host `playwright-driver` can drift far enough that the browser
fails to launch at all.

## Without Nix

Each [release](https://github.com/WakaTaira/tegata/releases) ships prebuilt
artifacts for x86_64 Linux: `tegatad-x86_64-linux-gnu` (glibc 2.35 baseline),
`tegata-executor-node.tar.gz` (the executor `index.js` with `playwright-core`
beside it), and `tegata-mcp-node.tar.gz` (the broker with its production
dependencies), plus `SHA256SUMS`. Unpack a bundle anywhere and point
`executor_entry` or the agent at its `index.js`.

Otherwise build the daemon and the executor from a checkout:

```sh
cargo build --release -p tegatad
sudo install -Dm755 target/release/tegatad /usr/local/bin/tegatad

npm ci
npm run build --workspace @tegata/executor
```

The executor is not a single file: `packages/tegata-executor/dist/index.js`
resolves `playwright-core` from the workspace's `node_modules` at run time. Set
`executor_entry` to that `dist/index.js` and leave the checkout's
`node_modules` in place, or copy the two side by side preserving the layout.
Install the browsers with the version pinned in
`packages/tegata-executor/package.json`:

```sh
npx playwright-core@1.61.1 install chromium
```

Run the daemon as a dedicated user with a systemd unit of your own:

```ini
[Unit]
Description=tegata credential isolation daemon
Requires=tegata.socket
After=network.target tegata.socket

[Service]
Type=simple
User=tegata
Group=tegata
ExecStart=/usr/local/bin/tegatad --config /var/lib/tegata/config.toml
Restart=on-failure
UMask=0077
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
ReadWritePaths=/var/lib/tegata /run/tegata

[Install]
WantedBy=multi-user.target
```

With a matching socket unit listening on `/run/tegata/tegatad.sock`, the daemon
inherits the socket through socket activation. Without one, it binds the path
itself.

Requirements on the host: Node.js for the executor, and the Bitwarden CLI on
`PATH` if a `bitwarden-cli` provider is configured — 2025.12.1 or newer, the
first release without the session-key persistence race the daemon otherwise
retries around. The CLI only talks to servers over HTTPS; if your vault's
certificate comes from a private CA, add `Environment=NODE_EXTRA_CA_CERTS=…` to
the unit and the daemon passes it on to bw. The executor finds the browsers
through `PLAYWRIGHT_BROWSERS_PATH`; the install above lands them in the cache of
whoever ran it, so either install them as the daemon's user or set
`Environment=PLAYWRIGHT_BROWSERS_PATH=…` in the unit to a directory that user
can read.

Set up the accounts and permissions to match the
[operator checklist](security.md#operator-checklist) — in particular, the agent's
user must have no sudo path to the `tegata` user, and
`kernel.yama.ptrace_scope` should be at least 1.

## Configuration reference

The daemon reads one TOML file, given with `--config`. It must be owned by the
daemon's user and mode 0600.

```toml
socket_path    = "/run/tegata/tegatad.sock"
state_dir      = "/var/lib/tegata"
audit_log_path = "/var/lib/tegata/audit.log"
allowed_uids   = [1000]

session_ttl_secs = 300

[[providers]]
namespace      = "vw"
type           = "bitwarden-cli"
server_url     = "https://vault.example.com"
email          = "vault-account@example.com"
askpass_cmd    = "/usr/local/libexec/tegata-askpass"
totp_exposable = ["Example Service"]
session_ttl_secs = 900
```

### Top level

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `socket_path` | string | yes | Path of the UNIX socket the daemon listens on |
| `state_dir` | string | yes | Directory the daemon owns; holds per-provider CLI state |
| `audit_log_path` | string | yes | Where the audit log is appended, created mode 0600 |
| `audit_log_max_bytes` | integer | no | Rotate to `<path>.1` past this size, at most once per daemon process. Unset means no rotation |
| `allowed_uids` | list of integer | yes | uids permitted to connect. An empty list admits nobody |
| `session_ttl_secs` | integer | no | Browser session lifetime; default `300` |
| `approve_cmd` | string | no | Command that must approve each `login`. Unset means no approval gate |
| `approve_timeout_secs` | integer | no | How long to wait for that command; default `60` |
| `executor_entry` | string | no | Path to the executor's `index.js`. May also come from `TEGATA_EXECUTOR_ENTRY` |

### `[[providers]]`

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `namespace` | string | yes | Prefix for this provider's credential ids |
| `type` | string | yes | `bitwarden-cli`, `age-file`, or `pass` |

Every provider table carries those two; the rest depend on `type`. The namespace is
an arbitrary label you choose — nothing derives it from the backend, which is the
point: the agent cannot tell from an id's shape what is behind it.

#### `type = "bitwarden-cli"`

Drives the `bw` CLI against Bitwarden's cloud, a self-hosted Bitwarden, or
Vaultwarden.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `server_url` | string | yes | Vault server |
| `email` | string | yes | Vault account address |
| `askpass_cmd` | string | yes | Command that supplies the master password |
| `totp_exposable` | list of string | no | Item **names** whose current code `get_totp` may return |
| `session_ttl_secs` | integer | no | Unlock lifetime; defaults to the global value |

#### `type = "age-file"`

An age-encrypted TOML file. The daemon decrypts it in process with the pure-Rust
age crate — no CLI to install, no agent to keep running.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `entries_path` | string | yes | The age-encrypted entries file |
| `identity_path` | string | yes | X25519 identity file. **Must be mode 0600**, or the daemon refuses to start |
| `session_ttl_secs` | integer | no | Lifetime of the decrypted entries in memory |

The plaintext inside `entries_path` is a TOML document of `[[entries]]` tables:

```toml
[[entries]]
id             = "example"
name           = "Example Service"
uri            = "https://example.com/login"
kind           = "login"
username       = "agent@example.com"
password       = "…"
totp_seed      = "…"      # optional
totp_exposable = false    # optional, defaults to false
```

Creating the pair is one `age` ceremony, done as the daemon's user:

```sh
age-keygen -o identity.txt           # prints the recipient public key
age -r age1… -o entries.toml.age entries.toml
shred -u entries.toml
chmod 600 identity.txt
```

Decryption is lazy — it happens on the first call that needs a value, not at
startup. Locking zeroes the decrypted values, and the next such call decrypts
again.

That makes `age-file` the provider to reach for on an unattended host: its unlock
ceremony is a file read rather than a human, so nothing blocks waiting for a
person. The trade is that whoever can read both files has the credentials, which is
why the identity file's mode is enforced rather than merely recommended.

A failed decryption reaches the agent as `INTERNAL`; the reason goes to the
daemon's stderr only.

#### `type = "pass"`

GNU pass. UNIX only — a Windows configuration containing a `pass` provider is
refused at startup with an explicit error.

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `store_dir` | string | yes | Root of the password store |
| `gnupghome` | string | no | Passed to `pass` as `GNUPGHOME` |
| `pass_bin` | string | no | The `pass` executable; defaults to `pass` |
| `totp_exposable` | list of string | no | Entry **names** whose current code `get_totp` may return |
| `session_ttl_secs` | integer | no | Lifetime of resolved values in memory |

The catalog comes from scanning `store_dir` for `*.gpg`. An entry's name and its id
are both the store-relative path without the extension, so
`store_dir/sites/example.gpg` is `sites/example` — with a namespace of `pw`, the
agent sees `pw:sites/example`.

Resolution runs `pass show <name>` in its own process group, under a 60-second
timeout that kills the whole group. Its output is read as:

| Part of the entry | How it is read |
| --- | --- |
| Password | The first line |
| Username | A `username:` line, or a `login:` line; `username:` wins if both appear |
| TOTP seed | The `secret` parameter of any line containing an `otpauth://` URI |

Reading the seed straight out of the `otpauth://` line means TOTP works without the
`pass-otp` extension installed.

**A `url:` line is not read.** The catalog `uri` for a pass entry is always empty.
That costs nothing in practice, since `login` navigates to the `target_url` the
agent supplies rather than to the catalog's `uri` — but do not expect the field to
be populated.

**Locking does not touch `gpg-agent`.** It discards the values tegata resolved;
whether `gpg` then asks for a passphrase again is `gpg-agent`'s business. The
daemon takes no part in supplying that passphrase, so an unattended deployment
needs either a passphrase-less key or a `gpg-agent` and `pinentry` the operator has
arranged to answer with no human present. This is the one provider whose headless
operation depends on configuration outside tegata.

### Running several backends at once

Providers are not an either/or. Register as many as you like, each under its own
namespace, and the agent sees a single catalog:

```toml
[[providers]]
namespace      = "vw"
type           = "bitwarden-cli"
server_url     = "https://vault.example.com"
email          = "vault-account@example.com"
askpass_cmd    = "/usr/local/libexec/tegata-askpass"
totp_exposable = ["Example Service"]

[[providers]]
namespace        = "ci"
type             = "age-file"
entries_path     = "/var/lib/tegata/ci-entries.toml.age"
identity_path    = "/var/lib/tegata/ci-identity.txt"
session_ttl_secs = 3600
```

That deployment resolves `vw:a1b2c3` from Vaultwarden behind a human askpass
prompt and `ci:deploy-bot` from an encrypted file with nobody involved. The agent
calls `login` identically for both and cannot tell them apart except by reading the
`source` field.

Lock state, TTLs, and unlock ceremonies are per namespace, which is the whole
point: a `bw` session and an age file have nothing in common in how long they
should stay open. Locking one leaves the others listing and resolving normally.

`totp_exposable` matches an entry's **name**, and the default is an empty list: no
credential exposes a code to the agent unless it is named there. See
[security.md](security.md#totp) before adding anything to it.

## The askpass command

`askpass_cmd` is how the master password enters the daemon. The daemon runs it
through `sh -c` with stdin closed and stderr discarded, and reads the **first line
of its stdout** as the password.

The rule that matters is not how the prompt looks; it is who owns the input
channel. The password must be typed into something belonging to the isolated side.
Typing it into a terminal that shares a session with the agent defeats the
boundary no matter how the characters are masked.

Workable shapes:

- A prompt program running as the daemon's user — a `pinentry` variant, or an
  equivalent — so the keystrokes land in a process the agent cannot read.
- A named FIFO owned by the daemon's user, mode 0600, written by an operator from
  a session that is not the agent's (an `ssh` as the daemon's user, or a root
  shell). `askpass_cmd` then reads one line from it and the daemon blocks until an
  operator supplies it.
- `systemd-ask-password`, if the deployment gives the daemon's user access to the
  ask-password directory.

The command must not read from a terminal shared with the agent, and must not
retrieve the password from anywhere the agent's user can read — a file mode 0600
owned by the daemon's user is acceptable, but understand that this trades the
vault's own at-rest encryption for an OS permission boundary. Prefer an
interactive prompt unless the deployment truly needs to survive reboots
unattended.

The password is never passed to `bw` on a command line. The daemon writes it to a
private file inside the state directory, hands `bw` a `--passwordfile` path, and
deletes the file as soon as the command returns.

The command runs on the first call that needs a credential value, and again
whenever the vault session has gone — after the TTL expires, after `lock_vault`,
and after a daemon restart. It does not run for `list_credentials`, which answers
from the cached catalog while locked.

`session_ttl_secs` is therefore a genuine dial rather than a fuse: a shorter TTL
narrows the window in which unlocked material sits in the daemon's memory, and
costs a prompt each time it lapses. An unattended deployment that cannot answer a
prompt wants either a TTL long enough to cover its working period or the `sealed`
unlock mode, which is why that is the Windows default.

## The approval hook

`approve_cmd` puts a human in front of every `login`. Without it, an agent that has
been talked into a login by an injected instruction makes a call indistinguishable
from a legitimate one; with it, someone has to say yes first.

```toml
approve_cmd          = "/usr/local/libexec/tegata-approve"
approve_timeout_secs = 60
```

The daemon runs the command through `sh -c` on the isolated side and reads the exit
status: **zero approves, anything else denies.** No answer within
`approve_timeout_secs` kills the command's whole process group and fails the login
with `APPROVAL_TIMEOUT`. Three environment variables describe the request, and
nothing else is passed — no credential value ever reaches the hook:

| Variable | Contents |
| --- | --- |
| `TEGATA_CRED_ID` | The namespaced credential reference |
| `TEGATA_TARGET_URL` | The login destination |
| `TEGATA_PEER` | The calling peer's uid, in decimal |

A graphical prompt is the simplest workable hook, since the exit status is already
the answer:

```sh
#!/bin/sh
# Exit 0 approves, anything else denies. The hook is given references only.
exec zenity --question --title="tegata" \
  --text="Approve login to $TEGATA_TARGET_URL as $TEGATA_CRED_ID (uid $TEGATA_PEER)?"
```

That requires the daemon's user to be able to reach a display, which is a
deployment decision. A headless host wants the other shape instead: a script that
sends a push notification and blocks on the reply, exiting non-zero on refusal and
letting the timeout handle silence. Either way the command runs as the daemon's
user, so an approval prompt is not something the agent can draw, dismiss, or
answer.

Two ordering details worth knowing:

- The gate runs after the credential is confirmed to exist and be reachable, so a
  bogus `cred_id` fails with `INVALID_CREDENTIAL` without raising a prompt. That
  ordering is deliberate: approving first would let the agent raise a prompt with
  any string it liked, and an operator interrupted for nothing soon starts
  approving without reading.
- That confirmation step lists the provider's catalog. On a daemon that has not
  unlocked the vault yet, this means the `askpass` prompt comes first and the
  approval prompt second; once the vault is unlocked, only the approval prompt
  appears. A refused login can therefore leave the vault unlocked — acceptable
  because unlocking is itself a human ceremony and no value reaches the agent
  either way, but worth knowing before you see it happen.

`approve_cmd` is UNIX-only. A Windows configuration containing it is refused at
startup rather than ignored.

## Connecting an agent

The broker is a flake package; nothing needs a checkout. Point it at the socket:

```sh
TEGATA_SOCKET=/run/tegata/tegatad.sock nix run github:WakaTaira/tegata#tegata-mcp
```

For Claude Code, registration is one command:

```sh
claude mcp add tegata --env TEGATA_SOCKET=/run/tegata/tegatad.sock \
  -- nix run github:WakaTaira/tegata#tegata-mcp
```

Or, as MCP client configuration:

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

Without Nix, build the broker from a checkout and use `node` with the built
entry point as the command:

```sh
npm ci
npm run build --workspace @tegata/mcp
TEGATA_SOCKET=/run/tegata/tegatad.sock node packages/tegata-mcp/dist/index.js
```

Then deny the agent every other route to the same secrets — direct `bw` invocation
and any socket client it could write. tegata isolates the vault, but it cannot stop
an agent that is separately allowed to run `bw get password` itself.

## Verifying the boundary

```sh
nix flake check
```

The `boundary` check builds a two-user NixOS VM and asserts the things this whole
setup exists to guarantee: the agent's user cannot read the daemon's state, a peer
whose uid is not on the allowlist is refused at the socket while the allowed one
succeeds, and a complete login driven as the agent's uid — with `ps -eo args`
sampled for the whole login window — leaves no canary anywhere that user can
observe or read.

For a quick liveness check against a running daemon, the `status` method answers
`{"ok": true}`:

```sh
printf '{"jsonrpc":"2.0","id":1,"method":"status"}\n' | nc -U /run/tegata/tegatad.sock
```

## Development

```sh
nix develop
```

The shell provides `rustc`, `cargo`, `clippy`, `rustfmt`, `nodejs_24`, `biome`,
`bitwarden-cli`, `vaultwarden`, and `playwright-driver`.

```sh
nix develop -c cargo build
nix develop -c cargo test --features mock-provider
nix develop -c npm run test:acceptance
nix develop -c biome check .
```

`npm run test:acceptance` builds the workspaces and the `tegatad` and `leakscan`
binaries first, then runs the suite under Vitest against a mock provider — no real
vault, no real credential.
