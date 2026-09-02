# Windows and WSL setup

This is the Windows service boundary. The daemon runs as the virtual service
account `NT SERVICE\tegatad`; the agent runs either as an ordinary Windows user or
inside WSL. It is the recommended configuration for a WSL agent.

**Why this shape.** A WSL process reaching Windows — through interop, or through
`/mnt/c` — does so with the privileges of the Windows user who started WSL. It
therefore cannot read files owned by a different local account. Putting the daemon
on the Windows side and the agent inside WSL points the trust boundary away from
the agent. The reverse arrangement, with the daemon inside the distro, is
defeated by the agent launching `powershell.exe` and reading back into the distro
as root.

## How the distro is started matters

The boundary holds only while the WSL side runs under the user's *non-elevated*
token. Interop processes inherit the token of whatever started the distro, and
that includes its elevation. A distro started by a scheduled task set to "run
whether user is logged on or not" runs with the user's full token — high
integrity, `Administrators` enabled — even when the task is marked "run with
limited privileges", because that logon type never receives the UAC split token.
The daemon's elevation gate then accepts `token issue` and `seal` from inside
WSL. The protected files stay protected; what opens up is the administrative RPC
surface, which lets the agent side re-seal the password or invalidate the token.

Start the distro from a non-elevated interactive session: the user's own
terminal, or an at-logon task with the interactive logon type ("run only when
user is logged on") and least privilege. A boot-time task that runs without a
logon is not acceptable on a host that also runs the daemon.

Check before installing, from inside the distro:

```sh
whoami.exe /groups | grep 'Mandatory Level'
```

Expect `Mandatory Label\Medium Mandatory Level`. `High Mandatory Level` means the
launcher is elevated and the gate is open; fix the launcher first.

## Prerequisites on the Windows host

- Node.js LTS
- Bitwarden CLI 2025.12.1 or newer. The CLI only talks to servers over HTTPS;
  if your vault's certificate comes from a private CA, give the service
  `NODE_EXTRA_CA_CERTS` pointing at that CA's certificate — in the system
  environment, or scoped to this service alone through the `Environment` value
  (`REG_MULTI_SZ`) under `HKLM\SYSTEM\CurrentControlSet\Services\<service_name>`.
  The daemon passes its environment on to its bw processes.
- The Playwright browsers, installed into the directory you will configure as
  `browsers_path`, with the version pinned in
  `packages/tegata-executor/package.json`:

  ```powershell
  $env:PLAYWRIGHT_BROWSERS_PATH = "C:\ProgramData\tegata\browsers"
  npx playwright-core@1.61.1 install chromium
  ```

The service account needs read access to the browser directory. `service install`
sets that up for the configured path; if you install the browsers afterwards,
grant the ACL yourself.

## Install

Write the configuration first — `service install` reads it to decide the firewall
rule, the state directory, and the ACLs. `C:\ProgramData\tegata\config.toml` is
the conventional location. Place each configuration at
`C:\ProgramData\<dir>\config.toml`: `service install` resolves junctions and
symbolic links first, treats the configuration's real parent directory as the
protected root, and refuses — before it touches the service manager — any
configuration whose real location is not a directory directly under
`%ProgramData%`.

```toml
state_dir      = "C:\\ProgramData\\tegata\\state"
audit_log_path = "C:\\ProgramData\\tegata\\state\\audit.log"

pipe_name      = "tegatad"
tcp_port       = 21575
tcp_bind       = "auto"
allowed_sids   = ["S-1-5-21-…-1001"]
operator_sid   = "S-1-5-21-…-1001"
browsers_path  = "C:\\ProgramData\\tegata\\browsers"

unlock_mode = "sealed"

[[providers]]
namespace      = "vw"
type           = "bitwarden-cli"
server_url     = "https://vault.example.com"
email          = "vault-account@example.com"
askpass_cmd    = ""
totp_exposable = ["Example Service"]
```

Then, from an **elevated** PowerShell or command prompt:

```
tegatad.exe service install --config C:\ProgramData\tegata\config.toml
```

That single command registers the service under `NT SERVICE\tegatad` with
auto-start, adds an inbound firewall rule for the daemon's TCP port scoped to the
`vEthernet (WSL*` interface, creates `C:\ProgramData\tegata` along with the state
and browser directories, applies a protected DACL to each, and — when
`operator_sid` is set — grants that SID permission to start and stop the service.

The DACL names only the service account and `SYSTEM`. The local administrators
group is deliberately left out: the WSL file server behind `/mnt/c` reads with that
group enabled, so including it would hand the WSL side exactly the read this
boundary exists to prevent. Administrators keep *ownership* of the paths they
created, which is enough to repair a DACL without being enough to read through one.

A consequence worth knowing before you need it: once installed, the configuration
file can no longer be edited from an ordinary elevated shell. Editing it requires
running as `SYSTEM`.

### Issue a client token

```
tegatad.exe token issue
```

Elevated only. The plaintext token is printed to standard output exactly once; the
daemon keeps only its hash. Copy it to the client and store it mode 0600. Running
the command again replaces the stored hash and invalidates the previous token.

### Seal the master password

```
tegatad.exe seal
```

Elevated only. The command prompts for the vault master password and hands it to
the daemon, which seals it with DPAPI under its own account. The daemon unseals it
by itself after every subsequent restart, with no prompt.

This is why `unlock_mode` defaults to `sealed` on Windows: the service runs in
session 0 and cannot draw an interactive prompt at all. `askpass` is available as
an opt-in for a deployment that provides its own helper.

**Never seal a real vault password on a test or development rig.**

### Other commands

| Command | Requires elevation | Purpose |
| --- | --- | --- |
| `tegatad.exe status` | no | Liveness check over the named pipe |
| `tegatad.exe token issue` | yes | Issue a client token |
| `tegatad.exe seal` | yes | Seal the master password |
| `tegatad.exe service install --config <path>` | yes | Register and provision |
| `tegatad.exe service uninstall [--name <name>]` | yes | Remove the service and its firewall rule |
| `tegatad.exe --config <path> --foreground` | — | Run in the foreground for debugging |

Each of the first three takes `--pipe <name>` if the pipe was renamed.

Elevation is not a convention here — the administrative RPCs are refused unless the
calling peer is both elevated and a member of the local administrators group, and
they are refused outright over the TCP front, which carries no operating system
identity.

### Running a second instance

A second daemon has its own `C:\ProgramData\<dir>\config.toml` and unique values
for `service_name`, `pipe_name`, `tcp_port`, `state_dir`, and `browsers_path`.
The `bw_path`, `node_path`, and `executor_entry` values may be shared. Installing
that configuration with `service install` creates the named service, its virtual
account, the `<name> WSL TCP` firewall rule, and the protected DACLs. Choose the
other daemon from CLI commands with `--pipe <name>`; from WSL, point a bridge at
the second instance explicitly with `--daemon-addr <gateway>:<port>`, because
default resolution assumes port `21575` and does not select the second instance.
This supports, for example, an acceptance rig next to the daemon you actually
use, each with its own sealed password.

```toml
service_name    = "tegatad-rig"
pipe_name       = "tegatad-rig"
tcp_port        = 21576
state_dir       = "C:\\ProgramData\\tegata-rig\\state"
audit_log_path  = "C:\\ProgramData\\tegata-rig\\state\\audit.log"
browsers_path   = "C:\\ProgramData\\tegata-rig\\browsers"
```

## Configuration reference

### Top level

| Key | Type | Required | Meaning |
| --- | --- | --- | --- |
| `state_dir` | string | yes | Directory the service account owns |
| `audit_log_path` | string | yes | Where the audit log is appended, created with a protected DACL |
| `audit_log_max_bytes` | integer | no | Rotate to `<path>.1` past this size, at most once per daemon process |
| `unlock_mode` | string | no | `sealed` (default) or `askpass` |
| `session_ttl_secs` | integer | no | Browser session lifetime; default `300` |
| `executor_entry` | string | no | Path to the executor's `index.js` |

`approve_cmd` and `approve_timeout_secs` are UNIX-only. A Windows configuration
containing `approve_cmd` is refused at startup with an explicit error rather than
silently ignored — see [setup-linux.md](setup-linux.md#the-approval-hook).

### Transport

| Key | Default | Meaning |
| --- | --- | --- |
| `service_name` | `tegatad` | Name of the Windows service. The virtual account `NT SERVICE\<name>` and the firewall rule `<name> WSL TCP` are derived from it; `service uninstall --name` takes the same value; allowed characters are ASCII letters, digits, `-`, `_`, and `.`, with 1 to 256 characters |
| `pipe_name` | `tegatad` | Named pipe name, without the `\\.\pipe\` prefix |
| `tcp_port` | `21575` | Loopback TCP port. `0` disables the TCP front entirely |
| `tcp_bind` | `auto` | IPv4 bind address, or `auto` for the WSL adapter |
| `allowed_sids` | `[]` | SIDs permitted to call the ordinary RPC surface over the pipe |
| `operator_sid` | unset | SID granted permission to start and stop the service |
| `token_hash_path` | `<state_dir>\token_hash` | Where the client token hash is stored |
| `sealed_blob_path` | `<state_dir>\sealed.blob` | Where the sealed master password is stored |
| `browsers_path` | unset | Passed to the executor as `PLAYWRIGHT_BROWSERS_PATH` |
| `bw_path` | `bw` | Bitwarden CLI executable |
| `node_path` | `node` | Node.js executable |

An empty `allowed_sids` refuses every ordinary RPC over the pipe — which is the
right setting when only the WSL client, authenticating with a token over TCP,
should be able to reach the daemon.

Set `tcp_port = 0` for a Windows-only deployment with no WSL client. The pipe then
becomes the only way in, and no firewall rule is added.

Provider tables use the same keys as on Linux; see
[setup-linux.md](setup-linux.md#providers). `totp_exposable` matches the entry's
**name**.

Two of the three backends work here. `bitwarden-cli` and `age-file` are
cross-platform; `pass` is UNIX-only, and a Windows configuration containing one is
refused at startup with an explicit error rather than ignored.

The mode-0600 check on an `age-file` identity is UNIX-only, so on Windows nothing
verifies that file for you. Put the entries file and the identity inside the
daemon's state directory, which `service install` gives a protected DACL naming
only the service account and `SYSTEM`; a copy left anywhere else keeps whatever
permissions it was created with, and an identity readable by an interactive
account is the whole vault readable by that account.

## WSL client

The agent's broker talks to an ordinary UNIX socket. `tegata-bridge` provides that
socket and relays to the Windows daemon's TCP front with the token in its preamble.

Install the release binary (x86_64, built against glibc 2.35), or build it from a
checkout:

```sh
curl -fsSLO https://github.com/WakaTaira/tegata/releases/latest/download/tegata-bridge-x86_64-linux-gnu
install -Dm755 tegata-bridge-x86_64-linux-gnu ~/.local/bin/tegata-bridge

# or
cargo build --release -p tegata-bridge
```

Install the token issued by `tegatad.exe token issue`, readable only by its owner:

```sh
install -m 600 /path/to/issued-token ~/.config/tegata/bridge.token
```

Run the bridge as a user systemd unit:

```ini
[Unit]
Description=tegata WSL bridge

[Service]
ExecStart=/path/to/tegata-bridge --socket %h/.local/state/tegata/bridge.sock --token-file %h/.config/tegata/bridge.token
Restart=on-failure

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now tegata-bridge
```

`--daemon-addr` is optional. Without it the bridge reads the default gateway from
`/proc/net/route`, which is the Windows host's address on a NAT-networked distro.
Pass it explicitly for a mirrored-networking distro, where the daemon is reachable
at `127.0.0.1`.

The bridge's own socket is mode 0600, so only the agent's user can use it, and the
token file is never read by the broker.

### Pointing the broker at the bridge

The broker runs inside the distro and is a flake package:

```sh
TEGATA_BRIDGE=1 TEGATA_SOCKET=~/.local/state/tegata/bridge.sock \
  nix run github:WakaTaira/tegata#tegata-mcp
```

Or as MCP client configuration:

```json
{
  "mcpServers": {
    "tegata": {
      "command": "nix",
      "args": ["run", "github:WakaTaira/tegata#tegata-mcp"],
      "env": {
        "TEGATA_BRIDGE": "1",
        "TEGATA_SOCKET": "/home/agent/.local/state/tegata/bridge.sock"
      }
    }
  }
}
```

Without Nix in the distro, build the broker from a checkout — `npm ci && npm
run build --workspace @tegata/mcp` — and use
`node packages/tegata-mcp/dist/index.js` as the command instead.

`TEGATA_BRIDGE=1` matters. The CDP endpoint the daemon returns names a port on the
Windows side, which a NAT-networked WSL client cannot reach. With the flag set, the
broker opens a tunnel for the session after a successful `login` and rewrites the
endpoint to its WSL-local port, so the agent receives something it can connect to
without knowing a tunnel exists.

The daemon accepts a tunnel only for the CDP port of the named active session and
refuses anything else with `FORBIDDEN`. It is a session handoff, not a port
forwarder.

### NixOS bridge module

On a NixOS distro, `nixosModules.tegata-bridge` provides the same thing:

```nix
services.tegata-bridge = {
  enable = true;
  user = "alice";
  tokenFile = "/home/alice/.config/tegata/bridge.token";
  socketPath = "/run/tegata-bridge/bridge.sock";   # default
  # daemonAddr = "127.0.0.1";                      # mirrored networking only
};
```

## Watching a login happen

The service runs in session 0, and the executor launches Chromium headless, so
there is nothing to see on the desktop by design.

To watch a session anyway, attach DevTools to its CDP endpoint from an interactive
session: open `chrome://inspect` in a browser, choose **Configure…**, add the
endpoint's host and port, and select **Inspect** on the discovered target. The
DevTools window is the viewing window; the service session stays invisible.

## Troubleshooting

**Everything returns `INTERNAL`.** The daemon converts every unclassified failure
to `INTERNAL` on purpose — details would be a leak channel. Look at the audit log
in `state_dir` for the method and outcome, and the Windows event log for the
service.

**The browser fails to launch.** The Playwright browser revision must match the
`playwright-core` bundled with the executor, and the service account needs read
access to `browsers_path`. A revision mismatch fails immediately at launch.

**The bridge cannot connect.** Confirm the firewall rule exists and the distro's
gateway address is what the bridge resolved; a mirrored-networking distro needs
`--daemon-addr 127.0.0.1`. Confirm `tcp_port` is not `0`.

**`UNAUTHORIZED` from the bridge.** The token file does not match the stored hash.
Re-issue with `tegatad.exe token issue` and copy the new value; issuing invalidates
the previous token.

**`token issue` or `seal` succeeds from inside WSL without elevation.** The
distro was started from an elevated context, so every interop process carries
the full administrator token. See [How the distro is started
matters](#how-the-distro-is-started-matters).

**The daemon starts but no credential resolves.** The master password has not been
sealed on this machine, or was sealed by a different account. DPAPI blobs are
account- and machine-bound; re-run `tegatad.exe seal`.
