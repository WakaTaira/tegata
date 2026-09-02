# Windows/WSL acceptance rig

These acceptance tests are the Phase 2 contract for `WindowsServiceBoundary`.
They do not run on a plain developer machine: they exercise a real Windows
service reached from inside WSL. The suite fails fast (it never silently
skips) when the rig is not configured — see `requireRig()` in
`support/winrig.ts`.

## Topology

- **The Windows host** — runs the `tegatad` service (virtual account
  `NT SERVICE\tegatad`), the loopback TCP listener, and the named pipe. The
  TCP listener binds the host side of the WSL NAT (the vEthernet (WSL)
  gateway address) and is firewalled to the WSL subnet; vsock was ruled out
  on 2026-08-28 because Windows editions without the Hyper-V VMMS never
  consult `GuestCommunicationServices`, leaving a guest->host AF_HYPERV
  listener unreachable from WSL.
- **The WSL distro** — a WSL2 distro on the Windows host, **NAT networking, interop and
  automount enabled** (the weakest configuration, on purpose: the point is
  that isolation holds even when interop is available). The vitest harness
  runs here. Start the distro from a non-elevated interactive session, never
  from a boot-time task that runs without a logon: that hands interop the
  full administrator token, AC-24 fails, and the harness's `token issue` /
  `seal` calls land on the daemon (see `docs/setup-windows-wsl.md`, "How the
  distro is started matters"). `whoami.exe /groups` must report
  `Medium Mandatory Level`.

## One-time Windows setup (the Windows host, elevated)

1. Install Node LTS, `bw` CLI **2025.12.1 or newer** (the rig runs
   2026.8.0), and the Playwright browsers into the daemon's `browsers_path`,
   then grant that path's ACL to the service account.
2. Mint the throwaway vault certificate on WSL. bw refuses plain-http
   servers, so the harness's vaultwarden serves TLS with this certificate,
   and the service's bw trusts it:

   ```sh
   mkdir -p ~/.config/tegata/test-vault-tls && cd ~/.config/tegata/test-vault-tls
   openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=localhost \
     -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout key.pem -out cert.pem
   ```

   Copy `cert.pem` to `C:\ProgramData\tegata\test-vault-ca.pem`, next to the
   config, before the next step (`service install` protects the directory,
   and the service account reads through that DACL). Point the provider at
   `server_url = "https://localhost:8087"`.
3. `tegatad.exe service install --config C:\ProgramData\tegata\config.toml`
   (registers the service, adds the WSL-subnet-scoped inbound firewall rule
   for the daemon TCP port, creates and ACLs `C:\ProgramData\tegata`, grants
   the operator SID service start/stop).
4. Hand the certificate to the service's bw processes, scoped to this
   service alone rather than the machine environment:

   ```powershell
   Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\tegatad -Name Environment `
     -Type MultiString -Value 'NODE_EXTRA_CA_CERTS=C:\ProgramData\tegata\test-vault-ca.pem'
   Restart-Service tegatad
   ```

   The daemon passes its environment on to bw. `service uninstall` removes
   the value along with the service; set it again after a reinstall.
5. `tegatad.exe token issue` (elevated) — write the printed token to the WSL
   file `TEGATA_TOKEN_FILE` (mode 0600).
6. `tegatad.exe seal` (elevated) — enter the **test** master password
   (never a real vault password). Store the same value in
   `TEGATA_TEST_MASTER_PASSWORD_FILE` on WSL so `provision-test-vault` can
   create a throwaway vault that matches.

## Rig environment (the WSL distro)

Defaults live in `support/winrig.ts`; override via env when the rig differs.

| Env var | Default | Meaning |
| --- | --- | --- |
| `TEGATA_BRIDGE_BIN` | `target/debug/tegata-bridge` | bridge binary |
| `TEGATA_TOKEN_FILE` | `~/.config/tegata/token` | client token (0600) |
| `TEGATA_DAEMON_PORT` | `21575` (`0x5447`) | daemon TCP port |
| `TEGATA_DAEMON_HOST` | WSL default gateway | daemon TCP host override (e.g. `127.0.0.1` on a mirrored-networking rig) |
| `TEGATA_POWERSHELL` | `.../v1.0/powershell.exe` | interop PowerShell |
| `TEGATA_WIN_TEGATAD_EXE` | `/mnt/c/Program Files/tegata/tegatad.exe` | Windows CLI |
| `TEGATA_WIN_PROGRAMDATA` | `/mnt/c/ProgramData/tegata` | protected dir (WSL view) |
| `TEGATA_WIN_SERVICE` | `tegatad` | service name |
| `TEGATA_TEST_VAULT_PORT` | `8087` | throwaway vaultwarden port |
| `TEGATA_TEST_VAULT_EMAIL` | `acceptance@test.local` | test account email |
| `TEGATA_TEST_MASTER_PASSWORD_FILE` | `~/.config/tegata/test-master-password` | sealed test password (0600) |
| `TEGATA_TEST_VAULT_TLS_DIR` | `~/.config/tegata/test-vault-tls` | `cert.pem` + `key.pem` the throwaway vaultwarden serves; the service trusts the same `cert.pem` |

Also required on WSL: `vaultwarden`, `openssl` (once, to mint the
certificate), and the built workspace (`npm run build --workspaces`,
`cargo build`).

## Running

The suite has its own vitest config (serial execution, long interop
timeouts); the root `npm run test:acceptance` covers only the Linux suite.

```sh
nix develop -c npm run test:acceptance:windows
```

## Never

- Never use a real vault password. The sealed password and the test vault's
  master password are the same throwaway value, created only for the rig.
- Never modify anything under `tests/acceptance/` during implementation; this
  suite is the pinned contract.
