# Boundary acceptance tests AC-16..AC-18 (NixOS VM, two-user setup).
# Traceability: docs/secret/briefs/tegata-phase1.md acceptance criteria #16-#18.
#
# Owned by the acceptance suite (gauntlet); do not modify during
# implementation. The flake wires it in as:
#
#   checks.<system>.boundary = import ./nix/vm-test.nix {
#     inherit pkgs;
#     tegataModule = self.nixosModules.tegata;
#     tegataPackages = {
#       # each provides the same-named executable under bin/
#       leakscan = ...;             # bin/leakscan
#       target-fixture = ...;       # bin/tegata-target-fixture
#       provision-test-vault = ...; # bin/provision-test-vault
#     };
#   };
#
# Pinned module contract (services.tegata):
#   enable        : bool
#   allowedUsers  : [str]  — rendered into allowed_uids peer-cred allowlist
#   providers     : [attrset] — rendered into [[providers]] in the TOML config
# The daemon config must land in /var/lib/tegata/config.toml (0600
# tegata:tegata, NOT in the world-readable nix store), and the socket at
# /run/tegata/tegatad.sock.
{ pkgs, tegataModule, tegataPackages }:
let
  support = ../tests/acceptance/support;
  masterPassword = "acceptance-master-password";
  vaultUrl = "https://127.0.0.1:8222";
  fixtureUrl = "http://127.0.0.1:18080";
  credName = "AC Test Site";
  # bw refuses plain-http servers since 2025.10, so the throwaway vault serves TLS
  # with a certificate minted at build time. The key is throwaway too: it only
  # ever exists inside this VM.
  vaultTls = pkgs.runCommand "tegata-boundary-vault-tls" {
    nativeBuildInputs = [ pkgs.openssl ];
  } ''
    mkdir -p $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
      -keyout $out/key.pem -out $out/cert.pem
  '';
  vaultCertificate = "${vaultTls}/cert.pem";
in
pkgs.testers.runNixOSTest {
  name = "tegata-boundary";

  nodes.machine = { pkgs, ... }: {
    imports = [ tegataModule ];

    services.tegata = {
      enable = true;
      allowedUsers = [ "agent" ];
      providers = [
        {
          namespace = "vw";
          type = "bitwarden-cli";
          server_url = vaultUrl;
          email = "acceptance@test.local";
          askpass_cmd = "cat /var/lib/tegata/master-pass";
        }
      ];
    };

    services.vaultwarden = {
      enable = true;
      config = {
        ROCKET_PORT = 8222;
        ROCKET_TLS = ''{certs="${vaultCertificate}",key="${vaultTls}/key.pem"}'';
        SIGNUPS_ALLOWED = true;
        DOMAIN = vaultUrl;
      };
    };

    # The daemon's bw child processes are node programs; this is how node learns
    # to trust the throwaway certificate. The provisioning tool gets the same
    # variable on its command line below.
    systemd.services.tegata.environment.NODE_EXTRA_CA_CERTS = vaultCertificate;

    users.users.agent = { isNormalUser = true; };
    users.users.outsider = { isNormalUser = true; };

    environment.systemPackages = [
      pkgs.nodejs
      tegataPackages.leakscan
      tegataPackages.target-fixture
      tegataPackages.provision-test-vault
    ];

    # Plenty of room: vaultwarden + chromium-driving daemon + node clients.
    virtualisation.memorySize = 4096;
    virtualisation.cores = 2;
  };

  testScript = ''
    import json
    import secrets

    machine.wait_for_unit("vaultwarden.service")
    machine.wait_for_open_port(8222)

    # Per-run canaries: real credential values never appear in this test.
    user_canary = "LEAK_CANARY_vm_user_" + secrets.token_hex(16)
    pass_canary = "LEAK_CANARY_vm_pass_" + secrets.token_hex(16)
    canaries = json.dumps({"canaries": [user_canary, pass_canary]})
    machine.succeed(f"echo '{canaries}' > /root/canaries.json")

    # Provision the throwaway vault: account + one login item (canaries only).
    items = json.dumps([{
        "name": "${credName}",
        "uri": "${fixtureUrl}",
        "username": user_canary,
        "password": pass_canary,
    }])
    machine.succeed(
        f"echo '{items}' | NODE_EXTRA_CA_CERTS=${vaultCertificate} provision-test-vault"
        " --server ${vaultUrl}"
        " --email acceptance@test.local"
        " --password ${masterPassword}"
    )

    # Master password lands in a tegata-owned 0600 file; the daemon reads it
    # through askpass_cmd on the isolated side.
    machine.succeed(
        "printf '%s' '${masterPassword}' > /var/lib/tegata/master-pass"
        " && chown tegata:tegata /var/lib/tegata/master-pass"
        " && chmod 600 /var/lib/tegata/master-pass"
    )
    machine.systemctl("restart tegata.service")
    machine.wait_for_file("/run/tegata/tegatad.sock")

    # Dummy target site, credentials via root-owned file (never argv/env).
    fixture_creds = json.dumps({"username": user_canary, "password": pass_canary})
    machine.succeed(
        f"echo '{fixture_creds}' > /root/fixture-creds.json"
        " && chmod 600 /root/fixture-creds.json"
    )
    machine.succeed(
        "systemd-run --unit=target-fixture"
        " tegata-target-fixture --port 18080 --creds-file /root/fixture-creds.json"
    )
    machine.wait_for_open_port(18080)

    with subtest("AC-16: agent uid cannot read the isolated state"):
        # Given: the two-user VM with tegata running
        # When: the agent user reads the daemon's config, secrets and state
        # Then: every attempt is denied
        machine.fail("su -s /bin/sh agent -c 'cat /var/lib/tegata/config.toml'")
        machine.fail("su -s /bin/sh agent -c 'cat /var/lib/tegata/master-pass'")
        machine.fail("su -s /bin/sh agent -c 'ls /var/lib/tegata'")

    with subtest("AC-17: peer-cred allowlist rejects other uids"):
        # Given: a user outside the allowlist
        # When: it speaks JSON-RPC directly to the socket
        # Then: the connection is rejected (and the allowed agent still works)
        machine.fail(
            "su -s /bin/sh outsider -c"
            " 'node ${support}/vm-rpc.mjs --socket /run/tegata/tegatad.sock --method status'"
        )
        machine.succeed(
            "su -s /bin/sh agent -c"
            " 'node ${support}/vm-rpc.mjs --socket /run/tegata/tegatad.sock --method status'"
        )

    with subtest("AC-18: full E2E as the agent uid, leak-free"):
        # Given: the vault holds canary credentials for the fixture site
        # ps sampling runs for the whole login window (argv leak surface).
        machine.succeed(
            "( while true; do ps -eo args >> /root/ps-samples.txt; sleep 0.2; done )"
            " >/dev/null 2>&1 & echo $! > /root/ps-sampler.pid"
        )
        # When: the agent runs catalog → login → raw-CDP DOM inspection
        machine.succeed(
            "su -s /bin/sh agent -c"
            " 'node ${support}/vm-e2e.mjs"
            " --socket /run/tegata/tegatad.sock"
            " --target-url ${fixtureUrl}"
            " --cred-name \"${credName}\""
            " --out /home/agent/obs.json'"
        )
        machine.succeed("kill $(cat /root/ps-sampler.pid)")
        # Then: the session is logged in (vm-e2e exit code checked above) and
        # no canary appears in anything the agent observed or could read
        machine.succeed(
            "leakscan --canaries /root/canaries.json --json"
            " /home/agent /root/ps-samples.txt /tmp"
        )
  '';
}
