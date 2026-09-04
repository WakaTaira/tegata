{ tegatadPackage, executorEntry, bitwardenCliPackage, playwrightBrowsersPackage }:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.tegata;
  effectiveExecutorEntry = if cfg.executorEntry != null then cfg.executorEntry else executorEntry;

  tomlValue = value:
    if builtins.isString value then builtins.toJSON value
    else if builtins.isBool value then if value then "true" else "false"
    else if builtins.isInt value then builtins.toString value
    else if builtins.isList value then
      "[${lib.concatStringsSep ", " (map tomlValue value)}]"
    else throw "services.tegata: unsupported TOML value";

  renderAssignments = attrs:
    lib.concatStringsSep "\n" (
      map (name: "${name} = ${tomlValue (builtins.getAttr name attrs)}")
        (lib.attrNames attrs)
    );

  renderEntry = entry:
    "\n[[providers.entries]]\n${renderAssignments entry}";

  renderProvider = provider:
    let
      values = lib.filterAttrs (name: value:
        name != "entries" && value != null
      ) provider;
    in
      "[[providers]]\n${renderAssignments values}"
      + lib.concatStringsSep "" (map renderEntry provider.entries);

  baseConfig = {
    executor_socket = "/run/tegata-executor/executor.sock";
    state_dir = "/var/lib/tegata";
    audit_log_path = "/var/lib/tegata/audit.log";
  } // lib.optionalAttrs (cfg.executorEntry != null) {
    executor_entry = cfg.executorEntry;
  } // lib.optionalAttrs (cfg.sessionTtlSecs != null) {
    session_ttl_secs = cfg.sessionTtlSecs;
  } // lib.optionalAttrs (cfg.approveCmd != null) {
    approve_cmd = cfg.approveCmd;
  } // lib.optionalAttrs (cfg.approveTimeoutSecs != null) {
    approve_timeout_secs = cfg.approveTimeoutSecs;
  } // lib.optionalAttrs (cfg.auditLogMaxBytes != null) {
    audit_log_max_bytes = cfg.auditLogMaxBytes;
  };

  unixListenConfig = ''
    [[listen]]
    kind = "unix"
    path = "/run/tegata/tegatad.sock"
    allowed_uids = [__TEGATA_ALLOWED_UIDS__]
    operator_uids = ${tomlValue cfg.operatorUids}
  '';

  tcpListenConfig = lib.optionalString (cfg.listen.tcp != null) ''
    [[listen]]
    kind = "tcp"
    bind = ${tomlValue cfg.listen.tcp.bind}
    port = ${tomlValue cfg.listen.tcp.port}
  '';

  configTemplate = ''
    ${renderAssignments baseConfig}

    ${unixListenConfig}
    ${tcpListenConfig}

    ${lib.concatStringsSep "\n\n" (map renderProvider cfg.providers)}
  '';

  allowedUserArgs = lib.concatStringsSep " " (map lib.escapeShellArg cfg.allowedUsers);
in
{
  options.services.tegata = {
    enable = lib.mkEnableOption "the tegata credential isolation daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = tegatadPackage;
      description = "The tegatad package to run.";
    };

    allowedUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Users allowed to connect to the tegatad socket.";
    };

    listen = {
      tcp = lib.mkOption {
        type = lib.types.nullOr (lib.types.submodule {
          options = {
            bind = lib.mkOption {
              type = lib.types.str;
              description = "Address on which the daemon's TCP listener binds.";
            };
            port = lib.mkOption {
              type = lib.types.port;
              description = "Port on which the daemon's TCP listener binds.";
            };
          };
        });
        default = null;
        description = "Bind the daemon's TCP front (named-token peers such as the container bridge) to this address and port; null = no TCP listener.";
      };
    };

    operatorUids = lib.mkOption {
      type = lib.types.listOf lib.types.int;
      default = [];
      description = "UIDs allowed to call the administrative RPCs (peer issue/revoke/list) over the UNIX socket, in addition to root.";
    };

    providers = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          namespace = lib.mkOption { type = lib.types.str; };
          type = lib.mkOption { type = lib.types.str; };
          entries = lib.mkOption {
            type = lib.types.listOf (lib.types.attrsOf lib.types.anything);
            default = [];
          };
          server_url = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          email = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          askpass_cmd = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          totp_exposable = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
          };
          session_ttl_secs = lib.mkOption {
            type = lib.types.nullOr lib.types.ints.unsigned;
            default = null;
          };
          entries_path = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          identity_path = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          store_dir = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          gnupghome = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
          pass_bin = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
          };
        };
      });
      default = [];
      description = "Provider configurations written to the daemon TOML file.";
    };

    executorEntry = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = executorEntry;
      description = "Path to the tegata executor entrypoint.";
    };

    sessionTtlSecs = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = null;
      description = "Default daemon session lifetime in seconds.";
    };

    approveCmd = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Command used to approve sensitive operations.";
    };

    approveTimeoutSecs = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = null;
      description = "Approval command timeout in seconds.";
    };

    auditLogMaxBytes = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = null;
      description = "Maximum audit log size in bytes.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.listen.tcp == null
          || !(builtins.elem cfg.listen.tcp.bind [ "0.0.0.0" "::" "auto" ]);
        message = "services.tegata.listen.tcp.bind must be a specific address, not 0.0.0.0, ::, or auto.";
      }
    ];

    users.groups.tegata = {};
    users.groups.tegata-browser = {};
    users.users.tegata = {
      isSystemUser = true;
      group = "tegata";
    };
    users.users.tegata-browser = {
      isSystemUser = true;
      group = "tegata-browser";
    };

    environment.systemPackages = [ bitwardenCliPackage ];

    systemd.tmpfiles.rules = [
      "d /var/lib/tegata 0700 tegata tegata -"
      "d /run/tegata 0755 tegata tegata -"
      "d /run/tegata-executor 0755 root root -"
    ];

    systemd.sockets.tegata = {
      description = "Tegata daemon socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/tegata/tegatad.sock" ];
      socketConfig = {
        SocketMode = "0666";
        SocketUser = "tegata";
        SocketGroup = "tegata";
      };
    };

    systemd.sockets.tegata-executor = {
      description = "Tegata executor socket";
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/tegata-executor/executor.sock" ];
      socketConfig = {
        Accept = true;
        SocketUser = "tegata";
        SocketGroup = "tegata";
        SocketMode = "0600";
        MaxConnections = 16;
      };
    };

    systemd.services."tegata-executor@" = {
      description = "Tegata executor";
      serviceConfig = {
        User = "tegata-browser";
        Group = "tegata-browser";
        ExecStart = "${pkgs.nodejs}/bin/node ${effectiveExecutorEntry}";
        UMask = "0077";
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        Environment = [ "PLAYWRIGHT_BROWSERS_PATH=${playwrightBrowsersPackage}" ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      };
    };

    systemd.services.tegata = {
      description = "Tegata credential isolation daemon";
      wantedBy = [ "multi-user.target" ];
      requires = [ "tegata.socket" "tegata-executor.socket" ];
      after = [ "network.target" "tegata.socket" "tegata-executor.socket" ];
      # sh is needed because frozen tegatad code shells out via Command::new("sh");
      # /bin/sh is provided by NixOS, but this unit's path list replaces PATH entirely.
      path = [ pkgs.coreutils pkgs.nodejs pkgs.bash bitwardenCliPackage ];

      preStart = ''
        set -eu
        allowed_uids=""
        for user in ${allowedUserArgs}; do
          uid="$(${pkgs.coreutils}/bin/id -u "$user")"
          if [ -n "$allowed_uids" ]; then
            allowed_uids="$allowed_uids, "
          fi
          allowed_uids="$allowed_uids$uid"
        done

        umask 077
        tmp="$(${pkgs.coreutils}/bin/mktemp /var/lib/tegata/config.toml.XXXXXX)"
        trap '${pkgs.coreutils}/bin/rm -f "$tmp"' EXIT
        ${pkgs.gnused}/bin/sed \
          "s/__TEGATA_ALLOWED_UIDS__/$allowed_uids/" \
          > "$tmp" <<'TEGATA_CONFIG'
        ${configTemplate}
        TEGATA_CONFIG
        ${pkgs.coreutils}/bin/chmod 600 "$tmp"
        ${pkgs.coreutils}/bin/mv -f "$tmp" /var/lib/tegata/config.toml
        trap - EXIT
      '';

      serviceConfig = {
        Type = "simple";
        User = "tegata";
        Group = "tegata";
        ExecStart = "${cfg.package}/bin/tegatad --config /var/lib/tegata/config.toml";
        Restart = "on-failure";
        RestartSec = 1;
        UMask = "0077";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        ReadWritePaths = [ "/var/lib/tegata" "/run/tegata" ];
        Environment = [
          # Use the browser package injected by the flake rather than the host-side pkgs so that
          # its revision matches the playwright-core bundled with the executor (see flake.nix).
          "PLAYWRIGHT_BROWSERS_PATH=${playwrightBrowsersPackage}"
        ] ++ lib.optional (cfg.executorEntry != null) "TEGATA_EXECUTOR_ENTRY=${cfg.executorEntry}";
      };
    };
  };
}
