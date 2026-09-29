{ tegatadPackage, executorEntry, bitwardenCliPackage, playwrightBrowsersPackage }:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.tegata;
  effectiveExecutorEntry = if cfg.executorEntry != null then cfg.executorEntry else executorEntry;

  tomlValue = value:
    if builtins.isString value then builtins.toJSON value
    else if builtins.isBool value then if value then "true" else "false"
    else if builtins.isInt value then builtins.toString value
    else if builtins.isAttrs value then
      "{ ${lib.concatStringsSep ", " (map (name: "${name} = ${tomlValue (builtins.getAttr name value)}") (lib.attrNames value))} }"
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

  renderApiProxy = name: proxy:
    "[[api_proxy]]\n${renderAssignments (lib.filterAttrs (_: value: value != null) {
      inherit name;
      cred_id = proxy.credId;
      upstream = proxy.upstream;
      header = proxy.header;
      value = proxy.value;
    })}"
    + lib.optionalString (proxy.oauth != null) "\n[api_proxy.oauth]\n${renderAssignments (lib.filterAttrs (_: value: value != null) {
      client_id = proxy.oauth.clientId;
      device_authorization_url = proxy.oauth.deviceAuthorizationUrl;
      token_url = proxy.oauth.tokenUrl;
      revocation_url = proxy.oauth.revocationUrl;
      scope = proxy.oauth.scope;
      login_cred_id = proxy.oauth.loginCredId;
      steps = proxy.oauth.steps;
      success_selector = proxy.oauth.successSelector;
      failure_selector = proxy.oauth.failureSelector;
    })}";

  renderMcpServer = name: mcpServer:
    "[[mcp_server]]\n${renderAssignments {
      inherit name;
      cred_id = mcpServer.credId;
      command = mcpServer.command;
      args = mcpServer.args;
    }}"
    + lib.optionalString (mcpServer.env != {}) "\n[mcp_server.env]\n${renderAssignments mcpServer.env}";

  baseConfig = {
    executor_socket = "/run/tegata-executor/executor.sock";
    state_dir = "/var/lib/tegata";
    audit_log_path = "/var/lib/tegata/audit.log";
  } // lib.optionalAttrs (cfg.executorEntry != null) {
    executor_entry = cfg.executorEntry;
  } // lib.optionalAttrs (cfg.sessionTtlSecs != null) {
    session_ttl_secs = cfg.sessionTtlSecs;
  } // {
    browser_max_lifetime_secs = cfg.browserMaxLifetimeSecs;
  } // lib.optionalAttrs (cfg.approveCmd != null) {
    approve_cmd = cfg.approveCmd;
    approval_grant_ttl_secs = cfg.approvalGrantTtlSecs;
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

    ${lib.concatStringsSep "\n\n" (lib.mapAttrsToList renderApiProxy cfg.apiProxies)}

    ${lib.concatStringsSep "\n\n" (lib.mapAttrsToList renderMcpServer cfg.mcpServers)}
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
      type = lib.types.listOf lib.types.ints.unsigned;
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
          persist_cookies = lib.mkOption {
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

    apiProxies = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          credId = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "The namespaced credential reference whose value is injected.";
          };
          upstream = lib.mkOption {
            type = lib.types.str;
            description = "The fixed upstream base URL requests are relayed to.";
          };
          header = lib.mkOption {
            type = lib.types.str;
            default = "Authorization";
            description = "The header the injected value is written to.";
          };
          value = lib.mkOption {
            type = lib.types.str;
            default = "Bearer {{secret}}";
            description = "The header value template; {{secret}} is replaced with the credential's password.";
          };
          oauth = lib.mkOption {
            type = lib.types.nullOr (lib.types.submodule {
              options = {
                clientId = lib.mkOption {
                  type = lib.types.str;
                  description = "The public OAuth client ID sent with the device authorization, token, and revocation requests.";
                };
                deviceAuthorizationUrl = lib.mkOption {
                  type = lib.types.str;
                  description = "The device authorization endpoint; https://, or http:// to a loopback host, as for upstream.";
                };
                tokenUrl = lib.mkOption {
                  type = lib.types.str;
                  description = "The token endpoint for the device-code and refresh-token grants; https://, or http:// to a loopback host, as for upstream.";
                };
                revocationUrl = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  description = "The RFC 7009 revocation endpoint called when the lease ends; https://, or http:// to a loopback host, as for upstream. null = no revocation.";
                };
                scope = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  description = "The scope requested with the device authorization; null = no scope parameter.";
                };
                loginCredId = lib.mkOption {
                  type = lib.types.str;
                  description = "The namespaced credential reference used to log into the provider in the browser.";
                };
                steps = lib.mkOption {
                  type = lib.types.nullOr (lib.types.listOf lib.types.attrs);
                  default = null;
                  description = "Explicit device-approval steps, as for authorize_device; null = the default device-flow procedure.";
                };
                successSelector = lib.mkOption {
                  type = lib.types.str;
                  description = "The selector that identifies a successful approval.";
                };
                failureSelector = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                  description = "The selector that identifies a rejected approval; null = no rejection check.";
                };
              };
            });
            default = null;
            description = "OAuth device-flow client configuration for the proxy.";
          };
        };
      });
      default = {};
      description = "Injection proxies (open_api_proxy), keyed by the name an agent passes to open_api_proxy.";
    };

    mcpServers = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          credId = lib.mkOption {
            type = lib.types.str;
            description = "The namespaced credential reference whose values fill the env placeholders.";
          };
          command = lib.mkOption {
            type = lib.types.str;
            description = "Absolute path to the stdio MCP server binary.";
          };
          args = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            description = "Arguments passed to the server on startup.";
          };
          env = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            description = "Environment variables passed to the server; values may contain {{secret}}, {{username}}, or {{totp}}, and at least one placeholder is required.";
          };
        };
      });
      default = {};
      description = "Hosted stdio MCP servers (open_mcp_server), keyed by the name an agent's tegata-mcp-run invocation passes.";
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

    browserMaxLifetimeSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 3600;
      description = "Absolute maximum browser lifetime in seconds.";
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

    approvalGrantTtlSecs = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 0;
      description = "Approval grant lifetime in seconds; zero requires approval every time.";
    };

    auditLogMaxBytes = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = null;
      description = "Maximum audit log size in bytes.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = lib.mapAttrsToList (name: proxy: {
      assertion = (proxy.credId == null) != (proxy.oauth == null);
      message = "services.tegata.apiProxies.${name} must set exactly one of credId and oauth.";
    }) cfg.apiProxies ++ [
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
