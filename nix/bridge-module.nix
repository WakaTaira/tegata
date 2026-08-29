{ tegataBridgePackage }:
{ config, lib, ... }:
let
  cfg = config.services.tegata-bridge;
in
{
  options.services.tegata-bridge = {
    enable = lib.mkEnableOption "the tegata bridge";

    package = lib.mkOption {
      type = lib.types.package;
      default = tegataBridgePackage;
      description = "The tegata-bridge package to run.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "agent";
      description = "The existing user that runs tegata-bridge.";
    };

    daemonAddr = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The optional tegatad address.";
    };

    tokenFile = lib.mkOption {
      type = lib.types.str;
      description = "The path to the bridge token file.";
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/tegata-bridge/bridge.sock";
      description = "The path to the bridge Unix socket.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.tegata-bridge = {
      description = "Tegata bridge";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        RuntimeDirectory = "tegata-bridge";
        RuntimeDirectoryMode = "0700";
        ExecStart =
          "${cfg.package}/bin/tegata-bridge --socket ${lib.escapeShellArg cfg.socketPath}"
          + " --token-file ${lib.escapeShellArg cfg.tokenFile}"
          + lib.optionalString (cfg.daemonAddr != null)
            " --daemon-addr ${lib.escapeShellArg cfg.daemonAddr}";
        Restart = "on-failure";
      };
    };
  };
}
