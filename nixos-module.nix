self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.sshcrab;
  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "sshcrabd.toml" ({
    ListenAddress = cfg.listenAddresses;
  } // cfg.settings);
in
{
  options.services.sshcrab = {
    enable = lib.mkEnableOption "sshcrabd, the sshcrab remote shell daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.sshcrabd;
      defaultText = lib.literalExpression "sshcrab.packages.\${system}.sshcrabd";
      description = "Package providing bin/sshcrabd.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 22;
      description = "UDP port for every listen address (passed as -p).";
    };

    listenAddresses = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "0.0.0.0:22" "[::]:22" ];
      description = "ListenAddress entries; the port is overridden by `port`.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open `port` for UDP in the firewall.";
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      example = { MaxSessionsPerUser = 16; AllowGroups = [ "wheel" ]; };
      description = "Further sshcrabd.toml settings (see SPECIFICATION.md §3).";
    };
  };

  config = lib.mkIf cfg.enable {
    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.sshcrabd = {
      description = "sshcrab remote shell daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        # workdir with host_key (generated on first start) and sshcrabd.toml
        StateDirectory = "sshcrab";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/sshcrab";
        ExecStartPre = "${pkgs.coreutils}/bin/install -m 0600 -o root ${configFile} /var/lib/sshcrab/sshcrabd.toml";
        ExecStart = "${cfg.package}/bin/sshcrabd -p ${toString cfg.port}";
        Restart = "on-failure";
        # Session processes are children of this unit, so no sandboxing options here:
        # they would apply to user shells too (SPECIFICATION.md §7.4).
        KillMode = "control-group";
      };
    };
  };
}
