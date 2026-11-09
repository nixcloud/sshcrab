self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.sshcrab;
  pkgsFor = self.packages.${pkgs.stdenv.hostPlatform.system};
  sandbox = import ./nix/sandbox.nix;
  keysDir = "/etc/sshcrab/authorized_keys.d";

  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "sshcrabd.toml" ({
    ListenAddress = cfg.listenAddresses;
    PermitRootLogin = cfg.permitRootLogin;
    AllowUsers = cfg.allowUsers;
    AllowGroups = cfg.allowGroups;
  } // lib.optionalAttrs (cfg.authorizedKeys != { }) {
    AuthorizedKeysDir = keysDir;
  } // lib.optionalAttrs cfg.p2p.enable ({
    P2P = true;
    P2PSocket = "/run/sshcrab/p2p.sock";
    P2PUser = "sshcrab-p2p";
  } // lib.optionalAttrs (cfg.p2p.bootstrap != [ ]) {
    P2PBootstrap = cfg.p2p.bootstrap;
  }) // cfg.settings);

  # `sshcrab-p2p-address`: the address only exists once sshcrabd generated
  # its host key, so it cannot be known at evaluation time.
  addressTool = pkgs.writeShellScriptBin "sshcrab-p2p-address" ''
    cd /var/lib/sshcrab && exec ${cfg.package}/bin/sshcrabd --p2p-address
  '';
in
{
  options.services.sshcrab = {
    enable = lib.mkEnableOption "sshcrabd, the sshcrab remote shell daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgsFor.sshcrabd;
      defaultText = lib.literalExpression "sshcrab.packages.\${system}.sshcrabd";
      description = "Package providing bin/sshcrabd.";
    };

    clientPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = pkgsFor.sshcrab;
      defaultText = lib.literalExpression "sshcrab.packages.\${system}.sshcrab";
      description = "Client tools (sshcrab, sshcrab-keygen-ed25519) to install system-wide; null = none.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 22;
      description = "UDP port for every listen address (passed as -p). sshcrab uses UDP, so it does not clash with OpenSSH.";
    };

    listenAddresses = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "0.0.0.0:22" "[::]:22" ];
      description = "ListenAddress entries; the port is overridden by `port`.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open `port` for UDP. Not needed for P2P-only access.";
    };

    permitRootLogin = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Allow logging in as root (always key-only).";
    };

    allowUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Only these users may log in; empty = everyone with a valid account and key.";
    };

    allowGroups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "wheel" ];
      description = "Only members of these groups may log in; empty = no restriction.";
    };

    authorizedKeys = lib.mkOption {
      type = lib.types.attrsOf (lib.types.listOf lib.types.str);
      default = { };
      example = { alice = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop" ]; };
      description = ''
        Public keys per user, as written by sshcrab-keygen-ed25519. Installed
        root-owned in ${keysDir}/<user> and accepted in addition to the
        user's own ~/.sshcrab/authorized_keys.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      example = "debug";
      description = "RUST_LOG for sshcrabd and sshcrabd-p2p.";
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      example = { MaxSessionsPerUser = 16; DisconnectedTimeout = "12h"; };
      description = "Further sshcrabd.toml settings (SPECIFICATION.md §3); they override the options above.";
    };

    p2p = {
      enable = lib.mkEnableOption ''
        reachability through the DHT, for hosts behind NAT or without open
        ports: runs the sandboxed sshcrabd-p2p helper. Run
        `sshcrab-p2p-address` for the host's address (`<key>.p2p`)'';

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgsFor.sshcrab-p2p;
        defaultText = lib.literalExpression "sshcrab.packages.\${system}.sshcrab-p2p";
        description = "Package providing bin/sshcrabd-p2p.";
      };

      bootstrap = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "bootstrap.nixcloud.io:49737" ];
        description = "DHT bootstrap nodes (`host:port`); empty = sshcrab's built-in list.";
      };

      maxPeers = lib.mkOption {
        type = lib.types.ints.positive;
        default = 64;
        description = "Most concurrent P2P connections.";
      };
    };

    dhtNode = {
      enable = lib.mkEnableOption "a DHT bootstrap node (sshcrab-dht-node), such as bootstrap.nixcloud.io";

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgsFor.sshcrab-p2p;
        defaultText = lib.literalExpression "sshcrab.packages.\${system}.sshcrab-p2p";
        description = "Package providing bin/sshcrab-dht-node.";
      };

      host = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0";
        description = "Address to bind. 0.0.0.0 works when the node joins others (`public` or `bootstrap`), from which it learns its address; otherwise set its public IPv4.";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 49737;
        description = "UDP port; must be reachable from the internet.";
      };

      public = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Also join the public HyperDHT network (recommended; false = a private sshcrab-only DHT).";
      };

      bootstrap = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Further nodes to join (`host:port`).";
      };

      openFirewall = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Open `port` for UDP.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [{
        assertion = cfg.dhtNode.enable -> (cfg.dhtNode.public || cfg.dhtNode.bootstrap != [ ] || cfg.dhtNode.host != "0.0.0.0");
        message = "services.sshcrab.dhtNode: a node that joins no other nodes (public = false, no bootstrap) must bind its public IPv4 address (dhtNode.host); its DHT id derives from it";
      } {
        assertion = cfg.p2p.enable -> cfg.enable;
        message = "services.sshcrab.p2p.enable needs services.sshcrab.enable";
      }];
    }

    (lib.mkIf cfg.enable {
      networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
      environment.systemPackages = lib.optional (cfg.clientPackage != null) cfg.clientPackage
        ++ lib.optional cfg.p2p.enable addressTool;

      # Copies (mode), not symlinks into the store: root-owned, read-only.
      environment.etc = lib.mapAttrs' (user: keys:
        lib.nameValuePair "sshcrab/authorized_keys.d/${user}" {
          text = lib.concatStringsSep "\n" keys + "\n";
          mode = "0444";
        }) cfg.authorizedKeys;

      systemd.services.sshcrabd = {
        description = "sshcrab remote shell daemon";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        restartTriggers = [ configFile ];
        environment.RUST_LOG = cfg.logLevel;
        serviceConfig = {
          # workdir with host_key (generated on first start) and sshcrabd.toml
          StateDirectory = "sshcrab";
          StateDirectoryMode = "0700";
          WorkingDirectory = "/var/lib/sshcrab";
          # /run/sshcrab/p2p.sock (mode 0660, group sshcrab-p2p)
          RuntimeDirectory = "sshcrab";
          RuntimeDirectoryMode = "0755";
          ExecStartPre = "${pkgs.coreutils}/bin/install -m 0600 -o root ${configFile} /var/lib/sshcrab/sshcrabd.toml";
          ExecStart = "${cfg.package}/bin/sshcrabd -p ${toString cfg.port}";
          Restart = "on-failure";
          # Session processes are children of this unit, so no sandboxing options here:
          # they would apply to user shells too (SPECIFICATION.md §7.4).
          KillMode = "control-group";
        };
      };
    })

    (lib.mkIf (cfg.enable && cfg.p2p.enable) {
      users.users.sshcrab-p2p = {
        isSystemUser = true;
        group = "sshcrab-p2p";
        description = "sshcrab P2P helper";
      };
      users.groups.sshcrab-p2p = { };

      # A fixed user, not DynamicUser: sshcrabd checks the helper's uid
      # (SO_PEERCRED) before handing it the P2P key.
      systemd.services.sshcrabd-p2p = {
        description = "sshcrab P2P (DHT) helper";
        # Started again whenever sshcrabd (re)starts; stopped with it.
        wantedBy = [ "multi-user.target" "sshcrabd.service" ];
        bindsTo = [ "sshcrabd.service" ];
        after = [ "sshcrabd.service" "network-online.target" ];
        wants = [ "network-online.target" ];
        environment.RUST_LOG = cfg.logLevel;
        serviceConfig = sandbox // {
          ExecStart = "${cfg.p2p.package}/bin/sshcrabd-p2p --socket /run/sshcrab/p2p.sock --max-peers ${toString cfg.p2p.maxPeers}";
          User = "sshcrab-p2p";
          Group = "sshcrab-p2p";
          # Of /run it sees sshcrabd's socket directory and, for DNS, the resolver sockets.
          TemporaryFileSystem = "/run";
          BindReadOnlyPaths = [ "/run/sshcrab" "-/run/systemd/resolve" "-/run/nscd" ];
        };
      };
    })

    (lib.mkIf cfg.dhtNode.enable {
      networking.firewall.allowedUDPPorts = lib.mkIf cfg.dhtNode.openFirewall [ cfg.dhtNode.port ];

      systemd.services.sshcrab-dht-node = {
        description = "sshcrab DHT bootstrap node";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        environment.RUST_LOG = cfg.logLevel;
        serviceConfig = sandbox // {
          ExecStart = lib.escapeShellArgs ([
            "${cfg.dhtNode.package}/bin/sshcrab-dht-node"
            "--host" cfg.dhtNode.host
            "--port" (toString cfg.dhtNode.port)
          ] ++ lib.optional cfg.dhtNode.public "--public"
            ++ lib.concatMap (b: [ "--bootstrap" b ]) cfg.dhtNode.bootstrap);
          DynamicUser = true;
        };
      };
    })
  ];
}
