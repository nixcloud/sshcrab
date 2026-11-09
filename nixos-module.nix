self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.sshcrab;
  pkgsFor = self.packages.${pkgs.stdenv.hostPlatform.system};
  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "sshcrabd.toml" ({
    ListenAddress = cfg.listenAddresses;
  } // lib.optionalAttrs cfg.p2p.enable ({
    P2P = true;
    P2PSocket = "/run/sshcrab/p2p.sock";
    P2PUser = "sshcrab-p2p";
  } // lib.optionalAttrs (cfg.p2p.bootstrap != [ ]) {
    P2PBootstrap = cfg.p2p.bootstrap;
  }) // cfg.settings);

  # Shared by the P2P helper and the DHT node: unprivileged network services
  # that parse untrusted input (SPECIFICATION.md §13.5).
  sandbox = {
    NoNewPrivileges = true;
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    RemoveIPC = true;
    UMask = "0077";
    # Netlink: the DHT lists local interface addresses.
    RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" ];
    SystemCallFilter = [ "@system-service" "~@privileged" ];
    SystemCallArchitectures = "native";
    # Its own cgroup: the unbounded queues of the young DHT stack cannot
    # take sshcrabd or the user sessions down with them.
    MemoryMax = "256M";
    TasksMax = 64;
    Restart = "on-failure";
    RestartSec = 2;
  };
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

    p2p = {
      enable = lib.mkEnableOption ''
        reachability through the DHT, for hosts behind NAT: runs the
        sandboxed sshcrabd-p2p helper. sshcrabd logs the host's P2P address
        (`<key>.p2p`) at startup'';

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
        description = "Open `port` for UDP in the firewall.";
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
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
        serviceConfig = sandbox // {
          ExecStart = lib.escapeShellArgs ([
            "${cfg.dhtNode.package}/bin/sshcrab-dht-node"
            "--host" "0.0.0.0"
            "--port" (toString cfg.dhtNode.port)
          ] ++ lib.optional cfg.dhtNode.public "--public"
            ++ lib.concatMap (b: [ "--bootstrap" b ]) cfg.dhtNode.bootstrap);
          DynamicUser = true;
        };
      };
    })
  ];
}
