# systemd units for Linux servers without NixOS (README.md, "Other distributions").
# They reference the binaries by store path, so install the package with
# `nix profile install` (or copy the closure) before linking the units.
{ lib, runCommand, writeText, sshcrabd, sshcrab-p2p }:
let
  sandbox = import ./sandbox.nix;

  value = v: if lib.isBool v then lib.boolToString v else toString v;
  # Lists become repeated keys, as systemd expects.
  section = name: attrs: "[${name}]\n" + lib.concatStrings (lib.mapAttrsToList (k: v:
    lib.concatMapStrings (x: "${k}=${value x}\n") (lib.toList v)) attrs) + "\n";
  unit = name: sections: writeText name (lib.concatStrings (lib.mapAttrsToList section sections));

  sshcrabdUnit = unit "sshcrabd.service" {
    Unit = { Description = "sshcrab remote shell daemon"; After = "network.target"; };
    Service = {
      # /var/lib/sshcrab: host_key (generated on first start) and your sshcrabd.toml
      StateDirectory = "sshcrab";
      StateDirectoryMode = "0700";
      WorkingDirectory = "/var/lib/sshcrab";
      RuntimeDirectory = "sshcrab";
      RuntimeDirectoryMode = "0755";
      Environment = "RUST_LOG=info";
      ExecStart = "${sshcrabd}/bin/sshcrabd";
      Restart = "on-failure";
      KillMode = "control-group";
    };
    Install = { WantedBy = "multi-user.target"; };
  };

  helperUnit = unit "sshcrabd-p2p.service" {
    Unit = {
      Description = "sshcrab P2P (DHT) helper";
      BindsTo = "sshcrabd.service";
      After = [ "sshcrabd.service" "network-online.target" ];
      Wants = "network-online.target";
    };
    Service = sandbox // {
      Environment = "RUST_LOG=info";
      ExecStart = "${sshcrab-p2p}/bin/sshcrabd-p2p --socket /run/sshcrab/p2p.sock";
      User = "sshcrab-p2p";
      Group = "sshcrab-p2p";
      TemporaryFileSystem = "/run";
      BindReadOnlyPaths = [ "/run/sshcrab" "-/run/systemd/resolve" "-/run/nscd" ];
    };
    Install = { WantedBy = [ "multi-user.target" "sshcrabd.service" ]; };
  };

  dhtNodeUnit = unit "sshcrab-dht-node.service" {
    Unit = { Description = "sshcrab DHT bootstrap node"; After = "network-online.target"; Wants = "network-online.target"; };
    Service = sandbox // {
      Environment = "RUST_LOG=info";
      ExecStart = "${sshcrab-p2p}/bin/sshcrab-dht-node --host 0.0.0.0 --port 49737 --public";
      DynamicUser = true;
    };
    Install = { WantedBy = "multi-user.target"; };
  };

  sysusers = writeText "sshcrab.conf" ''
    u sshcrab-p2p - "sshcrab P2P helper"
  '';

  exampleConfig = writeText "sshcrabd.toml" ''
    # /var/lib/sshcrab/sshcrabd.toml (owned by root, mode 0600); see SPECIFICATION.md §3
    ListenAddress = ["0.0.0.0:22", "[::]:22"]
    P2P = true
    P2PSocket = "/run/sshcrab/p2p.sock"
    P2PUser = "sshcrab-p2p"
  '';
in
runCommand "sshcrab-systemd-units" { } ''
  mkdir -p $out/lib/systemd/system $out/lib/sysusers.d $out/share/sshcrab
  cp ${sshcrabdUnit} $out/lib/systemd/system/sshcrabd.service
  cp ${helperUnit} $out/lib/systemd/system/sshcrabd-p2p.service
  cp ${dhtNodeUnit} $out/lib/systemd/system/sshcrab-dht-node.service
  cp ${sysusers} $out/lib/sysusers.d/sshcrab.conf
  cp ${exampleConfig} $out/share/sshcrab/sshcrabd.toml.example
''
