# NixOS tests of the P2P stack (SPECIFICATION.md §13, P4), as QEMU VMs or as
# systemd-nspawn containers. Both pass as containers (2026-11-27). They used to
# fail: the test framework gives every machine 192.168.<vlan>.<node number>
# besides the addresses set here, so the client's address was also the server's
# and the server's hole punch went to itself; the addresses are now set with
# mkForce. The VM variants have not been run since on a host with KVM.
#
# nat = false (checks.p2p): server, client and four DHT nodes on one network,
#   no firewalls, so peeroxide connects directly (no hole punching);
#   the client reaches the server through the DHT only. Covers the module, the
#   sandboxed helper, AuthorizedKeysDir, the announce retry, data transfer and
#   a helper restart.
#
# nat = true (checks.p2p-nat): the server sits behind a NAT router and has no
#   open ports, so the client needs hole punching:
#
#     client ── internet (vlan 1) ── dht
#                   │
#                 router (NAT)
#                   │
#     server ── lan (vlan 2)
#
#   The router is a Linux masquerading NAT; client and router run firewalls.
#
# containers = true (checks.p2p-containers, checks.p2p-nat-containers): the same
#   machines as systemd-nspawn containers instead of QEMU VMs: no KVM needed (WSL2,
#   CI), seconds instead of minutes. They share the host kernel. The Nix daemon
#   needs auto-allocate-uids, the uid-range system feature and the cgroups
#   experimental feature (nixpkgs manual, "Running Tests"; README.md).
#
# nix/test-keys/alice is a throwaway key used nowhere else.
self:
{ pkgs, nat ? false, containers ? false, ... }:
let
  lib = pkgs.lib;
  dhtIp = "192.168.1.2";
  serverIp = if nat then "10.0.0.2" else "192.168.1.4";
  p2pPkg = self.packages.${pkgs.stdenv.hostPlatform.system}.sshcrab-p2p;
  # The test driver gives every VM the same 10.0.2.15 on eth0 (QEMU user network).
  # peeroxide advertises local addresses and checks for a shared network, so
  # identical addresses on "different" hosts confuse it: no address on eth0.
  # Containers have no eth0, only the vlan interfaces.
  # The addresses below are set with mkForce: the test framework also gives every
  # machine 192.168.<vlan>.<node number>, which made the client's address the
  # server's too, so the server's hole punch went to itself.
  common = lib.optionalAttrs (!containers) {
    networking.useDHCP = lib.mkForce false;
    networking.interfaces.eth0.useDHCP = lib.mkForce false;
  };
in
pkgs.testers.runNixOSTest {
  name = (if nat then "sshcrab-p2p-nat" else "sshcrab-p2p") + lib.optionalString containers "-containers";

  ${if containers then "containers" else "nodes"} = {
    dht = { ... }: {
      imports = [ self.nixosModules.default common ];
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [{ address = dhtIp; prefixLength = 24; }];
      services.sshcrab.dhtNode = { enable = true; public = false; host = dhtIp; };
      services.sshcrab.logLevel = "debug";
      # Three more nodes are started by the test script: NAT classification
      # (and so hole punching) needs replies from at least three nodes.
      networking.firewall.allowedUDPPorts = [ 49738 49739 49740 ];
    };

    server = { ... }: {
      imports = [ self.nixosModules.default common ];
      virtualisation.vlans = [ (if nat then 2 else 1) ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [{ address = serverIp; prefixLength = 24; }];
      networking.defaultGateway = lib.mkIf nat { address = "10.0.0.1"; interface = "eth1"; };
      # Without NAT the server is directly dialable (firewall off); behind the NAT
      # nothing is opened. The sshcrabd UDP port is never used by the test.
      networking.firewall.enable = nat;
      users.users.alice = { isNormalUser = true; };
      environment.systemPackages = [ pkgs.tcpdump ];
      services.sshcrab = {
        enable = true;
        authorizedKeys.alice = [ (builtins.readFile ./test-keys/alice.pub) ];
        logLevel = "debug";
        p2p = { enable = true; bootstrap = [ "${dhtIp}:49737" ]; };
      };
    };

    client = { ... }: {
      imports = [ common ];
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [{ address = "192.168.1.3"; prefixLength = 24; }];
      # A firewall only in the NAT variant: without NAT the test covers the
      # direct path, with it the hole punch through both.
      networking.firewall.enable = nat;
      environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.sshcrab ];
    };
  } // lib.optionalAttrs nat {
    router = { ... }: {
      imports = [ common ];
      virtualisation.vlans = [ 1 2 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [{ address = "192.168.1.1"; prefixLength = 24; }];
      networking.interfaces.eth2.ipv4.addresses = lib.mkForce [{ address = "10.0.0.1"; prefixLength = 24; }];
      networking.nat = { enable = true; externalInterface = "eth1"; internalInterfaces = [ "eth2" ]; };
      networking.firewall.enable = true;
      environment.systemPackages = [ pkgs.tcpdump pkgs.conntrack-tools ];
    };
  };

  testScript = ''
    # The server comes up before its bootstrap nodes, as after a power cut:
    # the helper must keep retrying instead of announcing into nothing.
    ${lib.optionalString nat "router.start()"}
    server.start()
    client.start()
    server.wait_for_unit("sshcrabd.service")
    server.wait_for_unit("sshcrabd-p2p.service")
    server.wait_until_succeeds("journalctl -u sshcrabd-p2p | grep -q 'retrying every 5 s'", timeout=120)
    dht.start()
    dht.wait_for_unit("sshcrab-dht-node.service")
    dht.succeed(
        "for p in 49738 49739 49740; do systemd-run --unit=dht-$p -p DynamicUser=yes "
        "${p2pPkg}/bin/sshcrab-dht-node --host ${dhtIp} --port $p --bootstrap ${dhtIp}:49737; done"
    )
    server.wait_until_succeeds("journalctl -u sshcrabd-p2p | grep -q 'announced as'", timeout=90)

    addr = server.succeed("sshcrab-p2p-address").strip()
    assert addr.endswith(".p2p"), addr
    server.succeed(f"journalctl -u sshcrabd-p2p | grep -q 'announced as {addr}'")
  '' + lib.optionalString nat ''

    with subtest("the server cannot be reached directly"):
        client.fail("${pkgs.iputils}/bin/ping -c 1 -W 2 ${serverIp}")
  '' + ''

    client.succeed("mkdir -m 700 -p /root/.sshcrab")
    client.copy_from_host("${./test-keys/alice}", "/root/.sshcrab/id_ed25519")
    client.succeed("chmod 600 /root/.sshcrab/id_ed25519")
    ssh = f"sshcrab --bootstrap ${dhtIp}:49737 alice@{addr}"

    with subtest("unknown host key is refused without --accept-new"):
        # Retried: right after the announce the DHT may not have settled yet.
        server.succeed("systemd-run --unit=capture tcpdump -lni any -c 300 -w /tmp/cap.pcap 'udp and not port 49737 and not port 49738 and not port 49739 and not port 49740'")
        try:
            # stdin not a terminal: the client would ask instead of refusing. The
            # driver runs commands with `set -e`, and the refusal exits 1: `|| true`.
            client.wait_until_succeeds(f"RUST_LOG=debug {ssh} true </dev/null 2>/tmp/client.log || true; grep -q 'use --accept-new' /tmp/client.log", timeout=100)
        except Exception:
            print(client.execute("grep -vE 'DEBUG|TRACE' /tmp/client.log | cut -c1-240 | tail -20")[1])
            print(client.execute("grep -E 'deciding|direct-connect|stream connected|socket|bound|local' /tmp/client.log | cut -c1-240 | tail -20")[1])
            server.execute("systemctl stop capture; sleep 1")
            print(server.execute("tcpdump -nr /tmp/cap.pcap 2>&1 | head -60")[1])
            print(server.execute("ss -uanp | grep sshcrabd-p2p")[1])
            raise

    with subtest("a command runs as alice, key from AuthorizedKeysDir"):
        out = client.succeed(f"sshcrab --accept-new --bootstrap ${dhtIp}:49737 alice@{addr} 'id -un; echo p2p-ok' 2>&1")
        assert "alice" in out and "p2p-ok" in out, out
        server.succeed("test -f /etc/sshcrab/authorized_keys.d/alice && test ! -e /home/alice/.sshcrab")

    with subtest("exit codes pass through"):
        status, _ = client.execute(f"{ssh} 'exit 3'")
        assert status == 3, status

    with subtest("bulk data both ways"):
        client.succeed("head -c 3000000 /dev/urandom > /tmp/blob")
        want = client.succeed("sha256sum < /tmp/blob").split()[0]
        got = client.succeed(f"{ssh} sha256sum < /tmp/blob").split()[0]
        assert got == want, (got, want)
        got = client.succeed(f"{ssh} cat < /tmp/blob | sha256sum").split()[0]
        assert got == want, (got, want)

    with subtest("the helper runs unprivileged and sandboxed"):
        server.succeed("test \"$(systemctl show -p User --value sshcrabd-p2p)\" = sshcrab-p2p")
        server.succeed("journalctl -u sshcrabd | grep -q 'P2P helper connected'")
        server.succeed("test \"$(systemctl show -p ProtectHome --value sshcrabd-p2p)\" = yes")
        print(server.succeed("systemd-analyze security sshcrabd-p2p.service | tail -1"))

    with subtest("a helper restart keeps the address"):
        server.succeed("systemctl restart sshcrabd-p2p")
        server.wait_until_succeeds(f"journalctl -u sshcrabd-p2p --since '-60s' | grep -q 'announced as {addr}'", timeout=120)
        client.wait_until_succeeds(f"{ssh} 'echo again' | grep -q again", timeout=180)
  '';
}
