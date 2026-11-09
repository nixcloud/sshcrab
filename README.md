# sshcrab

A remote shell like `ssh`, over SCTP/UDP, whose sessions survive disconnects: close the laptop, change networks,
come back with `sshcrab -R` and the shell is where you left it. With the P2P backend, a server behind NAT or
without any open port is reachable by its address `<key>.p2p` through a DHT.

The design and the security analysis are in [SPECIFICATION.md](SPECIFICATION.md); the P2P background is in
[P2P.md](P2P.md).

| Program | Runs on | Purpose |
|---|---|---|
| `sshcrab` | your machine | client |
| `sshcrab-keygen-ed25519` | your machine | creates your key |
| `sshcrabd` | server, as root | the daemon; never links the P2P code |
| `sshcrabd-p2p` | server, unprivileged and sandboxed | announces the server in the DHT and passes connections to `sshcrabd` |
| `sshcrab-dht-node` | optional, a public host | a DHT bootstrap node (such as bootstrap.nixcloud.io) |

> Status: young software (see SPECIFICATION.md §12 and §13.8). Do not make it the only way into a machine yet.
> **P2P status:** works between distinct addresses in the host tests (hole punching included); not yet verified across
> real NATs. Treat it as experimental, and mind the security notes before enabling it.

## 1. Your key (client)

```sh
nix profile install github:nixcloud/nixcloud.sshcrab#sshcrab
sshcrab-keygen-ed25519 ~/.sshcrab/id_ed25519
cat ~/.sshcrab/id_ed25519.pub      # goes into the server configuration below
```

## 2. A NixOS server

Start from the template, or add the module to your existing flake:

```sh
nix flake init -t github:nixcloud/nixcloud.sshcrab#server
```

```nix
# flake.nix
inputs.sshcrab.url = "github:nixcloud/nixcloud.sshcrab";
# nixosSystem { modules = [ sshcrab.nixosModules.default ./configuration.nix ]; }
```

```nix
# configuration.nix
services.sshcrab = {
  enable = true;
  authorizedKeys.alice = [ "ssh-ed25519 AAAAC3Nza... alice@laptop" ];
  p2p.enable = true;        # reachable through the DHT, also behind NAT
  # openFirewall = true;    # also reachable directly on UDP port 22
};
```

Deploy (`nixos-rebuild switch --flake .#myserver`, with `--target-host root@server` for a remote machine), then
get the address:

```sh
sshcrab-p2p-address         # on the server, e.g. kxgpyjz9wb5o…ruwyo.p2p
```

The address belongs to the server's host key (`/var/lib/sshcrab/host_key`): it stays the same across restarts and
redeploys as long as that file is kept. Back it up like an SSH host key.

### Options

| Option | Default | Meaning |
|---|---|---|
| `services.sshcrab.enable` | `false` | run `sshcrabd` |
| `.port` / `.listenAddresses` | `22` / `0.0.0.0`, `[::]` | UDP listen addresses (no clash with OpenSSH, which uses TCP) |
| `.openFirewall` | `false` | open `port` for UDP; not needed for P2P-only access |
| `.authorizedKeys.<user>` | `{ }` | keys per user, root-managed in `/etc/sshcrab/authorized_keys.d/`; users' own `~/.sshcrab/authorized_keys` keep working |
| `.permitRootLogin`, `.allowUsers`, `.allowGroups` | `true`, `[ ]`, `[ ]` | who may log in |
| `.logLevel` | `"info"` | `RUST_LOG` of the daemon and the helper |
| `.settings` | `{ }` | any other `sshcrabd.toml` key (SPECIFICATION.md §3) |
| `.clientPackage` | the client | installed system-wide; `null` = none |
| `.p2p.enable` | `false` | the sandboxed `sshcrabd-p2p` helper and its `sshcrab-p2p` user |
| `.p2p.bootstrap` | built-in list | DHT bootstrap nodes (`host:port`) |
| `.p2p.maxPeers` | `64` | concurrent P2P connections |
| `.dhtNode.enable` | `false` | run a bootstrap node (section 5) |
| `.dhtNode.port`, `.public`, `.bootstrap`, `.openFirewall` | `49737`, `true`, `[ ]`, `true` | its settings |

The helper sees nothing of the host except the daemon's socket: no capabilities, read-only system, no `/home`, no
other processes, its own memory limit. Check with `systemd-analyze security sshcrabd-p2p`.

## 3. Connect

```sh
sshcrab alice@kxgpyjz9wb5o…ruwyo.p2p              # interactive shell
sshcrab alice@kxgpyjz9wb5o…ruwyo.p2p 'uptime'     # one command
sshcrab -R alice@kxgpyjz9wb5o…ruwyo.p2p           # pick a session to resume
sshcrab -L alice@…  /  sshcrab -C alice@…         # list / detach or remove sessions
sshcrab alice@server.example.org                  # directly over UDP, if openFirewall is set
```

The first connection asks you to trust the host key (or pass `--accept-new`); it is then pinned in
`~/.sshcrab/hostkeys`, and a different key is refused. A P2P connection takes 1–2 s, up to about 40 s when hole
punching is needed. Hole punching fails behind symmetric NATs (some mobile and corporate networks); there is no
relay yet.

Bootstrap nodes for the client: `~/.sshcrab/config.toml`

```toml
P2PBootstrap = ["bootstrap.nixcloud.io:49737"]
```

or `--bootstrap HOST:PORT` (repeatable). Without either, the built-in list is used: bootstrap.nixcloud.io first,
then the public HyperDHT nodes.

## 4. Other Linux distributions (systemd)

Install the binaries with Nix and link the unit files:

```sh
nix profile install --profile /nix/var/nix/profiles/sshcrab \
    github:nixcloud/nixcloud.sshcrab#default github:nixcloud/nixcloud.sshcrab#systemd-units
P=/nix/var/nix/profiles/sshcrab
sudo systemd-sysusers $P/lib/sysusers.d/sshcrab.conf          # creates the sshcrab-p2p user
sudo install -d -m 0700 /var/lib/sshcrab
sudo install -m 0600 $P/share/sshcrab/sshcrabd.toml.example /var/lib/sshcrab/sshcrabd.toml
sudo systemctl link $P/lib/systemd/system/sshcrabd.service $P/lib/systemd/system/sshcrabd-p2p.service
sudo systemctl enable --now sshcrabd.service sshcrabd-p2p.service
cd /var/lib/sshcrab && sudo $P/bin/sshcrabd --p2p-address
```

Keys go into `~<user>/.sshcrab/authorized_keys` (or a root-owned directory set as `AuthorizedKeysDir`). To update,
upgrade the profile and run `systemctl daemon-reload` and restart both services.

For a server that should run NixOS instead, [nixos-anywhere](https://github.com/nix-community/nixos-anywhere)
installs the template configuration over SSH.

## 5. A bootstrap node (bootstrap.nixcloud.io)

Needed only if you do not want to depend on the public HyperDHT nodes. On a host with a static public IPv4:

```nix
services.sshcrab.dhtNode = {
  enable = true;           # UDP 49737, joins the public network (public = true)
  host = "203.0.113.7";    # this host's public IPv4; optional with public = true
};
```

A node's DHT id derives from its public address. Bound to `0.0.0.0` it learns that address from the nodes it
joins, so a first node of a private DHT must bind its public IPv4 (the module refuses otherwise). Then point
clients and servers at it (`p2p.bootstrap`, `P2PBootstrap`). With `public = false` and only your own nodes
in the lists you get a private DHT; run at least three nodes then. To try without installing anything:
`nix run github:nixcloud/nixcloud.sshcrab#sshcrab-dht-node -- --public`.

## 6. Development

```sh
nix develop                          # rustc/cargo 1.99 (nixcloud cargo, nix backend)
cargo build && cargo test
tests/e2e.sh && tests/e2e-p2p.sh     # end to end on 127.0.0.1
nix build .#checks.x86_64-linux.p2p  # NixOS VM test: DHT node, NAT router, server, client
```

`nix/test-keys/alice` is a throwaway key for the VM test, public on purpose. Do not use it anywhere else.
