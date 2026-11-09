# systemd sandbox for sshcrabd-p2p and sshcrab-dht-node: unprivileged
# network services that parse untrusted input (SPECIFICATION.md §13.5).
# Shared by the NixOS module and the unit files for other distributions.
{
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
}
