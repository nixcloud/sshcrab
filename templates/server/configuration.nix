{ ... }:
{
  # Your existing configuration (hardware, boot loader, users, ...) goes here,
  # e.g. imports = [ ./hardware-configuration.nix ];

  users.users.alice.isNormalUser = true;

  services.sshcrab = {
    enable = true;

    # Keys from `sshcrab-keygen-ed25519 ~/.sshcrab/id_ed25519` (the .pub file).
    authorizedKeys.alice = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop" ];

    # Reachable through the DHT, also behind NAT and without open ports.
    # After the first start: `sshcrab-p2p-address` prints the address.
    p2p.enable = true;

    # Direct access over UDP as well (optional).
    # openFirewall = true;
  };

  system.stateVersion = "26.05";
}
