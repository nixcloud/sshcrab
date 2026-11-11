{
  description = "A NixOS server running sshcrabd, reachable through the DHT";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    sshcrab.url = "github:nixcloud/sshcrab";
  };

  outputs = { nixpkgs, sshcrab, ... }: {
    # nixos-rebuild switch --flake .#myserver
    #   (or --target-host root@server; nixos-anywhere for a server without NixOS)
    nixosConfigurations.myserver = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        sshcrab.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
