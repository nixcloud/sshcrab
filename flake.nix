{
  description = "sshcrab: SSH-like remote shell over SCTP/UDP with resumable sessions";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    cargo-libnix.url = "github:nixcloud/cargo";
    libfenix.url = "github:nixcloud/libfenix";
    libfenix.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
  { self, nixpkgs, flake-utils, libfenix, cargo-libnix }:
    (flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
          lib = pkgs.lib;

          lf = import libfenix { inherit system pkgs; };
          # rustc 1.99.0 + cargo (libnix) 1.99.0+v3 + the host std
          rust_toolchain = lf.rust-1_99.minimalToolchain;

          src = builtins.filterSource
            (path: type:
                let base = baseNameOf path;
                in !(base == "target" || base == "result" || builtins.match "result-*" base != null)
            ) ./.;

          lock = builtins.fromTOML (builtins.readFile ./Cargo.lock);
          crateTarballs = map (p: pkgs.fetchurl {
              name = "crate-${p.name}-${p.version}.tar.gz";
              url = "https://crates.io/api/v1/crates/${p.name}/${p.version}/download";
              sha256 = p.checksum;
            })
            (builtins.filter (p: (p.source or "") == "registry+https://github.com/rust-lang/crates.io-index") lock.package);

          generated = pkgs.runCommand "cargo-nix-generated" { inherit crateTarballs; nativeBuildInputs = [ rust_toolchain ]; } ''
            export HOME=$TMPDIR CARGO_BACKEND=nix
            cp -r ${src} project && chmod -R u+w project && cd project
            ${rust_toolchain}/bin/cargo build --release --offline write-nix-buildsystem --out-dir $out
          '';

          units = import "${generated}/cargo_build_caller.nix" { inherit system; project_root = src; };

          # the binary units of a package; their hashes aren't known in advance
          binUnits = crate: map (n: units.${n})
            (lib.filter (lib.hasPrefix "${crate}-0_1_0-bin-") (builtins.attrNames units));
          joinBins = name: crate: pkgs.symlinkJoin { inherit name; paths = binUnits crate; };
        in
        rec {
          # bin/sshcrab and bin/sshcrab-keygen-ed25519
          packages.sshcrab = joinBins "sshcrab" "sshcrab";
          # bin/sshcrabd
          packages.sshcrabd = joinBins "sshcrabd" "sshcrabd";
          packages.default = pkgs.symlinkJoin {
            name = "sshcrab-all";
            paths = [ packages.sshcrab packages.sshcrabd ];
          };

          devShells.default = pkgs.mkShell {
            buildInputs = [
              rust_toolchain
              pkgs.cargo-binutils
            ];
            shellHook = ''
              export CARGO_BACKEND=nix
            '';
          };
        }
      )) // {
        # services.sshcrab, see nixos-module.nix
        nixosModules.sshcrab = import ./nixos-module.nix self;
        nixosModules.default = self.nixosModules.sshcrab;
      };
}
