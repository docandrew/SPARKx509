{
  description = "Reproducible SPARKx509 build environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          alirePackages =
            if system == "x86_64-linux" then
              [ pkgs.alire ]
            else
              [ ];
        in
        {
          default = pkgs.mkShell {
            packages = alirePackages ++ (with pkgs; [
              bash
              coreutils
              findutils
              gcc
              git
              gnugrep
              gnused
              gnumake
              openssl
              which
            ]);

            shellHook = ''
              echo "SPARKx509 dev shell: use ci/check.sh for the reproducible CI lane."
            '';
          };
        }
      );
    };
}
