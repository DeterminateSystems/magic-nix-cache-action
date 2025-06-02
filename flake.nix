{
  description = "Magic Nix Cache";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1";
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1";
  };

  outputs = inputs:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: inputs.nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import inputs.nixpkgs { inherit system; };
      });
    in
    {
      devShells = forAllSystems ({ pkgs }: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            jq
            shellcheck
            nixpkgs-fmt
            nodejs-slim
            nodePackages_latest.pnpm
            biome
          ];
        };
      });
    };
}
