{
  description = "hasec";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    # flake-utils.lib.eachDefaultSystem
    flake-utils.lib.eachSystem [ flake-utils.lib.system.x86_64-linux ]
      (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          github = owner: repo: rev: sha256:
            builtins.fetchTarball { inherit sha256; url = "https://github.com/${owner}/${repo}/archive/${rev}.tar.gz"; };

          sources = { };

          jailbreakUnbreak = pkg:
            pkgs.haskell.lib.doJailbreak (pkgs.haskell.lib.dontCheck (pkgs.haskell.lib.unmarkBroken pkg));

          haskellPackages = pkgs.haskell.packages.ghc925.override
            {
              overrides = hself: hsuper: {
                # text = haskellPackages.text_2_0_2;
                # parsec = haskellPackages.parsec_3_1_16_1;
              };
            };
        in
        rec
        {
          packages.hasec-core =
            haskellPackages.callCabal2nix "hasec-core" ./hasec-core rec {
              # Dependency overrides go here
            };

          defaultPackage = packages.hasec-core;

          devShell =
            let
              scripts = pkgs.symlinkJoin {
                name = "scripts";
                paths = pkgs.lib.mapAttrsToList pkgs.writeShellScriptBin {
                  ormolu-ide = ''
                    ${pkgs.ormolu}/bin/ormolu -o -XNoImportQualifiedPost -o -XOverloadedRecordDot $@
                  '';
                };
              };
            in
            pkgs.mkShell {
              buildInputs = with haskellPackages; [
                haskell-language-server
                ghcid
                cabal-install
                scripts
                ormolu
              ];
              inputsFrom = [
                self.defaultPackage.${system}.env
              ];
            };
        });
}
