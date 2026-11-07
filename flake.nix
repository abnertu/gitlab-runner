{
  description = "Dedicated rootless Podman GitLab Runner manager CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nix-adapter.url = "github:abnertu/nix-adapter?ref=v0.8.0";
    nix-adapter.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-adapter,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      # pyproject.toml holds the only version literal.
      inherit (builtins.fromTOML (builtins.readFile ./pyproject.toml)) project;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          adapter = nix-adapter.packages.${system}.default;
          runnerctl = pkgs.python3Packages.buildPythonApplication {
            pname = "gitlab-runnerctl";
            inherit (project) version;
            src = ./.;
            format = "pyproject";
            nativeBuildInputs = [ pkgs.python3Packages.setuptools ];
            propagatedBuildInputs = [ adapter ];
            # Tests import the package from the source tree.
            checkPhase = ''
              PYTHONPATH="src:$PYTHONPATH" python -m unittest discover -s tests
            '';
            pythonImportsCheck = [
              "runnerctl.cli"
            ];
          };
        in
        {
          inherit runnerctl;
          default = runnerctl;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          runnerctl = self.packages.${system}.runnerctl;
          adapter = nix-adapter.packages.${system}.default;
          python = pkgs.python3.withPackages (ps: [
            ps.setuptools
            adapter
          ]);
        in
        {
          package = runnerctl;

          source-lint =
            pkgs.runCommand "gitlab-runnerctl-source-lint"
              {
                nativeBuildInputs = [
                  pkgs.deadnix
                  pkgs.nixfmt
                  pkgs.statix
                ];
              }
              ''
                cd ${./.}
                statix check .
                deadnix --fail flake.nix
                nixfmt --check flake.nix
                touch "$out"
              '';

          source-format =
            pkgs.runCommand "gitlab-runnerctl-source-format"
              {
                nativeBuildInputs = [ pkgs.ruff ];
              }
              ''
                ruff check --no-cache ${./.}
                ruff format --no-cache --check ${./.}
                touch "$out"
              '';

          python-types =
            pkgs.runCommand "gitlab-runnerctl-python-types"
              {
                nativeBuildInputs = [
                  pkgs.pyright
                  python
                ];
              }
              ''
                pyright --project ${./.} ${./.}/src
                touch "$out"
              '';
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          adapter = nix-adapter.packages.${system}.default;
        in
        {
          default = pkgs.mkShell {
            packages = [
              (pkgs.python3.withPackages (ps: [
                ps.setuptools
                ps.pytest
                adapter
              ]))
              pkgs.pyright
              pkgs.ruff
              pkgs.git-cliff
              pkgs.just
            ];
          };
        }
      );
    };
}
