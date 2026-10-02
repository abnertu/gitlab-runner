{
  description = "Dedicated rootless Podman GitLab Runner manager CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nix-adapter.url = "github:gin31259461/nix-adapter";
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
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          adapter = nix-adapter.packages.${system}.default;
          runnerctl = pkgs.python3Packages.buildPythonApplication {
            pname = "gitlab-runnerctl";
            version = "0.1.0";
            src = ./.;
            format = "pyproject";
            nativeBuildInputs = [ pkgs.python3Packages.setuptools ];
            propagatedBuildInputs = [ adapter ];
            checkPhase = ''
              python -m unittest discover -s tests
            '';
            pythonImportsCheck = [
              "runnerctl"
              "runner_model"
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

          source-format = pkgs.runCommand "gitlab-runnerctl-source-format" {
            nativeBuildInputs = [ pkgs.ruff ];
          } ''
            ruff check --no-cache --select F ${./.}
            ruff format --no-cache --check ${./.}
            touch "$out"
          '';

          python-types = pkgs.runCommand "gitlab-runnerctl-python-types" {
            nativeBuildInputs = [
              pkgs.pyright
              python
            ];
          } ''
            pyright --project ${./.} ${./runnerctl.py} ${./runner_model.py}
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
            ];
          };
        }
      );
    };
}
