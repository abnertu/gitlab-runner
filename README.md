# gitlab-runnerctl

Converge dedicated rootless Podman GitLab Runner instances, one system account per instance.

[![gitlab-runnerctl validation](https://github.com/abnertu/gitlab-runner/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/abnertu/gitlab-runner/actions/workflows/check.yml) [![Python](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fabnertu%2Fgitlab-runner%2Fmain%2Fpyproject.toml&query=%24.project%5B%27requires-python%27%5D&label=Python&logo=python&logoColor=white&color=3776AB)](https://www.python.org/)

## Install

Requirements:

- Arch Linux, the only supported host platform;
- Podman 4.2.0 or later, with aardvark-dns later than 1.10.0;
- systemd with user managers;
- Python 3.13 or later, and [nix-adapter](https://github.com/abnertu/nix-adapter).

Build it with Nix:

```bash
nix build "github:abnertu/gitlab-runner?ref=v0.2.0"
./result/bin/runnerctl --version
```

Without Nix, install nix-adapter from its tag first:

```bash
pip install git+https://github.com/abnertu/nix-adapter@v0.7.0
pip install git+https://github.com/abnertu/gitlab-runner@v0.2.0
```

## Configure

Write one TOML file for each instance, and name it after the environment that it serves. `frontend.toml` declares the `frontend` instance, which runs as the account `gitlab-runner-frontend`.

Put shared settings in a base file. Each instance names its base with `extends`, relative to the instance file. A base cannot extend another file.

```toml
# common.toml
provider = "gitlab"

[gitlab]
url = "https://gitlab.example"
health_url = "https://gitlab.example/users/sign_in"
# ca_certificate = "ca.crt"   # relative to the file that declares it

[network]
required_interface = "tailscale0"   # optional
dns = "100.100.100.100"             # optional
```

```toml
# frontend.toml
extends = "common.toml"
uid = 1001
subordinate_id_start = 165536

[runner]
name = "A-frontend-podman"
cpus = "2"
memory = "4g"
shm_size_bytes = 1073741824
default_job_image = "docker.io/library/node:22.22.0-bookworm"
allowed_images = ["docker.io/library/node:*"]
allowed_services = []
```

`validate` rejects unknown keys and wrong types before any host change. It also rejects colliding UIDs or subordinate ID ranges, unpinned images, and job images outside the allowlist. `tests/fixtures/` holds a complete example.

## Usage

```bash
runnerctl -c frontend.toml -c dotnet.toml [--platform arch] <command> [instance]
```

Pass every instance file on each call, so that names and IDs are checked across the whole set. The platform selects the host executable paths. When you omit it, runnerctl reads it from `/etc/os-release`.

| Command | Root | Action |
| --- | --- | --- |
| `validate` | no | Validate the instance declarations; it reads only the instance and CA files. |
| `check <instance>` | yes | Check the host prerequisites. |
| `reconcile <instance>` | yes | Converge the account, sub-IDs, runtime, configuration, image and service. |
| `register <instance>` | yes | Register with GitLab, with the token in `GITLAB_RUNNER_TOKEN`. |
| `verify <instance>` | yes | Verify the service, manager image, socket and a disposable job network. |
| `status <instance>` | yes | Show the account, sub-IDs, socket, service, container and registration. |

The token never goes on the command line. Read it into the environment, so that it stays out of the shell history:

```bash
read -rs GITLAB_RUNNER_TOKEN && export GITLAB_RUNNER_TOKEN
sudo --preserve-env=GITLAB_RUNNER_TOKEN runnerctl -c frontend.toml register frontend
```

A `reconcile` that fails after its first trust, configuration, unit, image or service change leaves a pending marker. The next `reconcile` restarts or starts the service, and then clears the marker.
