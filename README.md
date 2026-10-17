# gitlab-runnerctl

Manage dedicated rootless Podman GitLab Runner instances on any host with
Python 3.11+, Podman and systemd. Nix is optional.

## Configure

Write one TOML file per instance, named after the environment it serves.
`frontend.toml` declares the `frontend` instance, which runs as the account
`gitlab-runner-frontend`. Shared settings can live in a base file that each
instance names with `extends`, resolved relative to the instance file; a base
cannot extend another file.

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

Unknown keys, wrong types, colliding UIDs or subordinate ID ranges, unpinned
images and job images outside the allowlist are rejected before any host change.
See `tests/fixtures/` for a complete example.

## Usage

```bash
runnerctl -c frontend.toml -c dotnet.toml [--platform arch] <command> [instance]
```

Pass every instance file on each call, so names and IDs are checked across the
whole set. The platform selects host executable paths and is detected from
`/etc/os-release` when omitted.

Commands:
- `validate`: Validate instance declarations (no root, no host access)
- `check <instance>`: Check prerequisites
- `reconcile <instance>`: Reconcile account, sub-IDs, runtime, configuration, image and service
- `register <instance>`: Register with GitLab using `GITLAB_RUNNER_TOKEN` from the environment
- `verify <instance>`: Verify service health, manager image, socket and disposable network
- `status <instance>`: Show status of account, subids, socket, service, container and registration
