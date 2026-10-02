# gitlab-runnerctl

Manage dedicated rootless Podman GitLab Runner instances.

## Usage

```bash
runnerctl --config <instances.json> <command> [instance]
```

Commands:
- `validate`: Validate instance declarations
- `check <instance>`: Check prerequisites
- `reconcile <instance>`: Reconcile account, sub-IDs, runtime, configuration, image and service
- `register <instance>`: Register with GitLab using `GITLAB_RUNNER_TOKEN`
- `verify <instance>`: Verify service health, manager image, socket and disposable network
- `status <instance>`: Show status of account, subids, socket, service, container and registration
