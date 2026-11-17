# Changelog

## 0.4.2 (2026-11-17)

### Fixes

- **operations**: Run account commands from / and extend image pulls
- **verify**: Report an IPv4-only job network pass
- **removal**: Wait for zombies and name them in the error

### Documentation

- Follow the gitlab-runnerctl repo rename
- **removal**: Say when to refresh trust by hand

## 0.4.1 (2026-11-17)

### Fixes

- **verify**: Retry the job network check over IPv4

## 0.4.0 (2026-11-16)

### Features

- **cli**: Color text plans and validation on terminals
- **operations**: Pass stdin to native commands and name removal tools
- **removal**: Remove a Runner instance completely

### Refactoring

- **operations**: Share the Runner session environment

### Documentation

- **demo**: Show real configured runner plans

## 0.3.0 (2026-11-10)

### Features

- **inspection**: Add tokenless static previews
- **retirement**: Retire declared Runner policy explicitly
- **diagnostics**: Preserve safe native command output

### Fixes

- **status**: Recognize numeric subordinate ID ownership

## 0.2.0 (2026-11-05)

### Features

- Report the version and read it from pyproject.toml alone

### Refactoring

- Adopt nix-adapter v0.7.0 (breaking)
- Move runnerctl into a src/runnerctl package (breaking)
- Split instance validation into one check per concern
- Split registration parsing and reconcile into named stages
- Document every public symbol and gate it in ruff

### Documentation

- Rewrite the README and add agent rules from the repo-docs template

Earlier history is in `git log`.
