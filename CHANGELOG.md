# Changelog

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
