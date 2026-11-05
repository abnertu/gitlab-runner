set shell := ["bash", "-euo", "pipefail", "-c"]

# The commit before the first tagged release; its history stays in `git log`.
first_release_base := "fd5e599"

# List the available recipes.
default:
    @just --list

# Run every flake check with complete build logs.
check:
    nix flake check --no-update-lock-file --print-build-logs

# Prepare a release commit and tag locally; pushing stays a separate step.
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    version={{ quote(version) }}
    [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'usage: just release X.Y.Z\n' >&2; exit 2; }
    git diff --quiet && git diff --cached --quiet || { printf 'commit or stash changes first\n' >&2; exit 1; }
    sed -i "s/^version = \".*\"$/version = \"$version\"/" pyproject.toml
    if git describe --tags --abbrev=0 >/dev/null 2>&1; then
      range=(--unreleased)
      earlier=""
    else
      range=("{{ first_release_base }}..HEAD")
      earlier=$'Earlier history is in `git log`.\n\n'
    fi
    notes=$(git-cliff "${range[@]}" --tag "v$version" --strip all)
    # Keep the title, insert the new section, keep the older sections.
    changelog=$({ head -n 1 CHANGELOG.md; printf '\n%s\n\n%s' "$notes" "$earlier"; tail -n +3 CHANGELOG.md; })
    printf '%s\n' "$changelog" >CHANGELOG.md
    git add pyproject.toml CHANGELOG.md
    git commit -qm "chore(release): v$version"
    git tag -a "v$version" -m "gitlab-runnerctl $version"
    printf 'Tagged v%s. Push with: git push --atomic origin main "v%s"\n' "$version" "$version"
