# AGENTS Instructions

gitlab-runnerctl converges dedicated rootless Podman GitLab Runner instances on a host.

**Never read or print a Runner token.** Tests use the synthetic instances in `tests/fixtures/`.

## Runtime contracts

- Pass the registration token only through `GITLAB_RUNNER_TOKEN`.
- Keep the token out of argv, logs, progress output and error messages.
- Use only the lock `/run/lock/runnerctl.lock`, with the label `Runner operation`. Never share a lock with another tool.
- Keep each instance on its own account, with `concurrent = 1`.
- Write the pending marker before the first trust, configuration, unit, image or service change of a `reconcile`. Account, sub-ID and user-manager preparation come before it, and they are idempotent.
- Clear the marker only after the service runs as declared.
- `reconcile`, `register` and `verify` change live host state. Get the user's go-ahead before you run them on a real host.

## Git

- Write commits in [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/) format.
- For a non-trivial change, write a commit body that explains why.
- Mark a breaking change with `!` and a `BREAKING CHANGE:` footer.
- Author commits as the user alone, without `Co-Authored-By` or other co-author trailers.
- Commit as the plan progresses.
- Before you push, squash related commits into one commit to keep the history clean.
- Push only after the user approves that push.
- Version releases with [Semantic Versioning 2.0.0](https://semver.org/).
- `pyproject.toml` holds the only version literal.
- Use `just release X.Y.Z` to set the version, prepend git-cliff notes, commit and tag locally.
- Push the branch and its tag together with `git push --atomic`.
- Never move a pushed tag. If the release workflow fails, fix it on `main` and run it again with `workflow_dispatch`.

## Tests

- Add a test to the repo only when it guards behavior that no existing test covers.
- The test must fail when that behavior breaks. Weigh this before you add each test.
- Run throwaway tests freely to check your work.
- Keep throwaway tests out of the repo unless they meet the bar above.
- Validate with `nix flake check`. It runs the unit tests, ruff, pyright strict, statix, deadnix and nixfmt.
- Never let a test reach a real native command.
- `PLATFORMS` holds absolute executable paths, so stubs on `PATH` do not intercept them. Patch the collaborators in `runnerctl.operations` instead.
- Flakes see tracked files only. Stage each new file with `git add` before a Nix command.

## CI

- Keep a CI check only when it catches a concrete failure that no existing check covers.
- Identify that failure before you add or keep the check.
- Apply the test rules to CI checks too.
- Run the repo's entry points against real inputs or isolated fixtures.
- Reject duplicate checks, source-text assertions, copied inventories and checks that only prove that a command or file exists.
- Name each workflow, job and step by its target and its action.
- Propagate command failures.
- Count a missing prerequisite or skipped required coverage as a failure.
- After you change these rules, audit the repo against them.
- Validate changes locally. Then verify the required CI on the pushed commit.
- Report each uncovered contract and each unavailable check.

## Docs

- Keep each doc concise and plain. Each sentence must carry information.
- Write English docs in US English, to the [ASD-STE100](https://www.asd-ste100.org/) writing rules:
  - Give one instruction in each sentence.
  - Write instructions in the imperative and in the active voice.
  - Use one word for one meaning, and one meaning for one word.
  - An instruction has 20 words or fewer. A description has 25 words or fewer.
- Review each sentence over these limits. Split it if it holds more than one instruction or fact. A list of items can stay in one sentence. Make a bullet list from more than five items.
- Write a non-English doc in two passes:
  1. Write an English draft to these rules.
  2. Translate the draft. Keep its sentence boundaries and one term for each concept. Keep commands, paths and code unchanged. Use the natural word order of the target language.
