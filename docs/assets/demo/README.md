# Record the terminal demo

Use the actual configured controller on Arch Linux.
Build `runnerctl` from the machine flake without activation.
Authenticate with `sudo -v` in the recording terminal.
Run from the repository root:

```bash
nix shell github:NixOS/nixpkgs/4fe25e12eb9f4c744966dd3de5a05246cf098601#asciinema-agg -c python3 docs/assets/demo/record.py \
  --command /path/to/configured/bin/runnerctl --instance frontend --instance dotnet
```

The recorder runs the configured controller's version, validation and read-only plans.
The included GIF shows a development build of gitlab-runnerctl 0.3.0 with the machine's actual frontend and dotnet declarations.
Plans report proposed changes; runtime checks remain deferred.
Registration contents stay unread.

For explicitly authorized credential files, use `--sudo-password-file /path/to/credential`.
The recorder connects that file descriptor directly to native sudo before capturing output.
It never reads credential bytes into Python or recording data.
Authentication and noninteractive plans must share the same terminal.
Expired authorization or a failed command rejects the recording.

The recorder captures actual stdout and stderr in memory.
The [filter](redact.py) removes personal identifiers before logging or rendering.
Unsupported controls, invalid text and oversized output reject the recording.
The filter covers account names, hostnames, home paths, email addresses, endpoints and private addresses.
Review other identifying information manually.

[agg](https://github.com/asciinema/agg) renders the sanitized transcript with a neutral prompt.
Timing is edited for readability; command output stays unchanged except for redaction.
No native commands or machine observations are substituted.
The recorder replaces `docs/assets/demo.gif` only after every command and rendering step succeeds.
Temporary transcripts are removed on exit.

Inspect the beginning, middle and end frames before committing the GIF.
Check complete output, personal identifiers, duration and looping.
Never run recording automatically.
