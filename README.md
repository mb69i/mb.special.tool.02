# fim.py

A small file integrity monitor. It records a baseline of files and folders, then tells you
what changed. One file, Python 3.9+, no dependencies.

## Usage

```
python fim.py init /etc /usr/local/bin     # record a baseline
python fim.py check                        # compare the tree against it
python fim.py update                       # accept the current state as the new baseline
python fim.py watch -i 60                  # poll every 60 seconds and report changes
```

| Option | Meaning |
|---|---|
| `-b FILE` | baseline file (default `fim-baseline.json`) |
| `-x GLOB` | skip paths matching a glob, repeatable |
| `--force` | `init`: replace an existing baseline |
| `--follow` | follow symlinks |
| `--fast` | reuse the stored hash when size and mtime match |
| `--algo` | hash algorithm (default `sha256`) |
| `-q` | print nothing when everything is clean |
| `--json` | machine-readable output |
| `-n N` | lines printed per category (default 50) |

## What it detects

| Mark | Meaning |
|---|---|
| `+` | file or folder added |
| `-` | file or folder removed |
| `M` | content changed, symlink retargeted, or file type changed |
| `A` | permissions, owner or group changed |
| `?` | path could not be read |

- A content change where the modification time was put back is flagged as `timestamp preserved`.
- Folders are tracked too, so a `chmod` on a directory or a new empty directory shows up.
- Nothing is skipped by default. Every `-x` pattern is a blind spot, and each run says how many
  paths were skipped.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | changes found |
| 2 | error: unreadable paths, or a missing, outdated or tampered baseline |

This makes it usable from cron: `fim.py check -q || mail -s "FIM alert" you@example.com`.

## Protecting the baseline

The baseline is the thing an attacker wants to rewrite, so it carries a seal over both the
file records and the settings (monitored paths, skip patterns, hash algorithm).

- **With `FIM_KEY` set**, the seal is an HMAC. Any edit to the baseline makes `check`, `update`
  and `watch` stop with exit code 2. A baseline swapped for one without a key is refused too.
- **Without `FIM_KEY`**, the seal is a plain hash. It catches accidental damage only: anyone who
  can edit the baseline can also recompute the seal. Keep such a baseline on read-only media or
  on another machine.

```
export FIM_KEY='a long random secret'
python fim.py init /etc --force
```

Keep the key away from the monitored machine's ordinary users. A key stored next to the
baseline protects nothing.

## Notes and limits

- Unreadable paths are reported on every run and give exit code 2 until you either run with
  enough privileges or exclude them with `-x`. Nothing is silently left out.
- `--fast` skips hashing when size and mtime are unchanged, so it misses an edit that restores
  both. Run a full check regularly.
- `watch` polls. A change made and undone between two polls is not seen, and each change is
  reported once.
- With `--follow`, each real directory is walked once, so symlink loops cannot inflate the scan.
- Baselines written by the first version of this tool are refused. Re-create them with
  `init --force`.
- Not tracked: extended attributes, ACLs, SELinux labels.

## Tests

```
python -m unittest -v
```

Run them as a normal user. As root one test is skipped, because root can read every file.
