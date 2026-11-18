# `--global` means the system scope, and the old meaning moves to `--user`

Status: decided and implemented. This is an intentional public CLI behavior change
and needs review.

Related: [tool-runtime expansion plan](../tool-runtime-expansion.md)

## The question

Before this change, `-g`/`--global` installed beneath the caller's
`NEOENV_CONFIG_HOME` and `NEOENV_DATA_HOME` — a per-user scope. A machine-wide
installation needs a system scope with different configuration and install roots,
different permissions, and an explicit choice by whoever runs it.

The requested meaning is:

- `-u`/`--user`: the current per-user folders.
- `--global`/`-g`: a system-wide installation.

The change is not a rename. Reinterpreting an existing flag changes where an existing
command writes, and a user who runs the old command after an upgrade must not silently
install into a root they did not choose.

## Decision

`--user`/`-u` means the per-user scope. `--global` means the system scope.

`-g` is an alias for `--global` and therefore selects the system scope. It previously
selected the user scope, so this is an intentional behavior change; the fail-closed
system mutation guard means an old install/remove command does not silently write to a
new destination. A future release that enables system writes must add explicit
confirmation or an unambiguous noninteractive opt-in before doing so.

System **mutation** is disabled in this build. Publish and remove need
race-resistant directory-relative operations; path validation alone leaves a
time-of-check/time-of-use gap. `--global`/`-g` therefore supports inspection and dry-run, and
refuses install/remove/update/pin/unpin/purge with a diagnostic naming the blocker and
pointing at `--user`. This is a deliberate fail-closed limit, not a silent fallback.

System paths:

| Platform | Configuration | Installed tools |
| --- | --- | --- |
| Windows | `NEOENV_GLOBAL_CONFIG_DIR`, then `%ProgramData%\neoenv` | `NEOENV_GLOBAL_INSTALL_DIR`, then `%ProgramFiles%\neoenv` |
| Linux/macOS | `NEOENV_GLOBAL_CONFIG_DIR`, then `/etc/neoenv` on Linux or `/private/etc/neoenv` on macOS | `NEOENV_GLOBAL_INSTALL_DIR`, then `/usr/local/neoenv` |

`ProgramData` and `ProgramFiles` are read from the environment. The process never
raises privileges, invokes `sudo`/`runas`, or creates a privileged directory as a
side-effect of resolving a path. A permission failure names the path and exits
non-zero. System paths must be absolute; relative overrides are refused.

## Compatibility

There is no silent fallback and no automatic migration of the old `-g` destination.

- A user who wants the old per-user destination writes `--user`.
- `-g` and `--global` select the system scope; system mutation is refused by the
  fail-closed guard described above.
- The system scope is never inferred from permissions.
- Read-only commands that combine scopes report both; they never write to the other
  scope.

The current coverage is:

- `nenv use --user` — implemented, tested with temporary overrides.
- `nenv use --global --dry-run` — implemented; actual system mutation is refused.
- `tool remove/update/pin/unpin/purge --project|--user` — implemented.
- The same commands with `--global` — dry-run/read only; mutation is refused.
- `tool list --user|--global` — implemented read-only.
- `tool which`/`tool where --user|--global` — implemented; no cross-scope fallback.
- `tool cleanup --global` — refused as mutation; `--user` maps to user purge.
- `runtime list` and `runtime where` — read both scopes, expose `scope`, and select the
  same last-applied runtime the shell activation uses.
- Shell activation — contributes system runtimes first, then user runtimes so the user
  scope wins a collision.

System mutation remains a known blocker: it cannot be enabled until publish/remove use
race-resistant directory-relative operations.

## Command coverage

Scope selection applies to every command that installs, reads, changes, or removes a
global selection:

`use`, `tool list`, `tool which`, `tool where`, `tool remove`, `tool update`,
`tool pin`, `tool unpin`, `tool purge`, `tool cleanup`, `runtime list`, and shell
activation.

Read-only commands may report a scope that is not present as empty. They may not fall
back to the other scope. Mutating commands require the scope to be explicit.

## Tests

- Both scopes resolve under temporary overrides.
- `-g` resolves to the system scope like `--global`.
- `--user` and `--global` cannot be combined.
- A read-only root fails without a partial selection.
- No test writes to `/etc`, `/usr/local`, `Program Files`, or `ProgramData`.

The scope change is implemented. The remaining gaps are listed under Command coverage.
