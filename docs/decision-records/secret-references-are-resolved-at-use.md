# Secret references are resolved at use, not when configuration loads

**Status:** accepted for the first vault slice. See [`docs/vaults.md`](../vaults.md).

## Context

A configuration document can contain `DATABASE_PASSWORD: nsv://work/database`.
The value could be fetched while the project is loaded, or left as a reference
until a command is about to consume it.

Loading is not one command. `nenv validate`, `nenv inspect`, `nenv config`,
`nenv context`, `nenv task list`, and `nenv completion` all read configuration,
and none of them has any use for a decrypted password. Resolving at load makes
all of them depend on a KeePass password, an age identity file, or a keyring
that happens to be unlocked.

Eager resolution also collapses two different observations into one. `inspect`
is supposed to say where a value came from; if the value has already been
replaced, the reference is gone and the command cannot report what the file
said.

## Decision

A reference is parsed and resolved at the point a value is consumed:

- `nenv shell activate` resolves the project's `env:` values while it renders
  the activation diff.
- `nenv exec` resolves the child environment after activation and after `-E`
  and `-e` have been applied.
- `nenv run`, `nenv task run`, and `nenv job run` resolve the task environment
  immediately before the task action runs, and before a predicate that reads
  the environment. This includes the task's `env:`, its `dotenv:`, project
  values it inherits, and CLI overrides.
- `validate`, `inspect`, `config`, `context`, `task list`, and completion never
  resolve.

A reference must be the whole value. String-splicing a secret into a larger
value is refused, because the secret boundary becomes invisible and redaction
becomes a guess.

## Consequences

- A command that does not consume a secret does not need the vault to exist.
  This is testable, and the test asserts that removing the identity file does
  not make `validate` or `inspect` fail.
- A reference survives into `inspect` output. Showing the reference is the
  first-slice choice; it must never show the resolved value.
- The same rule has to be applied at every new consumption point. A new command
  that builds a child environment and forgets to resolve is the defect shape
  this decision creates; the alternative defect, resolving everywhere, would
  make every read command depend on a secret store.
- Resolution needs an environment context for `${NAME}` interpolation. That
  context is the final *effective* environment: inherited inputs, project values,
  task values, and CLI overrides with precedence settled. It is separate from the
  resolution scope, which contains only keys the run supplies. An inherited input
  can therefore be named explicitly, while an unrelated inherited value
  containing `nsv://` is neither scanned nor resolved.
- A dry run does not resolve. It plans with references as written; opening a
  vault is not part of planning.

## Rejected alternatives

- **Resolve while loading.** Simple, and makes `inspect` lie about provenance
  and every read command require the vault.
- **Resolve in the configuration crate.** The configuration crate is pure and
  does no I/O; opening a KDBX file there would make the pure layer an effect
  boundary and make `parse_project` non-deterministic.
- **A process-wide lazy cache.** A cache is a second place a secret lives. It
  needs invalidation, lifetime, and multi-tenant rules that the first slice does
  not have.
