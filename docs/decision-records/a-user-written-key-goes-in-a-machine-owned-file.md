# A user-written key goes in a machine-owned file, because every human-owned file is YAML

Status: decided
Ticket: #262 (`nenv config set`)
Related: [inventory-hosts-are-a-subject](inventory-hosts-are-a-subject.md),
[a-job-is-a-sequence-of-steps](a-job-is-a-sequence-of-steps.md)

## The question

`nenv config get <key>` reads. There is no way to write one, so a user who mistypes a
context name in their configuration has to open the file in an editor — and a file an
editor can also truncate. #262 asks for `nenv config set <key> <value>`.

The obvious implementation is "write the file it read from". **That is wrong**, and the
reason is a property of this repository's configuration rather than of the command.

## Why not the file it read from

Every human-owned file in this system is YAML:

| file | written by |
|---|---|
| `neoenv.yaml` in a project | a person |
| `$NEOENV_CONFIG_HOME/neoenv/neoenv.yaml` | a person |
| `neoenv/private/neoenv.yaml` | a person, for this repository's own secrets |

`serde_yaml` does not preserve comments, and neither does any round-trip in this
dependency set. **A rewrite of any of those files is a comment-stripping rewrite**, and
a `config set` that silently removes every comment in a user's project file is a worse
outcome than not having the command: the user finds out by reading the diff, or by not
reading it at all.

A line-oriented edit avoids the comment loss and is worse in a different way: it has to
understand enough YAML to find a key that may be nested, quoted, anchored, flow-style or
absent, and every case it gets wrong is a file it has just corrupted.

## The decision

**A user-written key goes in a new machine-owned file**, read as the highest-precedence
layer:

```
$XDG_CONFIG_HOME/neoenv/overrides.yaml
```

- **Machine-owned**, so rewriting it wholesale is safe and there is nothing to preserve.
  It is a file `nenv` writes, not a file a person writes, and it says so at the top.
- **Highest precedence**, because a person who ran `nenv config set context prod` means
  it. It sits above the project's own `context:` and above the private overlay, since
  the overlay is project-scoped and a user-level answer is not.

That is a new layer in the resolver, and the alternative was to put the file *below* the
project, where a user's correction would be silently overridden by the very file they are
correcting. **A `config set` that does not take effect is worse than a missing one**, and
that is the same reasoning as refusing an unknown subcommand: the user has to be told
which of the two things went wrong.

## The two refusals this makes possible

The highest-precedence layer is also the one a document does not control, which is where
two of #262's acceptance criteria come from.

**`set` corrects and does not invent.** An unset key is refused with the alternatives
named, the same treatment `config get` already gives. `nenv config set stage prod` on a
project with no `stage` is refused rather than creating one — because a typo that
silently creates a key is the shape of defect this repository has shipped eleven of, and
because the user who wanted `stage` will be told what the keys are.

**The write is atomic and says where it went.** Through `state_file::write_atomic`,
which is already the convention for every mutable `nenv` state file here: a temporary
file in the destination directory, synced, published with replacement semantics, and a
symlink target refused. And the confirmation names the file, because "it worked" without
a path is how a reader ends up wondering which of three configurations changed.

## What this does not decide

- **Whether the file is YAML or TOML.** YAML, because it is what the rest of the
  configuration is and because a person will eventually need to read it. The
  machine-owned convention elsewhere in this repository is TOML (`capabilities.toml`,
  the trust file), and *that* is a real tension — resolved here in favour of the
  reader over the convention, and recorded as a decision rather than left to be
  rediscovered.
- **Whether a project may opt out.** It may not, at first. A project that wants to
  forbid a user override has a capability grant to express that, and grants are
  already default-deny.
- **What happens to a key that is later removed from the project.** The override
  survives and starts applying again. `nenv config unset` removes it, and `config list`
  shows where each value came from — which is the property that makes the extra layer
  tolerable at all.

## The cost, stated plainly

A fourth configuration layer is more machinery than the command seems to need, and it
makes `inspect` — which reports where every value came from — one layer richer to reason
about. That cost is paid deliberately: the alternative is a command that corrupts the
files a person wrote, or that silently does not take effect.
