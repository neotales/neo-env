# Vaults and `nsv://` secret references

Existing references need a [scheme migration](migration.md#vault-reference-scheme).

Status: first implementation slice. This document is the plan; the code and its
tests are the claim. Read *Driver status* before trusting a driver.

Implemented in this slice:

- `vaults:` declarations for `age`, `keepass`, and `os` in YAML and TOML, with
  driver-specific required fields.
- The `nsv://` grammar, `${NAME}` interpolation, fragments, query options, and
  the refusals for options that would be inert.
- `age` `get`: identity file, inline identity, an identity fetched through
  another `nsv://` reference, `values:` ciphertext, and inline `?value=`.
- `keepass` `get`: a KDBX entry's password or `#username`, an ordinal path
  match, and a master password bootstrapped from an age value or another
  reference.
- Lazy resolution at shell activation, `exec` (including `-E` dotenv and `-e`
  values), and task/job execution (project env, task `env:`, task `dotenv:`,
  and CLI `-E`/`-e`).
- Dry runs never resolve a secret: not the project environment, not a task
  environment, and not a predicate. A plan reports what would run without
  opening a vault.
- Overrides are settled before resolution. A project value replaced by a task
  value or by `-e` is never fetched, and `${NAME}` in a project `nsv://`
  reference is preserved until use so a reference can see the final CLI value.
- Remote-module vault declarations are refused with `NEO343` before the merge;
  a remote module can neither add nor replace a local declaration.
- Bounded reference depth with cycle detection, bounded read retries, NUL and
  size validation, and diagnostics/Debug that never echo a reference path, a
  query key, a provider path, or a secret.

The `os` driver reads and writes through an injectable credential backend, and
the `keepass` driver updates an existing KDBX document. `ensure=true` is
supported for `os` and `keepass` through a cooperative global+resource lock,
with a fresh read under the lock. This is a lock among cooperating `neoenv`
processes, not a guarantee against other applications. Age remains read-only:
writing would mean rewriting its encrypted configuration file. Authorized
remote-module vault declarations remain refused. On Unix the lock directory is
walked and held through no-follow directory descriptors; the final directory
and lock files must be privately owned by the current user. Windows currently
has no safe lock implementation in this runtime: OS/keychain reads remain
available, but `set` and `ensure=true` fail closed there. OS keychain writes and
`ensure` are therefore not supported on every platform.

## The problem

A project configuration is data. A password, a token, or a generated value is
not data that belongs in a file that gets committed, printed by `inspect`, or
copied into a diagnostic. `nenv` already has a `secret` flag on an environment
entry, but that flag is a *rendering* decision: it redacts a value in `inspect`
and does not change where the value came from.

The vault feature adds the missing half: a configuration value can name a
secret in a provider, and the value is fetched only when something needs it.

```yaml
vaults:
  machine:
    driver: age
    identity: ~/.config/neoenv/age/identity.txt
  work:
    driver: keepass
    path: ./.neoenv/secrets.kdbx
    secret: nsv://machine/work-vault-password

env:
  DATABASE_PASSWORD: nsv://work/infrastructure/database
  GITHUB_TOKEN: nsv://work/github/token#password
```

`nenv validate` and `nenv inspect` must not open a vault. A command that only
reads configuration is not allowed to prompt for a KeePass password or touch a
keyring.

## Goals

- One reference grammar, one parser, one resolver. No second implementation in
  a provider.
- Lazy resolution. A reference is resolved at the point a value is consumed:
  shell activation for the project environment, and task/job execution for a
  task's `env:` and `dotenv:`. Configuration loading never resolves a reference.
- Fail closed. A missing provider, a missing entry, a bad password, an
  unsupported option, or an interpolated name that does not exist is an error
  that names the reference's vault and path. A value is never silently replaced
  with an empty string.
- A secret value never appears in a diagnostic, an error, a log line, or
  `Debug` output. This includes a provider configuration's `secret` and age
  `values` ciphertext.
- Local providers and one platform credential-store driver in this slice. A vault declaration is not a
  grant to read an arbitrary path on behalf of a remote module; see *Trust*.

## Non-goals for this slice

- Listing, searching, deleting, or rotating entries.
- Age writes. Age stays read-only; `ensure` for age would have to rewrite its
  encrypted configuration file and is refused.
- Caching. A value fetched once is not reused across commands. A cache is a
  second place a secret lives, and its invalidation is a design of its own.

## Configuration schema

`vaults:` is an ordered map. The key is the vault name used by `nsv://`; the
value is a provider declaration. The structured formats (`neoenv.yaml`,
`neoenv.yml`, `neoenv.toml`) support it. The line-oriented `.neoenv` syntax has
no vault form and produces an empty map, exactly as it does for `jobs:`.

```yaml
vaults:
  machine:                         # arbitrary name, used in nsv://machine/...
    driver: age
    identity: ~/.config/neoenv/age/identity.txt
    values:
      work-vault-password: |
        -----BEGIN AGE ENCRYPTED FILE-----
        ...
        -----END AGE ENCRYPTED FILE-----
  work:
    driver: keepass
    path: ./.neoenv/secrets.kdbx
    secret: nsv://machine/work-vault-password
```

### Names

A vault name is a non-empty lowercase identifier: ASCII lowercase letters,
digits, `-`, and `_`, starting with a letter or digit. Uppercase is refused
rather than folded, because a name is a lookup key and `nsv://Work/...` must not
become a second spelling of the same vault. A name is also the first segment of
every reference, so it cannot contain `/`, `?`, or `#`.

### `driver: age`

| key | required | meaning |
| --- | --- | --- |
| `identity` | no | Path to an age identity file, an inline `AGE-SECRET-KEY-...` value, or an `nsv://` reference. Relative paths are relative to the declaring configuration file. `~` and `${NAME}` are expanded. Absent means the machine identity below. A reference to `nsv://os/...` may hold the identity in the operating-system store; it resolves through the same lazy path and the same cycle check as every other reference. |
| `values` | no | Ordered map of path name to ASCII-armored age ciphertext. The ciphertext is decrypted on demand with the identity. |

The default machine identity is `$NEOENV_CONFIG_HOME/neoenv/age/identity.txt`
(with the usual `XDG_CONFIG_HOME` and `~/.config` fallbacks). The path is a
convention, not a keyring: a missing file is a clear error naming the path it
expected.

`values` is the *bootstrap* form. A keepass vault's master password can be an
age ciphertext in an age vault, so no password is written in the configuration
and no keyring is required:

```yaml
vaults:
  machine:
    driver: age
  work:
    driver: keepass
    path: secrets.kdbx
    secret: nsv://machine/keepass-work
```

`identity`, `path`, and `secret` are the only fields interpolated, and only the
braced `${NAME}` form is expanded. `values` ciphertext is not interpolated: a
`$` in a ciphertext is data, and expanding it would corrupt the value. For a
master password the same rule is a safety property: a bare `$` is part of the
password, not the start of a variable.

### `driver: keepass`

| key | required | meaning |
| --- | --- | --- |
| `path` | yes | Path to a KDBX file. Relative paths are relative to the declaring configuration file. `~` and `${NAME}` are expanded. |
| `secret` | yes | The master password: a literal, an interpolated value, or an `nsv://` reference. Only `${NAME}` is expanded; a bare `$` is part of the password. Never printed. |

The KDBX file is opened read-only. The entry path in `nsv://work/group/entry` is
split on `/` and passed to the KDBX library's own path query with **ordinal**
comparison. The library's default is case-insensitive; for a secret lookup that
is a wrong-entry bug waiting to happen, so `A` and `a` are different entries
here.

The fragment selects a field. `#username` returns the entry's username; the
default (no fragment) returns the password. `#password` is accepted as an
explicit spelling of the default. Any other fragment is refused. This is the
one place the first slice interprets `#username`; see *Unresolved choices*.

### `driver: os`

| key | required | meaning |
| --- | --- | --- |
| `service` | no | Keyring service name. Defaults to `neoenv`. The reference path is the account name. |

The OS driver reads and writes through `keyring` on Linux (Secret Service),
macOS (Keychain), and Windows (Credential Manager). A target with no adapter
reports the store as unavailable rather than silently falling back.

`provider` is not accepted as an alias for `driver`. Unknown keys are refused,
so a document that writes the old spelling fails instead of parsing into an inert
field.

`ensure=true` is supported for `os` and `keepass`. KeePass writes compare the
source fingerprint immediately before atomic replacement and refuse a detected
change. This cannot close the compare-to-rename race with external applications;
only neoenv processes coordinate. Every mutation takes a fixed
global lock first and then a resource lock named by a hash of the canonical
resource identity: service/account for `os`, canonical database path for
`keepass`. The operation re-reads under the lock, returns an existing value
unchanged, and only then generates and writes a missing one. Nested bootstrap
reuses the lock already held on the same thread, so an age identity held in the
OS store cannot deadlock against KeePass. Locks are cooperative between `neoenv`
processes; another application is outside that contract. The platform keyring
adapter has no atomic create-if-absent API, so `ensure` is serialized by this
lock and documented as cooperative, never as atomic against external writers.

KeePass updates read the current database under the lock, preserve existing
entries and fields, save through `neotales-keepass`, and publish with a
same-directory synchronous temp file. The database itself must already exist;
`ensure` creates a missing entry, not a new vault. A save or publish failure leaves the
original file untouched. The database's key metadata is whatever the library
writes on save; the existing master credential and all other entries are
preserved. `set` is an explicit overwrite. A `set` target must be a plain
reference or a KeePass `#username`/`#password` field; `?ensure=false` is refused
by its presence, not its truthiness. `Age` remains read-only.

The platform adapter builds `keyring` credentials through the platform
credential builder rather than `keyring::Entry`, whose debug logging includes
the service and account. A capturing-logger regression runs in an isolated
subprocess, requires the logger to install successfully, proves a positive
control (`keyring::Entry`) is captured, then exercises the adapter's get/set
path with a mock credential and asserts no service/account coordinates appear.
The caller's logger and global level are not changed. Backend reads and create
outcomes run the same NUL and size checks as age and KeePass, and an invalid
write is rejected before the backend call. `service` on a non-`os` driver is
refused by name.

The keyring target is platform-specific:

- **macOS:** no target override. Keyring's target is a keychain domain
  (`User`, `System`, `Common`, `Dynamic`), not an identifier, so the adapter
  leaves it at the default `User` keychain. The keychain identifies the item by
  the service (`name`) and account (`account`).
- **Linux:** no target override. The item is in the default Secret Service
  collection, identified by its `service` and `username` attributes. A
  per-account target would create a collection per account.
- **Windows:** the target is the sole identifier and Windows compares it
  case-insensitively. The adapter uses
  `neoenv:v1:<service-byte-len>:<lowercase-hex-service>:<account-byte-len>:<lowercase-hex-account>`.
  Hex is fixed lowercase, so `token` and `TOKEN` are distinct even after case
  folding, and length prefixes keep delimiter characters unambiguous. The
  encoded target is bounded to 32,767 bytes.

Interoperability differs by platform as a consequence. On macOS and Linux an
item created by another keyring client with the same service and account is
visible, because the adapter does not change the platform's target/collection
identity. On Windows only the canonical target is read; an item created by
another application under keyring's default `{user}.{service}` target is not.
There is no earlier released `neoenv` OS adapter to migrate from; recreation
with `nenv secret set` is the supported path. A future encoding change must bump
`v1` deliberately.

`Secret` has no public fields, so an external backend constructs values through
`Secret::try_new`, which applies the same bounds and returns a value-free error.
An integration test implements `OsBackend` outside the crate and resolves a
reference through it.

## `nsv://` reference grammar

```text
nsv://<vault>/<path>[?<query>][#<fragment>]
```

- `sv` is the only scheme. The prefix is case-sensitive.
- `<vault>` is a configured vault name.
- `<path>` is one or more non-empty segments separated by `/`. Segments are
  opaque bytes: they are **not** percent-decoded and are not treated as filesystem
  paths. A segment is passed to the provider unchanged. `..` is not special; it
  is a name, and a KDBX path query treats it as a name too.
- `#<fragment>` is optional and provider-defined. The first slice defines
  `username` and `password` for KeePass and refuses a fragment elsewhere.
- `<query>` is optional and is a `&`-separated list of `key=value` pairs.
  Values are percent-decoded (`%XX` only; `+` is literal). Repeated keys and
  unknown keys are refused.

The canonical order is `path?query#fragment`. The parser accepts the fragment
before the query as well, because both spellings are unambiguous and a user
writing `#username?ensure=true` should not get a confusing error; the parsed
form is stored separately.

### Interpolation

A reference is interpolated before parsing. Only the braced form `${NAME}` is
expanded; a bare `$NAME` is literal. This is deliberately stricter than the
configuration `env:` expansion: a reference is a URL-shaped value, `$` in a
path is more likely to be data than a variable, and a missing name must not
collapse to an empty segment. An undefined `${NAME}`, an empty name, or an
unterminated `${` is an error.

The lookup is the final **effective** environment at the point of use: inherited
inputs, project values, task `env:`/`dotenv:`, and `-E`/`-e`, with their override
precedence already applied. An inherited input is available when a reference
explicitly names it (`${HOME}`, `${CI}`), but it is never scanned or resolved
merely because it exists. This is why laziness matters: `nsv://${VAULT}/token`
cannot be parsed at configuration load time, because `${VAULT}` may be supplied
by `-e`, by a later declaration, or by the caller's environment.

### Query options

| key | values | meaning |
| --- | --- | --- |
| `ensure` | `true` / `false` | If missing, generate/store; supported for OS and KeePass. |
| `size` | 1–4096 | Generated value length in bytes. Default 32. Only valid with `ensure=true`. |
| `upper` | `true` / `false` | Include uppercase letters in a generated value. Default `true`. Only valid with `ensure=true`. |
| `value` | percent-encoded ciphertext | An inline age ciphertext. Only valid on an `age` vault. |

**`ensure=true` generates a uniform alphanumeric value and stores it only if the
entry is absent.** `size` defaults to 32 and is bounded 1–4096; `upper=false`
removes uppercase letters. Symbols are excluded so the value is safe in a shell
assignment or URL. External writers can race the cooperative read and write.
Age refuses `ensure`. `size` and `upper` without
`ensure=true` are refused as inert options.

The inline `?value=` form exists so a small encrypted value can live in a
template or an environment declaration without a separate `values:` map. The
ciphertext is ASCII-armored age, percent-encoded because armor contains `+`,
`/`, `=`, and newlines. It is decrypted with the same identity as the vault.

## Where resolution happens

| consumer | when | what is resolved |
| --- | --- | --- |
| `nenv shell activate` | while rendering the activation diff | every project `env:` value |
| `nenv exec` | after activation and after `-E`/`-e` | the child environment, including every `-E` dotenv assignment and every `-e KEY=VALUE` value |
| `nenv run`, `nenv task run`, `nenv job run` | immediately before each task action runs, and before a predicate that reads the environment | the task's `env:` values, its `dotenv:` values, the project values it inherits, and every CLI `-E`/`-e` value consumed by the run |
| a dry run of any of the above | never | nothing; project env, task env, and predicates keep references as written. A predicate that reads an unresolved reference is reported as `conditional`, not as false/skipped, and the same outcome propagates to dependents and to `outcome.TASK` predicates. |
| `nenv inspect`, `nenv validate`, `nenv config`, `nenv context` | never | nothing; a reference is shown as the reference |

A reference must be the **whole** value. `nsv://work/db` resolves; `prefix-nsv://work/db`
is refused rather than spliced. Composition is done by declaring two environment
entries, not by string concatenation, because concatenating a secret into a
larger string makes the boundary invisible and makes redaction harder.

A project or task `nsv://` value keeps its `${NAME}` text through configuration
loading. Loading does not know the final `-e`/`-E` context, and expanding there
would turn `nsv://vault/${WHICH}` into `nsv://vault/` before the resolver ran. The
interpolation context is the final effective environment, including inherited
inputs and the settled project/task/CLI values. The **resolution scope** is
separate: only project declarations, task dotenv assignments, task `env:`, and
CLI-supplied keys are fetched. An inherited value is not resolved merely because
it contains `nsv://`, and an inherited variable is not an implicit declaration;
it is an input a reference may name explicitly.

Resolution is bounded by a fixed depth (8). A KeePass `secret:` that is itself
an `nsv://` reference, which points at an age `values:` entry, is the intended
shape; a cycle is an error, not a hang. Reads that can be transient are retried
three times with a short bounded backoff. Wrong password, missing entry, and
missing file are permanent and are not retried.

A resolved value is written once. The interpolation context is not replaced with
resolved plaintext, so a secret whose text happens to look like `nsv://...` is not
scanned a second time and cannot become part of another reference's path.

## Trust and safe creation

- **A local declaration is local.** The first slice reads only paths named by a
  local project, user, or private-overlay configuration. A remote module that
  declares a vault is refused with `NEO343` before the merge, so it can neither
  add a declaration nor replace a local one by declaring the same name.
  **Origin is recorded by the loader, not inferred from a path**: a tarball cache
  path does not look like the commits cache, and a local project may contain a
  lookalike directory. A local import inside remote content inherits remote
  origin. Authorized remote vaults need a capability and a trust decision; that
  design is recorded as unresolved rather than guessed.
- **No creation.** A missing KDBX file or identity file is an error. `nenv` does
  not create a vault, a directory, or a key. `ensure` can create an entry in
  an existing KeePass vault or OS store.
- **No credential or interpolated coordinate in a diagnostic.** An error may
  name a declared vault, which is a local configuration name. It never echoes a
  reference path, a query key, a provider path, a value, a master password, an
  identity key, or a ciphertext. A reference's `Debug` redacts the path, the
  query key/value, and the provider path; a query key is attacker-adjacent
  because it can be produced by `${NAME}` interpolation.
- **No process-wide cache.** A resolved value lives in the child environment or
  the activation diff, not in a global.
- **A KDBX file is opened with the library's standard read limits.** The first
  slice treats the path as a local file the user named, not as hostile input.
  A service that resolves an untrusted KDBX needs the library's explicit
  Argon2 ceilings; that policy is not exposed here yet.

## Driver status

| driver | parse | `get` | `set` | notes |
| --- | --- | --- | --- | --- |
| `age` | yes | yes | no | identity file, inline identity, `nsv://` identity, `values:` map, inline `?value=` |
| `keepass` | yes | yes | yes | KDBX read/update; fingerprint check detects intervening edits but is not universal locking |
| `os` | yes | yes | yes | platform keyring adapter; `ensure` is cooperative-lock serialized, not atomic against other applications |

The age identity is the first bootstrap chain this feature needs to support,
and it is deliberately the same chain as every other reference:
`identity: nsv://os/machine-age-identity` resolves through the driver map, not
through a second side door. A reference cycle, including an `age` vault whose
identity points back at itself, is caught by the same bounded resolver.

## Diagnostics

| code | category | meaning |
| --- | --- | --- |
| `NEO146` | validation | a vault name is not a lowercase identifier |
| `NEO147` | validation | an unknown vault driver |
| `NEO148` | validation | a driver field is missing, or a field that belongs to another driver is present |
| `NEO149` | validation | a reserved driver that is not implemented |
| `NEO150` | validation | an age `values:` key is empty |
| `NEO704` | runtime | a reference cannot be parsed |
| `NEO705` | runtime | the named vault is not declared |
| `NEO706` | runtime | the driver cannot open or access the vault |
| `NEO707` | runtime | the entry or value is missing |
| `NEO708` | runtime | an option is not supported by this driver or backend (`ensure`, `size`, `upper`, an unknown fragment) |
| `NEO709` | runtime | a reference cycle or depth limit |
| `NEO710` | runtime | a resolved value is not a valid environment value (NUL, oversized) |
| `NEO343` | trust | a remote module declares a vault, including one that would replace a local declaration |

Codes are assigned here and used in the code; the table is the contract a user
can search.

## Unresolved choices (deliberately not guessed)

1. **`#username` semantics outside KeePass.** The fragment is a KeePass field
   selector here. For the OS keyring it could mean the account name, and for
   age it could mean a key. Those are different enough that inventing one
   grammar now would make the other two wrong. The parser carries the fragment;
   each provider decides whether it accepts it.
2. **OS keyring platform coverage.** The adapter builds against Secret Service,
   Keychain, and Credential Manager, but only the injectable memory backend has
   executable coverage here. A headless Linux CI machine has no Secret Service
   session, so a live read is a manual/platform verification, not a CI claim.
   The cooperative lock is the extent of the guarantee; external writers are not
   controlled.
3. **Write semantics and `ensure=true`.** Which values are writable, what
   "atomic" means for KDBX, how concurrent `nenv` processes coordinate, what
   character set `upper`/`size` generate, and whether a generated value is
   returned to the caller before or after it is stored. The cooperative semantics
   are described above; external writers remain outside the guarantee.
4. **Age recipients for `set`.** A write needs a recipient selection and a
   place to put the ciphertext: rewrite the `values:` map in the user's config,
   or a separate encrypted file. Neither is in the first slice.
5. **Reference retention in `inspect`.** The first slice leaves the reference
   in the value and shows it. Whether `inspect` should show the reference, a
   redacted marker, or the resolved length is a product decision; it must not
   show the value.
6. **Authorized remote-module vault declarations.** A remote module can
   contribute tasks and packages, but a vault declaration names a local file,
   identity, or keyring account. The first slice refuses every remote vault
   declaration with `NEO343`, before the merge, so it can neither add one nor
   replace a local one. A future capability grant would have to name the vault,
   the provider, and the allowed operation; that design is still open.
7. **Reference scheme scope.** `nsv://` is NeoEnv's own scheme, distinct from
   the mod-vault broker's `nsb://` scheme and grammar. NeoEnv does not parse,
   emit, or treat another scheme as an alias.

## Implementation phases

1. **This slice.** Configuration declarations for age and keepass; `nsv://`
   parser and interpolation; age and keepass `get`; recursive bootstrap;
   bounded depth and retries; resolution at shell activation, `exec`, and task
   execution; tests with real encrypted and KDBX fixtures, and an injected
   memory OS backend for the OS driver and `ensure`.
2. **OS driver.** Platform target features and an injectable backend.
3. **Write path.** `nenv secret set` reads the value from stdin (never argv).
   OS and KeePass writes use cooperative locking. KeePass fingerprint checks
   detect changes before atomic publication, but external-application races remain
   outside the lock.
4. **Trust and remote modules.** A vault declaration in a remote module is a
   capability request; a local file path is not granted by a declaration alone.
5. **Inspection.** A schema decision for showing references without resolving
   them.

## Compatibility and release impact

`TaskOutcome::Conditional` is a new public enum variant in `neoenv-core` and a
new value in the `run` / `task run` / `job run` `--format json` report
(`"conditional"`). The text report prints the same word.

What this touches:

- an exhaustive `match TaskOutcome` in a library consumer no longer compiles;
- a script that treats the set of outcome strings as closed may not recognize
  `conditional`;
- `outcome.TASK` predicates can observe the `"conditional"` string only in a
  dry-run report; no execution path records a conditional result;
- the checked-in JSON schemas do not cover the task-run report, so no schema
  version moves here.

The `neoenv-*` library crates are `publish = false`; the binary is the public
surface. Under [`release-process.md`](./release-process.md), this is observable
output, so it is not a patch. A consumer with an exhaustive outcome match makes
it a breaking change: release notes must name `conditional`, and the pre-1.0
version line takes a minor bump (semver's 0.x breaking rule), not a patch. No
release version is changed in this worktree.

The vault configuration key is `driver`, not `provider`. `provider` is not an
alias: it is an unknown key and is refused, so an old document cannot silently
keep working with different semantics. Renaming a configuration key is a major
change under the release policy; on the pre-1.0 line that is a minor version
bump. Release notes must name `driver`, and the next release must not be a
patch.

`nenv secret get <reference> [path]` and `nenv secret set <reference> [path]` are
new commands. `set` reads the value from standard input and has no value option,
because a password in argv is visible in the process list and shell history. The
input is bounded to 1 MiB before the backend is touched, and the bytes are
preserved exactly — a trailing newline is part of the value, so use `printf`
when no newline is wanted. Both commands are text-only; a secret is never placed
in a JSON document. Adding commands is a minor change under the release policy.

The OS driver adds target-specific keyring dependencies. On a target with no
adapter the driver reports the store unavailable. Only the injectable memory
backend has automated coverage; a live platform store is not touched by tests.


## Test plan

- Parser: every valid form, every refusal, interpolation success and missing
  name, query/fragment order, percent decoding, unknown/duplicate query keys,
  `ensure`/`size`/`upper` validation.
- Configuration: YAML and TOML, unknown driver, accepted `os` declarations, a field from
  the wrong driver refused by name, a bad vault name, `.neoenv` empty map,
  redacted `Debug` for age values and keepass `secret`.
- Age: generate an identity, encrypt a value, resolve `values:` and `?value=`,
  a missing identity, a wrong identity, an unreadable ciphertext.
- KeePass: build a KDBX fixture in a temp directory with the library, resolve
  an entry's password and `#username`, an ordinal-vs-case entry, a wrong master
  password, a missing entry, and a bootstrap password from an age vault.
- Resolution plumbing: project environment, task `env:`, task `dotenv:`, CLI
  `-E`/`-e`, a later declared value, and an environment value that is not a
  whole reference.
- Lazy boundaries: `validate`/`inspect` and every dry run do not open a vault,
  including when a project value or predicate names one. A conditional outcome
  propagates through `needs` and `outcome.TASK` predicates rather than becoming
  a definitive plan.
- Overrides: a project reference replaced by a task value or `-e` is never
  fetched; a reference sees the final CLI interpolation context.
- Explicitly named inherited inputs are available to a reference; unrelated
  inherited values are outside the resolution scope and are not scanned. A
  missing `${NAME}` is an error, not an empty segment.
- Ownership is by supplied key, not by comparing values: an `-e`, `-E`, or task
  dotenv assignment equal to the inherited value is still resolved.
- A resolved plaintext that itself looks like `nsv://...` is not resolved again.
- Remote modules: a tarball vault declaration, a local import nested inside a
  tarball, and a same-name replacement are refused; a local directory whose path
  looks like the remote cache is accepted as local.
- OS driver: injected memory backend `get`/`set`, cooperative `ensure` create and
  existing-value preservation, an
  age identity bootstrapped from `nsv://os/...`, invalid backend values rejected,
  and a capturing logger proving the platform adapter does not emit service or
  account coordinates.
- CLI: `secret` parsing/help paths, exact stdin byte preservation including a
  trailing newline, bounded oversize rejection before any write, and no live
  keyring access in tests.
- Locking: hashed resource filenames with no coordinates, two-process KeePass
  and OS ensure contention, and failed KeePass publication leaving the original
  bytes untouched.
- Leak check: diagnostics never contain the password, plaintext, ciphertext,
  reference path, interpolated query key, or provider path.
