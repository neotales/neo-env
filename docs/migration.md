# Migration plan: pvtlab to neotales/neoenv

**Status:** the code has moved and builds; the release machinery is written; the
rename beyond the binary is not done; the imported backlog is not started. This
document is the plan; [`../eng/issues/`](../eng/issues) is the ticket set; the
README's *Status, honestly* section is the current state.

## Vault reference scheme

Replace `sv://` with `nsv://` in NeoEnv vault references, including dotenv
assignments, CLI arguments, and references used to bootstrap KeePass passwords
or age identities. The old scheme is not an alias: commands that require a
reference reject it, and settings that also accept ordinary strings no longer
recognize it as a reference. Vault names, entry paths, and stored data are
unchanged. See [Vaults and secret references](vaults.md).

## Where the code came from

`neotales/pvtlab`, branch `dev`. Not the `rust-neoenv` branch — that branch is
fully merged into `dev` and the merge base of the two *is* the `rust-neoenv`
head, so `dev` at `4b22e3c8` is a strict superset. The last commit that touched
NeoEnv on `dev` was `5a6de42c`, "the newest installed version was decided by byte
order".

The code was written under a private repository that had **no CI at all**. One
GitHub Actions workflow, `.github/workflows/rust-release-gate.yml`, ran once on
2026-09-20 with a three-OS matrix, was cancelled, and was never committed — it
exists in the Actions API and in no branch. So "the release gate is green" meant
"a Deno script run by hand on one Linux machine, with two SSH runners standing
in for macOS and Windows that the repository's own toolchain file records as
never having completed a run."

That is the single most important fact about the migration. The code is good and
the evidence discipline is genuinely unusual for a project this size. The
*verification* is one platform deep, and it is about to become a public
repository's front door.

## The split

Twelve crates made up the closure. The split is not even, and that is the whole
design problem.

| Moves to `neoenv` | Already in `rust-libraries` |
| --- | --- |
| `neoenv-core` | `neotales-args` → `std/args` |
| `neoenv-config` | `neotales-dotenv` → `std/dotenv` |
| `neoenv-policy` | `neotales-env` → `std/env` |
| `neoenv-runtime` | `neotales-gotmpl` → `templates/gotmpl` |
| `neoenv-installer` | `neotales-sprig` → `templates/sprig` |
| `apps/nenv` (was `apps/neoenv`) | `neotales-process` → `os/process` |

The six on the right are a faithful port. Every public type, function, method,
field, enum variant, trait, type alias and default value that the NeoEnv closure
touches exists in `rust-libraries` with an identical signature. The copies are
the original files plus rustdoc. No missing items, no changed signatures, no
feature flags to enable, and no `NEOENV_*` read inside any of them.

**They are now also published**, to the package registry on the same Gitea
instance, at `0.0.0-alpha.1` — all eighteen crates, all at that version. That
removes the original reason for the submodule ("nothing is on a registry and there
is no account") and does not remove the submodule, because the crates stay alpha
until they reach crates.io, which is the author's call and settles the timing.

The submodule was also 78 commits behind for most of this repository's life, which
turned out to matter more than the registry question. Two of those commits fixed
defects reachable from this binary, and one of them shipped a silently wrong value:

| commit | defect | what a user saw |
| --- | --- | --- |
| `221bb81` | the unbraced `$NAME` form ate the character that ended the name | `$HOME/bin` → `/home/devbin`; `$PATH:/opt` → `/usr/bin/opt` |
| `88969f3` | a key that is not a name panicked in `render`, two calls after it was written | a crash, in a method whose signature promises it cannot fail |

Neither failed loudly, and nothing in this repository's 588 tests noticed (the suite is 593 now), because
no test interpolated a name next to a separator. Two tests cover both, and
`eng/check-submodule.sh` fails when the pin is more than ten commits behind the
furthest-ahead of the fetched `dev` refs — because a submodule that is never bumped
is a dependency nobody chose.

The guard now counts **every** fetched `refs/remotes/*/dev` and takes the furthest ahead,
because it used to name one remote and the one it named was the oldest of the three. It
printed `pin matches hyprx/dev` on a run where the pin was 32 commits behind
`origin/dev`, and the ref-age note did not fire because that ref was 8h old and the limit
is 24h. [Issue #273](../eng/issues/273-the-staleness-guard-read-one-remote-and-printed-green.md).

`88969f3` is a breaking change to four public methods: `set`, `unset`,
`path_prepend` and `path_append` now return `Result<&mut Self>`. The adaptation was
small, in one file, and it removed a lie rather than adding one. The three diff
builders here return `Result<EnvDiff, EnvError>`, and the key a user actually writes
in a config file is the only one that can be invalid — the `PATH` this crate
contributes is a name by construction. Swallowing that error would have meant a
declared variable silently not appearing, so it propagates and becomes `NEO133`,
which names the key and the file it was read from.

The pin moved a second time, to `c815464`, on the same rule: other work landed
upstream and three of the commits fixed `gotmpl`, which this binary renders task
`run:` lines through. `len` returned a character count where Go returns a byte
count, so `{{ len .env.MESSAGE }}` on `café` said `4` and every Go template in
existence says `5` — a wrong number in the shape of a right one. `index` had the
matching defect, and the two had been reconciled against Go and the .NET
reference rather than reasoned about.

Three tests here cover it, and two of them fail against the previous pin. The
third documents a contract that reads like a bug and is not one: `index` at a
position inside a multi-byte character returns the continuation byte rather than
refusing, because Go does and the .NET reference does, and a template engine that
invented a stricter rule than either target would trade a documented divergence
for an undocumented one.

Worth recording because of how it was found: **my first version of the boundary
test asserted a `slice` builtin that does not exist, and its second version
miscounted the UTF-8 bytes of an emoji from memory.** Both would have been
"verified" by a test that passed for the wrong reason if I had not run the
failure. The engine was right in both cases and the test was wrong, which is the
opposite of what a test is for.

Bumping also required `.cargo/config.toml`, because the crates' *internal* path
dependencies now carry `registry = "gitea"` and cargo refuses to resolve a graph
naming an undeclared registry. Declaring it needs no credential — the `path` still
wins and nothing is fetched — which is the property that makes the file safe to
commit, and the reason to watch for a `token` key ever appearing in it.

`nenv` depends on neither `neotales-ssh` nor any `neotales-docker-*` crate, so the
fact that those areas still need work does not gate this one. The migration off the
submodule is issue #253.

Two of the ports are better than the originals, and both changes are worth
knowing about because they are the kind of thing that reads as a regression in a
diff:

- `neotales-args`, `neotales-gotmpl` and `neotales-sprig` had `description`
  fields that said "for NeoEnv". A general-purpose library that describes itself
  as belonging to one application is a library with the wrong boundary, so the
  descriptions were rewritten.
- The sprig conformance fixtures are byte-identical to the originals, including
  the decision-record comments that explain the Sprig scope by reference to
  Compose files and to `ndocker`. They are a general-purpose fixture corpus now
  and should stop naming two products it has nothing to do with.

## What the move cost, concretely

### A C toolchain, and an architecture ceiling

`ureq`'s `tls` feature reaches `rustls`, which reaches **`ring`**, which compiles
C and ships pregenerated assembly objects for exactly `{x86, x86_64, arm,
aarch64}`. `xz2` reaches **`lzma-sys`**, which compiles bundled LZMA C. So every
build host needs a C compiler, and no target outside those four architectures
can link at all.

`ring`'s build script also forces **clang** for C on Windows aarch64. No C++
compiler and no `cmake` are needed, which is the cheap end of this — `aws-lc-rs`
would have added both, so `ring` is the right choice and should stay.

There is no pure-Rust TLS provider to switch to, and dropping TLS is not an
option: every URL the installer produces is `https://`. This is the price of
making network requests, it is already being paid, and the honest consequence is
a release matrix capped at four architectures.

### The MSRV moved, and three numbers had to move with it

`rust-libraries` declares `rust-version = "1.98"` and every crate in it inherits
that. Cargo enforces the declared version of every package in the graph, so
depending on it raises our floor from 1.88 whether or not our own code needs it.
A lower number here would be a promise the workspace cannot keep.

This is the exact failure that has already happened once. The floor moved 1.85 →
1.88 in `Cargo.toml`; the toolchain files stayed behind; and the gate failed on
every platform with a message naming only the crate that noticed:

```
rustc 1.85.1 is not supported by the following packages: ndocker@0.1.0 requires rustc 1.88
```

No single file mentioned both numbers. Worse, `RUSTUP_TOOLCHAIN` overrides
`rust-toolchain.toml` entirely, so a shell can be using a compiler no file
mentions — which is how `yoke-derive 0.8.3`, a dependency that compiles on the
newer compiler and not the pinned one, got into a lockfile during a session that
believed it was testing the pinned one.

The fix is not a comment. `eng/check-msrv.sh` asserts that `Cargo.toml`,
`rust-toolchain.toml`, the MSRV workflow and the compiler actually in use all
name the same version, and CI runs it. That script exists because the alternative
is a fourth comment.

### Lint scoping, and why the obvious CI setup is wrong

The obvious thing to write in CI is `RUSTFLAGS: "-D warnings"`. **It does not
work here.** It fails the build on two crates inside the `rust-libraries`
submodule, which this repository does not own and cannot fix. Scoping to
`cargo clippy --workspace --all-targets -- -D warnings` lints our crates and
leaves the submodule alone.

`RUSTDOCFLAGS: "-D warnings"` with `cargo doc --no-deps` *is* safe, because
`--no-deps` does not run rustdoc over path dependencies. Both facts are recorded
in `ci.yml` so that a later reader does not "fix" the working one and break the
build.

### Two doc defects the compiler found

Raising the compiler from 1.88 to 1.98 surfaced 35 clippy warnings that had been
warnings for a decade, and one genuine broken intra-doc link
(`cli::model::RuntimeCommand`, where `cli::model` is a private module that `cli`
re-exports wholesale). `cargo test --doc` was never in the old gate — a stale
doc import passed `clippy --all-targets` at zero while failing every time it ran
— so the README and crate docs now compile as part of the gate.

## The release plan

`nenv` ships as prebuilt binaries in GitHub Releases. A tag is the release.

**Six targets, all built on native runners. No cross-compilation.**

| Target | Runner | Status |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` | verified |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | feasible, unproven |
| `x86_64-apple-darwin` | `macos-13` | feasible, unproven |
| `aarch64-apple-darwin` | `macos-14` | feasible, unproven |
| `x86_64-pc-windows-msvc` | `windows-2022` | feasible, unproven |
| `aarch64-pc-windows-msvc` | `ubuntu-24.04` | **cross-compiled**, `cargo-xwin` |

Native rather than cross because of `ring` and `lzma-sys`: a cross build needs a
C cross-toolchain per target, and the source repository's `cross-check.sh` needed
a `zig cc` shim for exactly that reason. Native runners already have a C
compiler. If a target ever needs cross-compiling, that gets its own issue and its
own shim.

**Deliberately not built:**

- **32-bit (`i686`, `armv7`)** — `rust_target_triple` returns `None` for both and
  every resolver turns that into a named error. A shipped 32-bit `nenv` would be
  a `nenv` that cannot install anything. The width guard already models 32-bit
  hosts correctly, so this is a design refusal rather than a gap.
- **Linux/musl, any architecture** — a correctness bug, not a gap. See below.
- **riscv64, s390x, ppc64le, loongarch64, mips, sparc** — `ring` has no
  pregenerated objects for them. Unreachable without removing TLS.

### Why there is no musl build

`std::env::consts::OS` reports `linux` for both the glibc and musl ABIs. So on a
musl host, `host_target()` falls through to its `unwrap_or` arm and returns
`x86_64-unknown-linux-gnu`, and `nenv` hands a user on Alpine a glibc-linked
binary that cannot run. Separately, `platform_os_aliases("linux")` is
`["linux"]` — no `musl`, no `gnu` — so asset *matching* cannot prefer a musl
asset either.

Shipping a musl build would mean shipping a `nenv` that successfully installs
tools which then fail on first use. The worst kind of bug: the install reports
success. So the installer refuses musl explicitly and says why. The fix is to
give the platform table a libc dimension and to make the `unwrap_or` a refusal —
[issue #23](./eng/issues/023-musl-hosts-install-glibc-binaries.md).

### Phase two: package managers

`deb`, `rpm`, Homebrew, winget, scoop, pacman, chocolatey. The artifact layout
is chosen so these *wrap* rather than rebuild: one executable at the archive
root, no absolute paths inside, a `SHA256SUMS` file, and a version in the binary
itself. Every one of those ecosystems can then be added without a release
engineer and without changing a filename.

## The rename

The binary is `nenv`. Everything else is a decision with a cost, so each one is
its own ticket rather than one sweep.

| Surface | Decision | Why |
| --- | --- | --- |
| Binary | `nenv`, with a `neoenv` alias shipped alongside | The alias costs one file per release artifact and means every existing script, CI job and muscle-memory keeps working. |
| Crate names | stay `neoenv-*` | Renaming crates that nothing publishes buys nothing and costs a diff over 57,000 lines. |
| `NEOENV_*` variables | `NENV_*` canonical, `NEOENV_*` read as a deprecated alias | See the rule below. |
| Config filenames | `nenv.*` canonical, `neoenv.*` legacy, **refuse when both exist** | See the rule below. |
| `neoenv.lock` | `nenv.lock` | A lockfile is internal state, not a published format, so this is the cheapest rename available. |

**The rule that makes the alias safe.** A deprecated alias that *mostly* works is
worse than one that does not exist, because a user who set it believes it took
effect. So: **every** `NEOENV_*` variable either works fully, or is refused with a
message naming its replacement. There is no third state. This project's own
memory records the shape of the mistake — a Go config key that parsed
successfully and was then never read, so a file that asked for a behaviour got a
different behaviour and a message that never named the key the author wrote.

The same rule is why "both config files present" is a refusal rather than a
precedence rule. A file that is silently shadowed by another file is a wrong
answer with no symptom, and a wrong answer that fails closed still hides.

## The imported backlog

The private tracker had open work that has no home in a repository with no
issues. It is imported in [`../eng/issues/`](../eng/issues), grouped:

- **the rename** — five tickets
- **the release path** — installers, artifact contract, the later package managers
- **the verification gap** — the five unproven targets, the five Windows tests
  and one macOS test that have never executed
- **live defects** found by audits and not yet fixed, including the three
  wrong-install bugs and the duplicated platform logic in `tool_dispatch.rs`
- **accepted-not-closed residuals** from five completed slices, recorded as
  their own tickets rather than left in prose where they will be re-litigated
- **deliberately deferred** — SSH transport, the language runners, the Deno port

Two of those are worth calling out because they are the kind of thing that reads
as tidying and is actually a bug:

**`apps/nenv/src/tool_dispatch.rs:330-444` is 115 lines of duplicated platform
logic.** It re-derives the target triple table, the node and zig archive
targets, and six binary-name helpers, all of which already exist in
`neoenv-installer`. The copies exist because the installer's helpers are
`pub(super)` and therefore unreachable from `apps/nenv`. Make them `pub` and
delete the copies.

**And one of those copies is already wrong.** `tool_dispatch.rs:355-356`
hardcodes `root.join("dist").join(binary)` for Odin, while the installer's
`odin_binary` *probes* three locations because the archive nests the executable
under `dist/` **or a versioned directory**. A global Odin unpacked to the
versioned path installs successfully and is then not found by `exec`. That is a
live wrong-install, and it is the direct consequence of the duplication — which
is the argument for deleting the copies rather than for fixing this one.

## What "done" means for the migration

1. `eng/validate.sh` is green on Linux, and CI runs it on all three operating systems.
2. The five unproven targets have had the suite run on them, and the README says
   which ones have.
3. One tagged release exists, installed by `install.sh` and `install.ps1` on a
   machine that was not the build machine.
4. The rename is done and the `neoenv` alias still works.
5. The imported tickets are in this repository's tracker, not in prose.

Items 1 and 2 are the ones that matter. Everything else is bookkeeping.
