# Release process

How an `nenv` release is cut, what a tag means, and what has to be true before
anything is published.

## The model in one paragraph

A release is a GitHub Release attached to a git tag. The tag is `v<version>`.
There is no changelog file to hand-maintain, no version number in a manifest
that has to be edited in step with the tag, and no publish step to a registry —
`nenv` is a binary and the binary is the whole product. Tag `v1.2.3`, the
workflow builds six targets, checksums them, and attaches them.

The five library crates in `lib/` are **not** published to crates.io. That is a
deliberate consequence of the project being a CLI: the public surface is the
binary, and a library API nobody consumes is a compatibility promise nobody
asked for. It also means there is no crates.io account, no trusted-publishing
configuration, and no publish ordering to get wrong.

## What you actually do

```sh
# 1. The tree must be green. This is the whole checklist.
eng/validate.sh

# 2. Confirm CI is green on the commit you are about to tag, on all three
#    operating systems. Two of the six targets have never had the suite run on
#    them, so a green macOS and Windows lane is new information, not a formality.

# 3. Rehearse. This is the step people skip, and it is the one that catches
#    everything.
gh workflow run release.yml -f dry_run=true

# 4. Tag and push.
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0

# 5. Watch. The release job is the only one with write permission.
gh run watch
```

A release nobody has rehearsed is a release nobody has tested. The dry run
builds all six targets, produces all six archives, produces the checksum file,
and prints what it would upload — and creates nothing.

## Versioning

Semantic versioning, applied to the CLI's observable behaviour.

- **patch** — a bug fix. A wrong diagnostic, a crash, a formatting fix.
- **minor** — a new command, a new configuration key, a new provider, a new
  platform target.
- **major** — a change to something a script depends on.

What is a major change, specifically, because this is a CLI and the answer is
wider than it is for a library:

- any change to an exit code
- any change to the shape of a `--format json` document that has a checked-in
  schema
- removing or renaming a command, an option, or a configuration key
- changing which config filename is preferred
- changing a default that a reasonable user would not have overridden

What is **not** a major change: a new key in a JSON document that has a schema
laying out an object without `additionalProperties: false`, a new diagnostic
code, a new optional flag, or a bug fix that makes a documented behaviour
actually happen.

The rule behind the list: **a diagnostic schema change requires a new diagnostic
version rather than a change to v1 in place.** A new machine-readable shape
requires a versioned schema before it is advertised as stable. Both are in
[`schemas/`](./schemas) and both are load-bearing — the tests embed the files and
fail when a document stops matching.

## The target matrix

| Target | Runner | Artifact |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` | `nenv-<version>-x86_64_unknown_linux_gnu.tar.gz` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | `nenv-<version>-aarch64_unknown_linux_gnu.tar.gz` |
| `x86_64-apple-darwin` | `macos-13` | `nenv-<version>-x86_64_apple_darwin.tar.gz` |
| `aarch64-apple-darwin` | `macos-14` | `nenv-<version>-aarch64_apple_darwin.tar.gz` |
| `x86_64-pc-windows-msvc` | `ubuntu-24.04` | `nenv-<version>-x86_64_pc_windows_msvc.zip` |
| `aarch64-pc-windows-msvc` | `ubuntu-24.04` | `nenv-<version>-aarch64_pc_windows_msvc.zip` |

**Four of the six targets are cross-compiled from one x86_64 Linux runner**, and the two
that are not are macOS. This section used to say the opposite -- that every target needs a
native runner because `ring` compiles C and "ships pregenerated assembly objects for only
`{x86, x86_64, arm, aarch64}`" -- and that reasoning was wrong in a way worth recording:
**all six targets of this matrix are in that set**, so `ring` never capped the matrix. The
obstacle is the per-target C toolchain, and `cargo-xwin` and `cargo-zigbuild` hold that
mapping rather than a script this repository owns.
`docs/decision-records/cross-compile-windows-from-linux.md` has the measurements, and
[#265](../eng/issues/265-cross-platform-ci-gate-has-no-runner.md) has the fleet state.

If a target ever does change how it is built, that is a change to this document
and it gets a shim of its own rather than a `--target` flag bolted onto an
existing job.

### Not built, and why

**32-bit — `i686`, `armv7`.** Refused by design. `rust_target_triple` returns
`None` for both and every resolver turns that into a named error, so a shipped
32-bit `nenv` would be a `nenv` that cannot install anything. The width guard
models 32-bit hosts correctly and refuses them a 64-bit asset — that guard exists
because a 32-bit ARM host accepted arm64 assets in 112 releases across 39
repositories, and the failure mode was an `Exec format error` at first run.

**Linux/musl, any architecture.** A correctness boundary, not an omission.
`std::env::consts::OS` is `linux` for both ABIs, so a musl host resolves the
glibc triple and downloads glibc-linked binaries that cannot run on Alpine — and
the install reports success. See the README and issue #23.

**riscv64, s390x, ppc64le, loongarch64, mips, sparc.** `ring` has no
pregenerated objects for them and the link fails. Unreachable without dropping
TLS, which is not an option: every URL the installer produces is `https://`.

## The artifact contract

Every artifact is a `.tar.gz` (unix) or `.zip` (Windows) containing:

```
nenv            # or nenv.exe, at the archive root
LICENSE.md
README.md
```

The properties downstream packaging depends on, each of which exists for a
package manager that has not been written yet:

1. **One executable, at the archive root.** `dpkg`, `rpm`, Homebrew, scoop and
   chocolatey each want to place a binary at a known path. A nested
   `bin/nenv` inside a versioned directory means every one of them has to know
   the layout.
2. **No absolute paths inside the archive.** A tar entry named
   `/usr/local/bin/nenv` is a path traversal waiting to happen and cannot be
   extracted by `dpkg-deb` or `bsdtar` without complaint.
3. **A `SHA256SUMS` file with two spaces between digest and filename.** That is
   the format `sha256sum -c` reads and the format every one of those ecosystems'
   verifiers expects. Getting it wrong means rewriting it six times.
4. **No `.pdb` in the Windows archive.** It is several megabytes of symbols
   nobody has a use for and every Windows package format resizes around.
5. **The version is inside the binary**, from `CARGO_PKG_VERSION`, so a package
   manager can verify what it installed without trusting its own metadata.
6. **The binary at the root is a binary for the platform the filename names.**
   `MZ` for a `.zip` whose triple says `windows`, Mach-O for `darwin`, `\x7fELF`
   for `linux`.

   This one is here because it was violated, in this repository's own release, and
   nothing caught it. A `dist` built on a host that cannot cross-compile produced
   an empty archive for each target it could not build — which is correct — and
   the Windows archive was handed a Linux binary. `install.ps1` then fetched it,
   verified the checksum against a manifest generated from the same wrong archive,
   unpacked it, reported success, and left a 64-bit ELF binary at `nenv.exe`.

   The checksum is no defence here, and it is worth being exact about why: it
   proves the bytes arrived **intact**, it says nothing about what they **are**,
   and the manifest was built from the wrong file, so it vouched for the wrong
   file. A checksum verified a broken release and reported a match.

   So the identity check is separate from the integrity check, and it runs first.
   `eng/check-artifact-contents.sh` opens every archive and requires the root
   binary to start with the magic for the OS in the name. An empty archive, an
   unreadable archive, and a filename naming no known OS are three separate
   failures with three separate messages, because they have three different
   remedies and one message for three causes sends the reader to the wrong one.

Changing any of these after the first release renames files under every package
format that has already been written. That is why they are written down here and
enforced by the packaging job rather than discovered by the first person to try
installing on Alpine.

### `build-dist.sh` has two verdicts, and they are not the same

    $ ./eng/build-dist.sh --dry-run
    build-dist: 1 artifact(s), checksum manifest written
    build-dist: this machine cannot build 5 of the 6 targets:
      NOT-BUILT-ON-THIS-MACHINE  nenv-0.1.0-aarch64_apple_darwin.tar.gz
      ...
    build-dist: OK. Every target this machine can build was built.
    build-dist: THIS IS NOT A COMPLETE RELEASE. 5 of 6 artifact(s) are absent,
    build-dist: and eng/publish-to-gitea.sh will refuse this directory. ...

**The dry run exits 0 on that, and it used to exit 2.** A machine that
cannot build `aarch64-apple-darwin` has not *failed* to build it, and the old code
made every host on earth report a failure — which is a task whose only possible
outcome is failure, and therefore a task nobody runs. That is the "a step that runs
nowhere" shape caused by a task that invokes a script without a shebang.

The two verdicts are:

| exit | meaning |
|---|---|
| 0 | Every target this machine *could* build was built. **This is not a complete release**, and the message says so in those words. |
| 2 | `UNBUILT` holds an entry no skipped target accounts for — an artifact missing with no stated reason. |

**The publish guard does not depend on this exit code.** `publish-to-gitea.sh` refuses
on the *presence* of `UNBUILT`, so nothing that stands between a partial dist and a
registry is weakened by `build-dist.sh` returning 0. That separation is the point: the
build script reports what happened to it, and the publish script decides what may
happen next.

## Signing and provenance

Not yet, and it should be, in this order:

1. **Checksums** — shipped today, verified by default by both installers.
2. **Sigstore / cosign keyless** — a `.sigstore` bundle per artifact, verified in
   `install.sh` and `install.ps1`. Keyless, because a signing key that a person
   holds is a signing key that eventually leaks.
3. **SLSA provenance** — an attestation per target naming the workflow, the
   commit, and the runner image.

The install scripts print the URL they are about to fetch, and that is
deliberate: it is the difference between a user who can see what is about to
happen and one who cannot.

## Where CI runs and where releases come from

Two hosts, two jobs, and the distinction is not cosmetic:

| | Host | What runs there |
| --- | --- | --- |
| **CI** | `git.hyprx.cloud` (Gitea) | `ci.yml` and `msrv.yml` on every push |
| **Releases** | GitHub | `release.yml`, on a `v*` tag |

Gitea reads `.github/workflows/` as well as `.gitea/workflows/`, so putting the
release workflow in this directory keeps Gitea away from nothing. It carries an
explicit `if: ${{ !env.GITEA_ACTIONS }}` on **every** job for that reason, and
`eng/check-workflows.sh` fails if one is missing — guarding only the first would
still build the whole six-target matrix on the wrong host and then fail at the
release step, which is twenty minutes and nothing.

**Action references in the Gitea-run workflows are version tags, not commit
SHAs.** The SHA pins were observed to resolve on this instance — `actions/checkout`
and `dtolnay/rust-toolchain`, both pinned to full commits, ran in Gitea — so
this is not a fix for a resolution failure. It is one fewer host CI has to reach:
every SHA pin is a dependency on github.com being reachable *from the runner*, and
the account behind this repository is suspended there. The compensating control is
the instance's action allow-list, which is a stronger control than a SHA when the
list is curated and a weaker one when it is not. `release.yml` keeps its SHA pins,
because it only ever runs on the host where they were verified.

**What actually broke the first Gitea run** was not an action. It was
`cut -d'"'" -f2` inside `$( )` inside `" "` in the composite action that reports
the toolchain. Gitea's runner generates a shell script from each `run:` block,
and the generated script could not be parsed, so the step failed — and the step is
named after the action, so the natural reading is that the action could not be
resolved. It could; it had already installed rustc 1.98.1. **A quoting bug in a
shell line and an unresolvable dependency have the same symptom**, and the only
way to tell them apart is to read the log past the last line you expected.

## The gate

`eng/validate.sh` is the whole check, and it is what CI runs. It is sixteen steps
in the order that makes a failure cheapest to diagnose, and the script counts
them from its own source rather than carrying a written number — it said "ten"
for three steps after a step was added, and nothing was checking, because a
number written beside a counter is a second place to be wrong and this one
failed by being stale rather than wrong.

1. `eng/check-msrv.sh` — every version number agrees, and `rustc` is the one the
   files claim
2. `eng/check-workflows.sh` — no repeated YAML key, no action a Gitea-run
   workflow cannot resolve, no unguarded release job, no runner nobody has
   checked
3. `eng/check-task-scripts.sh` — every task script exists, is executable, and
   has a matching shebang
4. `eng/check-import-sweep.sh` — every finding in the `pvtlab` audits has a row in
   `docs/finding-map.md`, and every verified gap names a ticket
5. `eng/publish-to-gitea.sh --self-test` — the publisher's completeness check, over
   five version cases
6. `eng/check-ticket-refs.sh` — every `#<n>` in the prose and the tests names a
   ticket that exists, or says whose tracker the number is
7. `eng/check-submodule.sh` — the submodule is fetchable without a credential,
   which is the difference between a CI run and a three-minute "Repository not
   found"
8. `eng/check-artifact-names.sh` — the release workflow and both installers agree
   on the six artifact filenames
9. `eng/check-artifact-contents_tests.sh` — every artifact holds a binary for the
   platform its name says, asserted in both directions
10. `eng/check-issue-labels.sh` — every label a ticket uses is one the tracker
   creates, and every ticket carries exactly one status
11. `cargo fmt --all -- --check`
12. `cargo clippy --workspace --all-targets -- -D warnings`
13. `cargo test --workspace --all-targets`
14. `cargo test --workspace --doc`
15. `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
16. the compiled-binary smoke and the resource soak
17. `RUSTFLAGS="-D warnings" cargo xwin check --workspace --all-targets --target x86_64-pc-windows-msvc`

Steps 1 through 10 are first because all of them fail in under a second and all
of them would otherwise be discovered at release time.

**Step 17 is last because it is the slowest and the least often wrong, and because every
other step compiles for the host.** A green gate said nothing about Windows: `make_executable`
and the import that served it in `tools/archive.rs` were `cfg(unix)`-only in use but
unconditional in definition, which is a dead-code warning and an unused-import warning on
every Windows target, and neither is visible from a Linux build. `check` rather than `build`
because nothing is linked, so the cost is a type-check and the only extra thing it needs is
an MSVC `lib.exe`, which `cargo xwin` supplies.

It covers one non-native target, which is enough to see `cfg(unix)` dead code and **not**
enough to claim the matrix is covered. `aarch64-pc-windows-msvc` is blocked here for the
same reason it cannot be built (#265 — `ring`'s build script runs for `check` too), and the
two macOS legs are the same trade in the other direction.

The `tool_lifecycle` tests for interrupted updates, concurrent execution,
bounded process capture, and process-group cleanup currently run only on Linux
and macOS, where their fixture uses a non-reaping `waitid` to retain safe
process-group ownership. They do not cover those behaviours on Windows or
other Unix systems. The exited-leader/writer-descendant regression is
Linux-only because it inspects `/proc`. Other Unix lifecycle tests, including
truncated-transfer recovery, remain enabled. Adding equivalent safe process
ownership and tests is required before claiming the missing platform coverage.

**Step 3 checks that task scripts can run.** The parity script lacked a shebang
and produced `syntax error near unexpected token '('`. The check asserts each
task script exists, is executable, and carries a shebang matching its extension.
It does not run the tasks because some compile or publish.

The rest of the ordering, stated as the reasons rather than as a list:

- **Step 1** because a version disagreement produces a wall of type errors that all
  say the same thing and none of which is the cause.
- **Step 8** because a release that publishes
  `nenv-0.1.0-x86_64-unknown-linux-gnu.tar.gz` while the installer asks for
  `nenv-0.1.0-x86_64_unknown_linux_gnu.tar.gz` produces a 404 that is
  indistinguishable from a network problem, a moved release, or a repository the
  user cannot see — and a 404 is the first thing every user meets.

**Step 9 exists because a name is not a content check, and this project has
shipped the wrong binary before.** See "the artifact contract" below: a release
was published whose Windows archive held a 64-bit ELF binary, both installers
reported success, and one of them left that binary at `nenv.exe`. A checksum
cannot catch it, because a manifest generated from a wrong file matches that
wrong file. So the content check runs *before* the checksum in both publishers,
it runs in the gate in both directions on four-byte fixtures, and each installer
re-reads the extracted binary's first bytes and refuses when they are not a
binary for the machine it is on.

**The `-- -D warnings` on step 12 is scoped, and it has to be.** The global
`RUSTFLAGS: "-D warnings"` form fails the build on two crates inside the
`rust-libraries` submodule, which this repository does not own. Step 15 is
`--no-deps`, which is why `RUSTDOCFLAGS` *is* safe there: rustdoc never runs
over a path dependency.

Step 15 exists because a documentation example is the only documentation a tool
can check, and it was not in the gate: a stale doc import passed
`clippy --all-targets` at zero warnings while failing every time it was
actually run.

## Registering a runner, and why it is not a site-admin job

```sh
# 1. A registration token. **The repo- and org-scoped paths are the right ones.**
REG=$(curl -s -X POST -H "Authorization: token $TEA_TOKEN" \
  "$URL/api/v1/repos/neotales/neoenv/actions/runners/registration-token" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# 2. Register, carrying BOTH names for the machine.
gitea-runner register --no-interactive \
  --instance "$URL" --token "$REG" \
  --name "nenv-linux-amd64-$(hostname -s)" \
  --labels "ubuntu-latest,ubuntu-24.04,linux-amd64,self-hosted,nenv"

# 3. Run it. The subcommand is `daemon`; there is no `run`.
gitea-runner daemon
```

**The admin path returns 403 and is a dead end for this:** it is the *site* runner
registry, and a repository runner is not a site runner. The repo-scoped path works for
any account with write access to the repository.

Three things in that sequence are not obvious, and each cost a wrong turn:

| what | why |
|---|---|
| **Both** label names per runner | `runs-on: ${{ matrix.os }}` is the *same expression* on both hosts, so a Gitea runner needs `linux-amd64` **and** `ubuntu-24.04`, plus `ubuntu-latest` for the single-runner jobs. A runner with only the platform label matches no leg, and every job sits at `waiting` with nothing failed. |
| the subcommand is `daemon` | `gitea-runner run` is `unknown command`. |
| a label change is **not a thing you can do** | The API answers **405**, and editing the runner's own `.runner` file **does not survive a restart** — the daemon re-syncs from the server and the edit is silently undone. **Changing a runner's labels means re-registering it**, which creates a *second* runner rather than replacing the first, so the old one has to be deleted. Measured, after this table asserted the opposite. |

**`./eng/runner-labels.sh` is the check, and it is not a gate step.** It reports on
the instance rather than on this repository, and a gate step that fails on external
state teaches people to ignore gate steps. It exits non-zero while a target has no
runner, which is the answer worth having before a tag is pushed.

**The daemon is not supervised, and `offline` means what it says.** `gitea-runner
daemon` is a foreground process this repository does not and cannot supervise. When it
is not running, `./eng/runner-labels.sh` reports the runner `offline` -- and that is
*not* the same as the registration being gone, so the two states are worth telling
apart before anybody re-registers: a stopped daemon needs `gitea-runner daemon`, a
missing registration needs `gitea-runner register` again, and re-registering leaves the
old runner behind (see the table above).

### A release is all six targets or none

`checksums` needs every `build` leg, so one leg with no runner leaves the whole
workflow waiting rather than publishing a partial release. That is deliberate, and it
was verified: a tag push with one Linux runner built and uploaded
`nenv-x86_64-unknown-linux-gnu.zip` (4.2 MB, artifact 63) and left the other five legs
`queued` with `checksums` and `publish-gitea` at `waiting`. **A partial fleet produces a
workflow that never finishes, not a partial release**, and the README's *Intended*
column is where that state is recorded.

## A note on pre-releases

A tag containing `-rc` builds everything and creates no release. It is there so
the matrix can be exercised on a real tag without publishing. When the first
release candidate is good enough to ship, delete the suffix, push, and the same
commit gets a real release.
