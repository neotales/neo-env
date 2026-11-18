# Cross-compile `x86_64-pc-windows-msvc`; keep macOS native, and say why

Status: decided
Ticket: #265 (runners). This record is the decision; there is no separate ticket for it,
and citing a number nobody was given is a sentence that reads correctly and
sends a reader nowhere -- which is what `eng/check-ticket-refs.sh` now fails on.
Related: [a-user-written-key-goes-in-a-machine-owned-file](a-user-written-key-goes-in-a-machine-owned-file.md)

## What changed

**Two of the six targets are now cross-compiled from the Linux runner**, and the other
four are unchanged:

| target | how it is built | tool |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | native on `linux-amd64` | -- |
| `aarch64-unknown-linux-gnu` | **cross-compiled on `linux-amd64`** | `cargo-zigbuild` |
| `x86_64-pc-windows-msvc` | **cross-compiled on `linux-amd64`** | `cargo-xwin` |
| `x86_64-apple-darwin` | native on `macos-amd64` | -- |
| `aarch64-apple-darwin` | native on `macos-arm64` | -- |
| `aarch64-pc-windows-msvc` | **cross-compiled on `linux-amd64`** | `cargo-xwin` + a `clang` -> `clang-cl` symlink |

**The fleet requirement goes from six machines to two**: an Intel Mac and an
Apple-silicon Mac. A `windows-amd64` runner is no longer needed at all, and neither is a
Windows-on-arm64 host or an arm64 Linux host. **Every target except the two macOS ones is
produced by the single x86_64 Linux runner.**

The runner-label check fell from 5 missing labels to 3 and then to 2 with nothing
telling it to, because it reads the workflow rather than a restated list:

```
runner-labels: no runner carries 2 of the 4 label(s) the workflows ask for:
  macos-13 (a GitHub-hosted label)
  macos-14 (a GitHub-hosted label)
```

The second fall is the Windows ARM64 leg moving to the cross column, and the count went
with it. **The two that remain are both macOS, which is a platform boundary rather than a
missing tool.**

The matrix field is `cross: <tool>`, not a boolean, because the two cross legs are not
the same kind: one produces a Windows PE and one produces a Linux ELF, and the packaging
step that serves the Linux one is the *tarball* step that already existed. A boolean
would have handed it to the Windows-only step and produced a `.zip` named
`nenv.exe` around an ELF -- which `check-artifact-contents.sh` would catch, but only at
`checksums`, after every leg had run.

## The rule this replaces, and why its stated reason was wrong

The release workflow said:

> ## Native runners, never cross-compilation
>
> Every target below is built on a runner whose architecture it is for. That is not a
> convenience, it is the only thing that works, and the reason is the C in the
> dependency graph:
>
> * `ring` ... ships pregenerated assembly objects for exactly four architectures --
>   `{x86, x86_64, arm, aarch64}` -- and no more. Every other target has to fall back to
>   something that will not link.

**Every one of the six targets in the matrix is in that set.**

| target | architecture | in `ring`'s set |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `x86_64` | yes |
| `aarch64-unknown-linux-gnu` | `aarch64` | yes |
| `x86_64-apple-darwin` | `x86_64` | yes |
| `aarch64-apple-darwin` | `aarch64` | yes |
| `x86_64-pc-windows-msvc` | `x86_64` | yes |
| `aarch64-pc-windows-msvc` | `aarch64` | yes |

So `ring` was never the obstacle, and a rule justified by `ring` cannot justify a rule
about the whole matrix. **The reason was a plausible story about a real crate, and
checking it against the matrix took one command.** It is the same shape as the check that
invented a `SHA` scheme from `archive-SHA-256`: a pattern that matched something adjacent
to the thing, reported as if it were the thing.

The real obstacle is the **C toolchain per target** — a compiler, an assembler, an
archiver and a linker that all agree on one object format. That is solvable for more
targets than the rule assumed, and for exactly one more it is solvable today.

## The measurement

On an x86_64 Linux host, for the target that failed before:

```
$ cargo build --release --target x86_64-pc-windows-msvc
error: failed to run custom build command for `ring v0.17.14`
error occurred in cc-rs: failed to find tool "lib.exe": No such file or directory

$ cargo xwin build --release --bin nenv --target x86_64-pc-windows-msvc
   Finished `release` profile [optimized] target(s) in 36.74s

$ file target/x86_64-pc-windows-msvc/release/nenv.exe
nenv.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections
```

9,973,248 bytes, `PE32+`, `WINDOWS_CUI` subsystem, importing `KERNEL32.dll` and `ntdll`.
Packaged and read back through the same archive check every release uses:

```
artifact-contents: nenv-9.9.9-x86_64_pc_windows_msvc.zip   ok (windows, nenv.exe)
```

And the negative direction, which is the one that matters: a Linux ELF given the same
name is **refused**, by the packaging step and by `check-artifact-contents.sh` alike.

## Why this tool and not a shim

The workflow's own history is the reason. It recorded that the source repository's
`rust/tools/cross-check.sh` carried a `zig cc` shim, per-target sysroot variables, and a
list of known-good architectures, and that *the shim and not the Rust code* broke every
few weeks. That is still true, and it is the right instinct.

`cargo-xwin` is not that. It is a maintained tool that fetches the Microsoft CRT and SDK,
supplies the MSVC archiver, and drives `clang`/`lld` — with the target triple handling
inside it rather than in a shell script this repository owns. The distinction is who
absorbs the breakage when a toolchain moves.

The shim path was also tried here, for the macOS target, and it worked for exactly as far
as expected: the shim normalised `ring`'s `x86_64-apple-macosx` triple, `ring` compiled,
and then linking failed. The shim was not the hard part.

## macOS is a platform boundary, not a missing package

The same shim, against `x86_64-apple-darwin`:

```
error: unable to find dynamic system library 'System' using strategy 'paths_first'
error: unable to find dynamic system library 'iconv' using strategy 'paths_first'
```

`System` is Apple's libSystem. It exists only in the macOS SDK, which Apple does not
distribute and which is installed by Xcode on a Mac. So the answer for macOS is *a Mac*,
and it is worth saying that precisely, because "we could not find the right linker" and
"the platform does not publish the thing you need" lead a reader to different next steps
and only one of them can succeed.

`aarch64-pc-windows-msvc` fails differently, and in `cargo-xwin` rather than here:

```
clang: error: no such file or directory: '/imsvc'
```

**This line first appeared here as "a mangled MSVC include path", and that was a guess
that turned out to be wrong.** The path in the message is the *flag*, not a path: every
directory the flags name is present on disk (`crt/include`, `sdk/include/{ucrt,um,shared,
winrt}`, and 37 `.lib` files under `xwin/crt/lib/aarch64`), so nothing is mangled and
nothing is missing.

`/imsvc` is **clang-cl syntax**, and the compiler `cc` is driving is `clang` in GNU driver
mode, which does not read `/imsvc` as a flag and takes it for an input file name. The build
dies in `ring` 0.17.14, reached through `ureq`.

**The toolchain can do the job.** Run by hand, with the same include paths xwin passes:

```text
$ clang-cl --target=aarch64-pc-windows-msvc -imsvc .../crt/include ... -c probe.c
exit 0   -> produced 876 bytes
$ clang  --target=aarch64-pc-windows-msvc -imsvc ... -c probe.c
clang: error: unknown argument: '-imsvc'
exit 141   -> no object
```

So the fix is to pair the syntax with the driver: emit `-imsvc` for a GNU consumer, or
drive `clang-cl`. **`cc` records the choice and does not honour it** -- it logs
`CC_aarch64_pc_windows_msvc = Some(clang-cl)` and then runs `"clang" "-O3"` -- and
`cargo xwin build --cross-compiler clang-cl`, the tool's own switch for exactly this,
changes nothing. That is a pairing bug between `cc` and `cargo-xwin`, not a workflow
setting, and it is not this repository's to fix.
[#265](../../eng/issues/265-cross-platform-ci-gate-has-no-runner.md) has the commands, the
four overrides that do not help, and what is still unestablished.

**The leg is cross-compiled now.** `cc` cannot be told which driver to use -- it logs
`CC_aarch64_pc_windows_msvc = Some(clang-cl)` and runs `clang` anyway, and
`cargo xwin build --cross-compiler clang-cl`, the tool's own switch for exactly this,
changes nothing -- so the build step points the *name* `clang` at `clang-cl` for the
duration of that one build:

```text
clang-cl --target=aarch64-pc-windows-msvc -imsvc ... -c probe.c
  exit 0   -> 876-byte object
clang  --target=aarch64-pc-windows-msvc -imsvc ... -c probe.c
  clang: error: unknown argument: '-imsvc'

# with only the symlink changed:
PE32+ executable for MS Windows 6.00 (console), ARM64, 8 sections   8,078,336 bytes
```

That is a symlink and not a toolchain shim: nothing is translated, two drivers share a
name, and the flags say which one. It is scoped to one step and one temporary directory.

## What the cross build needs that a native one does not

**The archive must verify its own bytes.** A cross build can produce a file at the right
path that is not the right platform, and a native build cannot. The packaging step
therefore opens the archive it just wrote and checks for the `MZ` header *and* the `PE\0\0`
signature at the offset `e_lfanew` points to.

This was not a precaution invented for the design. It earned its place by accident: a test
run left a Linux ELF at `target/x86_64-pc-windows-msvc/release/nenv.exe`, **cargo did not
notice** — the fingerprint matched, because the inputs had not changed and cargo hardlinks
its output — and the step refused the archive. A native build has no equivalent failure,
because on a native runner the linker and the target triple cannot disagree.

## The cost, stated plainly

- A release artifact that no test suite has run on, on a host nobody has run it on. The
  README's **Tested** column covers `x86_64-unknown-linux-gnu` and nothing else, and
  this does not change that: the cross-built binary is a *build* claim, not a *test*
  claim, and the support matrix says so.
- One more tool in the release path, pinned to a version, downloaded at build time.
- The matrix gains a `cross:` field, and the build and package steps each gained a
  branch. Three packaging steps rather than two, deliberately: a step that branches on
  both `runner.os` and a matrix field is a step that can half-run.

Restoring a native Windows runner is a one-line matrix change — put `os: windows-2022` and
drop `cross: true` — and nothing else in the workflow knows which happened.
