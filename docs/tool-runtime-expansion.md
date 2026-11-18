# Tool and runtime expansion plan

Status: staged plan. Java, Bun, the narrow Cargo backend, tool-map aliases, `grep`,
`rn`, `pre`/`prerelease`, and the user/system scope split are implemented. System-scope
mutation is deliberately disabled pending race-resistant path operations. The Aqua
registry client, Erlang/Elixir, Swift, and npm install-manager selection remain planned.

This document is product-neutral and records what is implemented, what is planned,
and what is only parsed. A backend is listed as supported only when its resolver and
install path exist and a test exercises the contract.

## Current inventory

### Native runtimes

| id | Artifact source | Install layout | Status |
| --- | --- | --- | --- |
| `go` | go.dev release manifest | `<root>/go/bin` | Implemented |
| `node` | nodejs.org index and SHASUMS256 | version-named archive directory | Implemented |
| `dotnet` | Microsoft release metadata | SDK at the root | Implemented |
| `zig` | ziglang.org index | version/arch-named directory | Implemented |
| `deno` | Deno version and checksum feeds | executable at the root | Implemented |
| `uv` | Astral release metadata | target-named directory (Unix) | Implemented |
| `rust` | rustup channel manifest | `rustup/toolchains/<version>-<target>/bin` | Implemented |
| `odin` | Odin release assets | probed directory | Implemented |
| `python` | Astral standalone builds | `python/bin` (Unix) | Implemented |
| `java` | Adoptium release metadata | Temurin release directory; macOS uses `Contents/Home` | Implemented |
| `bun` | Bun release assets and `SHASUMS256.txt` | platform-named archive directory | Implemented |

Java and Bun were exercised by offline tests for artifact selection, checksum
validation, path layout, and install-boundary refusals. Their live network resolution
is not part of the automated suite. The macOS `Contents/Home` layout is asserted with
a representative archive fixture; it has not been run on macOS hardware.

### Providers

| Name | Status |
| --- | --- |
| `explicit-url` | Implemented. Requires a declared SHA-256. |
| `github-release` | Implemented. Asset templates, globs, `grep`, `rename`/`rn`, and `pre`/`prerelease` are honored. |
| `gitlab-release` | Pinned-tag v4 release resolver with a local HTTP fixture; requires a declared SHA-256. Live GitLab behavior remains untested. |
| `aqua` | Pinned-manifest provider only. Requires endpoint, revision, package, and manifest digest. Global selection refuses it. |
| `npm` | Implemented as a registry download with `dist.integrity` verification. It does not invoke an npm-compatible manager. |
| `dotnet-tool` | Implemented. |
| `go-module` | Implemented; requires a `go.sum` entry and a Go toolchain. |
| `ruby-gems` | Implemented. |
| extension provider | Parsed only. No resolver. |
| `cargo` | Exact `.crate` checksum planning and a dependency-free Unix source-build path are connected; other graphs and hosts refuse explicitly. |

### Configuration forms

- `tools:` as a sequence of full declarations is the native form.
- `tools:` as a mapping accepts a short name and a version scalar, or a short name and
  a mapping with `version` plus optional `binaries`, `asset`, `checksum`, `grep`,
  `prerelease`/`pre`, and `rename`/`rn`. A reserved `aliases` map connects that short
  name to `gh:owner/repo`. Example:

  ```yaml
  tools:
    aliases:
      dust: gh:bootandy/dust
    dust: 1.27
  ```

  Numeric versions are accepted. The short name is the executable name; it is never
  derived from the repository. `rg: gh:BurntSushi/ripgrep` therefore installs `rg`, and
  a display name such as `ripgrep` uses `binaries: [rg]`. The mapping form refuses an
  alias with no declaration, a declaration with no alias, and a non-`gh:` target.
- Go `use:` entries accept `rename` and its `rn` alias. Rename is honored for a raw
  single-binary artifact and refused for an archive, because the extractor does not yet
  carry an original-to-destination mapping; the refusal happens at plan time.
  `grep` is a regular expression over release artifacts. `pre` and `prerelease` are
  equivalent booleans that change `latest` resolution to the newest non-draft release,
  including a pre-release.
- Go `binpath` and `bindir` are parsed and then refused by the planner. The extractors
  place the declared binary list at the archive root, so accepting those keys silently
  would install the wrong file.

## Stage 1: scope migration and system installations

This is an intentional public CLI change and needs review before it ships.

### Target meaning

| Scope | Configuration | Installed tools |
| --- | --- | --- |
| User (`--user`, `-u`) | `NEOENV_CONFIG_HOME`, then `XDG_CONFIG_HOME`, then `~/.config` | `NEOENV_DATA_HOME`, then `XDG_DATA_HOME`, then `~/.local/share` |
| System (`--global`) | `NEOENV_GLOBAL_CONFIG_DIR`, then `%ProgramData%\neoenv`, `/etc/neoenv` on Linux, or `/private/etc/neoenv` on macOS | `NEOENV_GLOBAL_INSTALL_DIR`, then `%ProgramFiles%\neoenv` or `/usr/local/neoenv` |

`--global` and `-g` select the system scope. They previously meant the user scope, so
this is an intentional change; system mutation remains fail-closed, so an old
install/remove command cannot silently write to the new destination. See
[global scope decision](../decision-records/global-scope-is-system.md).

System mutation is disabled. The resolver rejects `..`, symlinked ancestors, and
symlinked `tools`/`locks` children, but a path check cannot make publish/remove
race-resistant; system install/remove/update/pin/unpin/purge fail closed until those
operations are directory-relative. `--global` supports inspection and dry-run.

`tool list --user|--global --format json` uses the distinct
`global-tool-config-v1` contract in `docs/schemas/global-tool-config-v1.schema.json`; it
reports configured selections only and explicitly does not imply installed state.

Implemented coverage: `use --user`, `use --global --dry-run`, `tool list --user|--global`,
`tool which/where --user|--global`, `tool remove/update/pin/unpin/purge
--project|--user`, `tool cleanup --user`, `runtime list`, `runtime where`, and shell
activation. `tool cleanup --global` and all other system mutations are refused. Tests
use temporary overrides only; no test writes to `/etc`, `/usr/local`,
`Program Files`, or `ProgramData`.

## Stage 2: Aqua registry client

The current Aqua provider is a pinned-manifest provider, not a registry client.

1. Read a registry document from an explicitly configured base and revision.
2. Hash the document and record the digest in the lock.
3. Parse package type, repository, asset template, format, files, URL replacements,
   checksum source, supported environments, and version overrides.
4. Resolve versions from the upstream release feed and require a publisher checksum.
5. Support `aqua:owner/repo@version` in global selection with revision, manifest
   digest, package, and resolved asset in provenance.
6. Refuse mutable registry state and changed digests in a locked install.

Global Aqua selection now accepts only when all three explicit pins are supplied:
`NEOENV_GLOBAL_AQUA_ENDPOINT`, `NEOENV_GLOBAL_AQUA_REVISION`, and
`NEOENV_GLOBAL_AQUA_MANIFEST_SHA256`. The revision is immutable and the manifest
digest is checked before package selection. Global selection is covered by a local
HTTP fixture; no live registry is contacted by the test suite.

## Stage 3: Cargo backend

The exact registry archive is checksum-verified. The currently supported install
subset is one dependency-free crate with explicit `[[bin]]` targets on Unix;
dependency graphs, build scripts, `links`, workspaces, proc macros, and unsupported
hosts are refused. Cargo and rustc must be present in the exact neoenv-managed Rust
toolchain named by the lock; neither falls back to PATH.

The accepted declaration is deliberately exact and closed:

```yaml
tools:
  - id: ripgrep
    version: 14.1.1
    provider: cargo
    binaries: [rg]
    cargo:
      crate_name: ripgrep
      version: 14.1.1
      registry: https://index.crates.io/
      checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      toolchain: 1.85.0-x86_64-unknown-linux-gnu
      scripts: deny
      build: isolated
      network: deny
```

`registry` is the canonical HTTPS registry index URL. `checksum` is the exact
64-character lowercase SHA-256 recorded by the registry for the `.crate` archive,
not a digest of a locally built executable. The optional lock field `cargo_build`
records its exact `tool_id`, crate name/version, registry URL and archive checksum, the selected
toolchain, and the three policy choices. Historical tool locks without
`cargo_build` remain readable and valid. The toolchain declaration must include an
explicit Rust target triple, for example `1.85.0-x86_64-unknown-linux-gnu` or
`1.85.0-x86_64-unknown-linux-musl`. Bare versions are rejected because the generic
platform model cannot distinguish Linux libc ABIs; specify the ABI actually used by
the managed Rust toolchain.
The target must come from the finite supported target registry. Common accepted targets include
`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`,
`x86_64-pc-windows-msvc`, and `wasm32-unknown-unknown`. The validator rejects
unknown targets and invalid Cartesian combinations even when each component
individually appears in some Rust target.

Only `scripts: deny`, `build: isolated`, and `network: deny` are accepted. The
narrow backend rejects build scripts and all dependencies, uses a private empty
`CARGO_HOME`, runs Cargo with `--locked --offline`, and builds only the declared
binary targets. `--offline` is Cargo's dependency-fetch policy, not a network
sandbox. The accepted dependency-free subset has no build scripts or proc macros
that can execute crate code during the build. Since source compilation still
executes trusted compiler and linker processes, installation requires the explicit
`NEOENV_ALLOW_CARGO_BUILD=1` capability grant. No claim of a general process
sandbox is made. Before execution, the installer checks for Cargo configuration
at the crate and every filesystem ancestor. This is a preflight, not race-resistant
isolation: those ancestor directories and their configuration must remain trusted
and unchanged for the duration of the build. A concurrent same-user change can race
the check; the backend does not claim to defend against that.
Compilation is not filesystem-sandboxed, and macro expansion is not analyzed.
The source scan refuses `macro_rules!` definitions, the `include`, `include_str`,
and `include_bytes` identifiers (including aliases), `#[path]`, conditional
module paths, and non-allowlisted attributes including procedural-macro
attributes. It also refuses raw strings and apostrophe-containing Rust token
streams when the scan cannot safely classify them. Other macro invocations, such
as `println!`, are not generally refused. These source checks neither inspect
expansions nor establish a compiler sandbox; the explicit capability grant and
trusted compiler/linker boundary still apply.

Cargo declarations and Cargo lock entries require a non-empty explicit binary
list. Crate names are not assumed to equal executable names. Lookup refuses names
attributable by declaration ID, declared binary aliases, or a validated Cargo
lock entry; unrelated commands such as `git status` remain eligible for ordinary
resolution. `cargo_build` must bind to exactly one locked Cargo entry by tool ID,
exact version, crate, registry, and checksum. Mismatched or ambiguous evidence
invalidates the lock even without a current declaration.

## Stage 4: npm install-manager selection

The npm provider currently downloads the registry tarball and verifies
`dist.integrity`. It does not run `npm`, `bun`, or `pnpm`.

A manager-based install would execute a package manager, so it needs its own contract:

- an explicit manager choice (`npm`, `bun`, `pnpm`) with an exact manager version;
- the manager executable's provenance and digest;
- lock entries for the manager and every installed package;
- no fallback from one manager to another;
- tests that use a local fixture and never execute a real global install.

Until that is designed, there is no manager selector and no silent choice.

## Stage 5: Erlang and Elixir

Elixir requires a compatible Erlang/OTP installation.

1. Add Erlang/OTP with an explicitly chosen artifact source. No fallback to a host
   Erlang.
2. Add Elixir release archives with SHA-256 verification.
3. Resolve Elixir's supported OTP range, or require an explicit pair such as
   `elixir@1.18 erlang@27`.
4. Activate both toolchains and record both in the lock.
5. Test paired install, refusal when Erlang is missing or mismatched, and offline
   replay.

## Stage 6: Swift

Swift is planned, not implemented. The official route is a Swift.org toolchain or the
Swiftly installer. Direct toolchain archives are published for Linux, macOS, and
Windows, with PGP signatures; Swiftly has its own signed archives, and official
container images are available.

Before implementation, confirm the exact artifact matrix and verification for each
host. At minimum:

- Linux: confirm distribution and architecture coverage, and choose glibc versus a
  static SDK separately.
- macOS: decide whether to manage a Swift.org toolchain or require the Xcode toolchain.
- Windows: confirm the supported architecture and installer form.
- Verify the selected archive against the publisher's PGP signature and a recorded
  SHA-256 before extraction. A signature check without a pinned key is not a trust
  decision this project can make implicitly.

Until that design is implemented and tested, Swift is not listed as a supported
runtime.

## Verification vocabulary

- Tested: the suite ran on that platform.
- Verified: a person ran the built binary on real hardware and recorded it.
- Intended: the path or lane exists and claims the platform, but has not run.
- Planned: no resolver or installer exists.
