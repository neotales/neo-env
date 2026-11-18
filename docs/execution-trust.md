# Execution trust

`nenv` will not let configuration direct an effect until the user has approved
the exact bytes that were parsed. This page states what an approval names, when
it is checked, and what it does not mean.

## Two stores, two questions

| file | question | answer |
|------|----------|--------|
| `trust.toml` | may `nenv` **fetch** from this repository? | a repository allow-list |
| `projects.toml` | may these exact bytes **execute**? | per-file execution records |

Both live under the user configuration directory (`$NEOENV_CONFIG_HOME/nenv` or
`$XDG_CONFIG_HOME/nenv`).

**Repository allowlisting authorizes fetch only.** Adding a repository with
`nenv trust add <github:owner/repo>` never makes a task, hook, install, render,
or environment activation runnable. Execution is a separate, explicit approval
of file identities.

## Identity

A trust identity is never a location, a URL, a revision, or a digest on its own.

- **Local** — the canonical absolute path plus the BLAKE3 digest of the exact
  file bytes.
- **Remote** — the canonical repository identity, the resolved immutable commit,
  the normalized repository-relative path, and the BLAKE3 digest of the exact
  file bytes. A Git identity is `github.com/<owner>/<name>`; a bare name, a
  path fragment, or a URL is not one. An archive import has no commit: its
  pinned `https` URL is the repository field: the original spelling must carry
  a non-empty authority (WHATWG parsing would repair `https:///host/path`), the
  URL must parse as HTTPS, and a root path is allowed because a server may serve
  its archive at `/`. A query is part of the address and is allowed; any `@` in
  the original authority is refused, even when WHATWG parsing would report an
  empty username and no password, and fragments are not allowed. Its immutable publisher digest occupies the commit
  coordinate.

Every contributing document is an identity: the project configuration, each
imported module, and each task package (with its own imports). A trusted root
with an untrusted dependency executes nothing. Path changes, content changes,
commit changes, subpath changes, and cache changes invalidate the affected
approval and leave the others alone.

## When it is checked

Before any config-directed effect — a task, a hook, an install, a render, an
environment activation, or `exec` — the root is checked first, then every
contributing identity in the selected graph. The check compares identities
computed from the bytes that were parsed; it does not reopen a mutable path to
decide what to run. A command that consumes the project after the check consumes
that same checked snapshot rather than loading the file again. A mismatch fails closed and reports the expected and
observed identity.

Reading a project is not an effect: `nenv validate`, `nenv inspect`,
`nenv config`, `nenv task list`, `nenv task help`, and `nenv task plan` still
work on an untrusted project, which is how `nenv trust status` can tell you what
to approve. A real run refuses with an actionable diagnostic naming the file and
the command that approves it.

## BLAKE3 and SHA-256 are not interchangeable here

New execution-trust identities and remote-file trust checksums are **BLAKE3**.
The store is verified on every effect, and BLAKE3 is fast and cryptographic.

Publisher-supplied artifact checksums stay **SHA-256**: tool installs, archive
digests, and upstream release manifests. The publisher supplied a SHA-256, so
converting it would mean comparing against a number nobody published. A local
project record written by an earlier build carries a `sha256` field and is still
honored and still verified with SHA-256; approving the file again replaces it
with a BLAKE3 record.

## A checksum is not authentication

A digest proves only that the bytes are the bytes that were approved. It says
nothing about who wrote them and it is not a signature. Trust here is a local
decision about content, not proof of authorship.

## Approving and revoking

```console
nenv trust status [--project <path>]      # identities, digests, and what is missing
nenv trust add <path>                     # approve one local file
nenv trust add --project <path>           # approve a project configuration
nenv trust revoke <path>                  # revoke one local approval
nenv trust add --remote <repo>@<commit>//<path>     # approve one cached remote file
nenv trust remove --remote <repo>@<commit>//<path>  # revoke it
```

Approving a root approves that file, not its imports. `nenv trust status` lists
each untrusted identity with the exact `nenv trust add` command that approves
it, so a project's approval grows one document at a time.

A record must name one canonical absolute local file, or one supported remote
repository form, commit, and normalized repository-relative path. Relative
paths, a `.`/`..` segment in the original spelling (not only in its normalized
components), empty remote fields, and duplicate identities are refused: the
whole store fails closed rather than half-loading. A generated record is
validated before it is written, so a legal filename that this parser accepts
cannot be turned into a record the next read rejects. The store is serialized
by the TOML library and the complete document is parsed again before it
replaces the old one; a control byte in a filename becomes a legal escape, not
a bare byte. Paths that are not valid UTF-8 are refused rather than rendered
lossily, because two distinct files must never share one approval through
replacement characters.

The store is updated under a coordination lock and replaced atomically. A
malformed store, an unknown key, or a record with two digests fails closed.

## Pinned remote task packages

A `task_packages:` entry may select a named task from another file by local path,
from a pinned local git repository, or from a pinned GitHub source:

```yaml
task_packages:
  lint:
    from: ./tasks/lint/task.yaml    # local, any depth below the project root
    task: lint
  review:
    from: github:owner/repo@<40- or 64-hex commit>//tasks/review/task.yaml
    task: review   # defaults to `default`
  release:
    from: file:///abs/path/repo@<40- or 64-hex commit>//tasks/release/task.yaml
    task: release
```

A local git source may also be written as an absolute path:
`/abs/path/repo@<commit>//tasks/release/task.yaml`. A relative path is always a
task-package file, never a repository.

A local package path is resolved against the declaring document, confined to the
project root after canonicalization, and confined again to the document's own
directory for its imports. The walk follows the reference's actual lexical path,
including `..` components that leave the declaring document's directory but stay
inside the permitted root. Any symbolic link on a component that exists is
refused *before* canonicalization, so a same-directory link — or one reached
through `..` — cannot select the target's identity instead of the name that was
written. A reference that would leave the permitted root is refused during
resolution, before any task, hook, or render can run.

A relative package declared by remote content stays remote content. It resolves
inside that checkout, carries the declaring module's repository, commit, and
checkout root, and therefore needs its own `nenv trust add --remote` record and
its own package execute grant. A cache path below `.neoenv` is never mistaken for
a project-local file.

A remote package reference must name a document file in a normalized subpath; a
branch, `HEAD`, or a traversal segment is refused. A full commit is the
immutable spelling. A local git reference accepts a commit only — a branch or
tag is refused rather than resolved. An exact `tag:<name>` is accepted for a
GitHub source only when the cache already binds it to a commit, and the trust
record always names that resolved commit. Loading the reference requires the
repository allow-list (the same gate as a remote module import) and the exact
bytes must then have a remote execution-trust record of `repository + commit +
repository-relative path`. **Allowlisting the repository does not approve the
file**, and approving the file does not authorize fetching anything. A package
from remote content is external, so its task also needs an explicit `execute`
capability grant for `package:<sha256>`.

## Pinned HTTPS direct files

A YAML or TOML document can be fetched as a **single file** using the explicit
`#sha256=<64 hexadecimal digits>&type=file` fragment. The `type=file` marker is
required: without it, the existing `#sha256=...` module syntax denotes a
tarball. Replace the example digest below with the SHA-256 of the exact file
bytes, obtained from a source you trust; the all-`a` value is illustrative.

For a module:

```yaml
imports:
  - "https://example.org/module.yaml#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=file"
```

For a task package, in the project's own configuration:

```yaml
task_packages:
  checks:
    from: "https://example.org/checks.toml#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=file"
    task: lint
tasks:
  check:
    uses: package:checks
```

Populate the cache only with an explicit user-initiated fetch, then separately
approve the project and the cached file for execution:

```console
nenv remote fetch 'https://example.org/checks.toml#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=file'
nenv trust add --project neoenv.yaml
nenv trust add --remote 'https://example.org/checks.toml#sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&type=file'
```

Fetching is a user-directed network operation, **not** an execution approval;
`trust add --remote` is the separate decision to approve the cached bytes.
The package task also requires an `execute` capability grant for
`package:<sha256>` (using the same lowercase digest). For example, a grant in
the user capability store is:

```toml
[[grants]]
subject = "package:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
capability = "execute"
```

A module task likewise requires the existing external-task capability grant.
Approving content does not grant capabilities. The cache is reverified before
parsing; a digest mismatch or later cache tampering fails closed. The URL must
use HTTPS, end in `.yaml`, `.yml`, or `.toml`, and contain no userinfo, query,
or other fragment. The current parser also refuses any literal `@` anywhere
in the URL, and spaces or control characters. Redirects are not followed.
Downloads are capped at the one-MiB document budget and use the configured HTTP
deadlines.

There is **no public-address-only or SSRF filter**: HTTPS hosts resolving to
loopback, private networks, or other locally reachable services are permitted.
Before explicitly fetching, inspect the URL and understand that it can contact
such services. The checksum verifies bytes, not the publisher or destination.

A direct file is not a verified directory tree. Nested module imports, task
packages, dotenv and inventory files, task file inputs/outputs and working
directories, task runner directories, workspace paths, PATH entries, tool
declarations, vaults, inventories, jobs, and deployments are currently refused
in a direct file. This conservative restriction also applies to independently
pinned nested imports; place such dependencies in the local project instead.
An approved inline command can still access files or the network according to
its capabilities and the operating system; the digest is not a sandbox.

### HTTPS test isolation

The controlled local HTTPS tests copy the source into a temporary directory and
build a separate fixture binary with a test-only transport modification. That
binary accepts a temporary test root certificate and still verifies the
certificate chain and hostname. The actual source and distributable contain no
test-root override or embedded fixture certificate. Both nested Cargo builds
use `--locked` and a per-run temporary target; the test-only dependency change
is reflected only in the temporary source copy's lockfile.

The tests separately build a release-mode binary from the unmodified source and
check for its `UnknownCA` handshake alert when given the fixture certificate,
even when the fixture variable is set. The hostname-mismatch test uses the
fixture binary with its test root trusted and first checks a matching-hostname
positive control. It checks for a `BadCertificate` handshake alert, but does
not contact a publicly trusted, hostname-mismatched server with the release
binary. The release-mode test build disables optimization for test runtime,
while retaining release-mode disabled debug assertions.

## Local git fetch

A local repository is populated only by an explicit `nenv remote fetch`, and
only over Git's file transport. The repository is first allow-listed for
fetching:

```console
nenv trust add file:///abs/path/repo
nenv remote fetch file:///abs/path/repo@<commit>//tasks/release/task.yaml
nenv trust add --remote file:///abs/path/repo@<commit>//tasks/release/task.yaml
```

The absolute-path spelling (`/abs/path/repo@<commit>//…`) is accepted by
`nenv remote fetch`, `nenv trust add --remote`, and `task_packages.from`. The
repository allow-list spelling uses `file://` so `nenv trust add` cannot confuse
a repository with a project file. The fetch is bounded to one commit
(`--depth=1 --no-tags`) and runs under the existing Git timeout and output
budgets. It does not execute the package, and it never changes what execution
approval means: the cache read and the BLAKE3 record for repository, commit, and
repository-relative path are checked exactly as for a GitHub cache entry. No
network, credential, GitHub, or SSH transport is reachable from a local
reference.

Git configuration supplied through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_*`/
`GIT_CONFIG_VALUE_*` or the legacy `GIT_CONFIG_PARAMETERS` channel is discarded
for every Git child, and protocol policy is `protocol.allow=never` with only
`protocol.file.allow=always` for a local fetch. An `url.*.insteadOf` rewrite
therefore cannot turn the local path into HTTPS or SSH, and the non-file
protocols are refused even if a rewrite were applied.

For Git repository references, `nenv remote fetch` refuses non-local sources.
The distinct HTTPS direct-file fetch described above does use the network.

## Limits in this change

Remote **execution** is verified against the controlled cache: the exact bytes
of the selected remote document are checked against the record, and the cache's
metadata, immutable commit, subpath containment, and symlink refusal are all
revalidated first. The checkout's bytes and file types are then compared
**directly** with the pinned commit tree: `git ls-tree` reads only the immutable
objects, and each blob object id is recomputed from the raw bytes on disk (or the
link target, for a symlink). On platforms with an executable bit, `100755` and
`100644` are distinguished by the **owner** execute bit, matching Git, so
flipping a cached script between executable and non-executable — including
`0755` to `0655` — fails verification. Replacement objects are disabled
(`GIT_NO_REPLACE_OBJECTS` and `--no-replace-objects`) for every object read, so a
`refs/replace/*` entry in the cache cannot make the pinned commit name another
tree. No command that reads the working tree is used, so neither the checkout's
index flags nor a clean filter declared in its
`.gitattributes`/`.git/config` can mask a substitution or run an external
program before trust is decided. A modified, untracked, or ignored file, a
gitlink, or a file-type change fails closed.

A config-directed import or task package still reads a populated cache and never
fetches. The only fetch path for a local repository is the explicit
`nenv remote fetch` above; its result is a normal cache entry subject to the
same verification and trust gate. Non-local Git repository fetch is refused;
the explicit direct-file HTTPS fetch is a separate network transport.
