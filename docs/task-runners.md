# Named task runners

A task's `uses:` can name a built-in runner instead of describing a command for
`portable`, `argv`, or `shell`.

| Family | `uses:` values |
| --- | --- |
| POSIX shells | `bash`, `sh`, `fish` |
| PowerShell | `pwsh`, `powershell` |
| JavaScript / TypeScript | `node`, `bun`, `deno` |
| Python | `python`, and the versioned `uv@<version>` |
| Go | `go` |
| .NET | `dotnet` |
| Windows bridge | `wsl` |
| Nushell | `nu` |
| Local templates | `tmpl` (and the reference's `tmpl://...` spelling) |

`use:` is accepted as the legacy spelling of `uses:` for all of them, as it
already was for every other runner.

## Inline versus file

The choice is explicit. Nothing infers file mode from a file extension.

```yaml
tasks:
  inline:
    uses: bash
    run: printf 'hello\n'

  file:
    uses: bash
    source: scripts/build.sh
    args: [--release]
```

- `run:` is the script text passed to the interpreter.
- `source:` is a script file. It is resolved relative to the document that
  declared it and must stay inside the project root (or the package root for a
  package task). The interpreter opens it; the engine does not read or rewrite
  the contents.
- Exactly one of `run` and `source` is required. Setting both, or neither, is a
  validation error. An empty `run:` counts as unset.
- `source:` is also the `render` runner's template input. It is refused on
  `portable`, `argv`, `shell`, and fallback runners rather than parsed and
  ignored.

This is a deliberate divergence from Cast's `Script` helper, which treats a
one-line `run: ./scripts/build.sh` as a file when the text ends in a known
extension. Here the same task is an inline program that tries to execute
`./scripts/build.sh` as shell syntax. Write `source:` when a file is meant.

## Arguments

Declared `args:` are appended in order, then arguments after the task's `--` on
the command line. The exact command shapes are:

| Runner | Inline | File |
| --- | --- | --- |
| `bash` | `bash --noprofile --norc -eo pipefail -c <run> neoenv-task <args...>` | `bash <source> <args...>` |
| `sh` | `sh -e -c <run> neoenv-task <args...>` | `sh -e <source> <args...>` |
| `pwsh`, `powershell` | `<exe> -NoLogo -NoProfile -ExecutionPolicy Bypass -Command <run> <args...>` | `<exe> -NoLogo -NoProfile -ExecutionPolicy Bypass -File <source> <args...>` |
| `node`, `bun` | `<exe> -e <run> -- <args...>` | `<exe> <source> <args...>` |
| `deno` | `deno eval <run> <args...>` | `deno run -A <source> <args...>` |
| `python` | `<exe> -c <run> <args...>` | `<exe> <source> <args...>` |
| `nu`, `fish` | `<exe> -c <run> <args...>` | `<exe> <source> <args...>` |
| `go` | `go build -o <temp-binary> <staged .go>` then `<temp-binary> <args...>` | `go build -o <temp-binary> <source>` then `<temp-binary> <args...>` |
| `dotnet` (.cs/.csx/no extension) | `dotnet run --file <staged .cs> -- <args...>` | `dotnet run --file <source> -- <args...>` |
| `dotnet` (project) | — | `dotnet run --project <source> -- <args...>` |
| `dotnet` (.dll/.exe) | — | `dotnet <source> <args...>` |
| `wsl` | `wsl.exe [--distribution <name>] [--cd <wsl-cwd>] --exec sh -lc <run> neoenv-task <args...>` | — |

The `neoenv-task` token in the inline shell rows is `$0`. It exists so declared
arguments land at `$1`, `$2`, and so on instead of shifting into `$0`.

The `--` in the inline Node and Bun rows is load-bearing. Without it,
`node -e script --version` prints Node's version and never runs the script;
Bun behaves the same way. With it, every declared and CLI argument reaches the
script as a script argument. Real Node and real Bun are both covered by the
integration suite when the interpreter is on `PATH`.

Interpreter-specific meanings after that (`process.argv`, `sys.argv`, `$argv`,
PowerShell `$args`) are the interpreter's; the engine appends arguments
verbatim and does not reinterpret them.

`deno` file mode carries `-A`, matching Cast. That grants the script all Deno
permissions; write a fallback or `argv` task if that grant is too wide.

## Executable resolution

The named executable is looked up on the task's effective `PATH`, never
installed or downloaded. On Unix, `python` tries `python3` first and then
`python`; every other runner has one name. A missing interpreter fails the task
with a message naming the candidates.

Environment, dotenv, `cwd`, task inputs, outputs, capability requests, timeout,
and cancellation are the same as for every other local runner. A named script
runner does not add an implicit capability: it is a process launch the project
asked for, like `shell`. `uv@<version>` is the exception and requires an
external `execute` grant, explained below. A coordinated cancel or an elapsed
`with.timeout` stops the process tree through the shared executor.

## `uses: tmpl`

`tmpl` renders declared local files with the same Go-template engine used by
`render`, not a shell. It is the file-mapping form from the Go reference:

```yaml
tasks:
  render:
    uses: tmpl
    with:
      files:
        - templates/app.yml.gotmpl:out/app.yml
        - config.txt.tmpl
      values: values.yml
```

- `with.files` is a non-empty list of `source` or `source:destination` strings.
  A missing destination is inferred: `.tmpl`, `.tpl`, and `.gotmpl` are
  stripped; any other extension gets `.out`.
- `with.values` names one local YAML mapping. It becomes `.Data`/`.data` in the
  template. `.Env`/`.env` is the task's effective environment. `.OS`/`.os` and
  `.Arch`/`.arch` use Go's names (`linux`, `darwin`, `amd64`, `arm64`), not
  Rust's.
- `with.disable-env: true` skips `${NAME}`/`$NAME` expansion.
  `with.disable-gotmpl: true` skips the template stage. Env expansion is applied
  only outside `{{ ... }}` actions, so a template variable such as `{{ $item }}`
  is left for the template engine rather than read as an environment name.
- A YAML integer outside the exactly representable ±2^53 range is refused rather
  than rounded through an `f64`. Quote it or keep it within the range.
- Paths are resolved relative to the declaring document under the same
  containment rules as `render`, including package-relative sources. Sources,
  values, and destinations may not escape the project or package root; a
  destination symlink is refused, a destination that exists as a directory or
  other non-regular file is refused untouched, and a destination path may not
  traverse a symlinked directory. Missing parent directories under the root are
  created.
- Every mapping is resolved, read, and rendered before any output is committed.
  A missing later source or values file therefore writes **no** output, including
  no earlier mapping. Outputs are staged and published with rollback: if a later
  destination cannot be committed, earlier destinations are restored to their
  previous content (or removed when newly created). Cancellation is checked
  before each mapping, after staging, and immediately before each persistence, so
  a cancelled final mapping does not leave a successful partial write.
- `with.files` and `with.values` carry their own declaring-document provenance, so
  a caller or `extends` override resolves against the file that wrote the
  override rather than the package or base task.
- `run`, `source`, `destination`, `args`, `cwd`, and `capabilities` are refused:
  they would be inert on a file renderer. Unknown `with` keys are refused by
  name.
- Command substitution is never executed. `$(...)` and backticks remain literal
  text. There is no URL source and no remote fetch; `tmpl://...` is accepted
  only as the reference's alternate spelling and has no URL semantics.
- `templ` is **not** an alias; the Go reference does not accept it either.
- No external `execute` grant is required. `tmpl` reads and writes local files;
  it does not start a process.

### Go and .NET source versus file

`go` and `dotnet` follow the same explicit contract as the other script runners:
`run:` is inline source, `source:` is a file. Nothing guesses file mode from the
text of `run:`.

- Inline Go is written to a private temporary `.go` file, built to a private
  temporary binary, and that binary is executed with the task arguments. This is
  deliberate: `go run main.go first.go` treats `first.go` as another source file
  instead of an argument, and no `go run` separator makes it reach the program
  unchanged. Building first avoids that parser entirely. The staged source and
  binary are removed when the run ends. Cancellation and the remaining deadline
  are checked after the build and before the binary is launched.
- Inline .NET is written to a private temporary `.cs` file. Both inline and
  `.cs`/`.csx` file mode require an SDK whose `dotnet run` supports `--file`.
  An older SDK is not silently accepted as a runnable environment; the real
  integration test probes `dotnet run --help` and skips when the capability is
  absent.
- Temporary names are random (a fresh `tempfile`), not a deterministic hash
  shared with another process.
- `dotnet` chooses its argv by the source extension: `.cs`, `.csx`, or no
  extension uses `run --file`; a project extension such as `.csproj`, `.fsproj`,
  or `.vbproj` uses `run --project`; `.dll` and `.exe` are executed directly
  without `run`. Inline and `.cs`/`.csx` file mode depend on the SDK's
  `run --file` capability.
- Both are looked up on the task's effective `PATH` only. The runner does not
  install a toolchain or fetch anything. The `go`/`dotnet` process itself may use
  the project's normal module or SDK behavior, which is outside the runner.
- `source:` uses the same contained-path resolution as the other runners, so a
  path outside the project or package root is refused.
- Cancellation and `with.timeout` apply through the shared process executor.
- Windows behavior is **intended, not natively verified**.

### Windows `bash`/`sh` and `uses: wsl`

`bash` and `sh` are refused on Windows. A `bash.exe` on `PATH` can be the WSL
launcher rather than a native Git Bash, and there is no safe path-based test that
distinguishes them; a path-contains-`System32` check is not a security boundary.
The refusal names `uses: wsl` and the fallback-runner option. `fish` is refused
for the same reason.

WSL is explicit:

```yaml
tasks:
  check:
    uses: wsl
    with:
      distribution: Ubuntu-22.04
      mount-root: /mnt
    run: |
      uname -a
      test -f /mnt/c/work/project/README.md
```

The argv is:

```text
wsl.exe [--distribution <name>] --cd <translated-cwd> --exec sh -lc <run> neoenv-task <args...>
```

- `with.distribution` is optional; without it WSL’s default distribution is used.
  `with` accepts only `distribution`, `mount-root`, and `timeout`.
- The runner resolves the exact executable name `wsl.exe` on `PATH`, without
  `PATHEXT`, so `wsl.com`/`wsl.cmd` cannot win and a `PATHEXT` that omits `.EXE`
  cannot hide it. Finding `wsl.exe` is a path lookup, not authentication.
- The working directory is translated only when `with.mount-root` names the
  selected distribution’s automount root. `/mnt` is an example for a default WSL
  configuration, not a general assumption; a custom automount root or disabled
  automount is not queried. Without `with.mount-root`, a Windows drive working
  directory is refused with an actionable diagnostic. UNC working directories
  are refused.
- Declared `args` and CLI passthrough become `$1...` inside `sh -lc`; `$0` is
  `neoenv-task`.
- The task environment is the environment given to `wsl.exe` on Windows. It is
  not automatically imported into the Linux process; no `WSLENV` translation is
  injected.
- `wsl.exe` exit status is propagated. Cancellation and `with.timeout` stop the
  `wsl.exe` process through the shared executor; the Linux-side child is not
  promised to die when the bridge is killed.
- No native Windows run is claimed for this slice. The argv and refusal paths are
  covered by fake-interpreter tests, including a `bash.exe` shim that must never
  be selected.

## `uses: uv@<version>`

`uv` is not resolved on `PATH`. `uses: uv@0.8.0` selects the managed install
whose **directory label** is exactly `0.8.0`. That label is not proof that the
executable is uv 0.8.0, and the receipt digest is not bound to the executable.

- The managed list comes from a stricter enumeration than shell activation's:
  the version directory must be real, the receipt must be a real file containing
  lowercase hex of the layout's digest length, and the exact `uv` executable must
  be real, executable and contained under the install root. An empty, malformed,
  missing or symlinked receipt, a missing binary, or a symlinked install is not
  reported.
- **The receipt is self-attesting, not signed and not a version proof.** There
  is no external manifest or signature for a runtime install. The digest is only
  shape-checked; it is not a hash of the executable, and the directory name is
  not authenticated. These checks prove the directory is structurally complete
  and self-consistent, not that nenv created it or that the binary is the
  labelled version. Executing `uv@<version>` therefore **requires an external
  `execute` grant** for the task subject. Without that grant the run is refused,
  even when the directory and receipt look valid. A grant does not make a
  missing version appear, and the `PATH`-no-fallback rule is not
  policy-configurable.
- The install is re-checked immediately before spawn. The version directory must
  still be a real directory whose name matches the selected label; the receipt
  must still match the enumerated text; the executable must still be the
  enumerated path, a real file, and contained under the root. A symlink is
  refused even when it points inside the root. On Unix, the root and executable
  must also be the same device/inode seen at enumeration, so a root or binary
  **replaced by rename/recreate** is refused.
- **Device/inode is object identity, not content integrity.** It does not detect
  content written in place through the same inode, and the receipt digest is not
  a hash of the executable. The checks provide no integrity guarantee for the
  binary.
- **There is no race-free guarantee.** The identity check narrows the window,
  but a process can still replace a path between the check and `spawn`. The
  `execute` grant, not these checks, is the authorization. On platforms without
  a filesystem identity source, that replacement check is unavailable.
- An absent selected install label is a planning error, including for
  `--dry-run`. The diagnostic lists the managed uv directory labels that are
  present.
- There is no fallback to a `uv` executable on `PATH`, no automatic install, and
  no network access to obtain one. `uv` without an exact version and ranges such
  as `uv@latest`, `uv@^0.8`, or `uv@~0.8` are refused.
- The selected executable runs:

  ```text
  uv run --no-project --no-sync --offline --no-python-downloads python -c <run> <args...>
  uv run --no-project --no-sync --offline --no-python-downloads python <source> <args...>
  ```

  `--offline` and `--no-python-downloads` keep uv from reaching the network or
  fetching an interpreter. The task cannot create or sync a project environment
  as a side effect of selecting the runner.

## Fallback runner compatibility

Before these names existed, `uses: bash` meant "look for an executable named
`bash` in the configured `task_dirs`". It now means the built-in target shell.
The same applies to every name in the table above, plus `wsl`, `uv`, any
`uv@...` spelling, and any `tmpl://...` spelling. `templ` is not reserved,
because the reference does not accept it as an alias.

- A fallback executable with one of those names is **shadowed**. It is not
  reached through `uses:`. Rename the file and update the task, or call it
  through `argv` with an explicit path.
- Unknown names still use the existing fallback: a bare file name is resolved
  inside a configured local or global `task_dirs` entry. A global fallback still
  requires an exact external `execute` grant for
  `global-task-dir:<directory>/runner:<name>`.
- Fallback runners still receive `run` as their first argument and do not read
  `source`.

## Windows

Windows behaviour here is **intended, not natively verified**. No test suite run
on Windows is recorded for this runner set.

- `bash`, `sh`, and `fish` are refused on Windows rather than resolved through
  `PATH`. Windows ships `bash.exe`/`sh.exe` shims that hand off to WSL; silently
  running a Linux shell when a task said `uses: bash` would be a different
  operating system than the one the user is on.
- `pwsh` and `powershell` are the intended Windows shells.
- `node`, `bun`, `deno`, `python`, and `nu` use the same `PATH`/`PATHEXT`
  resolution as any other child process. They are not claimed as tested on
  Windows.

On Unix, `bash`, `sh`, and `fish` use the normal `PATH` lookup.
