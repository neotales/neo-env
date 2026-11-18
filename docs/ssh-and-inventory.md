# Remote commands and inventory files

This is the implementation contract and review checklist for the first remote
execution slice, not a claim of cross-platform support.

## Plan and acceptance

1. Keep existing inline inventories and line-oriented `.neoenv` assignments.
   Add `inventory path` (repeatable) to `.neoenv`, and `inventory_files: [path]`
   to YAML/TOML. Paths are literal, relative to the declaring document, contained
   in its declaring directory after canonicalization; no traversal or symlink escape.
2. Load regular YAML/TOML inventory documents from the configuration directory's
   `neoenv/inventories/` in filename order. For each normal source layer, apply
   its explicit files in list order, then its inline inventories. Each named inventory replaces the previous
   inventory whole; hosts/defaults are never deep-merged. Unsupported extensions,
   auto-directory links, unknown keys and non-inventory content fail rather than disappearing.
3. Add explicit per-host SSH user, port, host-key pin and credential selection.
   Never discover SSH config or known-host files. An explicit `identity_file`
   (host setting, else inventory default) takes precedence and is the only key
   offered; `password_env`, if present, supplies its private-key passphrase.
   Without an identity file the SSH agent is tried. Login-password authentication
   is only selected by `password_auth: true` and requires `password_env`.
   Authentication never falls back to another mode after failure. No password
   literal is accepted and agent forwarding is not enabled by authentication.
4. Wire SSH command scripts and SCP file transfers through `neotales-ssh`.
   Require a command for non-plan SSH; interactive shells are not implemented.
5. Add `uses: ssh` task blocks. `with.inventory` names an inventory;
   `with.targets` is a comma-separated list of hosts/tags; `with.timeout`
   bounds execution. Reject other runner options and ignored local-only fields.
   Render `run` with the existing Go-template/Sprig engine. Template values in
   a shell script are executable code, not automatically shell-escaped.
6. Exercise the real CLI with two isolated SSH containers through testcontainers:
   successful command and template execution, SCP upload/download, host-pin
   mismatch, denied host, invalid paths, timeout and failed remote command.
   Generate credentials only inside the disposable test fixture. Docker absent
   means an explicit failing integration lane, never an apparent passing skip.

## Security and operational boundaries

External inventory I/O belongs to inventory consumers, not general project
resolution. Retain source layers and resolve them only for inventory listing,
SSH/SCP, or execution of a selected task graph containing SSH. Invalid unused
user/declared inventory files must not break local tasks, inspection or other
project commands; inventory consumers still fail strictly on invalid entries.
Each inventory operation takes one fresh snapshot, preserving user filename order
then declared-file/inline source precedence. Inspection/validation of the project
alone does not certify external inventories. Inline inventory grammar is still
validated when the project itself is parsed.

Before the first host executes, prepare and validate every endpoint's console
policy, including its authentication password, aliases and additional secrets.
Prepared consoles bind the validated redactor to that exact endpoint. Collect
additional secret references without plaintext copies; own only bounded,
zeroizing pattern storage. A later host's over-budget password or invalid
console configuration must leave every host untouched.
Prepared consoles are one-shot and endpoint-bound; execution cannot substitute
another endpoint after validation. Patterns deduplicate borrowed values before
copying into at most 16 KiB of zeroizing pattern bytes per prepared host. Hidden
lookbehind bytes are wiped before ring slots are vacated or buffers cleared, and
remaining buffers are wiped on drop. This is not a promise to erase caller-owned
environment maps, rendered template values, transport allocations or all compiler
temporaries.

### Console streaming

Replace whole-execution command buffering with incremental channel consumption.
Keep host concurrency at **one** in this slice: hosts cannot interleave each
other's lines. Buffer stdout and stderr independently in 4 KiB payload groups,
flush at most 100 ms after receipt (subject to local writer backpressure), and
flush both streams on EOF, failure and cancellation. Prefix every displayed
line/continued chunk with the escaped host alias and stream name. Preserve
bounded SGR colour sequences, reset before prefixes/after groups, and replay
bounded style state on continuation. Drop OSC, cursor movement and other terminal
controls, including incomplete escapes at termination.

Text mode routes remote stdout to stdout and stderr to stderr. JSON mode routes
both prefixed console streams to stderr, leaving stdout for the final JSON
document. Producers are synchronous and backpressured, never an unbounded queue;
ticks alternate the first-flushed stream. There is no concurrent-host fairness
claim. A blocked local output consumer can hold execution beyond its network
deadline; cancellation cannot interrupt an arbitrary blocking `Write`.

Redact the authentication password and known sensitive environment values
across packet/group boundaries, ignoring SGR sequences during matching. Refuse
console setup if known secrets exceed explicit redaction limits rather than
emitting an unsafe stream. Unknown secrets produced only on the remote host
cannot be detected reliably. Test alternating streams/hosts, fragmented ANSI,
secret splits, huge/no-newline output, final partial groups and writer failure.
Matching spans packet/group boundaries after safe-SGR normalization, but cannot
generally detect encoded, encrypted, transformed or reordered secret values.
Known-value limits are 64 distinct nonempty secrets, each at most 256 bytes with
no control bytes; aliases are at most 128 UTF-8 bytes before display escaping.
Over-budget values refuse console setup before connecting. Secret-prefix
lookbehind is at most 255 plain bytes. At a flush deadline an ambiguous prefix
is conservatively redacted, and a later matching remainder is suppressed; this
can censor a nonsecret prefix rather than leak data or wait indefinitely.
SGR escape tokens are at most 64 bytes, saved style history is at most 128 bytes,
and intermediate output writes are at most 8 KiB. Per-prepared-host grouping,
matching and framing storage stays below 1 MiB, excluding the caller's writers
and the SSH library's bounded packet storage. Data is consumed one packet at a
time; every payload returns SSH window credit only after console consumption.
Large input packets are consumed in 4 KiB quanta with due-flush checks between
quanta, so a busy stream does not indefinitely defer the other stream's tail.
Valid UTF-8 code points and complete SGR sequences are kept together at group
boundaries. C0/C1 controls are filtered, CR becomes a newline, and malformed or
incomplete UTF-8 is discarded/replaced rather than relayed as terminal controls.
Remote SGR remains data when output is piped; it is not local CLI styling.
`NO_COLOR` is not forwarded to the remote account; scripts choose remote colour
policy. SCP protocol data is never displayed as console text.

Configuration is not authorization. All selected hosts must have existing
`inventory:NAME/host:HOST` `connect` grants before the first network effect.
SSH tasks also require the existing project/task `execute` grant; remote module
and package trust remain in force. A host pin authenticates the actual endpoint,
not merely an inventory alias. There is no trust-on-first-use or insecure switch.
Execution additionally requires `connect` on the `ssh-endpoint:SHA256` subject
computed from the host name, numeric address, effective user/port, host pin,
password environment reference, authentication mode, and a hash of the resolved
identity path. Changing HOME or the project root can therefore invalidate an
identity grant. Path components are normalized lexically without following
symlinks. The identity path and passwords are not printed in the subject.
An execution refusal prints that opaque subject; passwords are not hashed into it.
`nenv inventory list --format json` also exposes `endpoint_subject` and
`endpoint_granted`; the existing `granted` field still describes the alias grant.
When an identity path cannot be resolved, JSON reports a null endpoint subject
and an ungranted endpoint. Task preflight applies task-local environment and
command-line overrides when computing the endpoint grant, without resolving
vault values. If a `~` identity follows any earlier planned task, the plan is
refused before any task runs: earlier handoffs could otherwise change HOME or
an input used to compute it. This deliberately conservative rule also refuses
plans where an earlier task happens not to change HOME. A vault reference used
as HOME cannot be resolved for this preflight and is refused. Execution
rechecks the endpoint before its first SSH effect.

Library callers should authorize the opaque value from `Endpoint::subject()`
on the same resolved endpoint they execute. Alternatively use
`endpoint_subject_with_context` with exactly the environment and project root
passed to `Endpoint::resolve_with_root`. The old `endpoint_subject` is
deprecated; for identity-file declarations it returns a non-executable
sentinel rather than guessing the caller's HOME. This sentinel is a reserved
policy subject: grant documents containing it are rejected, and capability
checks always deny it. Do not put it in a policy; obtain the actual subject
from `Endpoint::subject()` or `endpoint_subject_with_context` instead.
Write `[[grants]]` records in the existing user-owned capability policy, each
with `subject = "..."` and `capability = "connect"` for both subjects. SSH tasks
also need `capability = "execute"` on their existing project/task subject.
The first slice requires numeric IPv4/IPv6 addresses to keep synchronous DNS
outside the deadline boundary. DNS names are refused, not resolved without a bound.

Remote commands intentionally run through the remote account's shell. Neither
an address, a local path nor an SCP path may become shell syntax. The initial
SCP surface accepts only relative normal path components composed of ASCII
letters, digits, `_`, `-`, and `.`, without `.` or `..` components. No recursive
copy, glob, remote-to-remote copy, or multi-host pull into one destination.
Local SCP paths stay within the project root; destination links are refused.
These checks are not a hostile-server filesystem sandbox: the remote account's
permissions and server-side chroot govern remote symlinks and command effects.

No environment map is forwarded wholesale. Do not print passwords, rendered
scripts or transport causes in diagnostics. Console payloads are distinct from
diagnostics and use the bounded known-value redaction above; unknown remote
secrets remain the remote program author's responsibility.
Credentials and host pins are not included in plans.

Timeouts cover connect and blocking network operations with one shrinking
per-host SSH deadline, excluding a blocked local console writer; no automatic
retry. A timed-out command can have partial effects and
may continue remotely after disconnection. SCP failures may leave partial files.
Hosts execute serially in deterministic target resolution order; stop on first
failure and do not claim rollback or exactly-once execution.
The default is 30 seconds **per host**, with SSH tasks accepting positive
durations up to one hour. This is not a whole-fleet deadline. Task cancellation
is checked between hosts and during packet I/O (100 ms polls); the initial TCP
connect is bounded by its deadline, not immediately interruptible. Direct SSH
also installs the existing cooperative Ctrl-C handler. Abrupt termination can
leave temporary/partial copy files; no cleanup promise covers SIGKILL.
Uploads are limited to 8 MiB, incoming SCP wire data to 16 MiB per connection;
the shared SCP decoder separately caps advertised file allocation at 64 MiB.
Command output has no whole-execution byte buffer or total byte cap; its
streaming buffers are bounded independently of execution length.
Local path checks are not race-proof against concurrent hostile filesystem
mutation; use a project directory not writable by untrusted processes.

SSH task templates expose `.env`, `.host.name` and `.host.address`. Task
`env`/`dotenv` affect credential lookup and rendering, not remote environment
forwarding. Task input values use the existing `.env.NEOENV_INPUT_NAME` surface.
Direct SSH/SCP password lookup uses the resolved project environment layered over
the process environment. SSH tasks additionally apply their own env/dotenv and
explicit command-line overrides in the existing task order.
SCP does not preserve timestamps/modes or copy directories.
For values that must remain data in a POSIX shell, use the fully single-quoted
`.shell.env.NAME`, `.shell.host.name` or `.shell.host.address` word:
`printf '%s\n' {{ .shell.env.MESSAGE }}`. Do not add outer quotes around these
words. Raw `.env` and `.host` substitutions are intentionally code-capable;
Sprig's `quote`/`squote` are not substitutes for POSIX shell escaping.

## Running the isolated integration lane

From the repository root, with a local Linux Docker daemon (the workspace
directory selects its pinned Rust toolchain):

```sh
cd rs/apps
CARGO_TARGET_DIR=../../target/neoenv-ssh cargo test \
  -p nenv --features ssh-container-tests --test ssh_container -- --nocapture
```

The explicit feature-gated lane fails if Docker/image startup fails. It uses a
digest-pinned OpenSSH image, generated fixture passwords, independently generated
host keys, automatic loopback port bindings, no host mounts and remove-on-drop
container ownership. It is Linux-only; this is not a Windows/macOS execution claim.
Normal tests exercise inventory composition without Docker. The existing CI
`--all-features` Linux test leg includes this lane.

## Compatibility and review surface

`.neoenv` remains assignment-oriented; the repeatable `inventory PATH` directive
does not turn it into YAML. Native YAML/TOML gains `inventory_files`. External
inventory documents always use the strict native inventory-only format, not the
Go compatibility profile. Inline inventories and alias-only plan output retain
their existing resolution contract; a plan is not proof that transport settings
or credentials are ready.

`uses: ssh` is now a built-in runner, not a same-named fallback executable.
`identity_file` selects one explicit private key; otherwise the default agent is
used. `password_auth: true` is the explicit password-login mode. Inventory JSON
adds `endpoint_subject`/`endpoint_granted`;
`granted` continues to describe only the alias grant. Successful direct remote
execution emits `{ "status": "succeeded", "completed_hosts": N }` in JSON mode.

Review the native grammar, endpoint hash subjects, credential-source semantics,
stream/redaction limits, JSON routing and the shared SSH library's new
`SshClient::from_authenticated_sessions` adapter before release. That adapter
requires caller-verified host trust and completed authentication. The shared
transfer helpers also accept legal window-adjustment events before exec success
and send input EOF before transfer CLOSE.

Direct commands use `nenv ssh -i lab @test -- 'remote script'` and
`nenv scp -i lab local.txt remote.txt @test`; pull uses `--pull` and exactly one
host. The script tail is joined with spaces, intentionally shell code rather than
an argv-safe command interface. Plans never evaluate script templates or connect.

## Example (illustrative, no real credentials)

```text
# .neoenv remains line-oriented, not YAML
APP_MODE=development
inventory inventories/lab.yaml
```

```yaml
format_version: 1
inventories:
  lab:
    hosts:
      first:
        address: 127.0.0.1
        user: fixture
        port: 2222
        host_key: BASE64_SSH_PUBLIC_KEY_BLOB
        password_env: FIXTURE_SSH_PASSWORD
        password_auth: true
        tags: [test]
```

For key authentication, set `identity_file` on the host or inventory defaults
instead. The file must be a private regular file (Unix group/other permissions
must be clear); an unset `password_env` means an unencrypted key, while a set
value is its passphrase. Key mode never tries the agent or password login if the
file cannot be read, decrypted, or authenticated. With no identity file, nenv
uses the process SSH agent; it does not enable SSH agent forwarding.
Relative identity paths, including those declared in external inventory files,
are resolved against the project root, not the current directory or inventory
file directory. `~` and `~/...` expand using the effective `HOME` environment
value (`USERPROFILE` on Windows); the value must be absolute. `~user` is not
supported. No password-database or shell expansion is performed.
Identity file opening supports Unix; bounded agent access currently requires
Linux. Other platforms refuse these respective authentication modes rather than
using an unsafe fallback. Identity files must be owned by the effective user,
private (no group/other permissions), regular files of at most one MiB, with no
symlink path components or `..` components. Agent enumeration and signing share the SSH operation's
deadline and cancellation; at most 32 agent identities are accepted.

```yaml
format_version: 1
inventory_files: [inventories/lab.yaml]
tasks:
  check-remote:
    uses: ssh
    with:
      inventory: lab
      targets: "@test"
      timeout: 10s
    run: |
      printf '%s\n' '{{ "hello" | upper }}'
```

Review the new config keys, capability subject binding, pin representation,
runner options, credential-source interface and CLI script separator before
calling this a stable public contract. Record actual commands and outcomes in
the handoff; unrun lanes are not evidence.
