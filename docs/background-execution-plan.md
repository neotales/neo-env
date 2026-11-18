# Owned concurrent execution plan

## Goal

Allow declared work to overlap without turning launch into success, changing the
default declaration order, weakening authorization, or leaving owned processes
behind. This is structured concurrency, not a detached service manager. A wait
means completion, not readiness or a health check.

## Contract to implement

- `background: true` launches a task and proceeds to the next planned task.
  `wait: [name]` joins named tasks before evaluating the waiting task's predicate
  or launching its action. `wait: all` joins all previously launched work.
  A wait-only task is an explicit barrier. Unknown waits and cycles fail planning.
- `needs` keeps declaration ordering. A background dependency is launched, not
  implicitly joined; use `wait` when its result is required. A per-need
  `{id: name, parallel: true}` opts that dependency into overlapping execution,
  but joins it before the owner's action. This previously inert option now acts.
- Jobs retain ordered steps. Steps accept the same background/wait controls;
  step IDs (or referenced task names) are the wait namespace. Job dependencies
  resolve only against jobs; they support background and parallel in the same
  manner. The selected job is always joined before returning.
- An implicit final wait-all joins finite work. No running task is reported as
  successful. Indefinite work requires a deadline or caller cancellation; a wait
  does not stop it. The implementation bounds active workers and rejects graphs
  exceeding that bound rather than blocking launch and deadlocking barriers.
- A joined failure blocks downstream work under the existing force policy.
  Already running work is cancelled on an observed failure; caller cancellation
  propagates to every worker. Every return path joins workers, including errors.
  Cancellation does not roll back effects.
- Each launch snapshots the current environment. Successful handoffs are applied
  only when joined, in launch order, not completion order. Failed work publishes
  no handoff. Output streams remain inherited and may interleave; reports retain
  plan order and contain final outcomes only.
- Authorization is checked for the entire reachable plan before launch, including
  dry runs. Dry runs validate the graph and record Planned without spawning,
  waiting, reading handoffs, or claiming execution success.
- Background processes use owned process groups on Unix and existing tree-stop
  facilities on Windows. Background descendants are cleaned up even if their
  leader exits. Default foreground descendant behavior remains unchanged.

## Implementation sequence

1. Add explicit declarations and strict normalization; preserve every existing
   fixture byte. Extend closure/planning to include wait edges and validate them.
2. Add an owned worker scope to the scheduler; keep the sequential default path,
   predicates, force, provenance, and external grants intact.
3. Add background process containment and error-path cleanup with no shared
   process-global configuration.
4. Lower job graphs and step controls into the same execution contract.
5. Exercise public config/runtime/CLI boundaries with isolated temporary roots:
   overlap and completion barriers, wait-all, failure, deadlines, caller
   cancellation, descendant cleanup, output handoff ordering, limits, trust and
   dry-run. Run offline gates with an exclusive target directory.

## Verification constraints

No network, credentials, commits or pushes. The legacy full gate contains network
preflights; do not run those under a false claim of offline validation. Record the
commands actually run and distinguish host-only evidence from intended platforms.
This worktree starts from committed HEAD; no changes from the parallel vault,
SSH, or tools work are included.

## Implementation boundary for review

The Unix CLI opts into a private single-command supervisor backend; library
callers default to no backend and reject overlap before effects. The CLI and
helper install safe `signal-hook` SIGCHLD handlers in their own processes.
The CLI exclusively owns and waits for its helper child; the helper exclusively
owns and waits for its command child, and kills that command's process group
before reaping its leader. EOF cancels the group. A SHA-256 handshake binds the
helper to the exact executable image the CLI launched. Portable command chains
and pipelines fail closed in background mode until the supervisor can own each
stage and pipe lifecycle. Supervisor crash and deliberate process-group escape
can still leave descendants. Windows Job Objects and actual platform tests
remain follow-up scope. The [execution contract](background-execution.md)
distinguishes intended behavior from what is currently available.

The CLI does not use the experimental pidfd-transfer mode. Its owned backend
uses ordinary `Child::wait` only for the helper it spawned, under the CLI's
exclusive-waiter policy; the runtime library never changes process-global
signal policy and enables the backend only when explicitly passed by the CLI.
The supervisor then reaps only its own direct child. This contract does not
extend to arbitrary embedders that install broad child waiters.

### Startup alternatives investigated

- The available nix 0.31.3 `fork` and `clone` interfaces are unsafe, and its
  safe `posix_spawn` returns a numeric PID, not a pidfd. rustix 1.1.6 provides
  safe `pidfd_open`, but not `clone3`; opening a pidfd from the returned PID
  after a foreign waiter can reap the child is not atomic.
- The installed Rust 1.100.0 rejects `CommandExt::create_pidfd` with E0658
  (`linux_pidfd` unstable). The installed glibc 2.44 exposes `pidfd_spawn`,
  which is a candidate atomic primitive, but the available nix, rustix and
  libc Rust bindings do not expose a safe wrapper. Introducing an FFI wrapper
  in this repository would violate its `unsafe_code = "forbid"` policy.
- A host-spawned launcher or persistent broker can own its own descendants, but
  the launcher/broker is itself a host child. If it dies before sending its
  own pidfd, the same startup window applies. Double-forking changes ownership
  of the grandchild, not that of the initial launcher. Delegating its reaping
  to a broad host waiter is not valid when that waiter may not exist.
- An **independently provisioned**, service-manager-owned broker could avoid
  host child creation altogether; it would require a reviewed deployment and
  peer-authenticated protocol, per-invocation stdout/stderr descriptor
  transport, cleanup and crash handling, and build identity checks. A user
  systemd manager is present on this machine, but that is not evidence of
  availability on supported systems, and no service was installed or started.

The smallest Linux-specific unblock found is a reviewed safe library exposing
atomic `pidfd_spawn`/`clone3(CLONE_PIDFD)` and accepting the required stdio
file actions, with a fail-closed fallback for unsupported libc/kernel
combinations. That would still require protocol integration, foreign-waiter
handling, and exact-build verification; it is not a completed implementation.
