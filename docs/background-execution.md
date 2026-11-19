# Background work, barriers, and parallel dependencies

Platform support is narrower than the Unix family. On Linux, `nenv` CLI
background task execution and job scheduling use the private owned supervisor.
On macOS, foreground tasks continue to use the historical adapter, but owned
background tasks and background job steps are unavailable and fail with an
explicit diagnostic before starting commands. Sequential jobs without graph
controls remain supported as foreground step sequences; job DAG/graph execution
requires owned background workers and is unavailable on macOS, as do
job-level timeouts. Runtime library callers default to no backend and reject
overlap before effects; no library API changes process-global signal policy.
On Linux, shell pipelines can run under the owned supervisor, which owns and
cleans up their process group. Portable command-chain forms whose stages cannot
be supervised fail closed when background execution is requested. Dry-run
validates and plans without starting a helper.

The Linux owned supervisor's waitable-leader process-group cleanup primitive is
not a portability contract for macOS. A Darwin-only CI diagnostic records the
result for a waitable zombie-only group and for a group with a ready descendant;
it expects the observed zombie-only `EPERM` but does not infer a safe cleanup
strategy from either result. In particular, this diagnostic does not enable
owned supervision on macOS or change how production cleanup handles errors.

Tasks and job steps run in their existing dependency/declaration order unless
overlap is requested. These controls are structured concurrency, not exact
GitHub Actions syntax, a detached-service manager, or a readiness check.
Only the requested root's reachable plan runs; background mode never launches
unrelated declarations. Controls use structured YAML/TOML in the native and Go
compatibility profiles; the line-oriented environment format is unchanged.

Where owned background execution is available, job definitions are DAG nodes:
independent jobs are launched concurrently by default, and each job joins its
declared `needs` before its own steps begin. Job step sequences remain ordered.
Sequential foreground jobs remain available on macOS, but DAG jobs,
job-level `timeout`, and `background: true` steps require the owned backend
there and are refused before commands start. The job-level `background` key is
rejected because job-level concurrency is already the default for DAG
execution.

```yaml
tasks:
  compile:
    background: true
    uses: shell
    timeout: 30s
    run: ./compile
  lint:
    needs: [compile]       # compile launches; lint need not await it
    uses: shell
    run: ./lint
  test:
    needs: [lint]
    wait: [compile]        # completion, not “the server is ready”
    uses: shell
    run: ./test
```

## Controls

| Control | Meaning |
| --- | --- |
| `background: true` | Launch this task or job step and proceed without joining it. For jobs themselves, independent DAG nodes run concurrently by default; the job-level `background` key is rejected as unsupported. |
| `wait: [name, other]` | Join named actions before evaluating this action's predicates or starting it. Names are ordinary task keys, IDs/slugs or context-selected names. |
| `wait: all` | Join every previously launched action in this graph. `all` is reserved in waits. |
| `wait-all: true` | Equivalent to `wait: all`; `wait_all` is an alias. Cannot combine with named waits. |
| `needs: [{id: one, parallel: true}, {id: two, parallel: true}]` | Launch these dependencies concurrently and join them before the owner's action. |

A declaration with only a nonempty `wait`/`wait-all` is a barrier and needs no
runner. A named wait includes its target in the reachable plan. Unknown names
and cycles fail planning; a forward step wait that contradicts job step order is
a cycle, not a reordered pipeline.

Ordinary dependencies remain ordered. An explicitly background dependency means
“launch before me”, not “succeed before me”; add a wait to require completion.
Per-edge `parallel: true` means “overlap this dependency, then require its result
before my action”. It does not change that dependency's own prerequisites.
The mapping-of-names compatibility extension to `needs` does not support parallel
options; use the sequence-of-mappings form above.
An attempted `parallel` option in that legacy name-keyed form is refused by name,
not accepted as an inert request.

At graph end there is an **implicit wait-all**, including for a requested root
marked background. No running work is reported as successful and no worker is
detached. A process intended to run indefinitely must have a timeout or be stopped
by caller cancellation. Wait does not terminate a healthy process.

## Failure and ownership

A background failure or timeout cancels running siblings (including an active
foreground command). It is observed before subsequent dispatch or at a join;
work already launched may have made effects. Joining a failure blocks subsequent
normal work under the existing fail-closed ordering. Explicit `force` recovery
can still run after the failed workers have been joined. A skipped dependency
still blocks a named dependent, as before.

Caller cancellation reaches all workers and their running descendants; returning
from a run joins all workers, including on preparation errors. Cancellation does
not roll back files, network effects, or other work already completed.

The Linux background implementation owns process groups. Its descendants are stopped even
when the group leader exits successfully. Background stdin is closed; it cannot
race foreground work for interactive input. Intentionally escaping containment
(for example, creating a new session) is outside this mechanism; trusted commands
are not sandboxed. Default foreground descendant behavior is unchanged.

The CLI supervisor owns a single argv command group and cleans it on timeout,
cancellation, or control-channel EOF. The Windows backend is experimental and
requires `neoenv-windows-launcher.exe` beside the executable. Windows release
archives and the Windows installer place it there. It refuses a destination
unless it is a pipe, disk file, or character handle. Verified overlapped pipes
use cancellable writes; verified synchronous pipes and disk files are forwarded
by a separately job-owned process. Character handles, including normal console
output, use synchronous writes of at most 4 KiB. A shared admission gate
serializes the entire character call with cancellation-event signalling: after
the event is signalled no new character call can start. A cancellation request
first prevents further admission without waiting; signalling the event itself
waits for any already-admitted call to return. Unknown types fail explicitly.
Windows ordinary foreground execution continues to use the historical adapter.

Native test evidence: Windows 11 Enterprise LTSC evaluation guest under
dockur/windows on this host; windows_launcher_tests.exe,
neoenv_windows_job_tests.exe, and background_tasks.exe each exited 0 twice on
the same binaries. This is not a full neoenv suite and not broad platform
support.

The experimental Windows adapter passes its kill-on-close Job Object in
`PROC_THREAD_ATTRIBUTE_JOB_LIST` during suspended creation, so assignment is
atomic with creation and restrictive nested jobs or unsupported Windows
versions cause startup failure rather than an uncontained fallback. A dedicated
no-stdio launcher creates a detached process in the job with handle inheritance
disabled. A control listener checks a live
retained launcher PID. The experimental client compares the pipe server PID
with a retained process handle whose PID and creation time match values passed
through trusted startup arguments; fixed non-secret handshake bytes precede
bounded versioned frames. Null security attributes select Windows' default
named-pipe security descriptor, not an owner-only ACL. Remote clients are
rejected, but an allowed local process can connect first and deny service.

Before launching a Windows helper, the runtime resolves the install directory,
opens the adjacent helper without write/delete sharing, rejects reparse points,
and holds that handle across startup and execution to prevent replacement. The
control handshake requires the matching adapter package version before any task
environment is sent. This is an install-directory trust boundary, **not a code
signature**: a malicious helper already present in that trusted directory can
forge the version handshake.

PID plus creation time is not a cryptographic capability: its threat model
assumes trusted launcher arguments, no ability to rewrite either peer or
duplicate a handle from either process, and no PID/creation-time collision
after clock manipulation or reuse. PID checks alone cannot stop an attacker
who can duplicate a pipe handle. The client rejects nonlocal and noncanonical
pipe paths, but its synchronous Windows `CreateFileW` call is not guaranteed to
return before the deadline in every OS/driver failure. This scheme and its
partial-I/O failure behavior require further security review and broader
testing. An experimental acknowledged transfer duplicates only an
adapter-created anonymous pipe end into the launcher; the retained host
handle does not grant `PROCESS_DUP_HANDLE`. This is not a sandbox: the trusted
launcher may independently open the host with that right if the process ACL
permits it. After acknowledging its duplicate, the launcher waits for the host
to close the temporary handle, then confirms completion before the host reports
success. Failed transfers attempt
to terminate the launcher job and report possible outstanding authority on
cleanup failure, while panic cleanup is best effort. An experimental dedicated
launcher binary receives two pipe writers and runs one command in a nested job;
its worker-creation function is private and is entered before application
threads start. The dedicated launcher uses `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
to give its worker only the three intended standard handles, and closes the
temporary inheritable copies immediately after `CreateProcessW` returns. It
does not inspect or suspend Windows/runtime threads. Isolation from *other*
concurrent process creation in the launcher is a cooperation invariant: this
binary's own application code starts no concurrent `CreateProcess`, and its
thread-pool callbacks must not do so. The handle list applies only to this
worker; it does not stop another `CreateProcess` in the launcher from inheriting
the temporary handles. Arbitrary injected code, third-party callbacks or DLLs
that can start another process, and attackers able to duplicate peer handles are
excluded. This is not a kernel-enforced guarantee. The Windows thread pool may
create runtime threads without affecting launch eligibility.
The helper checks for
control disconnection before worker creation and again while the job-assigned
worker is suspended, before resume. Disconnect can still race the final check
and resume, and the worker may have effects before job cleanup. A separate
proxy copies adapter-owned pipes; host output writers own duplicates of the
caller's handles and use overlapped writes with cancellation events. For a
synchronous pipe or disk file, a separately job-owned forwarding process writes
the duplicated destination. Console output uses the caller's duplicated handle
in the host, with synchronous writes capped at 4 KiB. A cancellation request
prevents further admissions; its event is signalled only after any admitted call
returns, so an admitted call can start after the request but not after the event
is signalled. Windows cannot cancel a write already inside a console call, so
there is no wall-clock bound if that call blocks. The runtime requests event
signalling on a separate thread, terminates the task job without waiting for the
gate, and reports cleanup failure if the event or writer misses the deadline. Cancellation terminates the
forwarder's job and reports a cleanup error if the operating system cannot verify termination. A driver
that fails to complete a cancelled operation within three seconds causes the
operation storage and duplicate to be retained rather than freed unsafely.
Cleanup reports job-termination and bounded writer-join failures alongside the
primary result; a failed termination can still leave work behind.

The experimental code supports only individual `.exe`/`.com` commands, not
pipelines, chains, `.cmd` or `.bat` scripts. Broader Windows testing and
security review remain outstanding. A Job Object is not a sandbox and cannot
contain work delegated to an external broker.

Sequential foreground commands use the historical adapter, including its
existing cancellation and descendant behavior. In particular, its Unix
numeric group signal is not protected against a foreign child reaper or
automatic child reaping; this pre-existing limitation is not a safety guarantee.

The intended owned background pipelines clean each exited stage's group immediately, rather
than waiting for downstream EOF first. This stops detached descendants retaining
pipe writers without killing downstream readers or discarding already-written
pipe data. A stage intending a descendant to produce more data must itself wait
for that descendant before exiting.

`waitid(WNOWAIT)` alone cannot reserve a child against a concurrent waiter or
automatic reaping, and is not an adequate basis for a numeric group signal.
A supervisor design must account for startup failures, control-channel EOF,
packaging and protocol compatibility. Even with a supervisor, unconditional
descendant cleanup after supervisor death or intentional process-group escape
must not be claimed.

A reachable graph, including job step graphs, may declare at most **32 background
actions** in total. This deliberately conservative static budget counts actions,
not CPUs or currently running processes. Exceeding it fails before any action,
even during dry-run. It never waits for a free slot while a worker might require
a later action to proceed.

## Environment, output, and dry-run

Each launch receives a snapshot of the environment at that point. Successful
handoffs become visible only at a barrier; workers selected by one barrier merge
in launch order, not completion order. Separate barriers publish in barrier
order. The last assignment applied by that ordering wins. Failed/cancelled/timed-out
work publishes no handoff. Different explicit joins intentionally publish at
different points.

Until joined, `outcome.NAME` is `running` and the `success` predicate is false.
Even a process that has already exited is not inferred successful before the
scheduler collects its result. Final reports never contain `running`.

Child stdout/stderr remain inherited and concurrent bytes may interleave. No
per-task stream ordering, output capture, or bounded log buffer is introduced.
Final reports retain plan order and contain final outcomes only. The existing
CLI's final JSON report does not capture child streams; commands that write to
stdout can still precede it. Consumers needing a standalone JSON document must
keep command stdout separate; JSON streaming/log framing is not added here.

Dry-run validates reachable dependencies, barriers, concurrency limits and
external capability policy, including nested jobs. It spawns nothing, reads no
handoffs and does not sleep at barriers. Planned is not executed success.
Task plan/help JSON includes `background`, `wait`, and
`parallel_dependencies`. The versioned inspection document remains unchanged.

## Jobs

Job `needs` and `wait` resolve against **jobs only**. Independent jobs run
concurrently by default; a job waits for its required predecessors before its
steps run. The job-level `background` key is rejected. Steps inside a job remain
ordered unless a step requests `background: true`.
`timeout: 30s` on a job covers its entire execution, including steps and joins,
starting when the job launches, not while its prerequisites run.

```yaml
jobs:
  checks:
    timeout: 2m
    steps:
      - id: compile
        background: true
        uses: shell
        timeout: 30s
        run: ./compile
      - uses: shell
        run: ./lint
      - wait: [compile]
  package:
    needs: [checks]
    wait: [checks]
    steps:
      - uses: shell
        run: ./package
```

A step can wait on a step `id` or an unambiguous referenced task name. Duplicate
identities and repeated task references are refused rather than collapsed.
Step `timeout` overrides the deadline of a referenced task. A step's own
background setting overrides its referenced task's setting. Job conditions gate
the whole container, and step conditions run after their completion barriers.

Independent jobs snapshot their launch environment. A completed successful job
publishes its net environment and public outputs when joined; failed jobs publish
none, although completed step effects are not undone. Jobs with graph controls
report one final result per reachable job; a simple sequential job retains its
existing per-step report. Referenced tasks keep inheritance, dependencies, package
identity, and execution trust requirements.

## Compatibility changes

- The previously accepted-but-inert per-need `parallel` flag now executes work
  concurrently. Remove it or use `false` to retain its old effective behavior.
- Job `needs` is now implemented instead of refused by the runner.
- Independent jobs run concurrently by default. Task and job-step background
  execution remains opt-in, as do explicit waits. A declaration requests
  capabilities; it never grants them, including through job lowering.

## Supervisor child-wait ownership

On Linux, the CLI opts in to `CooperativeOwnedBackend` only after installing a
waitable `SIGCHLD` handler. The CLI's ownership invariant is that no other
thread or linked library reaps its runtime-owned children, including via a
broad `waitpid(-1)` or `waitid(P_ALL)`. Before the supervisor's pidfd arrives,
failure cleanup closes the control socket and waits for that specific direct
child under this invariant. After pidfd transfer, cleanup waits by pidfd and
does not fall back to a numeric wait if another waiter has already reaped it.
Cancellation closes the control socket and resumes a stopped supervisor so it
can clean up its group. If it remains unresponsive, the CLI force-kills it by
pidfd after a bounded grace period and reports that descendants may remain.
Before pidfd transfer it kills and reaps the direct child under the explicit
exclusive-wait contract.
The host also enforces the action's deadline while polling the supervisor, so a
stopped supervisor cannot suppress that timeout. Protocol lines are capped at
128 bytes and read in bounded chunks. Request writes, descriptor transfer, and
pidfd receipt also use short bounded polls, checking deadline and cancellation
between operations even if a peer continually makes partial progress. Explicit
cleanup retries report any final failure alongside the original outcome; library
destructors only make silent best-effort cleanup and do not write diagnostics.
For an action, the timeout begins after the current executable's identity has
been verified and hashed, but before terminal-lease acquisition and supervisor
startup. Whole-job deadlines still cover their containing job.

This is a cooperation contract, **not a kernel-enforced guarantee**. An embedder
must leave `owned_backend` unset unless it can establish the same process-wide
policy and its own current executable implements the private supervisor modes.
The backend path must identify the current executable; arbitrary helper paths
are rejected.

Foreground work contends on a controlling-device lease. A nested foreground
invocation whose ancestor already holds that lease is refused with a diagnostic
rather than waiting on itself, even if the nested invocation uses a copied
executable. The ancestry inspection uses kernel process and descriptor lock
information, not a task-supplied environment flag. If `/proc` permissions,
`hidepid`, credential boundaries, or a disappearing descriptor prevent that
inspection, contested foreground execution fails closed with
`cannot inspect terminal lease ancestry; refusing contested foreground execution`.
This can refuse an otherwise unrelated competing invocation. Different terminals
use independent keys.

An offline source audit of the `nenv` dependency closure on 2026-11-15 found no
application call to a broad child wait. The CLI helper waits for explicitly
owned children; the runtime's remote Git runner and `neotales-process` also
wait on their own `Child` values. This search covered the CLI and source trees
of the 163 packages in its then-current Cargo dependency closure. It is not a
proof about dynamically loaded code, later dependency changes, or embedding
applications, and should be repeated when that closure or wait policy changes.
