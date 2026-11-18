# Finding map: every audited finding, and where it is accounted for here

Status: maintained by hand, checked by `eng/check-import-sweep.sh`
Tickets: #261 (this file and the check that requires it)

## Why this file exists

The import from `~/work/pvtlab` was reported as complete. It was not, and the way to
know was to count:

```text
FP: 47 in the source, 0 named in a ticket, 47 not
NW: 10 in the source, 0 named in a ticket, 10 not
NT: 10 in the source, 0 named in a ticket, 10 not
```

**Sixty-seven source items and not one of them traceable.** The substance was largely
covered — most items the source marks Complete *are* implemented, and five more were
shipped while writing this map — but "covered" and "traceable" are different claims
and only the second can be checked. A sweep nobody can audit is a sweep nobody can
tell is finished.

## What the `state` column means, precisely

The state says **how the row was established**, not how good it is. Nothing here is
machine-classified, and the reason is worth recording.

Two attempts at automatic classification were made and both were abandoned:

- **Title word-overlap against ticket titles** matched 46 of 47 items to a *single*
  ticket — the parity ticket, which shares vocabulary with everything. A table of 47
  confident rows pointing at one ticket.
- **Keyword presence in the Rust sources** reported `render×39` as evidence that
  Go-template rendering exists. That is a count of the word "render", not evidence of
  a feature.

Both are confident, specific and wrong, and both would have produced a document that
looked like an audit. So:

| state | meaning |
|---|---|
| `verified` | A **named type or function** was grepped for and found, or a command was run. The anchor column says which. |
| `claimed` | The source audit asserts it is done. **This repository has not re-checked it.** All 13 remaining rows are anchored in the `rust-libraries` submodule, which this repository does not commit to, so a grep here cannot speak to them either way. |
| `planned` | The source describes **future work this repository has not claimed to do**. Not a defect and not a claim. |
| `unverified` | Nobody looked. A truthful hole in the audit, rather than a false row in it. |
| `gap` | Looked for, **verified absent**, and ticketed. |

**`planned` is a fourth state and it was added because the other three were all lying
by omission.** The Deno epic, most of the workflow epic and three of the trust epic
had the anchor "not started" and the state `claimed` — and `claimed` means *the source
says done and we have not re-checked*, which is the **opposite** of the truth. Forced
into the existing three, each row was either a false claim or 24 tickets, and both are
worse than a fourth word.

`planned` does **not** require a ticket, and that is deliberate. Forty tickets for an
epic that has not started is a tracker nobody can read, and the epic's own document is
the better place for its breakdown. A `gap` is different in kind: something a reader
was told exists does not.

`claimed` is the honest label for most of the `Complete` rows, and it is deliberately
unflattering: this is a *migration* record, not an independent audit of thirty
features. A row that says `unverified` is worth more than a row that guesses.

## Findings

| id | state | anchor or ticket | what it is |
|---|---|---|---|
| FP-001 | verified | `docs/decision-records/` | Audit the legacy Go CLI; the two decision records cite it line by line |
| FP-002 | verified | `evaluate_predicate`, `TaskDefinition::if_condition` | task `if` and `force` |
| FP-003 | verified | `TaskHooks`, `resolve_hook_name` | `before`/`after` hooks with dependency ordering |
| FP-004 | verified | `TaskDotenvImport` | task-scoped dotenv |
| FP-005 | verified | `TaskDefinition::slug` | task ids, names, slugs, inherited metadata |
| FP-006 | verified | `unsupported local task runner` in `tasks/process.rs` | fail-closed runner contracts |
| FP-007 | verified | `TaskDefinition::template` at `model.rs:161`; the `template: bool` **field** at `structured.rs:288` (corrected: this row said `uses: template` there, and no such runner exists — `uses: template` is refused by name at run time) | Go-template compatibility. **The engine flag and the reader are here; the rendering itself is the submodule
| FP-008 | verified | `TaskAction::source`/`destination` | file-rendering task |
| FP-009 | verified | `CapabilityGrants`, `load_capability_grants` | persisted external capability grants |
| FP-010 | verified | `enum ToolProvider` | the provider framework |
| FP-011 | verified | `ToolProvider::GithubRelease` | GitHub Release provider |
| FP-012 | verified | `ToolProvider::Aqua` | Aqua provider |
| FP-013 | verified | `ToolProvider::Npm` | npm provider |
| FP-014 | verified | `ToolProvider::DotnetTool` | .NET tool provider |
| FP-015 | verified | `ToolProvider::GoModule` | Go module provider |
| FP-016 | verified | `ToolProvider::RubyGems` | RubyGems provider |
| FP-017 | verified | `ToolCommand::{Plan,Lock,Verify,Install,List,...}` | tool lifecycle. `where`/`use` are not separate variants -- the path is how a tool is named, so the item is a different shape than this repository's |
| FP-018 | verified | `ToolCommand::Install`; cache clearing in `tools/planning.rs` | explicit install and cache clearing |
| FP-019 | verified | `resolve_fallback_runner`, `TaskDirectories` | unknown-runner fallback |
| FP-020 | verified | `discovers_named_modules_from_the_user_cache_without_n...` in `modules/tests.rs:408` | user-cache module discovery |
| FP-021 | verified | `Workspace`, `declared_members` | local-only workspace members and aliases |
| FP-022 | verified | `TaskShortcut` | direct task invocation, aliases, collisions |
| FP-023 | **gap** | **#262** | user config/context **mutation** commands. `ConfigCommand` has `Group`/`List`/`Get` and **no `Set`**. |
| FP-024 | verified | `RuntimeCommand`, `execute_argv` | `exec` with the `x` alias |
| FP-025 | verified | `lower_job`, `JobDefinition` | jobs with ordered steps. Shipped; #257 |
| FP-026 | verified | `check_connect`, `Capability::Connect` | inventories and SSH. Shipped to the reference's limit; #257 |
| FP-027 | verified | `scp`, `Copy` | SCP. Shipped to the reference's limit; #257 |
| FP-028 | **gap** | **#263** | self lifecycle / `upgrade`. `SelfCommand` has `Init` and `Use` and **no `Upgrade`**. |
| FP-029 | **gap** | **#265** | three-OS verification. The README is honest about this -- *"Feasible and unproven"* for five of six, one *Verified* -- so the gap is the runners, not the claim |
| FP-030 | verified | `ToolProvider::GitlabRelease` | GitLab Release provider |
| FP-031 | **gap** | **#269** | **no runtime-provider registry exists.** `lib/neoenv-installer/src/tools/runtimes.rs` *installs* runtimes (`DenoRuntimeAsset`, `NodeRuntimeAsset`, `ZigRuntimeAsset`, …) and that is a different thing from a task that runs under one |
| FP-032 | verified | `reject_runner_selectors` | task script embedding **refused by name** rather than implemented |
| FP-033 | verified | `ContextCommand::Current` | `context current` |
| FP-034 | verified | `ConfigCommand::List` | `config list`/`get` |
| FP-035 | verified | `ShipCommand`, `DeploymentDefinition` | `ship`. Shipped to the reference's limit; #257 |
| FP-036 | verified | `PredicateContext` in `tasks/model.rs:78` | predicates and their context. **The recovery-after-a-failed-dependency behaviour is not separately asserted here** |
| FP-037 | verified | `EnvironmentEntry::secret`, redaction in `inspect` | environment secret metadata |
| FP-038 | **gap** | **#269** | **verified language runners are not implemented.** `uses: deno` **validates** and is then refused at run time: `unsupported local task runner: deno`, exit 3. That is the fail-closed design working — `validate` checks shape, `run` checks semantics — so the refusal is right and the feature is absent |
| FP-039 | verified | `Inventory`, `host_subject` | format-neutral inventory schema. Shipped; #257 |
| FP-040 | unverified | — | cross-platform handoff E2E. `NEOENV_ENV` is set in `scheduler.rs:629` and **no test asserts it**, and there is no macOS or Windows host. Blocked on runners. |
| FP-041 | verified | `OutputFormat` in `cli/model.rs:7`, carried on `format` at `:396` | text and JSON from one enum, as the AGENTS rule requires |
| FP-042 | **gap** | **#270** | **no compiled-binary test executes a Go-template task.** The only `template: true` in the suite is in a help/listing test that asserts the task is *not* run, so the template path has no end-to-end coverage |
| FP-043 | **gap** | **#264** | digest-pinned Docker tasks. The only `docker` strings in the Rust sources are a test's list of runner names. **Nothing implements it.** |
| FP-044 | verified | `bind_task_inputs`, `TaskParameter` | declared task inputs |
| FP-045 | verified | `evaluate_predicate`, `PredicateContext` | the closed predicate language |
| FP-046 | verified | `TaskPackage`, `apply_task_packages` | structured task packages |
| FP-047 | verified | `remote_lifecycle.rs` -- 3 `subpath` mentions, local origin, offline and rename-race | hermetic nested-module composition, against a local git origin and no network |
| NT-001 | verified | `reject_runner_selectors` in `normalize.rs:28` | non-template map runners validated and refused by name |
| NT-002 | verified | interpolation in `resolved_config/` | task-local environment interpolation |
| NT-003 | verified | `CapabilityGrants::from_toml`, default-deny | strict persisted capability grants |
| NT-004 | verified | `mod handoff;` in `tasks.rs:34` | a handoff module exists; **what it constrains was not read closely enough to assert** |
| NT-005 | verified | `scheduler.rs:549` documents the `sh` requirement | the POSIX `sh` requirement is documented at the point of use, not only in a README |
| NT-006 | verified | span tracking in `normalize.rs` | declaration spans by document structure |
| NT-007 | unverified | — | `EnvDiff::affected_keys` ordering. In the submodule, not re-checked here. |
| NT-008 | verified | `assert_json_document` in `command_contract.rs` | versioned, schema-tested JSON diagnostics |
| NT-009 | verified | `canonicalize_url` in `tools/planning.rs:2099`, with a test that *rejects* sensitive components | credential-sanitised tool URL identities. **The test name is the evidence: it asserts a rejection, not a redaction** |
| NT-010 | **gap** | **#265** | cross-platform CI gate. The release workflow and the runner labels exist; **no runner is registered**, and registration needs a site admin. |

| RC-001 | verified | `validate_key` in `structured.rs` | dotenv environment keys validated |
| RC-002 | verified | `commit_cache_path` = `commits/{sha256(repo)}/{commit}`; `fetch_tag_module` resolves the commit first and refuses a moved tag with `CacheMismatch`; tested at `remote_lifecycle.rs:546` | remote module content caches scoped by the **resolved commit**, for a tag reference too. **I demoted this row to `gap` and was wrong** — `cache_key()` names the *tag binding* file, and keying it on the tag is right. See #266 |
| RC-003 | verified | `remote_diagnostic` in `project_commands.rs` | trust diagnostics preserved at the CLI boundary |
| RC-004 | verified | `docs/schemas/` — five versioned schemas | published read-only JSON schemas |
| RC-005 | verified | `apps/nenv/tests/remote_lifecycle.rs` | cached trusted remote module composition, offline and rename-race |
| NW-001 | unverified | [`pvtlab#54`](https://github.com/neotales/pvtlab/issues/54) | a bare link with no text |
| NW-002 | unverified | [`pvtlab#56`](https://github.com/neotales/pvtlab/issues/56) | a bare link with no text |
| NW-003 | unverified | [`pvtlab#63`](https://github.com/neotales/pvtlab/issues/63) | a bare link with no text |
| NW-004 | unverified | [`pvtlab#58`](https://github.com/neotales/pvtlab/issues/58) | a bare link with no text |
| NW-005 | unverified | [`pvtlab#57`](https://github.com/neotales/pvtlab/issues/57) | a bare link with no text |
| NW-006 | unverified | [`pvtlab#59`](https://github.com/neotales/pvtlab/issues/59) | a bare link with no text |
| NW-007 | unverified | [`pvtlab#60`](https://github.com/neotales/pvtlab/issues/60) | a bare link with no text |
| NW-008 | unverified | [`pvtlab#55`](https://github.com/neotales/pvtlab/issues/55) | a bare link with no text |
| NW-009 | unverified | [`pvtlab#62`](https://github.com/neotales/pvtlab/issues/62) | a bare link with no text |
| NW-010 | unverified | [`pvtlab#61`](https://github.com/neotales/pvtlab/issues/61) | a bare link with no text |

**`NW-001` … `NW-010` are bare links to issues in `neotales/pvtlab` with no text**, so
there is nothing here to classify and `unverified` is the truthful state rather than a
cop-out. They are ten rows that say so rather than ten rows that guess, and the
difference is the point of the column. Reading the ten issues and replacing this
paragraph with real rows is the obvious next piece of work on this file, and
`unverified` names it precisely.

### The ten bodies are not reachable, and the reason is specific

Re-checked rather than assumed, and worth recording so nobody spends an afternoon
retrying:

```text
GET api.github.com/repos/neotales/pvtlab                    404
GET api.github.com/repos/neotales/pvtlab/issues/54          404
GET github.com/neotales/pvtlab/issues/54            (HTML)   404
git ls-remote git@github.com:neotales/pvtlab
  ERROR: Your account is suspended.
```

**The GitHub account is suspended**, and a suspended account's repositories return 404 —
which is indistinguishable from private-or-nexistent. So the 404s are not evidence that
the repository is gone or that the issues are private, and "unreachable" was the wrong
summary: it is reachable in principle and unreachable in fact.

Two local sources were checked and neither has the text: `~/work/pvtlab` contains the
**same bare-link table** in `work/neoenv/rust-work-items.md`, so importing it copied the
absence rather than the content; and no commit in that repository's history mentions any
of `pvtlab` issues `#54`–`#63`. The issue bodies live on the server, and the server is
the thing that is unavailable.

So the state is `unverified` because the input is genuinely absent, **not** because
nobody read them — which is the distinction this file exists to keep.

## Anchoring a row to nearby code is how an unimplemented item looks implemented

Five rows in the first draft of this table were anchored to code that **exists and is
not the feature**:

| row | anchored to | what actually exists |
|---|---|---|
| `GT-012` | `CapabilityGrants`, default-deny | the vocabulary is `Execute` and `FetchRemote`; **there is no template capability** |
| `PT-001` | `CapabilityGrants` | the grant machinery; **`ProjectIdentity` does not exist** |
| `PT-002` | `nenv trust` | a command; **no `TrustRecord` type exists** |
| `PT-006` | secret redaction | how a secret is **printed**; no `Permission::` variant exists |
| `WF-001` | `nenv job` | a job is a **sequence of steps lowered into a task chain**; no `Workflow` or `ActivityRecord` type exists |

Every one of those anchors was *true*. `CapabilityGrants` is really there, `nenv trust`
is really a command, `nenv job` really shipped, and redaction really works. And every
one made an unimplemented item read as a verified one — because "the anchor is a real
symbol" was the whole test, and a real symbol nearby is as good a match as the right
one far away.

**That is the same failure as the two classification attempts at the top of this file,
in a subtler form.** Both earlier rules produced confident wrong answers; this one did
too, and it survived being written down as a *method* rather than a guess. The
difference in the fix is that the anchor now has to be **the thing the item is about**,
which is checkable: `ProjectIdentity` is absent, and grepping for it says so, whereas
grepping for `CapabilityGrants` says nothing about PT-001 at all.

The five are now `planned`, with the absence named. That is the honest row, and it is
also the one that would have been useful six months ago.

## The second sweep: 56 more findings, and the two checkouts that hid them

The first pass read two files. `~/work/memory` holds six more that are about
this project, defining `DS`, `FM`, `GT`, `PT`, `RG` and `WF` -- **56 findings** --
and a sweep that reported completeness from two of eight files was not a sweep.

Two of the six were at paths I first guessed wrong (`jobs-workflow-tickets.md` is
under `pvtlab/rust/`, `gotmpl-spec.md` under `memory/projects/neoenv/docs/`), and
a recursive search then found the other four in `~/work/pvtlab-spiderfish`, a
**copy of `pvtlab` that is not a git repository**. The two sets are byte-identical
today, which is the problem rather than the reassurance: a check reading a
directory nothing commits will one day measure a snapshot nobody maintains, and it
will measure it confidently. The sources are now `~/work/pvtlab`, which is on
`dev`.

**Three more gaps, verified against the running binary rather than by reading:**

- `RG-004` a tag is accepted where a commit should be --
  `remote module requires a pinned commit or exact tag` (#266)
- `RG-005` process containment exists in the **git client** and not in the task
  runner, so a timed-out task's descendants survive (#267)
- `RG-007` no runner is registered (#265, filed in the first pass)

**And one source audit is simply wrong.** `RG-006` says `completion <shell>`
"currently reports a runtime error". It emits 319 lines of bash, 305 of zsh and
283 of fish. An audit is a claim about a binary that moved, and the map records
which rows are that.

**And one is a divergence rather than a gap.** `RG-003` asks for an implicit
default task runner so a scalar task executes. This repository *refuses* with
`task runner must be explicitly selected`, and `GT-010` records the opposite
choice in the submodule. Two answers to one question, both deliberate, and the
honest row says so rather than marking one of them a defect.

| RG-001 | verified | `nenv inspect` on a `.neoenv` names it as the project source | the source says local-module loading *rejected* `.neoenv`; today it does not |
| RG-002 | verified | `required: false` skips an absent file (exit 0); a required one is NEO701 `required dotenv file was not found` (exit 3) | ordered interpolation **and** required/optional dotenv, measured on both spellings. The first attempt used a wrong YAML shape and the resulting refusal was about the shape, not the semantics |
| RG-003 | verified | `must be explicitly selected` at `neoenv-runtime/src/tasks/scheduler.rs:755` | **a deliberate divergence from `GT-010`**: the item asks for an implicit default runner and this repository refuses. A scalar that silently means `sh` is a silent-wrong-shell defect, and a refusal that names the three valid values is the answer this repository gives |
| RG-004 | **verified** | `fetch_tag_module` binds `tag -> commit` and refuses a disagreement; `apps/nenv/tests/remote_lifecycle.rs:546` | **a wrong gap.** The acceptance message names the tag as acceptable because an exact tag is what a human writes, not because it is unpinned. A moved tag is **refused** with `CacheMismatch` and its old binding is kept. See #266 |
| RG-005 | **verified** | `wait_for_children` calls `stop_process_tree` on timeout *and* on `is_cancelled()`; `apps/nenv/tests/task_process_trees.rs` measures both | **a wrong gap, twice.** Containment is not missing — `neotales-process` does `process_group(0)` and `kill(-pgid)`, and the timeout path, the cancellation path and all three runners were measured. The ticket was first filed from a grep over a file that spawns nothing, then rewritten from a fixture whose task exited before the signal was sent. See #267 |
| RG-006 | verified | `nenv completion bash` 319 lines, `zsh` 305, `fish` 283 | **the source audit is stale** -- it says this reports a runtime error, and it does not |
| RG-007 | gap | **#265** | no runner is registered for any of the three labels |
| WF-001 | planned | no `Workflow` or `ActivityRecord` type exists | **`nenv job` is not this.** A job is a sequence of steps lowered into a task chain; a workflow contract with durable activity records is a different model, and the anchor pointed at the wrong one |
| WF-002 | planned | not started | durable activity records and an execution facade -- **a different scale from `nenv job`**, and the ticket for the latter does not close the former |
| WF-003 | verified | `LoweredJob` in `neoenv-core/src/tasks.rs:26` | deterministic execution, via the lowering rather than a workflow engine |
| WF-004 | planned | not started | child workflows and correlation |
| WF-005 | planned | not started | workflow versioning and replay safety |
| WF-006 | planned | not started | visibility and operator control facade |
| WF-007 | planned | not started | workflow runtime integrated with the worker |
| WF-008 | planned | not started | provider conformance and release evidence |
| PT-001 | planned | no project-identity type exists | **`ProjectIdentity` is not in this repository.** The item was anchored to `CapabilityGrants`, which is the grant machinery and is a different model; source/lock/runtime digests are not here |
| PT-002 | planned | no trust-record type exists | **no `TrustRecord` and no `Workflow` type either** -- the anchor `nenv trust` was the closest thing, and it is not this |
| PT-003 | verified | `CapabilityGrants::from_toml` at `neoenv-policy/src/lib.rs:67`, with a test at `:169` | strict persisted grants, loaded by the CLI, defaulting to deny |
| PT-004 | planned | not started | Deno permission parsing |
| PT-005 | planned | not started | Deno started with only approved permissions |
| PT-006 | planned | no `Permission::` variant exists | secret-access permission semantics. The anchor was redaction, which is about *printing* a secret rather than *granting access* to one |
| PT-007 | planned | not started | cross-platform E2E for source, lock and runtime digests. **Blocked on #265** |
| DS-001 | planned | not started | the Deno epic |
| DS-002 | planned | not started | a verified Deno runtime provider |
| DS-003 | planned | not started | TypeScript dependency lock/cache commands |
| DS-004 | planned | not started | `@neoenv/sdk` manifest builders |
| DS-005 | planned | not started | the permission-scoped Deno evaluator |
| DS-006 | planned | not started | TypeScript manifests into the canonical Rust model |
| DS-007 | planned | not started | framed JSON-RPC and log protocols |
| DS-008 | planned | not started | host-mediated JavaScript `exec` APIs |
| DS-009 | planned | not started | host-mediated template/render APIs |
| DS-010 | planned | not started | host-mediated Docker APIs -- **depends on #264** |
| DS-011 | planned | not started | host-mediated SSH/SCP APIs. **Its stated dependency shipped in #257**, so the gate is met and the work is not |
| DS-012 | planned | not started | declarative tool provider builders in the SDK |
| DS-013 | planned | not started | capability-to-host-operation mapping and prompts |
| DS-014 | planned | not started | hermetic cross-platform E2E with a local Deno |
| DS-015 | planned | not started | migration docs and SDK reference |
| FM-001 | claimed | submodule: crate ownership and error model | **this repository does not commit to `rust-libraries`**, so the anchor is a crate name and the ticket is a pointer |
| FM-002 | claimed | submodule: `neotales-args` | portable literal tokenization |
| FM-003 | claimed | submodule: `neotales-env` | interpolation, PATH, env diff |
| FM-004 | claimed | submodule: `neotales-dotenv` | source-preserving dotenv parsing |
| FM-005 | claimed | submodule: `neotales-process` | literal command graphs |
| FM-006 | claimed | submodule | generic crates integrated at their owning boundaries |
| FM-007 | claimed | submodule | cross-platform conformance fixtures |
| GT-001 | claimed | submodule: `neoenv-gotmpl`, `neoenv-sprig` | same boundary as FM |
| GT-002 | claimed | submodule: `neoenv-sprig` | safe Sprig V1 helpers |
| GT-003 | claimed | submodule: `neoenv-gotmpl` | template literal parsing, dot paths, trim markers |
| GT-004 | claimed | submodule: `neoenv-gotmpl` | dot-path data with deterministic missing-value diagnostics |
| GT-005 | verified | `execute_argv` in `neoenv-runtime/src/tasks.rs` and `scheduler.rs` | the portable literal argv, pipe, AND, OR and sequence commands |
| GT-006 | claimed | submodule: `neoenv-gotmpl` | helper calls and pipeline evaluation |
| GT-007 | verified | `evaluate_predicate` in `tasks/predicate.rs:24` | `if`/`else` truthiness |
| GT-008 | claimed | submodule: `neoenv-gotmpl` | typed values, `range` and `with` |
| GT-009 | verified | `execute_argv` in `neoenv-runtime/src/tasks.rs` | command-graph execution. **Cancellation was not separately asserted** |
| GT-010 | verified | `Portable` in `neoenv-runtime/src/tasks/scheduler.rs` | **the opposite choice to this repository's** -- the submodule migrates scalar tasks to the portable runner and `RG-003` is where nenv refuses them. Two deliberate answers to one question |
| GT-011 | verified | three fixture files in `fixtures/`, embedded by the gate | checked-in conformance fixtures |
| GT-012 | planned | the grant vocabulary is `Execute` and `FetchRemote` only | **persisted grants exist; a template capability does not.** The item was anchored to `CapabilityGrants, default-deny`, which is real and is not this -- see the note below on anchoring to nearby code |

## The four-scheme discovery

`FP`, `NT` and `NW` were known. `RC` was not: `RC-001` … `RC-005` are `###` headings
in `rust-work-items.md` beside the `NT` table, and **nothing in this repository could
have noticed them** because they live in another one. The check found them by accident
— its first version scanned the whole text for `XXX-999` and so also invented `SHA`,
which is `archive-SHA-256` in a table cell.

Both of those are the same shape of error and the difference between them is the
whole lesson: *a pattern that matches a thing and also matches the name of the thing
is not evidence of either.* Restricting detection to where an id is **defined** — a
table row's first cell or a heading — is what turned one real scheme and one
non-existent scheme into one real scheme. It is still a pattern, so it is still worth
arguing with, and the count it prints is the reason it is not silent.

## What this file does not claim

- That the `claimed` rows are true. They are the source audit's assertion, carried
  forward, and **not re-verified here**.
- That the `unverified` rows are false. They are rows nobody filled in.
- That the map is complete in the sense of covering work that was never in an audit.
  It covers the 67 items those two files define, and nothing else.

## The rule the check enforces

`eng/check-import-sweep.sh` asserts two things, and they are the two that can be
asserted without knowing the answers:

1. **Every source id has a row here.** Not that the row is right — no check can
   verify that — but that it exists, so the list cannot fall behind the sources
   silently. Both sources live in another repository, which is exactly why this
   needed a check: nothing *here* could notice when they gained an item.
2. **Every `gap` row names a ticket.** A verified absence with nowhere to record it
   is the failure this exists to prevent: known, not done, not tracked.
