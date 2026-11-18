# A job is a sequence of steps, and it is neither a task nor a sibling of one

Status: accepted
Date: 2026-09-28
Tickets: #257 (parity gaps)

Update: [owned background execution](../background-execution.md) adds explicit
step barriers and job dependencies without merging the task/job namespaces.
Simple jobs still lower to ordered steps; concurrent job graphs use owned step
containers and one final result per job. The historical refusals below describe
the original decision, not the current `needs` contract.

## The question that was open

#257 recorded, without answering it:

> So the question is not "add a `job` command" — it is **whether a job is a task**.

That is the right question and it was open for a while, because answering it looked
like a design project. It is answerable from the code, and this record is the
answer.

## What the reference has

`neofile/job.go:6-20`, and the comment on line 5 says it outright:

> Job is an experimental pipeline definition made of ordered steps.

| | `Task` (`neofile/task.go:10-33`) | `Job` (`neofile/job.go:6-20`) |
|---|---|---|
| list of sub-actions | **none** | `Steps []Step` |
| namespace | `Tasks *TaskMap` | `Jobs *JobMap` |
| `needs` resolves against | `TaskMap` only (`runner.go:793`) | `JobMap` only (`runner.go:562`) |
| entry point guards on | `nf.Tasks` (`runner.go:85`) | `nf.Jobs` (`runner.go:393`) |

**There is no conversion, no alias, no fallback, and no comment claiming they are
the same thing.** `resolveJob` takes a `*JobMap` and `resolveTask` takes a
`*TaskMap`; neither is ever handed the other's type. The one shared code path,
`cli/embed.go:146` (`embedJobNode` calling `embedTaskNode`), is a helper for two
identically-spelled `embed:` fields, not a model conversion.

Execution is ordered at both levels — `for _, job := range jobs`
(`runner.go:414`), then `for i, step := range job.Steps` (`runner.go:449`) — with
no goroutines anywhere in the runner.

## What this repository has

No `jobs:` at all, and it says so by name rather than by silence:

    $ nenv validate      # with a `jobs:` section
    nenv: neoenv.yaml:11:1: unknown field `jobs`, expected one of `format_version`,
    `env`, `environment`, `dotenv`, `path`, `tools`, `context`, `task_dirs`,
    `packages`, `task_packages`, `tasks`, `import`, `imports`, `modules`, `workspace`

`TaskDefinition` has no field that is a list of steps. `TaskAction` is a struct, not
an enum, and none of its fields holds a list of sub-actions. The two `Vec`s it has —
`needs` and `hooks` — are *edges to other tasks*, not inline actions.

## The decision

**A job is a sequence of steps, and in this repository it would be a third kind of
node.** Not a task, and not a sibling model that reads tasks.

This is not a preference. Two facts force it:

1. **The current model cannot represent a container node.**
   `validate_task` requires `!template && action.is_some()` and returns
   `MissingAction` otherwise. A `jobs:` node with only steps has no action, so it
   would fail validation with a diagnostic that means the opposite of what happened.
   The model has to change, not just the readers.

2. **Nine readers would each need a policy**, and only one of them is load-bearing.
   `task list` would have to decide whether to show a container. `plan_task` would
   have to expand it or invent a third outcome beside `Planned` and `Succeeded`.
   `inspection_document` maps every task to an `InspectionTask` and a step sequence
   has no slot. `context list` harvests context names out of task keys, so a
   `job:prod` key would register `prod` as a context. And `scheduler.rs:93` is a
   linear loop assuming every node has one action and one exit status.

So `nenv job list` is **not** a filtered `task list`, which was the cheap reading.

## What is deliberately *not* ported

**The reference's own job model is incomplete, and porting it literally would import
its bugs.** These fields are parsed and never read anywhere in the tree:

| field | where | status |
|---|---|---|
| `Job.Extends` | `job.go:18`, written `job.go:90` | never read |
| `Job.Cron` | `job.go:19`, written `job.go:91-93` | never read; *not* wired to `On.Schedule.Crons` either |
| `Step.Embed` | `steps.go:14` | never copied into the synthesised task |
| `Step.With` | `steps.go:16` | never copied into the synthesised task |
| `Step.Desc` | `steps.go:18` | never read outside the struct |

`taskFromJobStep` (`runner.go:680-696`) copies `Id`, `Name`, `Run`, `Template`,
`Env`, `Cwd`, `If`, `Force` and `Uses` — and nothing else. So `embed:` and `with:`
on a step parse and do nothing.

This is the same shape as #31, which is hooks that parse and never run, and it is
the reason #257's acceptance criteria say a new node kind that three readers do not
handle is exactly the thing to avoid. **A port that accepts `extends:` or `cron:` on
a job and ignores them would be a new inert key in this repository**, which is the
one outcome this record exists to rule out.

The rule that follows: **each key is ported with its behaviour or refused by name.**
No key is ported on the strength of the reference having a field for it.

## A note on `extends:` while we are here

`Job.Extends` being inert is part of a wider finding, recorded in #259: **the
reference does not resolve `extends` on tasks either.** Both `.Extends` occurrences
in the whole tree are the writes. nenv resolves it, with `MissingBase` and
`InheritanceCycle`, which is better and is a divergence — one that changes whether a
config runs at all.

## What would change this decision

- A `Step` gaining a nested `steps` field, or a step gaining a nested-job
  reference. A recursive `Step` makes a job a *tree*, which is a third answer, not
  a first.
- Evidence that `job list` is expected to surface something `task list` cannot. The
  two produce byte-identical rows (`printListItem(name, desc)` at
  `cli/cli.go:2827`, `{name, desc}` JSON at `cli.go:554` and `cli.go:708`), so a
  committed expectation of, say, a step count would mean the listing changes too.
- A decision recorded *against* the reference — modelling a job as a task on
  purpose. That is allowed, and it has to be written down here, because "port the
  reference" is not an answer to "is this the same shape".
