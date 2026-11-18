# An inventory of hosts is a capability *subject*, not a capability

Status: accepted
Date: 2026-09-28
Tickets: #257 (parity gaps), #40 (capability trust)

## What was blocked

`ssh`, `scp` and `ship` are three of the six commands the reference has and this
repository does not. All three need a named list of hosts to act on, and all
three were recorded as blocked on "a trust decision first". That phrasing made the
work look like a design project, and design projects do not get started.

This record exists because reading the code says the design is **already done**,
and what is actually missing is one enum variant and one rule about wording.

## What exists, measured rather than assumed

**1. Capabilities are declared by tasks and refused by name.**

    $ cat neoenv.yaml
    format_version: 1
    tasks:
      deploy:
        uses: portable
        capabilities: [network, filesystem-write]
        run: echo shipping
    $ nenv run deploy
    nenv: task deploy requests unsupported capability: network

An unknown capability is refused and *named*. This is the opposite of #31, which
parses a key and never acts on it.

**2. The policy is a user-owned file, default-deny, and read-only at runtime.**

`lib/neoenv-policy/src/lib.rs`:

    pub struct CapabilityGrants { grants: BTreeSet<(String, Capability)> }
    pub fn authorizes(&self, capability: Capability, subject: &str) -> bool

`capability_policy_path()` reads `$NEOENV_CAPABILITY_POLICY` or
`$XDG_CONFIG_HOME/nenv/capabilities.toml`, and a *missing* file is an empty
default-deny set rather than an implicit approval. Unknown capability names are
rejected by the document schema, so a typo in a grant is a parse error and not a
grant that silently matches nothing.

**3. The refusal is diagnosable, and it tells you what to write.**

    $ NEOENV_CAPABILITY_POLICY=./empty.toml nenv run custom
    nenv: ./empty.toml:1:1: task custom requested capability execute is not
          granted to global-task-dir:/tmp/.../.nenv/tasks/runner:myrunner by
          external policy ./empty.toml

    $ # with exactly that subject and capability in the file:
    $ NEOENV_CAPABILITY_POLICY=./ok.toml nenv run custom
    custom runner ran
    custom Succeeded

It names the task, the capability, the subject, and the policy file. Adding the
line it implies makes it work.

**4. The subject is an open, structured string, not an enum.**

From `lib/neoenv-runtime/src/tasks/scheduler.rs:392`:

    let subject = format!("global-task-dir:{}/runner:{}", resolved.directory.display(), runner);

and `policy_subject()` for packages, with a `TaskEdgeOrigin::Caller` /
`TaskEdgeOrigin::Package` split. The subject vocabulary is already
prefix-structured and open-ended.

## The decision

**An inventory host is a subject. `connect` is a capability.**

    subject   = "inventory:{inventory}/host:{host}"
    capability = Capability::Connect        # one new variant, "connect"

The host list does **not** go in the policy file. It stays in the project's
configuration, where the user wrote it, and the grant is written per host. That
fallout is the property worth having:

**Adding a host to an inventory requires a new grant.** The grant is keyed by
host, so a config that grows `web3` is refused until the user grants
`inventory:prod/host:web3`. The failure direction is the safe one, and it is safe
by construction rather than by a check somebody has to remember to write.

This is the direction `EntryFilter::matches` argues for at length — "widening a
filter that names a context this run does not have is the one failure mode worth
spending a line on here" — and here it is free rather than a judgement call.

### Why not put the hosts in the policy file

A policy file listing hosts duplicates the config, and the two drift. When they
drift, one of them is authoritative by accident rather than by decision, and
"which one did the user mean" has no answer in the code. A grant that names a
host the config does not contain is a grant for something nothing will ever do,
which is at least visibly inert; a config that names a host the policy does not
is a refusal, which is at least visibly a refusal.

### Why not a new top-level trust mechanism

There is a second, separate mechanism: `ProjectTrust { path, sha256 }` in
`lib/neoenv-runtime/src/remote/trust.rs`, which grants a *project file* the right
to fetch remote modules and is bound to the file's content digest
(`project_record` hashes the whole file). It is a good mechanism and it is the
**wrong one for inventories**, for two reasons:

- It grants a whole file one permission. An inventory needs the same file to be
  able to reach `web1` and *not* `db1`, and a per-file boolean cannot say that.
- Its unit is "this config", not "this operation". Re-granting on every edit is
  right for "may download and run remote code" and wrong for "may open a socket
  to a host the user already listed".

The two mechanisms compose rather than compete: content-digest trust answers
"is this the config you read", and capability grants answer "is this operation
allowed". An inventory needs only the second, because the host list is the thing
being authorized and it is already in the config the user reads.

## The one new correctness requirement

**The refusal must distinguish two denials that look identical from outside:**

1. `connect` is not granted to this subject *at all* — the user has never
   authorized this inventory.
2. `connect` is granted for a *different* host in the same inventory — the user
   authorized `web1` and the config now also names `web2`.

A single message covering both is the "wrong classification that fails closed and
still hides" shape: a correct refusal that a reader cannot act on, because the
remedy is different in each case. One is "grant the capability", the other is
"grant this host" or "remove it from the inventory". The message must name the
inventory and the host, in prose as well as in the subject string, because the
subject string for a host the user has never seen is a blob with nothing in it
they recognise.

The same argument applies to a host that is in the inventory but was refused for
being malformed, and to a host whose name is a wildcard match. Each needs its own
sentence; a shared "access denied" is the undiagnosable version.

## The reference does not execute these either, and that changes what parity is

Checked after the decision was made, because it was not known when the decision was
deferred -- and it is the most useful thing in this record.

    $ grep -rn 'not implemented yet' --include=*.go ~/work/neoenv-ref | grep -v _test
    cli/cli.go:817:  "ship %s for deployment %q (%s)%s is not implemented yet"
    cli/cli.go:821:  "ship %s is not implemented yet"
    cli/cli.go:2298: "ssh target %q resolved to %s; SSH execution is not implemented yet"
    cli/cli.go:2347: "scp %s %q -> %q for target %q (%s) is not implemented yet"
    cli/cli.go:550:  "task %s is not implemented yet"
    cli/cli.go:704:  "job %s is not implemented yet"
    cli/cli.go:915:  "tool use is not implemented yet; installer backends are being added"

`runSSHCommand` (`cli/cli.go:2262`) resolves the inventory targets, prints a plan
for `--plan-only`, and then for every host writes *"SSH execution is not implemented
yet"* to stderr and returns 1. `scp` does the same. So the reference's
`ssh`/`scp`/`ship` **resolve targets and refuse to execute.**

Two consequences, and they point opposite ways:

**Parity here is achievable without a network, and it is worth having.** What the
reference does is: resolve the target, print the plan on request, and refuse
execution *by name*. That is implementable, testable end to end without an SSH
server, and it is what a user of the reference actually gets. Building it is not
"porting an unimplemented feature" -- it is porting a resolver and a refusal.

**It would be easy to ship three inert commands and call it parity.** The failure is
exactly #31 in a new place: a command that resolves a host and then does nothing
about it. The difference here is that the reference says *"execution is not
implemented"* and exits non-zero, so the limit is visible and attributed. Copying the
shape without the message would produce something that looks like it works.

**The reference's inventory is richer than a list of host names.** `neofile/inventory.go:12`
has `Defaults`, `Hosts map[string]HostInfo` and a `HostOrder`; `HostInfo` carries
`Tags`, and a target is either a host name or `@tag`
(`projects/inventory.go:62`, `strings.TrimPrefix(target, "@")`). The tag form is the
convenience the feature exists for, so a model of `Vec<String>` would be parity in
name only.

## What this does not decide

- **Whether `ship` should exist at all.** It is an order of magnitude larger than
  `ssh` and `scp`, and may well be intended divergence rather than a gap.
- **Transport.** `neotales-ssh` is in the submodule and already implements SSH-2.
  The transport was never the obstacle.
- **Whether the grant is per-host or per-inventory.** This record chooses per-host
  because it is the safe direction for free. If a real inventory has forty hosts
  the ergonomics may force per-inventory, and that is a change to this record, not
  an exception to it.

## What would change this decision

- A requirement that a grant survive a config edit. Today it does not, and that is
  the point; a tool that must re-grant on every edit needs the digest mechanism
  instead.
- Evidence that the reference authorizes by inventory rather than by host. The
  reference's own trust model was not read for this record — the decision is
  about what fits *this* repository's model, and the reference's model is not
  evidence about this one.
- A capability that cannot be expressed as a subject because it constrains the
  *arguments* rather than the target. `connect` is about the target, so a subject
  is enough. A capability about, say, "may write outside the project tree" is not,
  and would need the grant key to carry data.
