# Conformance fixtures

Fixture groups live here, and each is an *input* rather than source code. Do not
reformat them, do not let a formatter add a final newline, and do not "fix" what
looks like a typo: several files deliberately have no trailing newline, a leading
tab, or trailing spaces, because a parser's behaviour on those is the thing under
test. `.gitattributes` marks the tree `binary` and `.editorconfig` turns off
whitespace trimming for the same reason.

## What is here, and what is not

| Group | Where it lives | Why |
| --- | --- | --- |
| `config/v1` | here | Read by `neoenv-config`'s unit tests and by the CLI's compiled-binary tests. |
| `modules/local` | here | Read by the CLI's compiled-binary tests at run time. |
| `tmpl` | here | Templates and a values file copied by the `tmpl` runner's compiled-binary tests. |
| `gotmpl/v1`, `sprig` | [`rust-libraries/`](../../rust-libraries) | The Go template engine and the Sprig set moved to the shared library repository, and their conformance corpus moved with them. |
| `compose/v1`, `docker` | not in this repository | They belong to the Docker port, which has its own home. |

Both trees that reference a fixture do so with a path relative to the *file* doing
the referencing, and both are compile-time (`include_str!`) or run-time
(`CARGO_MANIFEST_DIR`) lookups. That makes the depth of each crate directory part
of the contract: moving `lib/neoenv-config` one level changes eleven
`include_str!` paths, and a partial move fails to compile rather than failing a
test, which is the good kind of breakage.

## `config/v1`

A fixture group contains equivalent YAML, TOML, and `.neoenv` documents plus an
expected normalized result. Tests must parse every format and compare normalized
values, not source text or implementation internals.

In format version 1, `.neoenv` is intentionally environment-only. It accepts
blank lines, full-line comments, `KEY=VALUE` assignments, single-quoted literal
values, and double-quoted values with `\"`, `\\`, and `\n` escapes. An odd number
of trailing backslashes continues the value on the following physical line; the
last backslash and newline are removed. YAML and TOML are the extensible
configuration formats for later tool, task, and module declarations.

Tool declarations are YAML/TOML only. They are an ordered `tools` sequence.
`explicit-url` artifacts require a lowercase 64-character SHA-256 value.
`github-release` declarations use `github_release.repository`, an exact `asset`
selector with optional `{os}` and `{arch}` substitutions, and either `sha256` or
`checksum_asset`. GitHub metadata uses `NEOENV_GITHUB_API_URL`, defaulting to the
public API, and optionally `NEOENV_GITHUB_TOKEN`; neither is persisted in a
lockfile. `.neoenv` never accepts tool declarations.

Task declarations are YAML/TOML only. `tasks` is an ordered map; a scalar task is
shorthand for `run`, while a map can declare `uses`, `run`, `needs`, `extends`,
`description`, `help`, `inputs` (or `params`), and planning metadata.

`environment-extensions.yaml` and `environment-extensions.toml` define equivalent
ordered dotenv and PATH declarations. `environment-extensions.env` is their
required source-relative dotenv file.

## `modules/local`

A YAML/TOML depth-first local module composition fixture. Its ordered overrides
and source provenance are covered by inspection and shell activation black-box
tests.

## The Go reference runners

`gotmpl/reference.go` and `htmltmpl/reference.go` are Go programs that execute
the conformance corpus with the standard library's `text/template`, so a claim
about Go parity is a claim somebody ran rather than a claim somebody reasoned
about. They live with their corpus in `rust-libraries` now:

```sh
cd rust-libraries && go run ./fixtures/gotmpl/reference.go ./fixtures/gotmpl/v1.json
```

They validate successful outputs and that error fixtures fail, but do not compare
Go and Rust diagnostics, because the error text is implementation-specific. The
HTML runner is intentionally valid-output-only: its error cases describe V1
context restrictions that `html/template` does not model, so they are exercised by
the language-specific consumers instead.
