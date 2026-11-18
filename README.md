# neo-env

neo-env is a Rust workspace for the `nenv` command. The `neotales-*` crates are vendored here under `crates/`.

Repository: [github.com/neotales/neo-env](https://github.com/neotales/neo-env)

## Build

```sh
cargo build -p nenv
```

## Test and format

```sh
cargo test --workspace
cargo fmt --all --check
```

The workspace uses Rust 1.98.1. The license is MIT. Copyright Neotales and x0craft; see [LICENSE.md](LICENSE.md).

## CI and release archives

The workflow matrix is configured to run the workspace tests and build on native hosted runners for
Linux, macOS, and Windows on amd64 and arm64. Windows arm64 uses the `windows-11-arm` runner. Each
successful run uploads a platform-specific archive (`nenv-<os>-<arch>.tar.gz` on Unix and `.zip` on
Windows); Windows archives include both `nenv.exe` and its `neoenv-windows-launcher.exe` helper.
The workspace test step sets `RUST_TEST_THREADS=1` to mitigate observed timing-sensitive parallel
test failures; it runs the full suite and skips no tests. This is a mitigation, not a fix for the
parallel test instability.
Pull requests and branch builds retain these as workflow artifacts. An annotated `v*` tag pointing
at the exact workflow revision publishes the same archives to a GitHub Release. Lightweight tags
and tags not pointing to the checked-out revision are rejected. No release is created from a branch
build. These matrix jobs have not yet been verified by a GitHub-hosted workflow run.
