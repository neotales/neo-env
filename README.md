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

CI builds and tests `nenv` for Linux, macOS, and Windows on amd64 and arm64. Each run uploads a
platform-specific archive (`nenv-<os>-<arch>.tar.gz` on Unix and `.zip` on Windows); Windows
archives include both `nenv.exe` and its `neoenv-windows-launcher.exe` helper. Pull requests and
branch builds retain these as workflow artifacts. An annotated `v*` tag pointing at the exact
workflow revision publishes the same archives to a GitHub Release. Lightweight tags and tags not
pointing to the checked-out revision are rejected. No release is created from a branch build.
