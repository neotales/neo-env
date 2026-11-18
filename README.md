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
