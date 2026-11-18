# neoenv-config

Pure parsing and normalization for nenv YAML, TOML, and compact configuration.
It exists to turn source text into a validated domain model without filesystem,
network, or process effects.

```rust
let project = neoenv_config::parse_project(
    std::path::Path::new("neoenv.yaml"),
    "env: { APP: neoenv }",
)?;
# Ok::<(), neoenv_config::Diagnostic>(())
```

## License

MIT. See [`LICENSE.md`](../../LICENSE.md).
