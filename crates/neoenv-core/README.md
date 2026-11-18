# neoenv-core

nenv's pure domain model: task planning, tool locking, diagnostics, and shell
diff contracts. It exists to make policy-independent behavior testable.

```rust
let context = neoenv_core::tasks::select_context(Some("prod"), None, None);
assert_eq!(context, "prod");
```

## License

MIT. See [`LICENSE.md`](../../LICENSE.md).
