# neoenv-policy

Trust, capability-grant, and redaction policy primitives for `nenv`. It exists
to keep authorization decisions independent from parsers and runtime effects.

```rust
assert!(neoenv_policy::should_redact_environment("API_TOKEN"));
```

## License

MIT. See [`LICENSE.md`](../../LICENSE.md).
