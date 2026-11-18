# neoenv-runtime

nenv's filesystem, process, discovery, cache, and remote-module effect
adapters. It exists to keep effects outside the pure configuration and domain
crates.

```rust
use neoenv_runtime::remote::is_remote;

assert!(is_remote("github:neotales/example@tag:v1.0.0"));
```

## License

MIT. See [`LICENSE.md`](../../LICENSE.md).
