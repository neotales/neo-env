# neoenv-installer

Verified artifact installation and activation planning for `nenv`. It exists to
centralize digest verification, hardened extraction, and transactional publish
behavior at the effect boundary.

```rust
let path = neoenv_installer::lockfile_path(std::path::Path::new("."));
assert!(path.ends_with("neoenv.lock"));
```

## License

MIT. See [`LICENSE.md`](../../LICENSE.md).
