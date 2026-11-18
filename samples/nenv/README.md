# NeoEnv configuration samples

The `yaml` and `toml` directories contain equivalent, self-contained
configuration examples. They demonstrate environment variables, ordered PATH
updates, a default context, and planned portable tasks without requiring a
tool download or a capability grant.

Use a NeoEnv binary to inspect either sample:

```sh
neoenv validate samples/neoenv/yaml/neoenv.yaml
neoenv inspect samples/neoenv/yaml/neoenv.yaml
neoenv task list samples/neoenv/yaml/neoenv.yaml
neoenv task plan build samples/neoenv/yaml/neoenv.yaml
```

Replace `yaml/neoenv.yaml` with `toml/neoenv.toml` to use the TOML version.
`task plan` is intentionally used here: executing a task requires an explicit
user capability grant.
