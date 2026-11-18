# neoenv

The `nenv` command-line application. It discovers project configuration,
inspects composed environments, manages locked tools, and executes authorized
tasks.

```text
neoenv validate
neoenv inspect --format json
neoenv task plan build
```

The CLI output contract lives in the memory repo at
`projects/neoenv/docs/output-contract.md` (`github.com/neotales/memory`).
It defines stable stdout, stderr, JSON, streaming, and exit-status rules.

## License

MIT. See [`LICENSE.md`](../../LICENSE.md).
