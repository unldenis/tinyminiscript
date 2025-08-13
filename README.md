# tinyminiscript

tinyminiscript — `no_std`, blazing fast [Miniscript](https://bitcoin.sipa.be/miniscript/) library.

## Analyzing Implementation Size

To analyze the size of the miniscript implementation in the compiled binary:

```bash
rustc analyze_miniscript.rs && ./analyze_miniscript
```

| Architecture | Size    |
| ------------ | ------- |
| x86_64       | 34.2 KB |