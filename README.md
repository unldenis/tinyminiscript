# miniscript-rs

miniscript-rs — `no_std`, blazing fast [Miniscript](https://bitcoin.sipa.be/miniscript/) library.

## Analyzing Implementation Size

To analyze the size of the miniscript implementation in the compiled binary:

```bash
rustc analyze_miniscript.rs && ./analyze_miniscript
```

This will show you the breakdown of all miniscript-related functions and their individual sizes, plus the total implementation size in KB.

| Architecture | Size    |
| ------------ | ------- |
| x86_64       | 57.3 KB |