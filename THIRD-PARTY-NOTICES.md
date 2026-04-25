# Third-Party Notices

This file summarizes third-party Rust crates reached by the Windows x64 `rsync-cli` normal dependency graph for `v0.1` (`0.1.0`). It was checked with:

```powershell
cargo tree -p rsync-cli --target x86_64-pc-windows-msvc -e normal
cargo metadata --format-version 1
```

The repository does not vendor third-party source code. Authoritative license terms remain in each dependency's published package metadata and source distribution on crates.io. Regenerate this file before publishing a release if dependencies change.

## Workspace Crates

The `rsync-win` workspace crates are licensed under `MIT OR Apache-2.0`.

## Runtime and Build Dependencies

| Crate | Version | License expression |
| --- | --- | --- |
| `anstream` | 1.0.0 | MIT OR Apache-2.0 |
| `anstyle` | 1.0.14 | MIT OR Apache-2.0 |
| `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 |
| `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 |
| `anstyle-wincon` | 3.0.11 | MIT OR Apache-2.0 |
| `anyhow` | 1.0.102 | MIT OR Apache-2.0 |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 |
| `clap` | 4.6.1 | MIT OR Apache-2.0 |
| `clap_builder` | 4.6.0 | MIT OR Apache-2.0 |
| `clap_derive` | 4.6.1 | MIT OR Apache-2.0 |
| `clap_lex` | 1.1.0 | MIT OR Apache-2.0 |
| `colorchoice` | 1.0.5 | MIT OR Apache-2.0 |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 |
| `digest` | 0.10.7 | MIT OR Apache-2.0 |
| `filetime` | 0.2.27 | MIT/Apache-2.0 |
| `generic-array` | 0.14.7 | MIT |
| `heck` | 0.5.0 | MIT OR Apache-2.0 |
| `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 |
| `md4` | 0.10.2 | MIT OR Apache-2.0 |
| `once_cell_polyfill` | 1.70.2 | MIT OR Apache-2.0 |
| `proc-macro2` | 1.0.106 | MIT OR Apache-2.0 |
| `quote` | 1.0.45 | MIT OR Apache-2.0 |
| `strsim` | 0.11.1 | MIT |
| `syn` | 2.0.117 | MIT OR Apache-2.0 |
| `thiserror` | 2.0.18 | MIT OR Apache-2.0 |
| `thiserror-impl` | 2.0.18 | MIT OR Apache-2.0 |
| `tinyvec` | 1.11.0 | Zlib OR Apache-2.0 OR MIT |
| `tinyvec_macros` | 0.1.1 | MIT OR Apache-2.0 OR Zlib |
| `typenum` | 1.20.0 | MIT OR Apache-2.0 |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `unicode-normalization` | 0.1.25 | MIT OR Apache-2.0 |
| `utf8parse` | 0.2.2 | Apache-2.0 OR MIT |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 |

No GPL-licensed dependency is present in this checked Windows release dependency graph.
