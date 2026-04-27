# rsync-win

[![CI](https://github.com/Linorman/rsync-win/actions/workflows/ci.yml/badge.svg)](https://github.com/Linorman/rsync-win/actions/workflows/ci.yml)
[![Release](https://github.com/Linorman/rsync-win/actions/workflows/release.yml/badge.svg)](https://github.com/Linorman/rsync-win/actions/workflows/release.yml)

`rsync-win` is a native Windows rsync-compatible command line application written in Rust. It aims to provide useful rsync-style local sync and remote-shell interoperability without requiring a Cygwin/MSYS POSIX runtime.

This is an early development release. Version `v0.1.4` maps to Cargo package version `0.1.4` and focuses on ordinary files, directories, explicit metadata degradation, and a clean-room protocol implementation.

## Status

| Area | v0.1.4 status |
| --- | --- |
| Local Windows sync | Supported for ordinary files and directories, including multiple source operands. |
| Recursion and mtimes | `-r`, `-t`, and `-a` planning are supported, with unsupported archive metadata reported. |
| Deletion and dry-run | `--delete`, `--dry-run`, `--plan`, itemized changes, and structured stats are available. |
| Filters | `--include`, `--exclude`, `--filter`, `--files-from`, and `--from0` are available. |
| Update modes | Quick-check, `--checksum`, `--size-only`, `--ignore-times`, `--partial`, `--partial-dir`, `--inplace`, and `--append-verify` are represented. |
| Large files | Local copies and remote whole-file token IO stream through bounded buffers instead of staging whole files in memory. |
| Remote shell | Experimental ordinary-file push/pull path over SSH with protocol 31 work, protocol 27 compatibility fallback, and multiple local-source push support. |
| Windows-native metadata | Long path, collision, link, and metadata policy work is in progress. |
| Daemon mode | Planned, not implemented in v0.1.4. |

## Install

Download the Windows x64 zip from the `v0.1.4` GitHub Release, extract it, and run:

```powershell
.\rsync-win.exe --version
```

The release zip also includes the project license files and third-party dependency notice. A SHA-256 checksum file is published next to the zip.

## Build From Source

Prerequisites:

- Rust 1.76 or newer
- Windows 10/11 or Windows Server with a normal Rust MSVC toolchain

```powershell
cargo build --release -p rsync-cli
.\target\release\rsync-win.exe --help
```

Run the test suite:

```powershell
cargo test --workspace --all-features
```

Formatting and lint checks used by CI:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
```

## Usage Examples

Plan a recursive local sync:

```powershell
rsync-win --plan -r .\source .\dest
```

Run a local portable sync, preserving mtimes and deleting receiver-only files:

```powershell
rsync-win -rt --delete .\source .\dest
```

Transfer multiple sources into one destination directory:

```powershell
rsync-win -r .\file.txt .\folder .\dest
```

Preview archive mode metadata handling:

```powershell
rsync-win --plan -a --fail-on-metadata-loss .\source .\dest
```

Use filters:

```powershell
rsync-win -r --include "*.rs" --exclude "target/" .\source .\dest
```

Remote-shell support is still experimental. Use `--plan` first when testing against a real remote peer.

Use a custom SSH command, matching rsync's `-e` style:

```powershell
rsync-win -avz --no-o --no-g .\source\ -e "ssh -p 10080" root@example:/tmp/source/
```

## Project Layout

| Path | Purpose |
| --- | --- |
| `crates/rsync-cli` | CLI parser, transfer planning, local execution, and remote-shell orchestration. |
| `crates/rsync-core` | Shared diagnostics, metadata policies, and reporting types. |
| `crates/rsync-delta` | Rolling checksum, block signatures, matching, and token application primitives. |
| `crates/rsync-filter` | Include, exclude, protect, and files-from parsing. |
| `crates/rsync-fs` | Portable filesystem model and local sync engine. |
| `crates/rsync-protocol` | Rsync protocol encoding, file list handling, checksums, and session primitives. |
| `crates/rsync-transport` | SSH subprocess and TCP transport helpers. |
| `crates/rsync-winfs` | Windows path, metadata, and link behavior helpers. |
| `tests/interop` | Tests that discover optional real `rsync` and `ssh` peers. |

## Clean-Room and License Notes

`rsync-win` is an independent implementation. The project uses public documentation, interoperability behavior, and tests as references; it does not copy source code from the upstream GPL-licensed rsync implementation. The name describes compatibility goals and is not an affiliation with the Samba or rsync maintainers.

The repository is dual-licensed under either Apache-2.0 or MIT, at your option. See `LICENSE`, `LICENSE-APACHE`, and `LICENSE-MIT`.

Third-party Rust crates used by the Windows release path are listed in `THIRD-PARTY-NOTICES.md`. The current dependency set is permissively licensed; update that file whenever dependencies change.

## References

- [Official rsync project](https://rsync.samba.org/)
- [The rsync algorithm technical report](https://rsync.samba.org/tech_report/)
- [Official rsync documentation index](https://rsync.samba.org/documentation.html)
- [rsync(1) manual page](https://download.samba.org/pub/rsync/rsync.1)
- [librsync project notes](https://librsync.github.io/)
