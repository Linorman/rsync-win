# rsync-win Compatibility Matrix

This matrix describes the current development build behavior. It is intentionally conservative: unsupported or degraded behavior should be reported rather than implied.

## Peer Compatibility

| Peer or mode | Current status | Notes |
| --- | --- | --- |
| Linux rsync 3.2.x/3.4.x over SSH | Experimental ordinary-file push/pull | Protocol 31 path is preferred, with protocol 27 fallback logic retained for older interop work. Use `--plan` and small smoke tests before real data. |
| Homebrew/macOS rsync 3.x over SSH | Experimental ordinary-file push/pull | Expected to follow the Linux rsync path when protocol 31 is available. Older protocol behavior remains best-effort. |
| macOS stock rsync 2.6.9 | Best-effort, not release-grade | Older protocol and option behavior is not a first-class target yet. |
| openrsync | Best-effort, not release-grade | Option and wire behavior may diverge from upstream rsync; test before use. |
| rsync daemon `host::module` / `rsync://` | Not implemented | Daemon operands are detected and reported instead of routed through remote-shell mode. |
| Local Windows-to-Windows portable sync | Implemented for tested ordinary files/directories | Covers recursion, mtimes, deletion, filters, multiple sources, and update modes in the current portable test suite. |

## Metadata Modes

| Mode | Current status | Notes |
| --- | --- | --- |
| `portable` | Default | Copies ordinary files/directories, compares size, applies mtime where requested, and applies explicit delete/filter behavior in tested paths. |
| `posix` | Reporting prototype | POSIX permissions/executability requests are represented; owner, group, ACL, xattr, fake-super, and symlink mtime limitations are reported. POSIX ACL/xattr/fake-super storage is not implemented unless a future sidecar says so explicitly. |
| `ntfs-native` | Capture-only sidecar prototype | Captures security descriptor summary, alternate stream summaries, Windows attributes, sparse/reparse status, identity fields, and VSS request status. Restore and stream payload copying are not implemented. |
| VSS snapshot mode | Rejected with diagnostics | `--vss` is parsed and reported, but snapshot reads are not implemented. |

## Hardening Status

| Area | Current status |
| --- | --- |
| Local file data | Local copy, append, checksum comparison, and prefix comparison use bounded streaming IO. |
| Remote whole-file tokens | Upload and download literal token IO streams through fixed-size buffers and checksums received data before finalizing. |
| Remote file-list paths | Remote pull validates all received file-list paths before filtering or writing, rejecting parent escapes, absolute paths, reserved Windows names, invalid characters, trailing dots/spaces, and case/normalization collisions. |
| Remote token lengths | Remote pull rejects literal token streams that exceed or undershoot the advertised file-list length and removes temporary receive files on error. |
| File-list size | Remote file-list readers enforce entry-count and path-length limits. Full incremental recursion is still future work. |
| Multiplexing | Data frames are streamed; remote error messages are surfaced; unsupported multiplex tags are rejected. |
| Compression | `-z/--compress` is accepted for CLI compatibility but compression is not applied yet. |
| Release package | `scripts/package-release.ps1` builds the Windows zip layout and SHA-256 checksum used by the GitHub release workflow. |
| Benchmarks | `cargo bench -p rsync-fs --bench local_sync` runs a small local recursive sync benchmark. |

## Known Not Implemented

- Daemon auth and daemon transfers are not implemented.
- VSS snapshot reads are not implemented.
- NTFS metadata restore is not implemented.
- Alternate data stream payload copying is not implemented.
- Full memory-bounded incremental recursion is not implemented.

## Recommended Smoke Tests

Run these against disposable directories before using a new build:

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
cargo bench -p rsync-fs --bench local_sync
rsync-win -rt --delete .\source .\dest
$env:RSYNC_WIN_SSH_TARGET = "user@host"
$env:RSYNC_WIN_SSH_TMP_ROOT = "/tmp"
cargo test -p rsync-cli --test interop_discovery --all-features -- --nocapture
```

`RSYNC_WIN_SSH_TARGET` enables disposable remote-shell smoke tests against the configured SSH host. The tests create and remove `rsync-win-*` directories under `RSYNC_WIN_SSH_TMP_ROOT`, which defaults to `/tmp`; use a path reserved for test data. `RSYNC_WIN_SSH_PROTOCOL27_TARGET` is optional and should only be set to a peer that explicitly exercises protocol 27 fallback behavior.
