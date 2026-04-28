# rsync-win Compatibility Matrix

This matrix describes the current development build behavior. It is intentionally conservative: unsupported or degraded behavior should be reported rather than implied.

## Peer Compatibility

| Peer or mode | Current status | Notes |
| --- | --- | --- |
| Linux rsync 3.2.x/3.4.x over SSH | Experimental ordinary-file push/pull | Protocol 31 path is preferred, with protocol 27 fallback logic retained for older interop work. Use `--plan` and small smoke tests before real data. |
| Homebrew/macOS rsync 3.x over SSH | Experimental ordinary-file push/pull | Expected to follow the Linux rsync path when protocol 31 is available. Older protocol behavior remains best-effort. |
| macOS stock rsync 2.6.9 | Best-effort, not release-grade | Older protocol and option behavior is not a first-class target yet. |
| openrsync | Best-effort, not release-grade | Option and wire behavior may diverge from upstream rsync; test before use. |
| rsync daemon `host::module` / `rsync://` | Experimental client MVP | Module listing, no-auth ordinary-file pull, and `--password-file` auth are implemented. Daemon push, encrypted transport, and broad option parity are not implemented. |
| Local Windows-to-Windows portable sync | Implemented for tested ordinary files/directories | Covers recursion, mtimes, deletion, filters, multiple sources, and update modes in the current portable test suite. |

## Metadata Modes

| Mode | Current status | Notes |
| --- | --- | --- |
| `portable` | Default | Copies ordinary files/directories, compares size, applies mtime where requested, and applies explicit delete/filter behavior in tested paths. |
| `posix` | Reporting prototype with narrow remote mode mapping | POSIX permissions/executability requests are represented. `--chmod` accepts numeric `600`/`0644` and scoped `F600`/`D755` forms for remote upload mode bits only. `--executability` infers peer execute bits from Windows script/executable extensions; it does not enforce NTFS execute permissions. Owner, group, ACL, xattr, fake-super, and symlink mtime limitations are reported. POSIX ACL/xattr/fake-super storage is not implemented unless a future sidecar says so explicitly. |
| `ntfs-native` | Narrow local restore path | Writes a parseable sidecar with security descriptor summary, alternate stream summaries, Windows attributes, sparse/reparse status, identity fields, and VSS request status. Local Windows syncs restore the tested readonly/hidden/archive/system attribute subset and copy named alternate data stream payloads. Security descriptor restore, sparse range preservation, arbitrary reparse restore, and cross-platform NTFS restore are degraded. |
| VSS snapshot mode | Rejected with diagnostics | `--vss` is parsed and reported, but snapshot reads are not implemented. See `docs/VSS-DESIGN.md` for the required source abstraction before any VSS calls are added. |

## Hardening Status

| Area | Current status |
| --- | --- |
| Local file data | Local copy, append, checksum comparison, and prefix comparison use bounded streaming IO. The local filesystem copy path uses a fixed 64 KiB buffer. |
| Remote whole-file tokens | Upload and download literal token IO streams through fixed 32 KiB buffers and checksums received data before finalizing. |
| Remote file-list paths | Remote pull validates all received file-list paths before filtering or writing, rejecting parent escapes, absolute paths, reserved Windows names, invalid characters, trailing dots/spaces, and case/normalization collisions. |
| Remote pull selection | Filters and `--files-from` are applied locally after receiving the remote sender file-list. Remote push routes include/exclude/filter rules to the remote receiver for delete protection; `--files-from` is not routed to the receiver yet. |
| Remote token lengths | Remote pull rejects literal token streams that exceed or undershoot the advertised file-list length and removes temporary receive files on error. |
| File-list size | Remote file-list readers enforce a 100,000 entry limit and 32 KiB path limit for the current non-incremental receive path. Full incremental recursion is still future work. |
| Multiplexing | Data frames are streamed; remote error messages are surfaced; unsupported multiplex tags are rejected. |
| Compression | `-z/--compress` is accepted for CLI compatibility but compression is not applied yet. |
| Release package | `scripts/package-release.ps1` builds the Windows zip layout and SHA-256 checksum used by the GitHub release workflow. |
| Benchmarks | `cargo bench -p rsync-fs --bench local_sync` runs local sync scenarios for a 128-file tree, many small files, and one large ordinary file. |

## Known Not Implemented

- Daemon push is not implemented.
- Daemon auth is not transport encryption; `--password-file` only answers the rsync daemon challenge-response prompt.
- VSS snapshot reads are not implemented.
- NTFS security descriptor restore, sparse range preservation, and arbitrary reparse restore are not implemented.
- Alternate data stream payload copying is implemented only for named streams in explicit `ntfs-native` local Windows syncs.
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
$env:RSYNC_WIN_DAEMON_URL = "rsync://host:873"
$env:RSYNC_WIN_DAEMON_MODULE = "module"
$env:RSYNC_WIN_DAEMON_PATH = "path/to/readable-fixture"
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

`RSYNC_WIN_SSH_TARGET` enables disposable remote-shell smoke tests against the configured SSH host. The tests create and remove `rsync-win-*` directories under `RSYNC_WIN_SSH_TMP_ROOT`, which defaults to `/tmp`; use a path reserved for test data. `RSYNC_WIN_SSH_PROTOCOL27_TARGET` is optional and should only be set to a peer that explicitly exercises protocol 27 fallback behavior.

`RSYNC_WIN_DAEMON_URL` enables daemon module listing smoke tests. Set `RSYNC_WIN_DAEMON_MODULE` and `RSYNC_WIN_DAEMON_PATH` only for a controlled no-auth readable fixture; the daemon test writes only to a local disposable destination.
