# rsync-win Compatibility Matrix

This matrix describes the current development build behavior. It is intentionally conservative: unsupported or degraded behavior should be reported rather than implied.

## Peer Compatibility

| Peer or mode | Current status | Notes |
| --- | --- | --- |
| Upstream rsync over SSH | Experimental ordinary-file push/pull with external fixture coverage | Protocol 31 path is preferred, with protocol 27 fallback logic retained for older interop work. The gated `rsync_compat` fixture compares rsync-win push and pull results against upstream manifests for `-a --no-o --no-g`, delete/exclude, `--files-from`, `--checksum`, `--partial-dir`, `--inplace`, `--append-verify`, zlibx compression, multiple sources, and names with spaces/Unicode. Use `--plan` and small smoke tests before real data. |
| macOS/Homebrew rsync-compatible peers over SSH | Experimental ordinary-file push/pull | Expected to follow the upstream rsync path when protocol 31 is available. Older protocol behavior remains best-effort. |
| macOS stock rsync 2.6.9 | Best-effort, not release-grade | Older protocol and option behavior is not a first-class target yet. |
| openrsync | Best-effort, not release-grade | Option and wire behavior may diverge from upstream rsync; test before use. |
| rsync daemon `host::module` / `rsync://` | Experimental client/server ordinary-file workflows with auth fixture coverage | Module listing, no-auth and authenticated pull, daemon push to writable modules, local daemon-server module listing/pull/push, daemon-server `auth users`/`secrets file`, `read only`, `write only`, `list`, `uid`, and `gid` parsing, client connection controls, `RSYNC_PROXY`, `RSYNC_CONNECT_PROG`, daemon-server logging format, socket options, and `--bwlimit` are implemented for tested paths. Daemon auth is rsync challenge-response only, not transport encryption; advanced `rsyncd.conf` keys remain unsupported. |
| Local Windows-to-Windows portable sync | Implemented for tested ordinary files/directories | Covers recursion, mtimes, deletion, filters, multiple sources, and update modes in the current portable test suite. |

## Metadata Modes

| Mode | Current status | Notes |
| --- | --- | --- |
| `portable` | Default | Copies ordinary files/directories, compares size, applies mtime where requested, and applies explicit delete/filter behavior in tested paths. |
| `posix` | Sidecar/reporting path with remote metadata mapping | POSIX permissions/executability requests are represented. `--chmod` accepts rsync-style symbolic and numeric forms for remote upload mode bits. `--executability` infers peer execute bits from Windows script/executable extensions; it does not enforce NTFS execute permissions. Owner/group mapping, protocol 31 ACL/xattr/time payload framing, fake-super sidecar manifests, and `--omit-dir-times` are implemented in tested paths. Native Windows restoration of POSIX owner/group/ACL/xattr semantics remains sidecar/reporting-only unless a remote POSIX peer applies them. |
| `ntfs-native` | Narrow local restore path | Writes a parseable sidecar with security descriptor summary, alternate stream summaries, Windows attributes, sparse/reparse status, identity fields, and VSS request status. Local Windows syncs restore the tested readonly/hidden/archive/system attribute subset and copy named alternate data stream payloads. Security descriptor restore, sparse range preservation, arbitrary reparse restore, and cross-platform NTFS restore are degraded. |
| VSS snapshot mode | Rejected with diagnostics | `--vss` is parsed and reported, but snapshot reads are not implemented. See `docs/VSS-DESIGN.md` for the required source abstraction before any VSS calls are added. |

## Hardening Status

| Area | Current status |
| --- | --- |
| Local file data | Local copy, append, checksum comparison, and prefix comparison use bounded streaming IO. The local filesystem copy path uses a fixed 64 KiB buffer. |
| Remote whole-file tokens | Upload and download literal token IO streams through fixed 32 KiB buffers and checksums received data before finalizing. |
| Remote file-list paths | Protocol file-list readers reject parent escapes, absolute paths, Windows prefixes, reserved Windows names, invalid characters, and trailing dots/spaces before the CLI maps entries to a destination. Remote pull still performs destination preflight for case/normalization collisions before filtering or writing. |
| Remote pull selection | Filters and `--files-from` are applied locally after receiving the remote sender file-list. Remote push routes include/exclude/filter rules to the remote receiver for delete protection; `--files-from` is not routed to the receiver yet. |
| Remote token lengths | Remote pull rejects literal token streams that exceed or undershoot the advertised file-list length and removes temporary receive files on error. |
| File-list size | Remote file-list readers enforce a 100,000 entry limit and 32 KiB path limit. Protocol 31 remote pull can receive upstream incremental file-list markers; remote push still uses `--no-inc-recursive`. |
| Multiplexing | Data frames are streamed; remote error messages are surfaced; unsupported multiplex tags are rejected. |
| SSH process lifecycle | Child stderr is drained for diagnostics, hung child processes can be terminated through the transport timeout path, and dropped child transports close stdin and kill still-running children. Remote-shell startup failures such as command-not-found and SSH auth errors map to rsync start-protocol exit code 5; unsupported protocol maps to 2; checksum/protocol-stream errors map to 12; timeout maps to 30. |
| Compression | `-z/--compress` negotiates and applies zlib/zlibx token compression on the remote protocol 31 transfer path, including `--compress-choice`, `--compress-level`, and `--skip-compress`. Local Windows-to-Windows copies are not compressed, and `--compress-threads` is parsed/forwarded but does not add a parallel local compressor. |
| Release package | `scripts/package-release.ps1` builds the Windows zip layout and SHA-256 checksum used by the GitHub release workflow, then runs staged `--version`, `--help`, and a disposable local sync smoke test. |
| Benchmarks | `cargo bench -p rsync-fs --bench local_sync` runs local sync scenarios for a 128-file tree, many small files, and one large ordinary file. |

## Option Status

The packaged option table is in [`docs/OPTION-STATUS.md`](OPTION-STATUS.md). It classifies upstream client options, daemon/server options, and project-specific options as implemented, explicit diagnostic, or planned diagnostic. Planned diagnostic entries are accepted by the parser but are not counted as behavioral compatibility.

## Known Not Implemented

- Daemon auth is not transport encryption; `--password-file` only answers the rsync daemon challenge-response prompt, and daemon server secrets files are parsed without logging password material or full secrets paths.
- Advanced daemon-server `rsyncd.conf` keys beyond `path`, `comment`, `auth users`, `secrets file`, `read only`, `write only`, `list`, `uid`, and `gid` are not implemented. `uid` and `gid` are parsed for compatibility diagnostics but process identity changes are not applied.
- VSS snapshot reads are not implemented.
- NTFS security descriptor restore, sparse range preservation, and arbitrary reparse restore are not implemented.
- Alternate data stream payload copying is implemented only for named streams in explicit `ntfs-native` local Windows syncs.
- Full cross-mode memory-bounded incremental recursion is not implemented; remote-shell push remains sender-side non-incremental.

## Recommended Smoke Tests

Run these against disposable directories before using a new build:

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
cargo test -p rsync-cli --test options --all-features
cargo test -p rsync-cli --test security_remote_peer --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo bench -p rsync-fs --bench local_sync
rsync-win -rt --delete .\source .\dest
$env:RSYNC_WIN_SSH_TARGET = "user@host"
$env:RSYNC_WIN_SSH_TMP_ROOT = "/tmp"
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
$env:RSYNC_WIN_DAEMON_URL = "rsync://host:873"
$env:RSYNC_WIN_DAEMON_MODULE = "module"
$env:RSYNC_WIN_DAEMON_PATH = "path/to/readable-fixture"
$env:RSYNC_WIN_DAEMON_AUTH_MODULE = "auth-module"
$env:RSYNC_WIN_DAEMON_AUTH_PATH = "path/to/auth-readable-fixture"
$env:RSYNC_WIN_DAEMON_WRITABLE_MODULE = "writable-module"
$env:RSYNC_WIN_DAEMON_USER = "user"
$env:RSYNC_WIN_DAEMON_PASSWORD_FILE = "C:\path\to\daemon-password.txt"
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

`RSYNC_WIN_SSH_TARGET` enables disposable remote-shell smoke tests against the configured SSH host. The tests create and remove `rsync-win-*` directories under `RSYNC_WIN_SSH_TMP_ROOT`, which defaults to `/tmp`; use a path reserved for test data. `RSYNC_WIN_MACOS_RSYNC_TARGET`, `RSYNC_WIN_OPENRSYNC_TARGET`, `RSYNC_WIN_CYGWIN_TARGET`, and `RSYNC_WIN_MSYS2_TARGET` enable optional peer version probes. `RSYNC_WIN_SSH_PROTOCOL27_TARGET` is optional and should only be set to a peer that explicitly exercises protocol 27 fallback behavior.

`RSYNC_WIN_DAEMON_URL` enables daemon module listing and connection-control smoke tests. Set `RSYNC_WIN_DAEMON_MODULE` and `RSYNC_WIN_DAEMON_PATH` for a controlled no-auth readable fixture. Set `RSYNC_WIN_DAEMON_AUTH_MODULE` and `RSYNC_WIN_DAEMON_AUTH_PATH` for an authenticated readable fixture; if omitted, auth tests fall back to `RSYNC_WIN_DAEMON_MODULE` and `RSYNC_WIN_DAEMON_PATH`. Set `RSYNC_WIN_DAEMON_USER` and `RSYNC_WIN_DAEMON_PASSWORD_FILE` to exercise authenticated pull and auth-failure paths. Set `RSYNC_WIN_DAEMON_WRITABLE_MODULE` only for a controlled writable fixture; the push test writes a small `rsync-win-auth-push-*` directory and attempts to clean its contents after the run.
