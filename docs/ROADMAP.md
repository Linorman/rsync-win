# Native Windows Rsync Development Roadmap

This roadmap breaks the greenfield Windows-native rsync project into delivery phases. It complements the detailed implementation plan in `docs/superpowers/plans/2026-04-25-native-windows-rsync.md`.

## Roadmap Principles

- Ship interoperability before breadth. The first real milestone is successful transfer against upstream Linux/macOS rsync, not a large option list.
- Keep Windows-native behavior explicit. NTFS ACLs, ADS, reparse points, VSS, and case-collision behavior must be surfaced as capabilities or warnings, never silently approximated.
- Build protocol code clean-room. Use rsync documentation and tests as references; avoid copying upstream GPL implementation code unless the repository license deliberately accepts that.
- Test against real peers continuously. Unit tests are not enough for protocol compatibility.

## Phase 0: Project Foundation

**Goal:** Establish a buildable, testable Rust workspace with clear module boundaries.

**Scope:**

- Initialize Rust workspace and crate layout.
- Add CLI skeleton with `--version` and help output.
- Add basic error/reporting model.
- Add CI-ready test commands.
- Add interop test discovery for `rsync`, `ssh`, and Windows platform capabilities.

**Deliverables:**

- `crates/rsync-cli`
- `crates/rsync-core`
- `tests/interop` discovery harness
- `cargo test --workspace` passing

**Exit Criteria:**

- A developer can clone/open the repo and run the full test suite.
- External rsync/ssh-dependent tests skip cleanly when unavailable.

## Phase 1: Protocol and Delta Core

**Goal:** Build protocol-independent primitives that can be tested deterministically.

**Scope:**

- Wire integer/string encoding.
- Protocol version constants and negotiation.
- Rolling checksum implementation.
- Strong checksum abstraction.
- Block signature generation.
- Literal/copy token generation and application.

**Deliverables:**

- `crates/rsync-protocol`
- `crates/rsync-delta`
- Unit tests for checksum, block matching, token apply, and version negotiation.

**Exit Criteria:**

- Delta engine reconstructs identical output across insert/delete/move/empty-file cases.
- Protocol negotiation tests cover valid, old, future, and invalid peers.

## Phase 2: Portable Filesystem Model

**Goal:** Define the portable rsync view of files before touching Windows-specific behavior deeply.

**Scope:**

- Platform-neutral filesystem trait.
- File type and metadata model for regular files, directories, symlinks, hardlinks, size, mtime, mode-like bits.
- In-memory filesystem for protocol tests.
- Local Windows filesystem read/write path for ordinary files and directories.
- Safe temp-file-write and atomic finalize behavior.

**Deliverables:**

- `crates/rsync-fs`
- Initial `crates/rsync-winfs`
- Local sync tests for ordinary files/directories.

**Exit Criteria:**

- Windows-to-Windows local portable sync works for ordinary files, directories, deletion, and mtime preservation.
- Metadata loss is reported through structured warnings.

## Phase 3: Windows-Native Filesystem Semantics

**Goal:** Make Windows behavior correct enough that remote interop will not corrupt user trees.

**Scope:**

- Long-path-safe Unicode path handling.
- Reserved-name and invalid-character preflight.
- Casefold and Unicode-normalization collision detection.
- Symlink capability detection and creation.
- Hardlink detection via volume/file id.
- Reparse point classification.
- Creation time and Windows attributes read path.

**Deliverables:**

- `rsync-winfs::path`
- `rsync-winfs::metadata`
- `rsync-winfs::links`
- Windows filesystem behavior test suite.

**Exit Criteria:**

- `Foo`/`foo` collision fails before transfer on default case-insensitive NTFS.
- Long path test passes.
- Symlink tests either pass or emit a precise capability warning.
- Junctions/reparse points are not traversed accidentally.

## Phase 4: Remote-Shell Interoperability MVP

**Goal:** Interoperate with upstream rsync over SSH for a minimal, useful file transfer subset.

**Scope:**

- Transport abstraction for child process stdio.
- Generate and parse minimal `--server` invocation.
- File-list serialization for regular files and directories.
- Push and pull support.
- Options: `-r`, `-t`, `--delete`, `--dry-run`, `--whole-file`, basic verbosity.
- Protocol 31/32 happy path first, then protocol 30 fallback.

**Deliverables:**

- `crates/rsync-transport`
- Minimal session engine in `crates/rsync-protocol`
- Interop tests against real Linux/macOS rsync when available.

**Exit Criteria:**

- Windows client pushes a small directory tree to Linux rsync over SSH.
- Windows client pulls a small directory tree from Linux rsync over SSH.
- Same tests pass against Homebrew/macOS rsync when available.
- Failure mode is understandable when remote shell emits non-protocol output.

## Phase 5: Rsync CLI Compatibility Surface

**Goal:** Expand from MVP transfer to the option subset users expect for daily rsync workflows.

**Scope:**

- Archive mode decomposition: `-a` as `-rlptgoD`, with unsupported pieces reported.
- Include/exclude/filter engine.
- `--files-from` and `--from0`.
- `--checksum`, `--size-only`, `--ignore-times`.
- `--partial`, `--partial-dir`, `--inplace`, `--append-verify`.
- `--numeric-ids`, `--chmod`, `--copy-links`, `--safe-links`, `--copy-unsafe-links`.
- Structured itemized output and stats.

**Deliverables:**

- `crates/rsync-filter`
- Expanded CLI parser and compatibility tests.
- Interop fixture suite covering common backup/mirror commands.

**Exit Criteria:**

- Common commands such as `rsync -rt --delete`, `rsync -a --delete`, and filtered syncs behave predictably.
- Unsupported `-a` components on Windows are reported, not ignored silently.
- Delete behavior respects filter protection rules.

## Phase 6: Daemon Client and Minimal Daemon Server Mode

**Goal:** Support `host::module` and `rsync://host/module` as a client, plus a controlled minimal daemon server for tested module workflows.

**Scope:**

- TCP transport.
- `@RSYNCD` greeting parsing.
- Protocol/subprotocol/digest-list validation.
- Module list request.
- Module selection.
- No-auth transfer first.
- Password-file auth second, with explicit warning that daemon auth is not transport encryption.
- Timeout and MOTD handling.
- Minimal daemon server module listing, ordinary-file pull, writable-module push, safe module path validation, socket controls, logging, and bandwidth limiting.

**Deliverables:**

- `rsync-protocol::daemon`
- Daemon interop tests against a controlled upstream rsync daemon.

**Exit Criteria:**

- Module listing works.
- Pull from no-auth daemon module works.
- Push to writable daemon module works in a controlled test.
- Local daemon server listing, pull, push, read-only rejection, socket options, formatted logging, and bandwidth-limit plumbing are covered by tests.
- Auth failures and protocol mismatches produce rsync-like errors.

## Phase 7: POSIX Metadata Expansion

**Goal:** Improve compatibility with Linux/macOS metadata while preserving honest Windows behavior.

**Scope:**

- POSIX mode mapping policy.
- Owner/group name and numeric id handling.
- `--executability`.
- Symlink mtime where protocol and platform support it.
- ACL/xattr protocol handling for peers that request it.
- `--fake-super`-style metadata storage design, if selected.

**Deliverables:**

- Metadata policy engine: `portable`, `posix`, `ntfs-native`.
- Compatibility report for applied/degraded/rejected metadata.
- Linux/macOS metadata interop tests.

**Current Implementation Status:**

- CLI accepts and reports POSIX metadata requests: `-p/--perms`, `-o/--owner`, `-g/--group`, `--executability`, `--acls`, `--xattrs`, `--fake-super`, `--omit-link-times`, `--numeric-ids`, and `--chmod`.
- Remote-shell sender file lists carry POSIX mode-like bits, including Windows executable-name inference for `--executability`.
- Owner/group, ACL, xattr, fake-super, and symlink mtime behavior is explicitly reported instead of silently approximated; POSIX ACL/xattr/fake-super payload storage is not release-grade yet.

**Exit Criteria:**

- POSIX metadata requests either apply correctly, store via explicit compatibility mechanism, or fail with clear diagnostics.
- Windows does not misrepresent NTFS ACLs as POSIX ACL fidelity.

## Phase 8: NTFS-Native Fidelity

**Goal:** Add Windows-specific backup-grade behavior beyond standard rsync semantics.

**Scope:**

- Security descriptor capture and restore strategy.
- Alternate data stream enumeration and restore.
- Sparse file preservation using native APIs.
- Windows attributes preservation.
- Reparse point preservation for safe types.
- Optional VSS snapshot source mode.
- Admin/elevated test categories.

**Deliverables:**

- `rsync-winfs::security`
- `rsync-winfs::streams`
- `rsync-winfs::vss`
- Native metadata sidecar or extension format.

**Current Implementation Status:**

- `rsync-winfs::security` captures a stable summary/hash of Windows security descriptors where available.
- `rsync-winfs::streams` enumerates alternate data stream names and sizes on Windows and safely reports none elsewhere.
- `rsync-winfs::vss` exposes explicit VSS request status; snapshot creation/restore remains rejected with diagnostics.
- `NtfsNativeSidecar` records file type, times, attributes, sparse/reparse status, identity fields, security summary, stream summaries, and VSS status. Restore and stream payload copying are not wired into local sync yet.

**Exit Criteria:**

- Windows-to-Windows `ntfs-native` sync stores and restores selected NTFS metadata in documented cases.
- VSS mode can read locked/open files from a snapshot in a controlled test.
- Cross-platform transfers keep `ntfs-native` metadata disabled unless explicitly requested.

## Phase 9: Performance, Robustness, and Release Hardening

**Goal:** Make the implementation suitable for real data volumes and packaged releases.

**Scope:**

- Streaming large files without high memory usage.
- Cross-mode incremental recursion or memory-bounded file-list handling; protocol 31 remote pull now handles upstream incremental file-list markers, while remote push remains non-incremental.
- Multiplexed message handling robustness.
- Checksum/compression negotiation hardening.
- Path traversal and malicious peer defenses.
- Structured logging and diagnostics.
- Windows installer/package generation.
- Benchmark suite against upstream rsync/cwRsync/MSYS2 where appropriate.

**Deliverables:**

- Performance benchmark suite.
- Security regression tests.
- Release packaging scripts.
- User-facing compatibility matrix.

**Current Implementation Status:**

- Local file copy, append, checksum comparison, prefix comparison, and remote whole-file token IO stream through bounded buffers.
- Remote pull validates all received file-list paths before filtering or writing, rejects destination escapes and Windows-invalid paths, and rejects literal token streams that exceed or undershoot the advertised file length.
- Protocol file-list readers now reject parent escapes, absolute paths, Windows prefixes, reserved names, invalid characters, and trailing dot/space components before entries reach destination planning.
- Remote file-list readers enforce entry-count and path-length limits; protocol 31 remote pull handles upstream incremental file-list batches, while full cross-mode incremental recursion remains future work.
- Daemon client and minimal daemon server paths cover module listing, ordinary-file pull/push, daemon client connection controls, proxy/connect-program support, formatted daemon logs, socket options, and daemon-server bandwidth limiting in tested paths.
- Progress logging, concise summaries, itemized changes, and structured stats are available through existing CLI output.
- `tests/security/remote_peer.rs` covers remote peer path, multiplex, and malformed length regressions as a dedicated security gate.
- `tests/interop/rsync_compat.rs` provides a gated upstream rsync matrix for SSH, optional peer probes, and daemon listing.
- `scripts/package-release.ps1` produces the Windows x64 release zip and SHA-256 checksum used by the GitHub release workflow; staged package smoke checks cover `--version`, `--help`, and a disposable local sync.
- `cargo bench -p rsync-fs --bench local_sync` provides a small local recursive sync benchmark.
- `docs/COMPATIBILITY.md` and `docs/OPTION-STATUS.md` document Linux rsync, Homebrew/macOS rsync, macOS stock/openrsync, daemon mode, metadata modes, hardening status, and current option classifications.

**Exit Criteria:**

- Large-tree transfer completes within defined memory limits.
- Malicious path/file-list tests cannot escape destination root.
- Release artifact installs and runs on supported Windows versions.
- Compatibility matrix documents Linux rsync, Homebrew/macOS rsync, macOS stock/openrsync, daemon mode, and Windows metadata modes.

## Suggested Release Milestones

| Milestone | Included phases | User-facing promise |
| --- | --- | --- |
| `v0.1-dev` | Phase 0-1 | Buildable project with protocol/delta primitives. |
| `v0.2-local` | Phase 2-3 | Local Windows portable sync for ordinary files. |
| `v0.3-ssh-mvp` | Phase 4 | Basic SSH push/pull interop with upstream rsync. |
| `v0.4-cli` | Phase 5 | Common rsync CLI workflows usable for daily portable sync. |
| `v0.5-daemon` | Phase 6 | Rsync daemon client support. |
| `v0.6-posix-meta` | Phase 7 | Broader POSIX metadata compatibility with reporting. |
| `v0.7-ntfs` | Phase 8 | Windows-native metadata preservation prototype. |
| `v1.0` | Phase 9 | Hardened release with documented compatibility matrix. |

## Go/No-Go Gates

- Do not start broad CLI option work until basic remote-shell interop passes against real rsync.
- Do not enable destructive delete by default in interop tests until destination-root escape checks are in place.
- Do not claim `-a` compatibility until unsupported metadata components are reported.
- Do not ship `ntfs-native` as default behavior; it is a separate backup-grade mode.
- Do not optimize protocol performance before correctness tests cover protocol 30/31/32 peer behavior.
