# Rsync-Win Next Development Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `rsync-win` from the current experimental ordinary-file build toward a daemon-capable, metadata-honest, release-hardened Windows rsync implementation without overclaiming unsupported POSIX or NTFS fidelity.

**Architecture:** Keep the existing clean-room Rust workspace and preserve the current boundary between protocol, transport, filesystem, Windows-native helpers, filter logic, and CLI orchestration. New work should first harden the protocol/file-list boundary and real remote-shell interop, then add daemon client mode as a separate transport, then promote metadata prototypes into explicit store/restore features with clear compatibility diagnostics.

**Tech Stack:** Rust 1.76+, `clap`, blocking std IO/TCP transports, existing `rsync-protocol`, `rsync-fs`, `rsync-winfs`, Windows APIs through `windows-sys`, upstream rsync/OpenSSH interop fixtures, PowerShell release tooling.

---

## Current Baseline

- Phase 0-5 are mostly implemented for ordinary files/directories: workspace, protocol/delta primitives, portable local sync, Windows path/link helpers, remote-shell protocol 31 with protocol 27 fallback, filters/files-from, update modes, partial/inplace/append paths, itemized output, stats, and metadata degradation reporting.
- Phase 6 is not implemented by design: daemon operands are recognized and rejected instead of being misrouted through remote-shell mode.
- Phase 7 is a reporting prototype: POSIX metadata requests are parsed, represented in plans, and degraded/rejected honestly; Windows local execution does not apply POSIX ownership/ACL/xattr fidelity.
- Phase 8 is a sidecar prototype: NTFS metadata summaries are captured, but security descriptor restore, ADS payload copy, sparse range preservation, arbitrary reparse restore, and VSS snapshot reads are not release-grade.
- Phase 9 has initial hardening: bounded streaming file IO, remote path preflight, remote token length checks, file-list size limits, packaging, benchmark, and compatibility matrix.

## File Structure

- Modify `crates/rsync-protocol/src/flist.rs`: keep all raw wire path validation in protocol readers before constructing platform `PathBuf`s.
- Create `crates/rsync-protocol/src/daemon.rs`: daemon greeting, module list, module selection, no-auth/auth challenge parsing, and daemon argument exchange.
- Modify `crates/rsync-protocol/src/lib.rs`: export daemon types once daemon mode exists.
- Modify `crates/rsync-transport/src/tcp.rs`: add daemon-friendly connect diagnostics, read/write timeout helpers if needed, and test hooks.
- Modify `crates/rsync-cli/src/lib.rs`: dispatch daemon operands separately from remote-shell operands; keep broad orchestration here until a focused split is justified.
- Consider creating `crates/rsync-cli/src/daemon.rs`: only after daemon logic becomes large enough to reduce `lib.rs` risk.
- Modify `crates/rsync-filter/src/rule.rs` and `crates/rsync-filter/src/matcher.rs`: only for filter semantics required by remote peer argument routing.
- Create `crates/rsync-core/src/chmod.rs`: POSIX chmod expression parser for the supported subset.
- Modify `crates/rsync-core/src/lib.rs`: export chmod and metadata capability status types.
- Create `crates/rsync-winfs/src/sidecar.rs`: structured NTFS sidecar encode/decode and restore planning.
- Modify `crates/rsync-winfs/src/metadata.rs`, `security.rs`, `streams.rs`, `vss.rs`: extend capture/restore one feature at a time.
- Modify `tests/interop/rsync_discovery.rs`: keep discovery tests, and add gated remote-shell smoke coverage.
- Create `tests/interop/daemon.rs`: controlled daemon interop tests gated on fixture availability.
- Modify `docs/COMPATIBILITY.md`, `README.md`, `docs/ROADMAP.md`: update only after behavior changes are implemented and verified.

## Chunk 1: Stabilize Current Remote-Shell and Hardening Baseline

### Task 1: Expand Malicious File-List Path Regression Tests

**Files:**
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] Add protocol 27 and internal file-list tests for raw backslash paths, matching the protocol 31 backslash rejection.
- [ ] Add reader tests for UTF-8 paths that parse as Windows absolute/prefix paths after conversion, such as `C:/x`, `/x`, and `//server/share`, and assert CLI preflight rejects them before writes.
- [ ] Add remote pull tests that verify rejected paths leave no destination directory or temp receive file behind.
- [ ] Run `cargo test -p rsync-protocol --all-features`.
- [ ] Run `cargo test -p rsync-cli --all-features remote_pull_rejects`.
- [ ] Commit: `test: expand malicious file-list path coverage`

### Task 2: Make Real Remote-Shell Smoke Tests Easier to Run

**Files:**
- Modify: `tests/interop/rsync_discovery.rs`
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`

- [ ] Add explicit environment variable documentation for `RSYNC_WIN_SSH_TARGET`, remote temp root behavior, and cleanup expectations.
- [ ] Add a gated remote-shell test for `-rt --delete` against a disposable remote directory.
- [ ] Add a gated remote-shell test for protocol 31 fallback behavior only if an older peer fixture is explicitly configured.
- [ ] Ensure all new tests skip cleanly without external binaries or target configuration.
- [ ] Run `cargo test -p rsync-cli --test interop_discovery --all-features`.
- [ ] Commit: `test: document and extend remote-shell smoke fixtures`

### Task 3: Keep Release Claims Tied to Verified Behavior

**Files:**
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/ROADMAP.md`

- [ ] Audit wording for "supported", "preserve", "compatible", and "release-grade".
- [ ] Downgrade wording to "experimental", "prototype", "reported", or "rejected" where restore/apply behavior is not implemented.
- [ ] Add a short "Known not implemented" block for daemon auth, VSS snapshot reads, NTFS restore, ADS payload copy, and incremental recursion.
- [ ] Run `cargo test --workspace --all-features`.
- [ ] Commit: `docs: align compatibility claims with implementation status`

## Chunk 2: Finish Phase 5 Remote-Shell Daily Workflow Gaps

### Task 4: Route Safe Filter Arguments to the Remote Receiver

**Files:**
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [ ] Extend `RemoteShellOptions` with a narrow `filter_args: Vec<String>` or equivalent structured representation.
- [ ] Generate upstream-compatible `--include`, `--exclude`, and supported `--filter` arguments for remote server argv.
- [ ] Keep local sender filtering as the source of truth for offered file lists.
- [ ] Remove the remote push `--delete` plus filters/files-from rejection only for filter cases where receiver-side delete protection is now represented in remote argv.
- [ ] Keep the rejection for `--files-from` plus remote push delete unless receiver semantics are proven.
- [ ] Add planner tests showing remote push with `--delete --exclude '*.tmp'` includes remote filter args and does not bail.
- [ ] Add interop test, gated by `RSYNC_WIN_SSH_TARGET`, proving excluded remote receiver files are protected from delete.
- [ ] Run `cargo test -p rsync-protocol --all-features`.
- [ ] Run `cargo test -p rsync-cli --all-features remote_push`.
- [ ] Commit: `feat: route remote-shell filter delete protection`

### Task 5: Tighten Remote Pull Selection Semantics

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] Add tests for remote pull with filters where the remote file-list includes excluded files, confirming transfer requests and local deletes respect protection.
- [ ] Add tests for remote pull with `--files-from` where parent directories are retained only as needed to request selected files.
- [ ] Document whether filters are applied locally after file-list receipt or passed to the remote sender.
- [ ] Do not claim memory-bounded incremental recursion until the sender file-list is bounded beyond current entry/path limits.
- [ ] Run `cargo test -p rsync-cli --all-features remote_pull`.
- [ ] Commit: `test: pin remote pull selection semantics`

### Task 6: Protocol 31 Transfer Robustness

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/session.rs`

- [ ] Add tests for unexpected multiplex messages during protocol 31 transfer and final handshake phases.
- [ ] Add tests for protocol 31 append-verify where the remote append basis exceeds the sender file length.
- [ ] Add tests for checksum mismatch on remote upload and download with temp cleanup.
- [ ] Keep protocol 27 fallback restricted to setup/negotiation failures, not mid-transfer corruption.
- [ ] Run `cargo test -p rsync-cli --all-features should_fallback remote_pull remote_push`.
- [ ] Commit: `test: harden protocol31 transfer edge cases`

## Chunk 3: Implement Phase 6 Daemon Client MVP

### Task 7: Add Daemon Operand Model and Parser

**Files:**
- Create: `crates/rsync-protocol/src/daemon.rs`
- Modify: `crates/rsync-protocol/src/lib.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] Add `DaemonOperand { host, port, module, path }`.
- [ ] Parse `host::module/path` and `rsync://host/module/path` without treating Windows drive letters as daemon syntax.
- [ ] Keep remote-shell operand parsing unchanged.
- [ ] Add CLI plan tests showing daemon operands route to daemon mode diagnostics, not remote-shell argv.
- [ ] Run `cargo test -p rsync-protocol --all-features daemon`.
- [ ] Run `cargo test -p rsync-cli --all-features daemon_operands`.
- [ ] Commit: `feat: parse daemon operands separately`

### Task 8: Implement Daemon Greeting and Module Listing

**Files:**
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `crates/rsync-transport/src/tcp.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] Implement `@RSYNCD:` greeting read/write with version validation.
- [ ] Implement module-list request by sending a blank module line.
- [ ] Parse module listing lines and MOTD text into structured output.
- [ ] Add fake in-memory daemon stream tests for greeting, bad greeting, MOTD, and module listing.
- [ ] Add CLI command behavior for `rsync-win --list-only host::` or equivalent existing rsync-like listing syntax if supported by the current parser.
- [ ] Run `cargo test -p rsync-protocol --all-features daemon`.
- [ ] Commit: `feat: add daemon greeting and module listing`

### Task 9: Implement No-Auth Daemon Pull for Ordinary Files

**Files:**
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Create: `tests/interop/daemon.rs`
- Modify: `crates/rsync-cli/Cargo.toml`

- [ ] Implement module selection and no-auth response handling.
- [ ] Generate daemon server args for a pull of ordinary files/directories using the same file-list/token receive path as remote-shell where protocol-compatible.
- [ ] Add a fake daemon protocol test for no-auth success and auth-required rejection.
- [ ] Add gated interop against a controlled rsync daemon fixture.
- [ ] Keep daemon push out of scope until pull is proven.
- [ ] Run `cargo test --workspace --all-features`.
- [ ] Commit: `feat: add no-auth daemon pull MVP`

### Task 10: Add Password-File Auth as Explicitly Insecure Transport Auth

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`

- [ ] Add CLI option for password-file only if it matches rsync-compatible usage and can avoid logging secrets.
- [ ] Implement daemon challenge response using the documented rsync daemon auth algorithm.
- [ ] Add tests that secrets do not appear in plan output, diagnostics, or errors.
- [ ] Add warning that daemon auth is not transport encryption.
- [ ] Run `cargo test --workspace --all-features`.
- [ ] Commit: `feat: add daemon password-file auth`

## Chunk 4: Promote Phase 7 POSIX Metadata Reporting into Narrow Apply/Store Features

### Task 11: Add a Supported Chmod Parser Subset

**Files:**
- Create: `crates/rsync-core/src/chmod.rs`
- Modify: `crates/rsync-core/src/lib.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] Implement numeric modes such as `600`, `0644`, `F600`, and `D755`.
- [ ] Implement only symbolic forms needed by tests if they are simple and well-scoped; otherwise reject with clear diagnostics.
- [ ] Apply chmod expressions to sender file-list mode bits for remote uploads where the remote receiver can apply POSIX mode.
- [ ] Keep local Windows chmod application degraded unless mapping is explicit and tested.
- [ ] Add tests for accepted numeric forms and rejected complex symbolic forms.
- [ ] Run `cargo test -p rsync-core --all-features chmod`.
- [ ] Run `cargo test -p rsync-cli --all-features chmod`.
- [ ] Commit: `feat: add chmod mode parser for remote metadata`

### Task 12: Store Fake-Super Metadata Only When Something Is Actually Stored

**Files:**
- Modify: `crates/rsync-core/src/lib.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Possibly create: `crates/rsync-cli/src/posix_sidecar.rs`

- [ ] Change diagnostics so `--fake-super` reports "stored" only for metadata that is actually written to a sidecar or received from a peer.
- [ ] Add a POSIX sidecar prototype for mode/uid/gid intent if selected.
- [ ] Keep ACL/xattr payload storage out of scope until protocol payloads are modeled.
- [ ] Add tests proving `--fake-super --fail-on-metadata-loss` does not silently pass when storage is not implemented.
- [ ] Run `cargo test -p rsync-core --all-features fake_super`.
- [ ] Run `cargo test -p rsync-cli --all-features fake_super`.
- [ ] Commit: `fix: make fake-super storage diagnostics truthful`

### Task 13: Preserve Executability Consistently

**Files:**
- Modify: `crates/rsync-fs/src/metadata.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] Confirm executable filename inference is used only for remote POSIX mode mapping, not as a local Windows permission claim.
- [ ] Add tests for `.exe`, `.bat`, `.cmd`, `.ps1`, and non-executable extensions.
- [ ] Add docs clarifying that `--executability` is mode-bit metadata for peers, not NTFS execute enforcement.
- [ ] Run `cargo test --workspace --all-features executability`.
- [ ] Commit: `docs: clarify executability metadata behavior`

## Chunk 5: Promote Phase 8 NTFS Sidecar Prototype into Restoreable Pieces

### Task 14: Make NTFS Sidecar Format Structured and Parseable

**Files:**
- Create: `crates/rsync-winfs/src/sidecar.rs`
- Modify: `crates/rsync-winfs/src/lib.rs`
- Modify: `crates/rsync-winfs/src/metadata.rs`

- [ ] Move sidecar manifest encoding out of ad hoc string formatting.
- [ ] Add parser tests for all current sidecar fields.
- [ ] Preserve forward-compatible unknown fields.
- [ ] Keep existing sidecar v1 files readable.
- [ ] Run `cargo test -p rsync-winfs --all-features sidecar`.
- [ ] Commit: `feat: add parseable ntfs sidecar format`

### Task 15: Restore Basic Windows Attributes

**Files:**
- Modify: `crates/rsync-winfs/src/metadata.rs`
- Modify: `crates/rsync-winfs/src/sidecar.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] Implement restore for safe file attributes such as readonly, hidden, archive, and system only if Windows API behavior is tested.
- [ ] Do not restore reparse tags, encrypted/compressed state, or sparse ranges in this task.
- [ ] Add Windows-only tests creating a file, writing a sidecar, restoring attributes, and verifying metadata.
- [ ] Report each attribute restore as applied/degraded/rejected.
- [ ] Run `cargo test -p rsync-winfs --all-features windows_attributes`.
- [ ] Commit: `feat: restore safe ntfs file attributes`

### Task 16: Copy Alternate Data Stream Payloads in NTFS-Native Local Sync

**Files:**
- Modify: `crates/rsync-winfs/src/streams.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] Add Windows-only stream read/write helpers.
- [ ] Copy ADS payloads only when `--metadata-policy=ntfs-native` is explicit.
- [ ] Keep cross-platform behavior as "not available" rather than failure.
- [ ] Add tests for one named stream and for default data stream exclusion.
- [ ] Run `cargo test -p rsync-winfs --all-features streams`.
- [ ] Commit: `feat: copy ntfs alternate stream payloads`

### Task 17: Keep VSS Explicitly Rejected Until Snapshot Reads Exist

**Files:**
- Modify: `crates/rsync-winfs/src/vss.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] Add tests ensuring `--vss --fail-on-metadata-loss` errors while snapshot reads are unavailable.
- [ ] Add a design note for the eventual VSS source abstraction before implementing any Win32/VSS calls.
- [ ] Do not introduce a partial VSS API that suggests locked-file consistency.
- [ ] Run `cargo test --workspace --all-features vss`.
- [ ] Commit: `test: keep vss rejection explicit`

## Chunk 6: Phase 9 Release Hardening and v1.0 Gate

### Task 18: Add Security Regression Fixtures

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Create: `tests/security/remote_peer.rs` if integration separation is useful

- [ ] Add fixtures for parent escape, absolute paths, Windows reserved names, trailing dots/spaces, Unicode normalization collisions, backslashes, excessive file counts, excessive path lengths, oversized literal streams, short literal streams, and checksum mismatch.
- [ ] Verify failed transfers remove temp receive files.
- [ ] Run `cargo test --workspace --all-features security`.
- [ ] Commit: `test: add remote peer security regressions`

### Task 19: Define and Measure Memory Bounds

**Files:**
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-fs/benches/local_sync.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] Document current file-list entry/path limits.
- [ ] Add benchmark cases for large ordinary files and many small files.
- [ ] Add a stress test that proves large file data streams through bounded buffers.
- [ ] Do not claim full incremental recursion until file-list memory use is bounded by design, not only by count limits.
- [ ] Run `cargo bench -p rsync-fs --bench local_sync`.
- [ ] Commit: `bench: expand local sync performance coverage`

### Task 20: Package Smoke Test

**Files:**
- Modify: `scripts/package-release.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `README.md`

- [ ] After packaging, run the packaged `rsync-win.exe --version`.
- [ ] Verify the zip contains `rsync-win.exe`, license files, README, third-party notices, and compatibility matrix.
- [ ] Verify SHA-256 checksum format in CI.
- [ ] Add release notes template with honest capability status.
- [ ] Run `.\scripts\package-release.ps1 -Tag v0.1.5 -SkipBuild` only after a release binary exists.
- [ ] Commit: `ci: smoke test release package`

## Go/No-Go Order

1. Do Chunk 1 before new feature work. Current remote-shell behavior is broad enough that hardening drift is the highest risk.
2. Do Chunk 2 before Phase 6 if remote-shell remains the primary user path for the next release.
3. Do Chunk 3 before claiming `v0.5-daemon`.
4. Do Chunk 4 before claiming `v0.6-posix-meta`.
5. Do Chunk 5 before claiming `v0.7-ntfs`.
6. Do Chunk 6 before any `v1.0` language.

## Verification Matrix

Run these before each milestone tag:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
cargo bench -p rsync-fs --bench local_sync
```

Run these when external fixtures are configured:

```powershell
$env:RSYNC_WIN_SSH_TARGET = "user@host"
cargo test -p rsync-cli --test interop_discovery --all-features -- --nocapture
```

For daemon work, add a controlled daemon fixture and run:

```powershell
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

