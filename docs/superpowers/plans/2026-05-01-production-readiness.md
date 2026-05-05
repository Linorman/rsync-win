# rsync-win Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `rsync-win` from an experimental ordinary-file rsync-compatible tool to a production-grade Windows rsync implementation for common local, SSH, and daemon workflows.

**Architecture:** Stabilize the current Rust workspace by turning broad option parsing into tested behavior, separating transfer runtime controls from protocol logic, and making large-tree/large-file paths memory-bounded. Production readiness is gated by real upstream rsync interop, Windows metadata fidelity tests, security regressions, and release packaging checks.

**Tech Stack:** Rust 1.76+ workspace, Windows MSVC toolchain, upstream `rsync` 3.2.x over SSH, local Windows filesystem APIs, PowerShell release scripts, Cargo test/clippy/fmt, optional Linux daemon fixtures.

---

## Production Definition

The project should be considered production-ready only when these gates pass on a clean branch:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture` with `RSYNC_WIN_SSH_TARGET` set to an upstream Linux rsync 3.2.x host
- `cargo test -p rsync-cli --test daemon --all-features -- --nocapture` with a controlled daemon fixture
- release package smoke tests from `scripts/package-release.ps1`
- documented large-tree and large-file stress runs with bounded memory
- no known silent metadata loss in documented supported modes

## Current Baseline

- Local ordinary-file sync is useful and well tested for recursion, deletion, filters, mtimes, update modes, and multiple sources.
- Remote-shell protocol 31 ordinary-file push/pull works against upstream Linux rsync in smoke tests.
- Daemon mode has tested local module listing/pull/push and limited external fixture coverage.
- Metadata support is explicit but incomplete: POSIX and NTFS-native modes report or sidecar many things instead of fully restoring them.
- Production blockers remain: clippy failure in `crates/rsync-cli/src/lib.rs`, memory-bound remote delta gaps, no incremental recursion, incomplete daemon auth/config, no VSS reads, incomplete NTFS restore, limited cross-peer matrix, and broad option statuses that overstate behavior.

---

## File Structure Map

Core runtime and CLI:

- Modify: `crates/rsync-cli/src/lib.rs` - planning, local execution, remote-shell execution, daemon client execution.
- Modify: `crates/rsync-cli/src/options.rs` - option registry and parser behavior/status classification.
- Modify: `crates/rsync-cli/src/output.rs` - diagnostics, stats, itemized output, progress output.
- Modify: `tests/compat/options.rs` - option parsing/status and behavior matrix.

Filesystem and metadata:

- Modify: `crates/rsync-fs/src/sync.rs` - local sync orchestration.
- Modify: `crates/rsync-fs/src/walk.rs` - local filesystem IO, streaming, preallocation, sparse files.
- Modify: `crates/rsync-winfs/src/metadata.rs` - Windows attributes, identity, security summaries.
- Modify: `crates/rsync-winfs/src/security.rs` - security descriptor capture/restore helpers.
- Modify: `crates/rsync-winfs/src/streams.rs` - alternate data stream copy/restore.
- Modify: `crates/rsync-winfs/src/links.rs` - symlink, hardlink, reparse point behavior.
- Modify: `crates/rsync-winfs/src/vss.rs` - VSS snapshot source abstraction.
- Modify: `crates/rsync-winfs/src/sidecar.rs` - NTFS/POSIX sidecar schemas.

Protocol and transport:

- Modify: `crates/rsync-protocol/src/session.rs` - remote-shell argv, negotiation, multiplexing, compression/checksum setup.
- Modify: `crates/rsync-protocol/src/flist.rs` - file-list encoding/decoding, incremental recursion primitives, safety limits.
- Modify: `crates/rsync-protocol/src/daemon.rs` - daemon greeting/auth/module behavior.
- Modify: `crates/rsync-protocol/src/io.rs` - bounded readers/writers and wire primitives.
- Modify: `crates/rsync-transport/src/bandwidth.rs` - shared rate limiter.
- Modify: `crates/rsync-transport/src/process.rs` - SSH child process lifecycle and stderr handling.
- Modify: `crates/rsync-transport/src/tcp.rs` - daemon TCP/proxy/connect-program behavior.

Interop, security, and release:

- Modify: `tests/interop/rsync_compat.rs` - upstream SSH matrix.
- Modify: `tests/interop/daemon.rs` - upstream daemon matrix.
- Modify: `tests/security/remote_peer.rs` - malicious peer and path hardening regressions.
- Create: `tests/stress/large_tree.rs` - large-tree bounded-memory regression tests.
- Create: `tests/stress/large_file.rs` - large-file streaming regression tests.
- Modify: `scripts/package-release.ps1` - release gates and smoke tests.
- Modify: `docs/COMPATIBILITY.md` - honest production support matrix.
- Modify: `docs/OPTION-STATUS.md` - option behavior status, not just parser status.
- Modify: `README.md` - production usage guidance and limitations.

---

## Chunk 1: Release Hygiene and Honest Status

### Task 1.1: Restore clean CI gates

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: existing workspace tests

- [ ] **Step 1: Reproduce clippy failure**

Run:

```powershell
cargo clippy --workspace --all-features -- -D warnings
```

Expected: FAIL on `clippy::too_many_arguments` for `serve_remote_receiver_requests` and `write_delta_tokens_from_path`.

- [ ] **Step 2: Extract runtime context structs**

Add small internal structs near the remote execution helpers:

```rust
struct RemoteTransferRuntime<'a> {
    compression: Option<&'a RemoteCompressionConfig>,
    progress: ProgressLog,
    max_alloc: Option<u64>,
    stop_deadline: Option<Instant>,
}

struct DeltaWriteRuntime<'a> {
    compression: Option<&'a RemoteCompressionConfig>,
    progress: Option<&'a mut FileProgress>,
    max_alloc: Option<u64>,
    stop_deadline: Option<Instant>,
}
```

Replace long parameter lists with these contexts. Keep behavior unchanged.

- [ ] **Step 3: Run targeted compile check**

Run:

```powershell
cargo check -p rsync-cli --all-features
```

Expected: PASS.

- [ ] **Step 4: Run full gates**

Run:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-cli/src/lib.rs
git commit -m "refactor: keep remote transfer helpers lint-clean"
```

### Task 1.2: Split option status into parser, planned, and execution support

**Files:**
- Modify: `crates/rsync-cli/src/options.rs`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `tests/compat/options.rs`

- [ ] **Step 1: Add status model test**

Add tests that prove options such as `--iconv`, `--compress-threads`, `--copy-as`, and `--early-input` cannot be marked as fully implemented unless they have verified execution behavior in each applicable mode.

- [ ] **Step 2: Introduce support levels**

Use explicit levels in the registry:

```rust
enum OptionSupport {
    Full,
    Partial,
    DiagnosticOnly,
    ParsedOnly,
    Planned,
}
```

Map old `implemented` entries into the new model conservatively.

- [ ] **Step 3: Regenerate or update docs**

Update `docs/OPTION-STATUS.md` to separate:

- Fully implemented
- Partially implemented by mode
- Diagnostic/reporting only
- Parsed for compatibility only
- Planned

- [ ] **Step 4: Verify**

Run:

```powershell
cargo test -p rsync-cli --test options --all-features
```

Expected: PASS, with tests asserting that partial options are not advertised as full upstream compatibility.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-cli/src/options.rs docs/OPTION-STATUS.md tests/compat/options.rs
git commit -m "docs: classify rsync options by execution support"
```

---

## Chunk 2: Memory-Bounded Transfer Engine

### Task 2.1: Remove whole-file reads from remote delta sender paths

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-delta/src/matcher.rs` if streaming matcher support is needed
- Test: `tests/stress/large_file.rs`

- [ ] **Step 1: Write failing stress test**

Create `tests/stress/large_file.rs` with a test that pushes and pulls a file larger than the configured `--max-alloc` while using `--whole-file` and a second test for non-whole-file delta mode.

Run:

```powershell
cargo test -p rsync-cli --test large_file --all-features -- --nocapture
```

Expected: FAIL or OOM-risk path identified because `read_local_file_limited` still returns `Vec<u8>` for delta generation.

- [ ] **Step 2: Stream literal token generation**

Keep whole-file literal token writing on `File`/`Read` streams. Ensure `write_literal_tokens_from_reader_with_checksum` enforces `stop_deadline` and bounded buffers.

- [ ] **Step 3: Replace delta full-buffer matching**

Implement a memory-bounded block matcher path:

- receiver basis signatures remain bounded by block metadata
- sender scans source with a fixed window
- literal spans are flushed incrementally
- final checksum is updated while scanning

- [ ] **Step 4: Verify max allocation behavior**

Run:

```powershell
cargo test -p rsync-cli --test large_file --all-features
cargo test --workspace --all-features
```

Expected: PASS; large files transfer with memory bounded by buffers and signature table, not full file size.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-cli/src/lib.rs crates/rsync-delta/src/matcher.rs tests/stress/large_file.rs
git commit -m "feat: stream remote delta token generation"
```

### Task 2.2: Define and enforce memory budgets

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-fs/src/walk.rs`
- Test: `tests/stress/large_tree.rs`

- [ ] **Step 1: Add tests for `--max-alloc`**

Test local copy, remote push, remote pull, file-list receive, and basis checksum paths with a low `--max-alloc`.

- [ ] **Step 2: Add allocation accounting**

Introduce a shared allocation budget helper for file-list entries, path buffers, signature tables, and transfer buffers.

- [ ] **Step 3: Fail early with clear diagnostics**

Return rsync-like resource errors before mutation when estimated metadata or signature memory exceeds budget.

- [ ] **Step 4: Verify**

Run:

```powershell
cargo test -p rsync-cli --test large_tree --all-features
cargo test --workspace --all-features
```

Expected: PASS; tests prove bounded memory and clean preflight failures.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-cli/src/lib.rs crates/rsync-protocol/src/flist.rs crates/rsync-fs/src/walk.rs tests/stress/large_tree.rs
git commit -m "feat: enforce transfer memory budgets"
```

---

## Chunk 3: Incremental Recursion and Large Trees

### Task 3.1: Implement sender-side incremental file-list batches

**Files:**
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `tests/stress/large_tree.rs`

- [ ] **Step 1: Write protocol batch tests**

Add tests that encode/decode multiple file-list batches and preserve directory ordering.

- [ ] **Step 2: Add internal batch representation**

Represent remote file-list batches as:

```rust
struct FileListBatch {
    base_index: usize,
    entries: Vec<RsyncFileListEntry>,
    is_final: bool,
}
```

- [ ] **Step 3: Route local walker into batches**

Emit batches from local traversal instead of requiring a complete tree before transfer.

- [ ] **Step 4: Verify against synthetic large tree**

Run:

```powershell
cargo test -p rsync-cli --test large_tree --all-features -- --nocapture
```

Expected: PASS for a tree over 100,000 entries without increasing memory linearly beyond the configured window.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-protocol/src/flist.rs crates/rsync-protocol/src/session.rs crates/rsync-cli/src/lib.rs tests/stress/large_tree.rs
git commit -m "feat: send incremental file-list batches"
```

### Task 3.2: Implement receiver-side incremental writes and deletes

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-fs/src/sync.rs`
- Test: `tests/stress/large_tree.rs`

- [ ] **Step 1: Add delete timing tests with batches**

Cover `--delete-before`, `--delete-during`, `--delete-delay`, `--delete-after`, and protected filter behavior when file-list entries arrive incrementally.

- [ ] **Step 2: Add receiver state machine**

Track pending directories, pending deletes, and completed file indexes without requiring all entries at once.

- [ ] **Step 3: Preserve destination safety**

Keep path validation, case collision checks, Unicode normalization checks, and destination escape checks before writes.

- [ ] **Step 4: Verify**

Run:

```powershell
cargo test -p rsync-cli --test large_tree --all-features
cargo test --workspace --all-features
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-cli/src/lib.rs crates/rsync-fs/src/sync.rs tests/stress/large_tree.rs
git commit -m "feat: receive large trees incrementally"
```

---

## Chunk 4: Remote-Shell Interop Hardening

### Task 4.1: Expand upstream rsync SSH matrix

**Files:**
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: Add command-family fixtures**

Cover:

- `-a --no-o --no-g`
- `-rt --delete --exclude`
- `--files-from`
- `--checksum`
- `--partial --partial-dir`
- `--inplace`
- `--append-verify`
- `--compress --compress-choice=zlibx`
- multiple source operands
- remote source names with spaces and Unicode

- [ ] **Step 2: Compare manifests with upstream rsync**

For each fixture, run upstream rsync on the Linux host into a parallel destination and compare file content, mtimes, mode bits where supported, and delete results.

- [ ] **Step 3: Verify**

Run:

```powershell
$env:RSYNC_WIN_SSH_TARGET = "root@192.168.100.181"
$env:RSYNC_WIN_SSH_TMP_ROOT = "/root/rsync-test"
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
```

Expected: PASS; all remote temp dirs are removed after each test.

- [ ] **Step 4: Commit**

```powershell
git add tests/interop/rsync_compat.rs docs/COMPATIBILITY.md
git commit -m "test: expand upstream ssh rsync compatibility matrix"
```

### Task 4.2: Harden SSH process lifecycle and failure behavior

**Files:**
- Modify: `crates/rsync-transport/src/process.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `tests/security/remote_peer.rs`

- [ ] **Step 1: Add failure tests**

Cover remote command not found, auth failure, remote stderr noise, early EOF, hung remote process, unsupported protocol, checksum mismatch, and local cancellation/timeout.

- [ ] **Step 2: Implement deterministic cleanup**

Ensure partial files, temp files, child stdin/stdout/stderr handles, and remote transport state are closed predictably.

- [ ] **Step 3: Verify exit codes**

Ensure errors map to rsync-like exit codes in `crates/rsync-cli/src/output.rs`.

- [ ] **Step 4: Verify**

Run:

```powershell
cargo test -p rsync-cli --test security_remote_peer --all-features
cargo test --workspace --all-features
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-transport/src/process.rs crates/rsync-cli/src/lib.rs crates/rsync-cli/src/output.rs tests/security/remote_peer.rs
git commit -m "fix: harden remote shell failure handling"
```

---

## Chunk 5: Daemon Production Support

### Task 5.1: Implement daemon server auth users and secrets file

**Files:**
- Modify: `crates/rsync-cli/src/daemon_server.rs`
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `tests/interop/daemon.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: Add failing daemon auth tests**

Cover:

- valid user/password
- invalid password
- missing user
- read-only module
- writable module with auth
- secrets file permissions warning on Windows

- [ ] **Step 2: Parse safe config subset**

Support `auth users`, `secrets file`, `read only`, `write only`, `list`, `uid`, `gid` as documented safe behavior or explicit diagnostics where Windows cannot apply them.

- [ ] **Step 3: Implement challenge-response**

Use the existing daemon digest helpers and never log password material or full secrets paths.

- [ ] **Step 4: Verify**

Run:

```powershell
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-cli/src/daemon_server.rs crates/rsync-protocol/src/daemon.rs tests/interop/daemon.rs docs/COMPATIBILITY.md
git commit -m "feat: support daemon auth users and secrets files"
```

### Task 5.2: Add upstream daemon fixture parity

**Files:**
- Modify: `tests/interop/daemon.rs`
- Modify: `scripts/package-release.ps1`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: Add external daemon fixture tests**

Support environment variables:

- `RSYNC_WIN_DAEMON_URL`
- `RSYNC_WIN_DAEMON_MODULE`
- `RSYNC_WIN_DAEMON_WRITABLE_MODULE`
- `RSYNC_WIN_DAEMON_USER`
- `RSYNC_WIN_DAEMON_PASSWORD_FILE`

- [ ] **Step 2: Test no-auth and auth flows**

Cover module listing, pull, push, auth failure, read-only rejection, timeout, `--no-motd`, `--bwlimit`, `--sockopts`, and proxy/connect-program where feasible.

- [ ] **Step 3: Verify**

Run:

```powershell
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

Expected: PASS with configured daemon fixture; skipped cleanly when missing.

- [ ] **Step 4: Commit**

```powershell
git add tests/interop/daemon.rs scripts/package-release.ps1 docs/COMPATIBILITY.md
git commit -m "test: add upstream daemon parity fixtures"
```

---

## Chunk 6: Windows Metadata and Filesystem Fidelity

### Task 6.1: Define supported metadata contract

**Files:**
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `README.md`
- Test: `tests/compat/options.rs`

- [ ] **Step 1: Write documentation tests or assertions**

Add tests that ensure `--metadata-policy=portable`, `posix`, and `ntfs-native` produce clear diagnostics for every unsupported metadata class.

- [ ] **Step 2: Document supported metadata by mode**

For each mode, state whether the project applies, stores in sidecar, reports only, rejects, or ignores:

- POSIX mode bits
- owner/group
- ACLs
- xattrs
- symlinks
- hardlinks
- mtimes/atimes/crtimes
- Windows attributes
- ADS
- security descriptors
- sparse ranges
- reparse points
- VSS

- [ ] **Step 3: Verify**

Run:

```powershell
cargo test -p rsync-cli --test options --all-features
```

Expected: PASS.

- [ ] **Step 4: Commit**

```powershell
git add docs/COMPATIBILITY.md docs/OPTION-STATUS.md README.md tests/compat/options.rs
git commit -m "docs: define metadata support contract"
```

### Task 6.2: Implement NTFS-native restore set

**Files:**
- Modify: `crates/rsync-winfs/src/metadata.rs`
- Modify: `crates/rsync-winfs/src/security.rs`
- Modify: `crates/rsync-winfs/src/streams.rs`
- Modify: `crates/rsync-winfs/src/links.rs`
- Modify: `crates/rsync-winfs/src/sidecar.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] **Step 1: Add Windows-only integration tests**

Cover readonly/hidden/archive/system attributes, creation time, ADS payloads, hardlinks, safe symlinks when capability is present, and security descriptor restore when elevated.

- [ ] **Step 2: Implement restore capabilities one at a time**

Recommended order:

1. creation time
2. attributes
3. ADS payloads for files
4. hardlink groups
5. safe symlink/reparse handling
6. security descriptor restore behind explicit elevated mode
7. sparse range preservation

- [ ] **Step 3: Keep explicit degradation**

When a capability is unavailable, emit a warning or fail with `--fail-on-metadata-loss`.

- [ ] **Step 4: Verify**

Run:

```powershell
cargo test -p rsync-winfs --all-features
cargo test -p rsync-cli --all-features local_ntfs -- --nocapture
```

Expected: PASS on non-elevated tests; elevated-only tests skip cleanly when permissions are unavailable.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-winfs crates/rsync-cli/src/lib.rs
git commit -m "feat: restore documented ntfs-native metadata"
```

### Task 6.3: Add VSS snapshot read support

**Files:**
- Modify: `crates/rsync-winfs/src/vss.rs`
- Modify: `crates/rsync-fs/src/walk.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `docs/VSS-DESIGN.md`

- [ ] **Step 1: Add source abstraction test**

Write tests proving local sync can read through a source abstraction rather than directly from live paths.

- [ ] **Step 2: Implement VSS provider behind explicit `--vss`**

Create snapshots only when `--metadata-policy=ntfs-native --vss` is explicit. Do not enable VSS by default.

- [ ] **Step 3: Add cleanup and failure tests**

Cover snapshot creation failure, locked-file read success, cancellation cleanup, and non-admin diagnostics.

- [ ] **Step 4: Verify**

Run elevated Windows tests:

```powershell
cargo test -p rsync-winfs --all-features vss -- --nocapture
cargo test -p rsync-cli --all-features vss -- --nocapture
```

Expected: PASS when elevated; clear SKIP/diagnostic when not elevated.

- [ ] **Step 5: Commit**

```powershell
git add crates/rsync-winfs/src/vss.rs crates/rsync-fs/src/walk.rs crates/rsync-cli/src/lib.rs docs/VSS-DESIGN.md
git commit -m "feat: read sources through explicit vss snapshots"
```

---

## Chunk 7: Security Hardening

### Task 7.1: Expand malicious peer tests

**Files:**
- Modify: `tests/security/remote_peer.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] **Step 1: Add malicious file-list cases**

Cover parent escapes, absolute paths, Windows prefixes, reserved names, trailing dots/spaces, Unicode normalization collisions, case collisions, symlink escapes, hardlink escapes, oversized paths, oversized counts, malformed varints, corrupt compressed tokens, and token length mismatches.

- [ ] **Step 2: Verify all fail before mutation**

Use temporary destinations with sentinel files and assert no writes occur on rejection.

- [ ] **Step 3: Verify**

Run:

```powershell
cargo test -p rsync-cli --test security_remote_peer --all-features
```

Expected: PASS.

- [ ] **Step 4: Commit**

```powershell
git add tests/security/remote_peer.rs crates/rsync-protocol/src/flist.rs crates/rsync-cli/src/lib.rs
git commit -m "test: expand malicious peer hardening matrix"
```

### Task 7.2: Add safe temp/finalize guarantees

**Files:**
- Modify: `crates/rsync-fs/src/walk.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `tests/security/remote_peer.rs`

- [ ] **Step 1: Add interruption tests**

Simulate checksum mismatch, short literal stream, timeout, and write failure. Assert final destination remains old content and temp files are removed.

- [ ] **Step 2: Make temp files isolated**

Ensure temp roots are destination-local, collision-resistant, and never follow untrusted links.

- [ ] **Step 3: Verify**

Run:

```powershell
cargo test --workspace --all-features
```

Expected: PASS.

- [ ] **Step 4: Commit**

```powershell
git add crates/rsync-fs/src/walk.rs crates/rsync-cli/src/lib.rs tests/security/remote_peer.rs
git commit -m "fix: preserve receiver state on failed transfers"
```

---

## Chunk 8: Performance and Observability

### Task 8.1: Add benchmarks for production workloads

**Files:**
- Modify: `crates/rsync-fs/benches/local_sync.rs`
- Create: `crates/rsync-cli/benches/remote_protocol.rs`
- Modify: `Cargo.toml` or crate `Cargo.toml` files if bench targets are needed

- [ ] **Step 1: Add benchmark scenarios**

Cover:

- 10,000 small files
- 100,000 empty files
- 1 GiB ordinary file
- small edits in a large file
- filters with many rules
- delete-heavy receiver tree

- [ ] **Step 2: Record baseline**

Run:

```powershell
cargo bench -p rsync-fs --bench local_sync
cargo bench -p rsync-cli --bench remote_protocol
```

Expected: benchmarks complete and record throughput/memory notes in `docs/COMPATIBILITY.md`.

- [ ] **Step 3: Commit**

```powershell
git add crates/rsync-fs/benches/local_sync.rs crates/rsync-cli/benches/remote_protocol.rs Cargo.toml
git commit -m "bench: add production workload benchmarks"
```

### Task 8.2: Make logs production-useful

**Files:**
- Modify: `crates/rsync-cli/src/output.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `README.md`

- [ ] **Step 1: Add output snapshot tests**

Cover quiet mode, verbose mode, progress, itemized changes, stats, log-file, log-file-format, and machine-readable summaries.

- [ ] **Step 2: Stabilize output contract**

Document what scripts can parse and what is human-only.

- [ ] **Step 3: Verify**

Run:

```powershell
cargo test -p rsync-cli --all-features output
cargo test -p rsync-cli --test options --all-features
```

Expected: PASS.

- [ ] **Step 4: Commit**

```powershell
git add crates/rsync-cli/src/output.rs crates/rsync-cli/src/lib.rs README.md
git commit -m "feat: stabilize production logging output"
```

---

## Chunk 9: Release Packaging and Operational Readiness

### Task 9.1: Strengthen release script gates

**Files:**
- Modify: `scripts/package-release.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `README.md`

- [ ] **Step 1: Add packaging tests**

The release script must run:

- `rsync-win.exe --version`
- `rsync-win.exe --help`
- local sync smoke
- local delete/filter smoke
- optional SSH smoke when env vars are set
- docs presence check
- SHA-256 checksum generation
- zip layout validation

- [ ] **Step 2: Add CI matrix**

Run Windows stable Rust, minimum supported Rust, and optional nightly lint if useful.

- [ ] **Step 3: Verify**

Run:

```powershell
.\scripts\package-release.ps1 -Tag v0.1.5-local
```

Expected: release zip and `.sha256` are created and smoke checks pass.

- [ ] **Step 4: Commit**

```powershell
git add scripts/package-release.ps1 .github/workflows/ci.yml .github/workflows/release.yml README.md
git commit -m "build: strengthen release package gates"
```

### Task 9.2: Produce production readiness release candidate

**Files:**
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/RELEASE-NOTES-TEMPLATE.md`
- Modify: `README.md`

- [ ] **Step 1: Freeze supported matrix**

Document supported:

- Windows versions
- filesystem types
- upstream rsync versions
- daemon modes
- metadata modes
- max tested file size
- max tested file count

- [ ] **Step 2: Run full release candidate verification**

Run:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
$env:RSYNC_WIN_SSH_TARGET = "root@192.168.100.181"
$env:RSYNC_WIN_SSH_TMP_ROOT = "/root/rsync-test"
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
.\scripts\package-release.ps1 -Tag v0.2.0-rc1
```

Expected: all PASS; remote test directories are cleaned.

- [ ] **Step 3: Commit**

```powershell
git add docs/COMPATIBILITY.md docs/OPTION-STATUS.md docs/RELEASE-NOTES-TEMPLATE.md README.md
git commit -m "docs: prepare production readiness release candidate"
```

---

## Milestone Sequence

1. **M0: Clean branch and honest docs** - Chunks 1.1 and 1.2. Required before any release.
2. **M1: Reliable ordinary-file production use** - Chunks 2, 3, 4, 7, 8. Suitable for local and SSH ordinary-file workflows.
3. **M2: Daemon production use** - Chunk 5. Suitable for controlled rsync daemon environments.
4. **M3: Windows backup-grade metadata** - Chunk 6. Required before advertising NTFS-native backup fidelity.
5. **M4: Release candidate** - Chunk 9. Produces a documented production-readiness build.

## Go/No-Go Rules

- Do not call an option fully implemented unless execution behavior is tested in every documented supported mode.
- Do not advertise production remote-shell support until upstream rsync fixture tests cover push, pull, delete, filters, checksum, compression, append, partial, and multiple sources.
- Do not advertise large-tree support until incremental recursion or an equivalent bounded-memory design is implemented and measured.
- Do not advertise NTFS-native backup support until restore behavior is implemented, tested, and documented for each metadata class.
- Do not enable destructive behavior by default in tests unless destination escape and failed-transfer rollback tests are passing.
- Do not ship a release candidate while clippy, packaging smoke tests, or external interop cleanup checks fail.
