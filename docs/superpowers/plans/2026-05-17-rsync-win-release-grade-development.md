# Rsync-Win Release-Grade Development Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `rsync-win` from a verified preview build to a release-grade Windows rsync-compatible distribution with mandatory interoperability evidence, honest option status, hardened remote handling, and auditable packaging.

**Architecture:** Keep the current Rust workspace and crate boundaries. Strengthen release gates first, then close remote-shell, daemon, metadata, security, performance, and packaging gaps in separate slices so every phase is independently testable.

**Tech Stack:** Rust 2021, Cargo workspace, Windows MSVC toolchain, PowerShell release scripts, GitHub Actions, upstream rsync over SSH, upstream rsync daemon fixtures, NTFS Windows test hosts.

---

## Current Evidence Snapshot

These commands passed locally on 2026-05-17:

```powershell
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
.\scripts\package-release.ps1 -Tag v0.2.0
```

The packaged executable reported:

```text
rsync-win 0.2.0
protocol primitives range: 20-32
transfer execution: local portable sync supported; remote-shell MVP tries protocol 31 first with protocol 27 compatibility fallback
```

The release package contained:

```text
docs/COMPATIBILITY.md
docs/OPTION-STATUS.md
docs/RELEASE-NOTES-TEMPLATE.md
LICENSE
LICENSE-APACHE
LICENSE-MIT
README.md
rsync-win.exe
THIRD-PARTY-NOTICES.md
```

The `rsync_compat` external tests passed only because all external peer fixtures skipped cleanly when environment variables were absent. Release-grade work starts by making those skips visible and then forbidden in release mode.

## Target File Structure

Create or modify the following files across the plan.

### Documentation and Status

- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/RELEASE-NOTES-TEMPLATE.md`
- Modify: `docs/DEVELOPMENT-GUIDE.md`
- Create: `docs/RELEASE-CHECKLIST.md`

### Fixture and Release Gates

- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `scripts/package-release.ps1`
- Create: `scripts/run-release-interop.ps1`
- Create: `scripts/write-release-fixture-report.ps1`
- Modify: `tests/common/mod.rs`
- Modify: `tests/compat/release_readiness.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/interop/daemon.rs`

### Remote-Shell Completion

- Modify: `crates/rsync-cli/src/plan/diagnostics.rs`
- Modify: `crates/rsync-cli/src/plan/remote_args.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-cli/src/remote/pull.rs`
- Modify: `crates/rsync-cli/src/remote/flist.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/stress/large_tree.rs`

### Daemon Completion

- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-cli/src/daemon_server/mod.rs`
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `tests/interop/daemon.rs`
- Modify: `scripts/package-release.ps1`

### Metadata and Windows Native Fidelity

- Modify: `crates/rsync-cli/src/execute/local.rs`
- Modify: `crates/rsync-cli/src/execute/remote_shell.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-winfs/src/metadata.rs`
- Modify: `crates/rsync-winfs/src/security.rs`
- Modify: `crates/rsync-winfs/src/streams.rs`
- Modify: `crates/rsync-winfs/src/vss.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/stress/large_file.rs`

### Security, Fuzzing, and Performance

- Modify: `tests/security/remote_peer.rs`
- Modify: `tests/stress/large_file.rs`
- Modify: `tests/stress/large_tree.rs`
- Create: `tests/fuzz/README.md`
- Create: `tests/fuzz/rsync_protocol_fuzz.rs`
- Modify: `crates/rsync-fs/benches/local_sync.rs`
- Modify: `crates/rsync-cli/benches/remote_protocol.rs`

### Packaging

- Modify: `scripts/package-release.ps1`
- Create: `scripts/sign-release.ps1`
- Create: `scripts/generate-sbom.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `THIRD-PARTY-NOTICES.md`

---

### Task 1: Reposition Current Release Status

**Files:**
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/RELEASE-NOTES-TEMPLATE.md`
- Create: `docs/RELEASE-CHECKLIST.md`
- Modify: `tests/compat/release_readiness.rs`

- [ ] **Step 1: Update public positioning**

Change release wording from production-ready to preview/experimental where the current implementation is still partial. Keep the local sync claims but make remote and daemon wording match `docs/COMPATIBILITY.md`.

Required replacement text for `README.md` status paragraph:

```markdown
This is a preview compatibility release. Version `v0.2.0` maps to Cargo package version `0.2.0` and focuses on ordinary files, directories, explicit metadata degradation, local Windows portable sync, experimental remote-shell push/pull, experimental daemon client/server workflows, streaming file data, POSIX metadata request reporting, and a narrow NTFS-native sidecar restore path.
```

- [ ] **Step 2: Add release-grade definition**

Add this section to `docs/COMPATIBILITY.md` after the support matrix:

```markdown
## Release-Grade Definition

A release-grade Windows rsync-compatible build requires mandatory upstream rsync interop fixtures, no skipped release interop gates, signed and checksummed artifacts, documented option status, and explicit metadata degradation behavior. Preview builds may ship with experimental remote-shell or daemon support only when the README and release notes identify those limits.
```

- [ ] **Step 3: Add release checklist document**

Create `docs/RELEASE-CHECKLIST.md` with:

```markdown
# Release Checklist

## Required Local Gates

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `cargo test -p rsync-cli --test options --all-features`
- `cargo test -p rsync-cli --test security_remote_peer --all-features`
- `.\scripts\package-release.ps1 -Tag <tag>`

## Required External Gates For Release-Grade Builds

- Linux upstream rsync over SSH push and pull.
- Linux upstream rsync daemon module listing, no-auth pull, authenticated pull, auth failure, writable push, and read-only rejection.
- Protocol 27 fallback peer or an explicitly documented waiver.
- At least one non-Linux peer probe from macOS, openrsync, Cygwin, or MSYS2.

## Artifact Requirements

- `rsync-win.exe`
- License files.
- Third-party notices.
- Compatibility matrix.
- Option status table.
- Release notes.
- SHA-256 checksum.
- Code signature for release-grade builds.
- SBOM or dependency inventory for release-grade builds.
```

- [ ] **Step 4: Extend release readiness tests**

Add assertions in `tests/compat/release_readiness.rs`:

```rust
#[test]
fn docs_define_preview_and_release_grade_terms() {
    let readme = read_repo_file("README.md");
    let compatibility = read_repo_file("docs/COMPATIBILITY.md");
    let checklist = read_repo_file("docs/RELEASE-CHECKLIST.md");

    assert!(readme.contains("preview compatibility release"));
    assert!(compatibility.contains("Release-Grade Definition"));
    assert!(checklist.contains("Required External Gates For Release-Grade Builds"));
    assert!(checklist.contains("Code signature for release-grade builds"));
}
```

- [ ] **Step 5: Verify status docs**

Run:

```powershell
cargo fmt --all -- --check
cargo test -p rsync-cli --test release_readiness --all-features
```

Expected: tests pass and docs no longer overstate current remote/daemon maturity.

- [ ] **Step 6: Commit**

```powershell
git add README.md docs/COMPATIBILITY.md docs/OPTION-STATUS.md docs/RELEASE-NOTES-TEMPLATE.md docs/RELEASE-CHECKLIST.md tests/compat/release_readiness.rs
git commit -m "docs: define preview and release-grade status"
```

---

### Task 2: Make External Fixture Skips Fail In Release Mode

**Files:**
- Modify: `tests/common/mod.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/interop/daemon.rs`
- Create: `scripts/run-release-interop.ps1`
- Create: `scripts/write-release-fixture-report.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `tests/compat/release_readiness.rs`

- [ ] **Step 1: Add release-required fixture helper**

In `tests/common/mod.rs`, add:

```rust
pub fn release_interop_required() -> bool {
    std::env::var("RSYNC_WIN_RELEASE_INTEROP_REQUIRED")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub fn skip_or_fail_external_test(name: &str, reason: Option<&str>) -> bool {
    let detail = reason.unwrap_or("external fixture is not configured");
    if release_interop_required() {
        panic!("release interop fixture `{name}` is required but unavailable: {detail}");
    }
    skip_external_test(name, Some(detail));
    true
}
```

- [ ] **Step 2: Replace clean skips in interop tests**

In `tests/interop/rsync_compat.rs` and `tests/interop/daemon.rs`, replace direct missing-fixture branches with `skip_or_fail_external_test`. Example:

```rust
if env::var(SSH_TARGET_ENV).ok().filter(|value| !value.trim().is_empty()).is_none() {
    skip_or_fail_external_test(
        "upstream rsync SSH interop",
        Some("set RSYNC_WIN_SSH_TARGET=user@host"),
    );
    return None;
}
```

- [ ] **Step 3: Add release interop runner**

Create `scripts/run-release-interop.ps1`:

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$env:RSYNC_WIN_RELEASE_INTEROP_REQUIRED = "1"

cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

- [ ] **Step 4: Add fixture report script**

Create `scripts/write-release-fixture-report.ps1`:

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$vars = @(
    "RSYNC_WIN_SSH_TARGET",
    "RSYNC_WIN_SSH_PROTOCOL27_TARGET",
    "RSYNC_WIN_MACOS_RSYNC_TARGET",
    "RSYNC_WIN_OPENRSYNC_TARGET",
    "RSYNC_WIN_CYGWIN_TARGET",
    "RSYNC_WIN_MSYS2_TARGET",
    "RSYNC_WIN_DAEMON_URL",
    "RSYNC_WIN_DAEMON_MODULE",
    "RSYNC_WIN_DAEMON_AUTH_MODULE",
    "RSYNC_WIN_DAEMON_WRITABLE_MODULE",
    "RSYNC_WIN_DAEMON_USER",
    "RSYNC_WIN_DAEMON_PASSWORD_FILE"
)

$lines = @("# Release Fixture Report", "")
foreach ($name in $vars) {
    $value = [Environment]::GetEnvironmentVariable($name)
    $state = if ([string]::IsNullOrWhiteSpace($value)) { "missing" } else { "configured" }
    $lines += "- ${name}: ${state}"
}

$lines | Set-Content -Path $OutputPath -Encoding utf8
```

- [ ] **Step 5: Wire release workflow**

In `.github/workflows/release.yml`, add a release interop step before build:

```yaml
      - name: Release interop fixtures
        shell: pwsh
        run: |
          .\scripts\write-release-fixture-report.ps1 -OutputPath dist\release-fixtures.md
          .\scripts\run-release-interop.ps1
```

- [ ] **Step 6: Test release-required failure locally**

Run without fixture variables:

```powershell
$env:RSYNC_WIN_RELEASE_INTEROP_REQUIRED = "1"
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
```

Expected: test command fails with a message naming the missing fixture. Then remove the variable:

```powershell
Remove-Item Env:\RSYNC_WIN_RELEASE_INTEROP_REQUIRED
```

- [ ] **Step 7: Verify normal skip behavior still works**

```powershell
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

Expected: external tests pass or skip when release-required mode is off.

- [ ] **Step 8: Commit**

```powershell
git add tests/common/mod.rs tests/interop/rsync_compat.rs tests/interop/daemon.rs scripts/run-release-interop.ps1 scripts/write-release-fixture-report.ps1 .github/workflows/release.yml tests/compat/release_readiness.rs
git commit -m "test: require external interop fixtures for release"
```

---

### Task 3: Update Upstream Rsync Compatibility Matrix

**Files:**
- Modify: `docs/COMPATIBILITY.md`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `scripts/write-release-fixture-report.ps1`
- Modify: `tests/compat/release_readiness.rs`

- [ ] **Step 1: Record peer versions during tests**

Add helper in `tests/interop/rsync_compat.rs`:

```rust
fn remote_rsync_version(ssh: &Path, target: &str) -> String {
    let output = remote_command_output(ssh, target, "rsync --version | head -n 1");
    assert_command_success("remote rsync version", &output);
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}
```

Call it at the start of SSH matrix tests and include the version string in assertion failure messages.

- [ ] **Step 2: Add explicit 3.4.x target language**

Update `docs/COMPATIBILITY.md` release matrix:

```markdown
| Upstream rsync versions | upstream rsync 3.4.x and 3.2.x over SSH are the release-grade interop targets; protocol 27 fallback remains best-effort unless a protocol 27 fixture is configured. |
```

- [ ] **Step 3: Add runtime peer version values to the fixture report**

Extend `scripts/write-release-fixture-report.ps1` to run `ssh $env:RSYNC_WIN_SSH_TARGET "rsync --version | head -n 1"` when `RSYNC_WIN_SSH_TARGET` is configured. Write the captured line into the report.

- [ ] **Step 4: Add release readiness assertions**

Add:

```rust
#[test]
fn compatibility_matrix_names_current_upstream_targets() {
    let compatibility = read_repo_file("docs/COMPATIBILITY.md");
    assert!(compatibility.contains("upstream rsync 3.4.x"));
    assert!(compatibility.contains("upstream rsync 3.2.x"));
    assert!(compatibility.contains("protocol 27 fallback"));
}
```

- [ ] **Step 5: Verify**

```powershell
cargo test -p rsync-cli --test release_readiness --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
```

Expected: release readiness passes; interop tests pass or skip outside release-required mode.

- [ ] **Step 6: Commit**

```powershell
git add docs/COMPATIBILITY.md tests/interop/rsync_compat.rs scripts/write-release-fixture-report.ps1 tests/compat/release_readiness.rs
git commit -m "docs: update upstream rsync compatibility targets"
```

---

### Task 4: Support Remote Push `--delete` With `--files-from`

**Files:**
- Modify: `crates/rsync-cli/src/plan/diagnostics.rs`
- Modify: `crates/rsync-cli/src/plan/remote_args.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `crates/rsync-cli/src/app/tests/remote.rs`

- [ ] **Step 1: Write planning regression test**

Add to `crates/rsync-cli/src/app/tests/remote.rs`:

```rust
#[test]
fn remote_push_delete_with_files_from_is_planned_for_receiver_scope() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-rt",
        "--delete",
        "--files-from=list.txt",
        "src/",
        "host:/dest/",
    ]);

    assert!(output.contains("remote direction: upload"));
    assert!(output.contains("files-from: list.txt"));
    assert!(!output.contains("remote-shell push does not yet support --delete together with --files-from"));
}
```

- [ ] **Step 2: Run the test and confirm current failure**

```powershell
cargo test -p rsync-cli remote_push_delete_with_files_from_is_planned_for_receiver_scope --all-features
```

Expected before implementation: failure because the existing diagnostic rejects this combination.

- [ ] **Step 3: Remove the hard rejection**

Delete this check from `ensure_remote_execution_options_supported` in `crates/rsync-cli/src/plan/diagnostics.rs`:

```rust
if plan.remote_direction == Some(TransferDirection::Push)
    && cli.delete
    && cli.files_from.is_some()
{
    bail!(
        "remote-shell push does not yet support --delete together with --files-from because receiver-side files-from semantics are not implemented"
    );
}
```

- [ ] **Step 4: Route files-from to receiver protection args**

In `crates/rsync-cli/src/plan/remote_args.rs`, ensure remote push receiver args include the files-from list restriction when delete is active. Use sender-side filter rules to protect receiver paths outside the selected list. The resulting remote server argv must include delete mode and filter protection arguments.

- [ ] **Step 5: Apply sender selection before remote file-list streaming**

In `crates/rsync-cli/src/remote/push.rs`, ensure the local file-list builder receives `load_files_from(cli)` selection and emits only selected entries while preserving required parent directories.

- [ ] **Step 6: Add upstream manifest case**

Add a push case in `tests/interop/rsync_compat.rs`:

```rust
PushManifestCase {
    name: "push-delete-files-from",
    win_options: vec![
        "-rt".to_string(),
        "--delete".to_string(),
        "--files-from".to_string(),
        push_files_from_arg.clone(),
    ],
    upstream_options: vec![
        "-rt".to_string(),
        "--delete".to_string(),
        format!("--files-from={remote_push_files_from}"),
    ],
    win_sources: vec![local_source_arg.clone()],
    upstream_sources: vec![remote_source_arg.clone()],
    prepopulate: vec![
        ("stale.txt", "delete-me"),
        ("drop.tmp", "receiver-protected"),
    ],
}
```

- [ ] **Step 7: Verify**

```powershell
cargo test -p rsync-cli remote_push_delete_with_files_from_is_planned_for_receiver_scope --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test --workspace --all-features
```

Expected: local tests pass; external interop passes when fixture exists or skips outside release-required mode.

- [ ] **Step 8: Commit**

```powershell
git add crates/rsync-cli/src/plan/diagnostics.rs crates/rsync-cli/src/plan/remote_args.rs crates/rsync-cli/src/remote/push.rs crates/rsync-cli/src/app/tests/remote.rs tests/interop/rsync_compat.rs
git commit -m "feat(remote): support push delete with files-from"
```

---

### Task 5: Implement Sender-Side Incremental Recursion For Remote Push

**Files:**
- Modify: `crates/rsync-cli/src/plan/mod.rs`
- Modify: `crates/rsync-cli/src/plan/remote_args.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `tests/stress/large_tree.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: Add stress test for push without forced `--no-inc-recursive`**

In `tests/stress/large_tree.rs`, add a test that builds a large local tree and asserts protocol 31 push can stream multiple file-list batches with incremental recursion enabled.

Test shape:

```rust
#[test]
fn protocol31_push_incremental_recursion_streams_batches_when_enabled() {
    let temp = FixtureTempDir::new("rsync-win-inc-recursive-push").unwrap();
    let source = temp.path().join("source");
    create_many_small_files(&source, 2_000).unwrap();

    let args = [
        "rsync-win",
        "--plan",
        "-r",
        "--inc-recursive",
        source.to_string_lossy().as_ref(),
        "host:/dest/",
    ];
    let output = rsync_cli::parse_and_render(args);

    assert!(output.contains("incremental recursion: true"));
    assert!(!output.contains("--no-inc-recursive"));
}
```

- [ ] **Step 2: Run the test and confirm current failure**

```powershell
cargo test -p rsync-cli protocol31_push_incremental_recursion_streams_batches_when_enabled --all-features
```

Expected before implementation: failure because push still forces `--no-inc-recursive`.

- [ ] **Step 3: Update remote argv generation**

In `crates/rsync-cli/src/plan/remote_args.rs`, stop adding `--no-inc-recursive` for protocol 31 push when `plan.incremental_recursion` is true.

- [ ] **Step 4: Stream sender file-list batches in push session**

In `crates/rsync-cli/src/remote/push.rs`, keep the existing bounded batch writer and emit incremental file-list markers between batches using `rsync-protocol` helpers. Ensure indexes remain stable across batches.

- [ ] **Step 5: Add protocol file-list writer coverage**

In `crates/rsync-protocol/src/flist.rs`, add or extend tests so streamed protocol 31 batches round-trip with the same final file-list entries as a single encoded list.

- [ ] **Step 6: Add upstream interop case**

In `tests/interop/rsync_compat.rs`, add a push manifest case using `--inc-recursive` with a nested fixture tree. Compare remote manifests against upstream rsync.

- [ ] **Step 7: Update docs**

Remove the known limitation line in `docs/COMPATIBILITY.md` that says full upstream sender-side incremental recursion for remote-shell push is not implemented. Replace it with the tested scope and remaining size limits.

- [ ] **Step 8: Verify**

```powershell
cargo test -p rsync-cli --test large_tree --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
```

Expected: push incremental recursion works in local stress tests and upstream fixture when configured.

- [ ] **Step 9: Commit**

```powershell
git add crates/rsync-cli/src/plan crates/rsync-cli/src/remote/push.rs crates/rsync-protocol/src/flist.rs tests/stress/large_tree.rs tests/interop/rsync_compat.rs docs/COMPATIBILITY.md
git commit -m "feat(remote): stream incremental push file lists"
```

---

### Task 6: Expand Remote And Daemon POSIX Metadata Support

**Files:**
- Modify: `crates/rsync-cli/src/plan/diagnostics.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-cli/src/remote/flist.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/interop/daemon.rs`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`

- [ ] **Step 1: Write rejection-to-support regression tests**

Add tests that prove `--metadata-policy=posix --perms --executability --chmod=F755` can run for remote upload plans and daemon upload plans.

Expected assertions:

```rust
assert!(!output.contains("remote-shell MVP currently supports only --metadata-policy=portable"));
assert!(output.contains("metadata policy: posix"));
assert!(output.contains("posix metadata:"));
```

- [ ] **Step 2: Run tests and confirm current failure**

```powershell
cargo test -p rsync-cli metadata_policy_posix --all-features
```

Expected before implementation: failure due to existing portable-only execution gate.

- [ ] **Step 3: Relax execution gates for supported POSIX subset**

In `ensure_remote_execution_options_supported` and `ensure_daemon_execution_options_supported`, allow `CliMetadataPolicy::Posix` for upload paths when the requested metadata features are supported by protocol payload generation.

Keep `CliMetadataPolicy::NtfsNative` rejected for remote and daemon paths.

- [ ] **Step 4: Encode POSIX mode payloads**

Ensure `remote/push.rs` and `remote/flist.rs` apply:

- `--perms`
- `--executability`
- `--chmod`
- `--numeric-ids`
- `--usermap`
- `--groupmap`
- `--chown`

to outgoing file-list mode and id metadata where the protocol supports it.

- [ ] **Step 5: Keep unsupported POSIX metadata explicit**

For ACL/xattr/fake-super payloads that are not fully restored by a peer path, keep diagnostics explicit. Do not mark them fully implemented in `docs/OPTION-STATUS.md` until interop tests prove behavior.

- [ ] **Step 6: Add upstream interop case**

In `tests/interop/rsync_compat.rs`, add an SSH push case comparing file mode manifests with upstream rsync for executable script names and `--chmod=F755,D755`.

- [ ] **Step 7: Add daemon metadata fixture case**

In `tests/interop/daemon.rs`, add a local daemon-server upload with POSIX metadata options and assert the transfer succeeds without claiming NTFS fidelity.

- [ ] **Step 8: Update docs**

Update `docs/COMPATIBILITY.md` to distinguish:

- POSIX mode and chmod upload supported in remote/daemon upload paths.
- POSIX owner/group mapping represented where protocol and peer accept it.
- POSIX ACL/xattr/fake-super remain reporting or sidecar unless tested end-to-end.

- [ ] **Step 9: Verify**

```powershell
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
```

- [ ] **Step 10: Commit**

```powershell
git add crates/rsync-cli/src/plan/diagnostics.rs crates/rsync-cli/src/remote crates/rsync-cli/src/execute/daemon_client.rs crates/rsync-protocol/src/flist.rs tests/interop docs/COMPATIBILITY.md docs/OPTION-STATUS.md
git commit -m "feat(metadata): support POSIX upload metadata subset"
```

---

### Task 7: Harden NTFS-Native Local Fidelity

**Files:**
- Modify: `crates/rsync-cli/src/execute/local.rs`
- Modify: `crates/rsync-winfs/src/metadata.rs`
- Modify: `crates/rsync-winfs/src/security.rs`
- Modify: `crates/rsync-winfs/src/streams.rs`
- Modify: `crates/rsync-winfs/src/vss.rs`
- Modify: `tests/stress/large_file.rs`
- Modify: `docs/VSS-DESIGN.md`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: Add NTFS fixture capability report**

Add a Windows-only helper in `crates/rsync-winfs/src/metadata.rs` that reports whether the current process can create symlinks, read/write SDDL, enumerate ADS, set sparse ranges, and create VSS snapshots.

Public crate API:

```rust
pub struct WindowsCapabilityReport {
    pub symlinks: bool,
    pub security_descriptors: bool,
    pub alternate_streams: bool,
    pub sparse_ranges: bool,
    pub vss_snapshots: bool,
}

pub fn windows_capability_report() -> WindowsCapabilityReport
```

- [ ] **Step 2: Add tests for capability reporting**

Add tests in `crates/rsync-winfs/src/metadata.rs` asserting the helper returns deterministic booleans and does not panic on non-Windows platforms.

- [ ] **Step 3: Add end-to-end NTFS-native fixture**

In `tests/stress/large_file.rs` or a new `tests/interop/ntfs_native.rs`, create a local test that writes:

- creation time
- readonly/hidden/archive/system safe attributes
- named ADS
- sparse file with holes
- security descriptor when elevated

Then run:

```powershell
rsync-win --metadata-policy ntfs-native --super --sparse -rt <source> <dest>
```

Assert supported fields are restored and unsupported fields are counted as degraded.

- [ ] **Step 4: Add VSS behavior gate**

Add a test that runs `--metadata-policy ntfs-native --vss --dry-run` without creating a snapshot and a separate opt-in elevated test for real snapshot creation. The dry-run test must pass everywhere; the real VSS test must skip outside a dedicated opt-in environment variable:

```text
RSYNC_WIN_ENABLE_VSS_INTEGRATION=1
```

- [ ] **Step 5: Update docs**

Update `docs/VSS-DESIGN.md` and `docs/COMPATIBILITY.md` with exact privilege and environment requirements for real VSS verification.

- [ ] **Step 6: Verify**

```powershell
cargo test -p rsync-winfs --all-features
cargo test -p rsync-cli --test large_file --all-features
cargo test --workspace --all-features
```

- [ ] **Step 7: Commit**

```powershell
git add crates/rsync-cli/src/execute/local.rs crates/rsync-winfs/src tests/stress/large_file.rs docs/VSS-DESIGN.md docs/COMPATIBILITY.md
git commit -m "test(ntfs): harden native metadata fidelity"
```

---

### Task 8: Add Protocol Fuzz And Security Gates

**Files:**
- Create: `tests/fuzz/README.md`
- Create: `tests/fuzz/rsync_protocol_fuzz.rs`
- Modify: `tests/security/remote_peer.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: Add fuzz documentation**

Create `tests/fuzz/README.md`:

````markdown
# Fuzz Targets

These fuzz targets exercise protocol parsers and remote-peer hardening code with arbitrary byte streams. They are not a replacement for deterministic security regressions in `tests/security`.

Run short local fuzz smoke:

```powershell
cargo test --test rsync_protocol_fuzz -- --ignored
```
````

- [ ] **Step 2: Add deterministic fuzz smoke test**

Create `tests/fuzz/rsync_protocol_fuzz.rs` as a Cargo integration test wired through `rsync-cli` or `rsync-protocol`. The test should feed fixed pseudo-random byte slices into file-list and token readers and assert errors are returned without panic.

Core pattern:

```rust
#[test]
#[ignore = "fuzz smoke is run explicitly in hardening jobs"]
fn malformed_protocol_inputs_do_not_panic() {
    let inputs = [
        vec![],
        vec![0xff; 1],
        vec![0xff; 1024],
        (0..4096).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
    ];

    for input in inputs {
        let _ = std::panic::catch_unwind(|| {
            let mut cursor = std::io::Cursor::new(input);
            let _ = rsync_protocol::flist::read_rsync31_file_list(&mut cursor);
        })
        .expect("protocol parser must not panic on malformed input");
    }
}
```

- [ ] **Step 3: Extend security regressions**

In `tests/security/remote_peer.rs`, add cases for:

- compressed token corruption
- ACL payload with invalid index
- xattr payload with oversized length
- multiplex frame with unsupported tag during final goodbye

- [ ] **Step 4: Add CI hardening step**

In `.github/workflows/ci.yml`, add after security tests:

```yaml
      - name: Fuzz smoke
        run: cargo test -p rsync-cli --test rsync_protocol_fuzz --all-features -- --ignored
```

- [ ] **Step 5: Verify**

```powershell
cargo test -p rsync-cli --test security_remote_peer --all-features
cargo test -p rsync-cli --test rsync_protocol_fuzz --all-features -- --ignored
cargo test --workspace --all-features
```

- [ ] **Step 6: Commit**

```powershell
git add tests/fuzz tests/security/remote_peer.rs .github/workflows/ci.yml docs/COMPATIBILITY.md
git commit -m "test(security): add protocol fuzz smoke gate"
```

---

### Task 9: Add Performance And Memory Release Gates

**Files:**
- Modify: `tests/stress/large_file.rs`
- Modify: `tests/stress/large_tree.rs`
- Modify: `crates/rsync-fs/benches/local_sync.rs`
- Modify: `crates/rsync-cli/benches/remote_protocol.rs`
- Create: `scripts/run-release-benchmarks.ps1`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/RELEASE-CHECKLIST.md`

- [ ] **Step 1: Add benchmark runner**

Create `scripts/run-release-benchmarks.ps1`:

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$env:RSYNC_WIN_BENCH_ITERS = "1"
cargo bench -p rsync-fs --bench local_sync
cargo bench -p rsync-cli --bench remote_protocol
```

- [ ] **Step 2: Add memory budget assertions**

Extend `tests/stress/large_tree.rs` to assert file-list batching does not build a single encoded buffer for 100,000 entries. Keep the existing max allocation checks and add a regression name that mentions release memory budget.

- [ ] **Step 3: Add benchmark baseline section**

Update `docs/COMPATIBILITY.md` benchmark baseline after running the benchmark script on the release machine. Include:

- date
- CPU
- storage type
- Windows version
- command
- elapsed values

- [ ] **Step 4: Update release checklist**

Add:

```markdown
## Required Benchmark Record

- `cargo bench -p rsync-fs --bench local_sync`
- `cargo bench -p rsync-cli --bench remote_protocol`
- Benchmark machine description.
- Max tested file size.
- Max tested file count.
```

- [ ] **Step 5: Verify**

```powershell
cargo test -p rsync-cli --test large_tree --all-features
cargo test -p rsync-cli --test large_file --all-features
.\scripts\run-release-benchmarks.ps1
```

- [ ] **Step 6: Commit**

```powershell
git add tests/stress crates/rsync-fs/benches crates/rsync-cli/benches scripts/run-release-benchmarks.ps1 docs/COMPATIBILITY.md docs/RELEASE-CHECKLIST.md
git commit -m "test(perf): add release benchmark gates"
```

---

### Task 10: Add Signing, SBOM, And Artifact Audit

**Files:**
- Modify: `scripts/package-release.ps1`
- Create: `scripts/sign-release.ps1`
- Create: `scripts/generate-sbom.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `THIRD-PARTY-NOTICES.md`
- Modify: `tests/compat/release_readiness.rs`
- Modify: `docs/RELEASE-CHECKLIST.md`

- [ ] **Step 1: Add signing script**

Create `scripts/sign-release.ps1`:

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Binary not found: $BinaryPath"
}

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    throw "signtool.exe is required for release-grade signing"
}

& $signtool.Source sign /fd SHA256 /tr $TimestampServer /td SHA256 $BinaryPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool signing failed for $BinaryPath"
}
```

- [ ] **Step 2: Add SBOM script**

Create `scripts/generate-sbom.ps1`:

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$metadata = cargo metadata --format-version 1 | ConvertFrom-Json
$packages = $metadata.packages | Sort-Object name, version
$lines = @("# rsync-win Dependency Inventory", "")
foreach ($package in $packages) {
    $license = if ($package.license) { $package.license } else { "NOASSERTION" }
    $lines += "- $($package.name) $($package.version) - $license"
}
$lines | Set-Content -Path $OutputPath -Encoding utf8
```

- [ ] **Step 3: Include SBOM in package**

Update `scripts/package-release.ps1` to generate and include:

```text
docs/DEPENDENCY-INVENTORY.md
```

Add it to `$expectedPackageFiles`.

- [ ] **Step 4: Add release signing workflow**

In `.github/workflows/release.yml`, add a signing step before packaging when a signing certificate is configured. If no certificate is configured for preview builds, release workflow must label artifacts as unsigned preview builds in release notes.

- [ ] **Step 5: Add readiness assertions**

In `tests/compat/release_readiness.rs`, assert the scripts and package list mention:

```rust
assert!(script.contains("DEPENDENCY-INVENTORY.md"));
assert!(release.contains("sign-release.ps1") || release.contains("unsigned preview"));
```

- [ ] **Step 6: Verify**

```powershell
cargo test -p rsync-cli --test release_readiness --all-features
.\scripts\generate-sbom.ps1 -OutputPath dist\DEPENDENCY-INVENTORY.md
.\scripts\package-release.ps1 -Tag v0.2.0
```

- [ ] **Step 7: Commit**

```powershell
git add scripts/package-release.ps1 scripts/sign-release.ps1 scripts/generate-sbom.ps1 .github/workflows/release.yml THIRD-PARTY-NOTICES.md tests/compat/release_readiness.rs docs/RELEASE-CHECKLIST.md
git commit -m "build(release): add signing and dependency inventory"
```

---

### Task 11: Final Release-Grade Audit

**Files:**
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/RELEASE-NOTES-TEMPLATE.md`
- Modify: `docs/RELEASE-CHECKLIST.md`

- [ ] **Step 1: Audit option status against registry**

Run:

```powershell
cargo test -p rsync-cli --test options --all-features -- --nocapture
```

Expected: every option status category in `docs/OPTION-STATUS.md` matches the parser registry and execution reality.

- [ ] **Step 2: Audit compatibility claims**

For every row in `docs/COMPATIBILITY.md`, identify one of:

- unit test
- integration test
- external fixture test
- release script gate
- documented limitation

Update text where no evidence exists.

- [ ] **Step 3: Run all release gates**

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
.\scripts\run-release-interop.ps1
.\scripts\run-release-benchmarks.ps1
.\scripts\package-release.ps1 -Tag v1.0.0
```

Expected: every command passes on the release machine with required external fixtures configured.

- [ ] **Step 4: Verify release artifact contents**

```powershell
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path "dist\rsync-win-v1.0.0-x86_64-pc-windows-msvc.zip"))
try {
    $entries = $zip.Entries | ForEach-Object { $_.FullName } | Sort-Object
    $entries
} finally {
    $zip.Dispose()
}
```

Expected entries include executable, licenses, notices, compatibility docs, option table, release notes, and dependency inventory.

- [ ] **Step 5: Record final go/no-go**

Update `docs/RELEASE-CHECKLIST.md` with a checked release section for the candidate tag. Include:

- command outputs summarized by pass/fail
- external fixture versions
- benchmark baseline
- package checksum
- signing status

- [ ] **Step 6: Commit final audit**

```powershell
git add README.md docs/COMPATIBILITY.md docs/OPTION-STATUS.md docs/RELEASE-NOTES-TEMPLATE.md docs/RELEASE-CHECKLIST.md
git commit -m "docs: record release-grade audit"
```

---

## Recommended Execution Order

1. Task 1: fix status language and release definition.
2. Task 2: make external fixture skips fail in release mode.
3. Task 3: update upstream rsync compatibility targets.
4. Task 4: close `--delete + --files-from` remote push gap.
5. Task 5: implement sender-side incremental recursion for remote push.
6. Task 6: expand POSIX metadata support for remote and daemon upload paths.
7. Task 7: harden NTFS-native local fidelity.
8. Task 8: add fuzz and security gates.
9. Task 9: add performance and memory release gates.
10. Task 10: add signing, SBOM, and artifact audit.
11. Task 11: run final release-grade audit.

## Completion Criteria

The project is ready to call itself a release-grade Windows rsync-compatible distribution only when all are true:

- README uses release-grade wording only for builds with mandatory external interop evidence.
- `RSYNC_WIN_RELEASE_INTEROP_REQUIRED=1` makes missing external fixtures fail.
- Linux upstream rsync 3.4.x and 3.2.x SSH push/pull matrix passes.
- Upstream rsync daemon module list, no-auth pull, auth pull, bad password, writable push, and read-only rejection pass.
- Remote push supports `--delete + --files-from`.
- Remote push supports sender-side incremental recursion or the feature is explicitly disabled with a release-blocking note.
- `--metadata-policy=posix` has tested remote/daemon upload behavior for the supported metadata subset.
- `--metadata-policy=ntfs-native` local fidelity tests cover creation time, safe Windows attributes, named ADS, sparse ranges, security descriptor restore, and VSS dry-run behavior.
- Security tests cover malicious path, malformed file-list, corrupt token stream, unsupported mux tags, and oversized metadata payloads.
- Benchmark baselines are recorded for large file, large tree, filter-heavy, and delete-heavy workloads.
- Release package includes executable, licenses, notices, compatibility docs, option status, release notes, dependency inventory, checksum, and signing status.
- `cargo fmt --all -- --check` passes.
- `cargo clippy --workspace --all-features -- -D warnings` passes.
- `cargo test --workspace --all-features` passes.
- `.\scripts\run-release-interop.ps1` passes on the release fixture environment.
- `.\scripts\package-release.ps1 -Tag <tag>` passes and verifies the staged binary.
