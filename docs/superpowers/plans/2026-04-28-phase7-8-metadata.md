# Phase 7-8 Metadata Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add verifiable POSIX metadata compatibility reporting and an NTFS-native metadata sidecar prototype without misrepresenting Windows fidelity.

**Architecture:** Extend the existing metadata policy/reporting model in `rsync-core`, keep portable sync behavior in `rsync-fs`, and add Windows-specific metadata capture modules in `rsync-winfs`. Wire CLI options through `rsync-cli` so users can request POSIX or NTFS behavior and receive applied/degraded/rejected diagnostics.

**Tech Stack:** Rust workspace, `clap`, existing filesystem abstraction, Windows APIs through `windows-sys` where available, focused unit tests.

---

## Task 1: POSIX Metadata Request Model

**Files:**
- Modify: `crates/rsync-core/src/lib.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Add explicit POSIX metadata features for permissions, owner, group, `--executability`, symlink mtime, ACL, xattr, and fake-super storage.
- [x] Add CLI flags `-p/--perms`, `-o/--owner`, `-g/--group`, `--executability`, `--acls`, `--xattrs`, `--fake-super`, and `--omit-link-times`.
- [x] Render requested POSIX metadata details in `--plan`.
- [x] Add tests proving requests produce applied/degraded/rejected diagnostics and `--fail-on-metadata-loss` upgrades losses to errors.

## Task 2: POSIX Mode and Executability Mapping

**Files:**
- Modify: `crates/rsync-fs/src/metadata.rs`
- Modify: `crates/rsync-fs/src/walk.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Add helpers to infer POSIX mode-like bits from portable metadata and executable filename conventions on Windows.
- [x] Preserve the current remote file list behavior while using the inferred mode for local sender entries.
- [x] Add unit tests for executable extension mapping and non-executable defaults.

## Task 3: NTFS Native Sidecar Prototype

**Files:**
- Modify: `crates/rsync-winfs/src/lib.rs`
- Create: `crates/rsync-winfs/src/security.rs`
- Create: `crates/rsync-winfs/src/streams.rs`
- Create: `crates/rsync-winfs/src/vss.rs`
- Modify: `crates/rsync-winfs/src/metadata.rs`

- [x] Add `NtfsNativeSidecar` with security descriptor hash/status, alternate data stream summaries, sparse/reparse/attribute metadata, and VSS source status.
- [x] Implement safe non-Windows stubs and Windows best-effort collection for attributes and stream discovery.
- [x] Add tests for sidecar serialization shape and missing/empty stream behavior.

## Task 4: CLI Reporting and Documentation

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `README.md`
- Modify: `docs/ROADMAP.md`

- [x] Show POSIX and NTFS policy capability details in plan/execution output.
- [x] Document phase 7/8 prototype status and unsupported/degraded behavior.
- [x] Add tests for `ntfs-native` plan output and fake-super reporting.

## Task 5: Verification

**Files:**
- No production edits expected unless verification finds defects.

- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo test --workspace`.
- [x] Run `cargo clippy --workspace --all-features -- -D warnings`.
- [x] If reachable, run a small SSH interop smoke test against `root@10.11.11.7:/root/rsync-test` and remove transferred test files.
