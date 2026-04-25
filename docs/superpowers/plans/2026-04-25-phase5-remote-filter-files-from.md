# Phase 5 Remote Filter and Files-From Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the Phase 5 compatibility surface by making remote-shell transfers honor include/exclude/filter and files-from selections for the ordinary-file protocol 31 path.

**Architecture:** Reuse the existing `rsync-filter` rule parser and local `files-from` parser in the CLI remote path. Filter local push file lists before sending, filter remote pull file lists before requesting files, and protect local deletes during pull; keep remote push `--delete` with filters rejected until receiver-side filter protection is implemented.

**Tech Stack:** Rust std I/O, `rsync-filter`, existing `rsync-cli` remote-shell protocol 31 implementation, existing OpenSSH interop fixture.

---

## Task 1: Remote Planning Guard

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Allow `--include`, `--exclude`, `--filter`, `--files-from`, and `--from0` through the remote execution guard.
- [x] Keep rejecting remote push `--delete` with filters/files-from because receiver-side delete protection is not implemented.
- [x] Keep rejecting checksum, partial, inplace, append, numeric-id, chmod, and link options for remote-shell execution.

## Task 2: Remote Sender Selection

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Load `--files-from` for remote execution.
- [x] Apply filter rules and files-from selection when collecting local push entries.
- [x] Preserve parent directory entries needed by selected files.

## Task 3: Remote Pull Selection and Delete Protection

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Filter protocol 27 and protocol 31 pull file lists before requesting files.
- [x] Preserve the remote top directory and required parent directories.
- [x] Protect excluded or files-from-unselected local receiver paths during `--delete`.

## Task 4: Tests and Interop

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Add unit tests for remote push filters and remote pull delete protection.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --workspace --all-features -- -D warnings`.
- [x] Run `cargo test --workspace --all-features`.
- [x] Manually verify filtered remote push/pull against `root@192.168.100.181:/root/demo_win_rsync/` and clean test files.
