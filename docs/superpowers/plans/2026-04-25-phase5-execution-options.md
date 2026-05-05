# Phase 5 Execution Options Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Phase 5 daily-workflow option surface that can be implemented safely on the current ordinary-file protocol path.

**Architecture:** Extend the portable filesystem write abstraction first, then route local sync and remote pull receiver writes through the same implementation. Pass only receiver-relevant options to remote rsync on push, and keep protocol-dependent or metadata-dependent options rejected with explicit diagnostics.

**Tech Stack:** Rust std filesystem APIs, existing `rsync-fs` sync planner, existing `rsync-cli` protocol 31 remote-shell path, upstream rsync SSH interop fixture.

---

## Task 1: Local Receiver Write Modes

**Files:**
- Modify: `crates/rsync-fs/src/walk.rs`
- Modify: `crates/rsync-fs/src/sync.rs`

- [x] Add atomic, in-place, partial-preserving, and partial-dir write options.
- [x] Add append support for `--append-verify`.
- [x] Preserve existing atomic-write behavior by default.

## Task 2: Local Phase 5 CLI Workflows

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Execute local `--partial`, `--partial-dir`, `--inplace`, and `--append-verify`.
- [x] Execute local file-symlink `--copy-links` and unsafe-link filtering behavior for `--safe-links` / `--copy-unsafe-links`.
- [x] Add `--itemize-changes` / `-i` and `--stats` output.
- [x] Keep POSIX owner/group/chmod metadata loss explicit instead of silently claiming fidelity.

## Task 3: Remote Phase 5 Boundary

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/session.rs`

- [x] Support remote pull `--size-only` / `--ignore-times` through local request selection.
- [x] Support remote pull `--partial`, `--partial-dir`, `--inplace`, and `--append-verify` on the local receiver path without passing receiver-only flags to the remote sender.
- [x] Pass remote push `--size-only`, `--ignore-times`, `--partial`, `--partial-dir`, and `--inplace` to the upstream receiver.
- [x] Reject remote push `--append-verify` until append receiver protocol handling is implemented.
- [x] Continue rejecting remote `--checksum`, POSIX metadata, and link metadata options until the file-list/protocol metadata support exists.

## Task 4: Verification

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-fs/src/sync.rs`

- [x] Add unit tests for local append/in-place/link behavior.
- [x] Add CLI tests for itemized stats and remote receiver-only option routing.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --workspace --all-features -- -D warnings`.
- [x] Run `cargo test --workspace --all-features`.
- [x] Run real SSH interop against `root@192.168.100.181:/root/demo_win_rsync/` and clean test files.
