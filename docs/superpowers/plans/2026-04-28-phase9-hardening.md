# Phase 9 Hardening Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the phase 9 release-hardening gaps that are practical in the current codebase: malicious peer defenses, bounded streaming checks, release packaging, benchmarks, and a user-facing compatibility matrix.

**Architecture:** Keep protocol validation in `rsync-protocol` and remote execution guards in `rsync-cli`. Keep local streaming behavior inside `rsync-fs`, add benchmark coverage without extra dependencies, and document compatibility separately from the README so release users can audit support quickly.

**Tech Stack:** Rust workspace, std IO, existing rsync protocol helpers, PowerShell packaging script, Markdown docs.

---

## Task 1: Remote Receive Hardening

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Add a file-token receive limit tied to the advertised file-list length.
- [x] Reject literal token streams that exceed or undershoot the advertised file length.
- [x] Preserve existing streaming behavior and temporary-file cleanup.
- [x] Add protocol-level errors that clearly identify the malicious or corrupt peer behavior.

## Task 2: Security Regression Tests

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Add tests for remote pull file-list paths that attempt `..` destination escape.
- [x] Add tests for remote pull token streams that send more bytes than advertised.
- [x] Add tests for remote pull token streams that end before the advertised length.
- [x] Verify these failures happen before destination mutation.

## Task 3: Benchmark Suite

**Files:**
- Modify: `crates/rsync-fs/Cargo.toml`
- Create: `crates/rsync-fs/benches/local_sync.rs`

- [x] Add a dependency-free `cargo bench -p rsync-fs --bench local_sync` target.
- [x] Benchmark local recursive copy planning/execution with small generated fixture data.
- [x] Keep generated data small enough for CI and local developer machines.

## Task 4: Release Packaging Script

**Files:**
- Create: `scripts/package-release.ps1`
- Modify: `.github/workflows/release.yml`

- [x] Move zip/checksum packaging logic into a reusable PowerShell script.
- [x] Keep the GitHub release workflow behavior equivalent.
- [x] Validate the script can build or package an existing release binary.

## Task 5: Compatibility Matrix and Roadmap Status

**Files:**
- Create: `docs/COMPATIBILITY.md`
- Modify: `README.md`
- Modify: `docs/ROADMAP.md`

- [x] Document Linux rsync, macOS/Homebrew rsync, macOS stock/openrsync, daemon mode, and Windows metadata modes.
- [x] Document phase 9 hardening status and remaining known limitations honestly.
- [x] Link the compatibility matrix from the README.

## Task 6: Verification

**Files:**
- No production edits expected unless verification finds defects.

- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo test --workspace --all-features`.
- [x] Run `cargo clippy --workspace --all-features -- -D warnings`.
- [x] Run `cargo bench -p rsync-fs --bench local_sync`.
- [x] If reachable, run a small SSH interop smoke test against `root@10.11.11.7:/root/rsync-test` and remove transferred test files.
