# Phase 5 Remote Checksum Metadata Links Append Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the remaining remote-shell Phase 5 options that require protocol support: `--checksum`, remote metadata/link routing, and remote push `--append-verify`.

**Architecture:** Add checksum-aware protocol file-list codecs, then wire CLI remote push/pull through checksum-capable flist reads/writes. Route link and metadata options according to which side is the rsync sender/receiver; implement sender-side link following locally, pass receiver-side chmod/numeric options to upstream rsync where the existing file-list metadata can support it, and keep unsupported preservation semantics explicit.

**Tech Stack:** Rust std I/O, existing `rsync-protocol` protocol 31 file-list implementation, `rsync-cli` remote-shell protocol 31 session, upstream rsync 3.2.7 SSH interop fixture.

---

## Task 1: Checksum File-List Support

**Files:**
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Add optional 16-byte whole-file checksum storage to `RsyncFileListEntry`.
- [x] Make protocol 31/27 file-list readers optionally consume sender checksums.
- [x] Make file-list writers optionally emit local sender checksums for `--checksum`.
- [x] Use plain MD4 whole-file checksums for protocol 31 `md4` negotiation.

## Task 2: Remote Checksum Execution

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/session.rs`

- [x] Add `--checksum` to remote `--server` argv only where protocol support exists.
- [x] For remote pull, skip local downloads when the remote flist checksum matches the local receiver file.
- [x] For remote push, include sender file checksums in the flist so the upstream receiver can quick-check by checksum.

## Task 3: Remote Metadata and Link Options

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/session.rs`

- [x] Implement remote push sender-side `--copy-links` / `--copy-unsafe-links` by following eligible local symlinks before writing the flist.
- [x] Route remote pull sender-side link options to upstream rsync.
- [x] Route receiver-side `--numeric-ids` and `--chmod` to upstream rsync when the receiver is remote.
- [x] Keep unsupported Windows-side metadata application reported through diagnostics.

## Task 4: Remote Push Append Verify

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/session.rs`

- [x] Allow remote push `--append-verify`.
- [x] Do not combine upstream `--append-verify` with `--whole-file`.
- [x] Verify the sender literal-token path satisfies receiver append requests.

## Task 5: Verification

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`

- [x] Add unit tests for checksum flist round-trip and option routing.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --workspace --all-features -- -D warnings`.
- [x] Run `cargo test --workspace --all-features`.
- [x] Run real SSH interop for checksum pull/push, link routing, chmod routing, and append-verify push; clean remote/local test files.
