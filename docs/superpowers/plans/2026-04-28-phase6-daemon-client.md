# Phase 6 Daemon Client Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add rsync daemon client support for `host::module` and `rsync://host/module` operands.

**Architecture:** Keep daemon setup in `rsync-protocol::daemon`, use the existing blocking TCP transport, and reuse the current protocol-31 ordinary-file sender/receiver paths after the daemon text handshake completes. CLI planning distinguishes remote-shell and daemon operands before execution so daemon mode no longer trips the old future-phase diagnostic.

**Tech Stack:** Rust workspace, blocking `std::net::TcpStream`, existing rsync protocol 31 file-list/session helpers, existing CLI transfer planner, cargo unit/integration tests.

---

## Task 1: Daemon Protocol Module

**Files:**
- Create: `crates/rsync-protocol/src/daemon.rs`
- Modify: `crates/rsync-protocol/src/lib.rs`

- [x] Define `DaemonEndpoint`, `DaemonGreeting`, `DaemonModule`, and `DaemonHandshake`.
- [x] Parse `host::module/path`, `rsync://[user@]host[:port]/module/path`, and module-list forms.
- [x] Parse `@RSYNCD` greeting lines, subprotocol, digest lists, `OK`, `AUTHREQD`, `ERROR`, and `EXIT`.
- [x] Implement module-list request and module-selection setup, including password-file challenge response helpers.
- [x] Add deterministic unit tests for parsing, module listing, no-auth setup, auth response, and protocol mismatch errors.

## Task 2: CLI Planning and Execution

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-transport/src/tcp.rs`

- [x] Add CLI options `--password-file` and `--contimeout`.
- [x] Add daemon fields to `TransferPlan` and render plan output for daemon mode.
- [x] Route daemon operands to TCP setup instead of remote-shell execution.
- [x] Build daemon server args as NUL-delimited `--server` arguments and reuse existing protocol-31 push/pull transfer functions after daemon setup.
- [x] Report daemon auth as non-encrypted transport authentication when a password file is used.

## Task 3: Tests and Interop

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `tests/interop/rsync_discovery.rs`
- Modify: `README.md`

- [x] Replace the old future-phase daemon test with planning tests for module list, pull, push, and auth diagnostics.
- [x] Add CLI-level fake-transport tests for daemon no-auth pull/push using captured protocol-31 byte streams.
- [x] Add daemon interop tests gated by environment variables so they skip cleanly unless a controlled daemon is configured.
- [x] Update README status and usage examples.
- [x] Run `cargo fmt --all`, targeted tests, and `cargo test --workspace --all-features`.
