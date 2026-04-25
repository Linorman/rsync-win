# Protocol 31 Remote-Shell Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the remote-shell MVP from protocol 27 compatibility to a tested protocol 31 happy path while retaining protocol 27 fallback.

**Architecture:** Add protocol 31 primitives in `rsync-protocol` first, then switch CLI session code one boundary at a time. Keep the existing protocol 27 path intact until real SSH interop passes for both push and pull.

**Tech Stack:** Rust std I/O, existing `rsync-protocol`, existing OpenSSH subprocess transport, upstream rsync 3.2.7 interop fixture.

---

## Task 1: Protocol 31 Setup Primitives

**Files:**
- Modify: `crates/rsync-protocol/src/io.rs`
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-protocol/src/lib.rs`

- [x] Add rsync varint read/write tests using captured protocol 31 compat flags.
- [x] Add rsync vstring read/write tests using captured checksum-list strings.
- [x] Implement a protocol 31 checksum-negotiated handshake helper.
- [x] Verify the helper parses the captured rsync 3.2.7 setup bytes.
- [x] Run `cargo test -p rsync-protocol --all-features`.

## Task 2: Protocol 31 File-List Boundary

**Files:**
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [x] Add tests from captured protocol 31 file-list frames for the ordinary-file subset.
- [x] Implement the minimal protocol 31 flist reader/writer needed by non-incremental `-r --whole-file`.
- [x] Preserve protocol 27 helpers as fallback.
- [x] Run remote pull/push tests against `root@192.168.100.181`.

## Task 3: CLI Session Switch

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `tests/interop/rsync_discovery.rs`

- [x] Make remote-shell execution try protocol 31 first against modern peers.
- [ ] Fall back to protocol 27 only when the peer or setup does not support protocol 31.
- [x] Report the actual selected protocol in output and tests.
- [x] Run `cargo test --workspace --all-features`.
- [x] Run `RSYNC_WIN_SSH_TARGET=root@192.168.100.181 cargo test --test interop_discovery -- --nocapture remote_shell`.

Note: protocol 27 fallback is currently implemented for protocol/checksum negotiation failures only; broader setup-level fallback still needs coverage.
