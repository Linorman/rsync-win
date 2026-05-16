# rsync-cli Refactor Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the remaining work from `docs/superpowers/specs/2026-05-04-rsync-cli-lib-refactor-design.md` so `rsync-cli` is a small CLI adapter with focused internal modules and no broad transfer internals in the crate facade.

**Architecture:** Keep every step behavior-preserving. Split large modules by responsibility first, preserve existing `pub(crate)` call sites through narrow module re-exports, then reduce the facade exports and decide whether stable CLI-independent APIs should move into a new `rsync-engine` crate. Do not change rsync-visible output, protocol bytes, option parsing, or exit-code behavior during these moves.

**Tech Stack:** Rust workspace, Cargo, `rsync-cli`, `rsync-protocol`, `rsync-delta`, `rsync-fs`, `rsync-transport`, Windows-first test environment.

---

## Current State Snapshot

The May 4 design is partly implemented:

- `crates/rsync-cli/src/lib.rs` is already a 37-line facade.
- `cli`, `plan`, `execute`, `remote`, and `transfer` modules exist.
- Verification currently passes:
  - `cargo fmt --all -- --check`
  - `cargo test -p rsync-cli`
  - `cargo test --workspace --all-features`
  - `cargo clippy --workspace --all-features -- -D warnings`

Remaining gaps:

- `crates/rsync-cli/src/transfer/mod.rs` is still a 1,520-line mixed transfer module.
- `crates/rsync-cli/src/daemon_server.rs` is still a 1,629-line mixed daemon module.
- `crates/rsync-cli/src/app/tests.rs` is still a 4,319-line private test module.
- `remote/` is missing the planned `session`, `send`, `security`, and `daemon_auth` ownership boundaries.
- `format.rs` has not been split into `format/report.rs`, `format/actions.rs`, and `format/names.rs`.
- `lib.rs` still has broad `pub(crate) use` forwarding for internals that should be referenced through owning modules.
- There is no `rsync-engine` crate yet.

## Target File Structure

Create or modify the following files.

### Transfer

- Modify: `crates/rsync-cli/src/transfer/mod.rs`
- Create: `crates/rsync-cli/src/transfer/progress.rs`
- Create: `crates/rsync-cli/src/transfer/checksum.rs`
- Create: `crates/rsync-cli/src/transfer/sum_head.rs`
- Create: `crates/rsync-cli/src/transfer/delta.rs`
- Create: `crates/rsync-cli/src/transfer/tokens.rs`
- Create: `crates/rsync-cli/src/transfer/limits.rs`
- Create: `crates/rsync-cli/src/transfer/fs_ops.rs`

`transfer/mod.rs` should become a small module index and re-export surface:

```rust
mod checksum;
mod delta;
mod fs_ops;
mod limits;
mod progress;
mod sum_head;
mod tokens;

pub(crate) use checksum::{
    remote_checksum_for_bytes, remote_file_checksum_builder, remote_file_checksum_for_path,
    remote_final_checksum_builder, remote_final_checksum_for_bytes, RemoteChecksumAlgorithm,
    RemoteChecksumBuilder, RemoteFileChecksum, RemoteFinalChecksum, RsyncStrongChecksum,
};
pub(crate) use delta::{
    local_basis_signature_request, read_remote_block_signatures_from_reader,
    read_remote_block_signatures_multiplexed, write_delta_tokens_from_bytes_with_checksum,
    write_delta_tokens_from_path, write_literal_tokens_from_reader_with_checksum,
    DeltaWriteRuntime, RemoteDeltaChecksums, RemoteDeltaStats, RemoteSignatureIndex,
};
pub(crate) use fs_ops::{
    create_local_dir_all, create_local_file, open_local_file, read_local_file,
    receive_temp_path, remove_local_file_best_effort,
};
pub(crate) use limits::{
    ensure_allocation_within_limit, ensure_basis_copy_budget, ensure_signature_table_budget,
    TransferLimits,
};
pub(crate) use progress::{
    FileProgress, RemoteCompressionConfig, RemoteExecutionStats, RemoteTransferRuntime,
    RSYNC31_MUX_FRAME_SIZE, RSYNC_ITEM_TRANSFER,
};
pub(crate) use sum_head::{
    read_rsync31_optional_item_attrs, read_sum_head, write_rsync31_optional_item_attrs,
    write_sum_head, RemoteSumHead, Rsync31ItemAttrs,
};
pub(crate) use tokens::{
    read_file_tokens_to_path_with_basis, write_append_verify_file_tokens_from_path,
    write_append_verify_literal_tokens_from_reader_with_checksum,
};
```

### Remote

- Modify: `crates/rsync-cli/src/remote/mod.rs`
- Create: `crates/rsync-cli/src/remote/session.rs`
- Create: `crates/rsync-cli/src/remote/security.rs`
- Create: `crates/rsync-cli/src/remote/send.rs`
- Create: `crates/rsync-cli/src/remote/daemon_auth.rs`
- Modify: `crates/rsync-cli/src/remote/pull.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-cli/src/remote/receive.rs`
- Modify: `crates/rsync-cli/src/remote/flist.rs`
- Modify: `crates/rsync-cli/src/execute/remote_shell.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`

`remote/mod.rs` should become:

```rust
pub(crate) mod daemon_auth;
pub(crate) mod flist;
pub(crate) mod pull;
pub(crate) mod push;
pub(crate) mod receive;
pub(crate) mod security;
pub(crate) mod send;
pub(crate) mod session;
```

### Format

- Move: `crates/rsync-cli/src/format.rs` to `crates/rsync-cli/src/format/mod.rs`
- Create: `crates/rsync-cli/src/format/actions.rs`
- Create: `crates/rsync-cli/src/format/names.rs`
- Create: `crates/rsync-cli/src/format/report.rs`

`format/mod.rs` should re-export only the functions used outside `format`:

```rust
mod actions;
mod names;
mod report;

pub(crate) use actions::{
    append_action_report, append_out_format_and_client_log,
    append_remote_source_out_format_and_client_log, append_structured_stats,
    log_sync_actions,
};
pub(crate) use names::{format_bytes, output_name, transfer_rate_label};
pub(crate) use report::{append_diagnostics, delete_mode_label, file_write_mode_label};
```

### Daemon Server

- Move: `crates/rsync-cli/src/daemon_server.rs` to `crates/rsync-cli/src/daemon_server/mod.rs`
- Create: `crates/rsync-cli/src/daemon_server/config.rs`
- Create: `crates/rsync-cli/src/daemon_server/args.rs`
- Create: `crates/rsync-cli/src/daemon_server/auth.rs`
- Create: `crates/rsync-cli/src/daemon_server/logging.rs`
- Create: `crates/rsync-cli/src/daemon_server/protocol31.rs`
- Create: `crates/rsync-cli/src/daemon_server/transport.rs`

Keep `daemon_server::run` as the only external entry point from `app.rs`.

### Tests

- Move: `crates/rsync-cli/src/app/tests.rs` to `crates/rsync-cli/src/app/tests/mod.rs`
- Create: `crates/rsync-cli/src/app/tests/options.rs`
- Create: `crates/rsync-cli/src/app/tests/plan.rs`
- Create: `crates/rsync-cli/src/app/tests/remote.rs`
- Create: `crates/rsync-cli/src/app/tests/daemon.rs`
- Create: `crates/rsync-cli/src/app/tests/output.rs`
- Create: `crates/rsync-cli/src/test_support.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

`lib.rs` should contain:

```rust
#[cfg(test)]
mod test_support;
```

Do not expose test-only fixtures through non-test facade exports.

---

### Task 1: Baseline Guardrail

**Files:**
- Read: `docs/superpowers/specs/2026-05-04-rsync-cli-lib-refactor-design.md`
- Read: `crates/rsync-cli/src/lib.rs`
- Read: `crates/rsync-cli/src/transfer/mod.rs`
- Read: `crates/rsync-cli/src/daemon_server.rs`

- [ ] **Step 1: Confirm the working tree before changes**

Run:

```bash
git status --short
```

Expected: existing user changes are visible. Do not revert unrelated changes.

- [ ] **Step 2: Capture current file sizes**

Run:

```bash
python - <<'PY'
from pathlib import Path
root = Path("crates/rsync-cli/src")
for path in sorted(root.rglob("*.rs")):
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) > 1200 or path.name == "lib.rs":
        print(f"{len(lines):5d} {path}")
PY
```

Expected: `lib.rs` is under 200 lines; `transfer/mod.rs`, `daemon_server.rs`, and `app/tests.rs` are the main large files.

- [ ] **Step 3: Run baseline verification**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
```

Expected: all commands pass before mechanical moves.

- [ ] **Step 4: Commit only if the baseline needed mechanical metadata changes**

Run:

```bash
git diff --stat
```

Expected: no commit if no files changed.

---

### Task 2: Split `transfer/mod.rs`

**Files:**
- Modify: `crates/rsync-cli/src/transfer/mod.rs`
- Create: `crates/rsync-cli/src/transfer/progress.rs`
- Create: `crates/rsync-cli/src/transfer/checksum.rs`
- Create: `crates/rsync-cli/src/transfer/sum_head.rs`
- Create: `crates/rsync-cli/src/transfer/delta.rs`
- Create: `crates/rsync-cli/src/transfer/tokens.rs`
- Create: `crates/rsync-cli/src/transfer/limits.rs`
- Create: `crates/rsync-cli/src/transfer/fs_ops.rs`

- [ ] **Step 1: Move progress and runtime structs**

Move these items from `transfer/mod.rs` into `transfer/progress.rs`:

```rust
pub(crate) struct RemoteExecutionStats { /* existing fields */ }
pub(crate) struct FileProgress { /* existing fields */ }
pub(crate) struct RemoteTransferRuntime { /* existing fields */ }
pub(crate) struct RemoteCompressionConfig { /* existing fields */ }
pub(crate) const RSYNC31_MUX_FRAME_SIZE: usize = /* existing value */;
pub(crate) const RSYNC_ITEM_TRANSFER: i32 = /* existing value */;
```

Preserve the existing implementations without behavior changes.

- [ ] **Step 2: Move checksum types and builders**

Move these items into `transfer/checksum.rs`:

```rust
pub(crate) enum RemoteChecksumAlgorithm { /* existing variants */ }
pub(crate) enum RemoteFileChecksum { /* existing variants */ }
pub(crate) enum RemoteFinalChecksum { /* existing variants */ }
pub(crate) enum RemoteChecksumBuilder { /* existing variants */ }
pub(crate) struct RsyncStrongChecksum { /* existing fields */ }
```

Also move the existing checksum functions:

```rust
remote_checksum_for_bytes
remote_final_checksum_for_bytes
remote_file_checksum_builder
remote_final_checksum_builder
remote_file_checksum_for_path
normalize_checksum_choice
normalize_remote_strong_checksum
```

- [ ] **Step 3: Move sum-head and optional attribute helpers**

Move these items into `transfer/sum_head.rs`:

```rust
pub(crate) struct RemoteSumHead { /* existing fields */ }
pub(crate) struct Rsync31ItemAttrs { /* existing fields */ }
pub(crate) fn read_rsync31_optional_item_attrs(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn write_rsync31_optional_item_attrs(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn read_sum_head(/* existing signature */) -> anyhow::Result<RemoteSumHead>
pub(crate) fn write_sum_head(/* existing signature */) -> anyhow::Result<()>
```

- [ ] **Step 4: Move delta writer and signature generation**

Move these items into `transfer/delta.rs`:

```rust
pub(crate) struct DeltaWriteRuntime { /* existing fields */ }
pub(crate) struct RemoteDeltaChecksums { /* existing fields */ }
pub(crate) struct RemoteDeltaStats { /* existing fields */ }
pub(crate) struct RemoteSignatureIndex { /* existing fields */ }
pub(crate) fn local_basis_signature_request(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn read_remote_block_signatures_multiplexed(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn read_remote_block_signatures_from_reader(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn write_remote_block_signatures(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn generate_signatures_from_path(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn write_delta_tokens_from_path(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn write_delta_tokens_from_bytes_with_checksum(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn write_literal_tokens_from_reader_with_checksum(/* existing signature */) -> anyhow::Result<_>
```

- [ ] **Step 5: Move token application helpers**

Move these items into `transfer/tokens.rs`:

```rust
pub(crate) fn read_file_tokens_to_path_with_basis(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn write_append_verify_file_tokens_from_path(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn write_append_verify_literal_tokens_from_reader_with_checksum(/* existing signature */) -> anyhow::Result<_>
```

- [ ] **Step 6: Move limits and filesystem wrappers**

Move limit helpers into `transfer/limits.rs`:

```rust
pub(crate) struct TransferLimits { /* existing fields */ }
pub(crate) fn ensure_basis_copy_budget(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn ensure_allocation_within_limit(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn ensure_signature_table_budget(/* existing signature */) -> anyhow::Result<()>
```

Move filesystem wrappers into `transfer/fs_ops.rs`:

```rust
pub(crate) fn open_local_file(/* existing signature */) -> anyhow::Result<std::fs::File>
pub(crate) fn create_local_file(/* existing signature */) -> anyhow::Result<std::fs::File>
pub(crate) fn create_local_dir_all(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn remove_local_file_best_effort(/* existing signature */)
pub(crate) fn receive_temp_path(/* existing signature */) -> std::path::PathBuf
```

- [ ] **Step 7: Replace `transfer/mod.rs` with module declarations and re-exports**

Use the `transfer/mod.rs` re-export skeleton from the Target File Structure section.

- [ ] **Step 8: Verify transfer split**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli
cargo clippy -p rsync-cli --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 9: Commit transfer split**

Run:

```bash
git add crates/rsync-cli/src/transfer
git commit -m "refactor(cli): split transfer mechanics"
```

---

### Task 3: Add Missing `remote/` Ownership Boundaries

**Files:**
- Modify: `crates/rsync-cli/src/remote/mod.rs`
- Create: `crates/rsync-cli/src/remote/session.rs`
- Create: `crates/rsync-cli/src/remote/security.rs`
- Create: `crates/rsync-cli/src/remote/send.rs`
- Create: `crates/rsync-cli/src/remote/daemon_auth.rs`
- Modify: `crates/rsync-cli/src/execute/remote_shell.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-cli/src/remote/receive.rs`

- [ ] **Step 1: Add remote module declarations**

Update `remote/mod.rs` to:

```rust
pub(crate) mod daemon_auth;
pub(crate) mod flist;
pub(crate) mod pull;
pub(crate) mod push;
pub(crate) mod receive;
pub(crate) mod security;
pub(crate) mod send;
pub(crate) mod session;
```

- [ ] **Step 2: Move session and fallback helpers**

Move these existing helpers from `execute/remote_shell.rs` into `remote/session.rs`:

```rust
pub(crate) fn should_fallback_to_protocol27(/* existing signature */) -> bool
pub(crate) fn protocol31_setup_error(/* existing signature */) -> anyhow::Error
```

Keep `execute/remote_shell.rs` responsible for process spawning and transport wiring only.

- [ ] **Step 3: Move remote safety validation**

Move these existing helpers from `remote/receive.rs` into `remote/security.rs`:

```rust
pub(crate) fn validate_remote_file_list_paths(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn windows_destination_path_preflight(/* existing signature */) -> anyhow::Result<()>
```

Update callers to import from `crate::remote::security`.

- [ ] **Step 4: Move sender-serving helpers**

Create `remote/send.rs` and move sender-side protocol helpers that serve local files to a remote receiver. At minimum, move sender request/write helpers that do not mutate local destination state:

```rust
pub(crate) fn request_remote_sender_files_protocol31(/* existing signature */) -> anyhow::Result<_>
```

Keep receiver-side destination mutation in `remote/receive.rs`.

- [ ] **Step 5: Move daemon auth helpers**

Move daemon auth helpers from `execute/daemon_client.rs` into `remote/daemon_auth.rs`:

```rust
pub(crate) fn daemon_auth_user(/* existing signature */) -> anyhow::Result<_>
pub(crate) fn daemon_auth_user_from_vars(/* existing signature */) -> Option<String>
pub(crate) fn daemon_password_from_vars(/* existing signature */) -> Option<String>
pub(crate) fn read_password_file(/* existing signature */) -> anyhow::Result<String>
```

Update `execute/daemon_client.rs` to use `crate::remote::daemon_auth`.

- [ ] **Step 6: Verify remote split**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli remote_shell
cargo test -p rsync-cli daemon
cargo test -p rsync-cli security
cargo clippy -p rsync-cli --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 7: Commit remote split**

Run:

```bash
git add crates/rsync-cli/src/remote crates/rsync-cli/src/execute
git commit -m "refactor(cli): split remote session and security helpers"
```

---

### Task 4: Split `format.rs`

**Files:**
- Move: `crates/rsync-cli/src/format.rs` to `crates/rsync-cli/src/format/mod.rs`
- Create: `crates/rsync-cli/src/format/actions.rs`
- Create: `crates/rsync-cli/src/format/names.rs`
- Create: `crates/rsync-cli/src/format/report.rs`

- [ ] **Step 1: Convert `format.rs` into a directory module**

Run:

```bash
git mv crates/rsync-cli/src/format.rs crates/rsync-cli/src/format/mod.rs
```

Expected: `mod format;` in `lib.rs` continues to resolve.

- [ ] **Step 2: Move name and byte helpers**

Move these items into `format/names.rs`:

```rust
pub(crate) fn format_bytes(bytes: u64) -> String
pub(crate) fn transfer_rate_label(bytes: u64, elapsed: std::time::Duration) -> String
pub(crate) fn output_name(/* existing signature */) -> String
```

- [ ] **Step 3: Move action and stats formatting**

Move these items into `format/actions.rs`:

```rust
pub(crate) fn append_action_report(/* existing signature */)
pub(crate) fn append_out_format_and_client_log(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn append_remote_source_out_format_and_client_log(/* existing signature */) -> anyhow::Result<()>
pub(crate) fn append_structured_stats(/* existing signature */)
pub(crate) fn log_sync_actions(/* existing signature */)
```

Also move `OutputActionRecord`, `OutputRemoteSourceRecord`, `ActionStats`, and itemized action helpers.

- [ ] **Step 4: Move diagnostics and label helpers**

Move these items into `format/report.rs`:

```rust
pub(crate) fn append_diagnostics(/* existing signature */)
pub(crate) fn delete_mode_label(/* existing signature */) -> &'static str
pub(crate) fn file_write_mode_label(/* existing signature */) -> &'static str
pub(crate) fn symlink_mode_label(/* existing signature */) -> &'static str
```

- [ ] **Step 5: Replace `format/mod.rs` with module declarations and re-exports**

Use the `format/mod.rs` skeleton from the Target File Structure section. Keep helper functions private unless used outside `format`.

- [ ] **Step 6: Verify format split**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli options
cargo test -p rsync-cli release_readiness
cargo clippy -p rsync-cli --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 7: Commit format split**

Run:

```bash
git add crates/rsync-cli/src/format
git commit -m "refactor(cli): split output formatting modules"
```

---

### Task 5: Split `daemon_server.rs`

**Files:**
- Move: `crates/rsync-cli/src/daemon_server.rs` to `crates/rsync-cli/src/daemon_server/mod.rs`
- Create: `crates/rsync-cli/src/daemon_server/config.rs`
- Create: `crates/rsync-cli/src/daemon_server/args.rs`
- Create: `crates/rsync-cli/src/daemon_server/auth.rs`
- Create: `crates/rsync-cli/src/daemon_server/logging.rs`
- Create: `crates/rsync-cli/src/daemon_server/protocol31.rs`
- Create: `crates/rsync-cli/src/daemon_server/transport.rs`

- [ ] **Step 1: Convert daemon server into a directory module**

Run:

```bash
git mv crates/rsync-cli/src/daemon_server.rs crates/rsync-cli/src/daemon_server/mod.rs
```

Expected: `mod daemon_server;` in `lib.rs` continues to resolve.

- [ ] **Step 2: Move config parsing**

Move these items into `daemon_server/config.rs`:

```rust
struct DaemonServerConfig { /* existing fields */ }
struct DaemonServerModule { /* existing fields */ }
fn parse_config(/* existing signature */) -> anyhow::Result<DaemonServerConfig>
fn apply_dparams(/* existing signature */)
fn apply_module_param(/* existing signature */)
fn validate_config(/* existing signature */) -> anyhow::Result<()>
fn daemon_config_warnings(/* existing signature */) -> Vec<String>
```

- [ ] **Step 3: Move daemon argument parsing**

Move these items into `daemon_server/args.rs`:

```rust
struct DaemonTransferArgs { /* existing fields */ }
fn read_daemon_args(/* existing signature */) -> anyhow::Result<DaemonTransferArgs>
fn read_null_daemon_args(/* existing signature */) -> anyhow::Result<Vec<String>>
fn read_line_daemon_args(/* existing signature */) -> anyhow::Result<Vec<String>>
fn decode_args(/* existing signature */) -> anyhow::Result<Vec<String>>
```

- [ ] **Step 4: Move auth and secrets handling**

Move these items into `daemon_server/auth.rs`:

```rust
fn authenticate_daemon_client(/* existing signature */) -> anyhow::Result<()>
fn daemon_auth_response_is_valid(/* existing signature */) -> bool
fn read_daemon_secrets(/* existing signature */) -> anyhow::Result<_>
fn parse_daemon_secrets(/* existing signature */) -> anyhow::Result<_>
fn daemon_auth_challenge(/* existing signature */) -> String
fn validate_daemon_secrets_file_permissions(/* existing signature */) -> anyhow::Result<()>
```

- [ ] **Step 5: Move logging**

Move these items into `daemon_server/logging.rs`:

```rust
struct DaemonLogRecord { /* existing fields */ }
fn log_daemon_message(/* existing signature */)
fn log_daemon_record(/* existing signature */)
fn render_daemon_log_format(/* existing signature */) -> String
fn daemon_log_timestamp(/* existing signature */) -> String
```

- [ ] **Step 6: Move protocol 31 sender and receiver serving**

Move these items into `daemon_server/protocol31.rs`:

```rust
fn serve_daemon_sender_protocol31(/* existing signature */) -> anyhow::Result<()>
fn serve_daemon_receiver_protocol31(/* existing signature */) -> anyhow::Result<()>
fn send_protocol31_setup(/* existing signature */) -> anyhow::Result<()>
fn exchange_receiver_protocol31_setup(/* existing signature */) -> anyhow::Result<_>
fn serve_daemon_sender_requests_protocol31(/* existing signature */) -> anyhow::Result<_>
fn write_daemon_sender_stats(/* existing signature */) -> anyhow::Result<()>
```

- [ ] **Step 7: Move transport adapters**

Move these items into `daemon_server/transport.rs`:

```rust
enum DaemonConnection { /* existing variants */ }
struct CursorStream { /* existing fields */ }
fn daemon_listen_address(/* existing signature */) -> anyhow::Result<_>
fn daemon_address_family(/* existing signature */) -> anyhow::Result<_>
fn parse_daemon_bwlimit(/* existing signature */) -> anyhow::Result<_>
```

- [ ] **Step 8: Keep `daemon_server/mod.rs` as orchestration**

After moves, `daemon_server/mod.rs` should keep only:

```rust
mod args;
mod auth;
mod config;
mod logging;
mod protocol31;
mod transport;

pub(crate) fn run(cli: &crate::Cli) -> anyhow::Result<String> {
    // existing top-level orchestration, delegating to submodules
}
```

- [ ] **Step 9: Verify daemon split**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli daemon
cargo test -p rsync-cli interop
cargo clippy -p rsync-cli --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 10: Commit daemon split**

Run:

```bash
git add crates/rsync-cli/src/daemon_server
git commit -m "refactor(cli): split daemon server modules"
```

---

### Task 6: Split Private App Tests and Add `test_support`

**Files:**
- Move: `crates/rsync-cli/src/app/tests.rs` to `crates/rsync-cli/src/app/tests/mod.rs`
- Create: `crates/rsync-cli/src/app/tests/options.rs`
- Create: `crates/rsync-cli/src/app/tests/plan.rs`
- Create: `crates/rsync-cli/src/app/tests/remote.rs`
- Create: `crates/rsync-cli/src/app/tests/daemon.rs`
- Create: `crates/rsync-cli/src/app/tests/output.rs`
- Create: `crates/rsync-cli/src/test_support.rs`
- Modify: `crates/rsync-cli/src/lib.rs`

- [ ] **Step 1: Convert app tests into a directory module**

Run:

```bash
git mv crates/rsync-cli/src/app/tests.rs crates/rsync-cli/src/app/tests/mod.rs
```

- [ ] **Step 2: Add test module declarations**

Replace the body of `app/tests/mod.rs` with declarations plus shared imports:

```rust
mod daemon;
mod options;
mod output;
mod plan;
mod remote;
```

Move each existing test into the file matching its behavior area.

- [ ] **Step 3: Add crate-level test support**

Create `crates/rsync-cli/src/test_support.rs` for shared fixtures used by multiple module tests:

```rust
#![cfg(test)]

use std::io::{Read, Result as IoResult, Write};

pub(crate) struct TestTransport {
    input: std::io::Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl TestTransport {
    pub(crate) fn new(input: Vec<u8>) -> Self {
        Self {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
        }
    }

    pub(crate) fn into_output(self) -> Vec<u8> {
        self.output
    }
}

impl Read for TestTransport {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.input.read(buf)
    }
}

impl Write for TestTransport {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.output.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.output.flush()
    }
}
```

Move only fixtures that are actually shared by two or more test modules into `test_support.rs`.

- [ ] **Step 4: Gate test support in `lib.rs`**

Add:

```rust
#[cfg(test)]
mod test_support;
```

- [ ] **Step 5: Verify test split**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli
cargo clippy -p rsync-cli --all-features -- -D warnings
```

Expected: all pass; no single `crates/rsync-cli/src/app/tests/*.rs` file remains near the original 4,319-line size.

- [ ] **Step 6: Commit test split**

Run:

```bash
git add crates/rsync-cli/src/app crates/rsync-cli/src/test_support.rs crates/rsync-cli/src/lib.rs
git commit -m "refactor(cli): split private app tests"
```

---

### Task 7: Reduce `lib.rs` Internal Forwarding

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify callers that import internals from `crate::{...}`

- [ ] **Step 1: Find facade-only internal imports**

Run:

```bash
rg "crate::\\{[^}]*Remote|crate::\\{[^}]*Delta|crate::\\{[^}]*read_|crate::\\{[^}]*write_" crates/rsync-cli/src
```

Expected: callers importing transfer and remote internals through `crate::{...}` are listed.

- [ ] **Step 2: Replace internal facade imports with owning module paths**

Replace imports like:

```rust
use crate::{read_sum_head, write_delta_tokens_from_path, RemoteExecutionStats};
```

with:

```rust
use crate::transfer::{read_sum_head, write_delta_tokens_from_path, RemoteExecutionStats};
```

Replace imports like:

```rust
use crate::{validate_remote_file_list_paths, RemoteReceiveContext};
```

with:

```rust
use crate::remote::receive::RemoteReceiveContext;
use crate::remote::security::validate_remote_file_list_paths;
```

- [ ] **Step 3: Shrink `lib.rs` to public facade plus module declarations**

The final `lib.rs` should be close to:

```rust
mod app;
pub mod batch;
mod cli;
mod daemon_server;
mod execute;
mod format;
pub mod options;
pub mod output;
mod plan;
mod remote;
mod transfer;

#[cfg(test)]
mod test_support;

pub use app::{
    build_command, parse_and_execute, parse_and_render, parse_and_render_result, run_from_env,
    run_from_env_main, supported_protocol_range, version_output,
};
pub use cli::{Cli, CliMetadataPolicy};
```

- [ ] **Step 4: Verify facade cleanup**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli
cargo clippy -p rsync-cli --all-features -- -D warnings
```

Expected: all pass; `lib.rs` no longer forwards transfer or remote internals.

- [ ] **Step 5: Commit facade cleanup**

Run:

```bash
git add crates/rsync-cli/src
git commit -m "refactor(cli): narrow crate facade"
```

---

### Task 8: Engine Extraction Decision and Minimal Move

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/rsync-engine/Cargo.toml`
- Create: `crates/rsync-engine/src/lib.rs`
- Candidate moves after Tasks 2-7:
  - `crates/rsync-cli/src/transfer/*`
  - `crates/rsync-cli/src/remote/security.rs`
  - `crates/rsync-cli/src/remote/session.rs`

- [ ] **Step 1: Identify CLI-independent modules**

Run:

```bash
rg "crate::cli|crate::options|crate::plan|Cli\\b|TransferPlan\\b" crates/rsync-cli/src/transfer crates/rsync-cli/src/remote/security.rs crates/rsync-cli/src/remote/session.rs
```

Expected: modules with no CLI-specific references are safe candidates for `rsync-engine`. Modules still depending on `TransferPlan` need a small config struct before moving.

- [ ] **Step 2: Create the engine crate only if at least one module is CLI-independent**

Add `crates/rsync-engine` to workspace members and create:

```rust
// crates/rsync-engine/src/lib.rs
pub mod transfer;
pub mod remote;
```

If no module is CLI-independent yet, do not create a placeholder crate. Instead, open a follow-up spec for the required config-type extraction.

- [ ] **Step 3: Move only stable CLI-independent code**

Move modules that pass Step 1 into `crates/rsync-engine/src/`. Keep `rsync-cli` call sites importing through `rsync_engine::...`.

Do not move daemon server orchestration, CLI plan rendering, or remote-shell process spawning in this task.

- [ ] **Step 4: Verify engine extraction**

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 5: Commit engine extraction or decision note**

If code moved:

```bash
git add Cargo.toml crates/rsync-engine crates/rsync-cli/src
git commit -m "refactor: extract CLI-independent engine helpers"
```

If code did not move, create:

```text
docs/superpowers/specs/YYYY-MM-DD-rsync-engine-extraction-blockers.md
```

and commit:

```bash
git add docs/superpowers/specs/YYYY-MM-DD-rsync-engine-extraction-blockers.md
git commit -m "docs: record rsync engine extraction blockers"
```

---

### Task 9: Final Completion Audit

**Files:**
- Read: `docs/superpowers/specs/2026-05-04-rsync-cli-lib-refactor-design.md`
- Read: `crates/rsync-cli/src/lib.rs`
- Read: `crates/rsync-cli/src`

- [ ] **Step 1: Re-run file-size audit**

Run:

```bash
python - <<'PY'
from pathlib import Path
root = Path("crates/rsync-cli/src")
bad = []
for path in sorted(root.rglob("*.rs")):
    lines = len(path.read_text(encoding="utf-8").splitlines())
    if path.name == "lib.rs":
        print(f"lib.rs lines: {lines}")
    if lines > 1500:
        bad.append((lines, path))
for lines, path in bad:
    print(f"OVER_LIMIT {lines} {path}")
raise SystemExit(1 if bad else 0)
PY
```

Expected: `lib.rs lines` is under 200 and no `OVER_LIMIT` rows are printed.

- [ ] **Step 2: Verify ownership boundaries**

Run:

```bash
rg "pub\\(crate\\) use app::\\{|pub\\(crate\\) use transfer::\\{|pub\\(crate\\) use remote::" crates/rsync-cli/src/lib.rs
```

Expected: no matches.

- [ ] **Step 3: Run final verification gates**

Run:

```bash
cargo fmt --all -- --check
cargo test -p rsync-cli
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 4: Document unavailable external interop fixtures**

Run:

```bash
cargo test -p rsync-cli --test rsync_compat -- --nocapture
```

Expected: tests pass or skip cleanly when optional upstream rsync/SSH fixtures are absent. Record any skipped fixture names in the final handoff.

- [ ] **Step 5: Commit final audit updates**

Run:

```bash
git status --short
git log --oneline -n 8
```

Expected: all planned commits are present; no accidental unrelated files are staged.

---

## Recommended Execution Order

1. Task 2: split `transfer/mod.rs`.
2. Task 3: add missing `remote/` boundaries.
3. Task 4: split `format.rs`.
4. Task 5: split `daemon_server.rs`.
5. Task 6: split private tests and add `test_support`.
6. Task 7: narrow `lib.rs`.
7. Task 8: extract engine code only if the module dependencies are ready.
8. Task 9: final audit.

This order reduces risk because the most mechanical module moves happen before public facade cleanup and crate extraction.

## Completion Criteria

The work is complete only when all are true:

- `crates/rsync-cli/src/lib.rs` is under 200 lines.
- No Rust source file under `crates/rsync-cli/src` exceeds 1,500 lines without an explicit documented reason.
- CLI parsing, planning, execution dispatch, remote state machines, transfer mechanics, formatting, daemon server orchestration, and test fixtures have separate ownership.
- `lib.rs` exports public API only; internal transfer/remote helpers are imported from their owning modules.
- CLI-independent transfer or remote helpers are either moved to `rsync-engine` or documented with specific blockers.
- Public API entry points remain stable.
- `cargo fmt --all -- --check` passes.
- `cargo test -p rsync-cli` passes.
- `cargo test --workspace --all-features` passes.
- `cargo clippy --workspace --all-features -- -D warnings` passes.
- Optional interop/security/stress tests pass or skip cleanly based on fixture availability.
