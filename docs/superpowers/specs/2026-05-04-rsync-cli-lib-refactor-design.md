# rsync-cli lib.rs Refactor Design

## Goal

Reduce `crates/rsync-cli/src/lib.rs` from a 14k-line mixed implementation file into a small crate facade backed by focused modules and, where appropriate, lower-level engine/protocol crates.

The refactor should preserve observable behavior while making the codebase easier to extend, review, test, and reason about. The desired end state is that `rsync-cli` acts as a CLI adapter and execution orchestrator, not as the home for transfer engine internals.

## Current Problem

`crates/rsync-cli/src/lib.rs` currently owns too many responsibilities:

- CLI public entry points and `clap` command construction.
- `Cli` and CLI metadata policy types.
- Transfer plan construction, rendering, diagnostics, and option gating.
- Local transfer execution.
- Batch orchestration and sidecar handling.
- Remote-shell session setup and protocol fallback.
- Protocol 27 and protocol 31 remote push/pull flows.
- Daemon client execution.
- File-list collection and adaptation.
- Remote security validation.
- Delta token generation, checksum validation, and token application.
- Output summaries, itemized changes, stats, and formatting helpers.
- A large private unit-test module with many unrelated fixtures.

This creates high edit conflict risk, weak ownership boundaries, slow code review, and tests that often depend on private details rather than explicit module contracts.

## Design Principles

- Preserve behavior first. Initial moves should be mechanical and covered by existing tests.
- Split by responsibility, not by arbitrary line count.
- Keep `rsync-cli` focused on user-facing CLI behavior and orchestration.
- Move wire-level and transfer-engine logic out of the CLI layer when it no longer depends on CLI-specific types.
- Prefer narrow module APIs over broad `pub(crate)` exposure.
- Keep tests close to the behavior they verify. Cross-module CLI behavior belongs in integration tests.
- Make the final module graph acyclic and easy to explain.

## Target Module Layout

```text
crates/rsync-cli/src/
  lib.rs
  app.rs
  cli.rs
  options.rs
  output.rs
  batch.rs
  daemon_server.rs

  plan/
    mod.rs
    render.rs
    diagnostics.rs
    remote_args.rs
    filters.rs
    metadata.rs

  execute/
    mod.rs
    local.rs
    batch_mode.rs
    daemon_client.rs
    remote_shell.rs

  remote/
    mod.rs
    session.rs
    push.rs
    pull.rs
    flist.rs
    receive.rs
    send.rs
    security.rs
    daemon_auth.rs

  transfer/
    mod.rs
    checksum.rs
    delta.rs
    tokens.rs
    progress.rs
    limits.rs

  format/
    mod.rs
    report.rs
    actions.rs
    names.rs

  test_support.rs
```

`lib.rs` should become a facade:

```rust
pub mod batch;
mod app;
mod cli;
mod execute;
mod format;
mod plan;
mod remote;
mod transfer;

mod daemon_server;
pub mod options;
pub mod output;

pub use app::{
    build_command, parse_and_execute, parse_and_render, parse_and_render_result, run_from_env,
    run_from_env_main, supported_protocol_range, version_output,
};
pub use cli::{Cli, CliMetadataPolicy};
```

The final `lib.rs` should be under 200 lines.

## Responsibility Boundaries

### `cli.rs`

Owns user-facing CLI data structures:

- `Cli`
- `CliMetadataPolicy`
- `impl From<CliMetadataPolicy> for MetadataPolicy`
- `impl Default for Cli`
- `build_command` may either live here or in `app.rs`; the preferred public export remains `rsync_cli::build_command()`.

`cli.rs` should not perform transfer planning or execution.

### `options.rs`

Continues to own rsync-compatible option registry and custom parsing:

- option specs
- `parse_options`
- `parse_cli`
- long/short option handling
- value parsing helpers
- unsupported-option recording

It depends on `crate::cli::{Cli, CliMetadataPolicy}`. It should not depend on transfer execution modules.

### `app.rs`

Owns public entry points and top-level command flow:

- `run_from_env`
- `run_from_env_main`
- `parse_and_render_result`
- `parse_and_render`
- `parse_and_execute`
- `supported_protocol_range`
- `version_output`
- `render_output`
- `execute_or_render`

`app.rs` chooses between help/version/plan/execution and delegates execution to `execute`.

### `plan/`

Owns conversion from parsed CLI to an execution plan and user-visible plan output.

Suggested files:

- `plan/mod.rs`: `TransferPlan`, `TransferMode`, basic constructors.
- `plan/render.rs`: `render_transfer_plan`, `render_transfer_plan_with`.
- `plan/diagnostics.rs`: metadata degradation, option conflict, option support, and mode gating diagnostics.
- `plan/remote_args.rs`: remote-shell and daemon argv construction from plan/CLI.
- `plan/filters.rs`: filter-rule construction and remote filter argument rendering.
- `plan/metadata.rs`: CLI-to-core metadata request conversion and metadata summaries.

`TransferPlan` should be the stable internal contract between parsing and execution. Execution modules should receive `TransferPlan` plus narrow context values, not reach deeply into `Cli` unless the field is truly presentation- or CLI-specific.

### `execute/`

Owns mode-level orchestration:

- `execute/mod.rs`: central dispatch from `TransferPlan`.
- `execute/local.rs`: local sync workflow.
- `execute/batch_mode.rs`: `--write-batch`, `--only-write-batch`, and `--read-batch` orchestration around the existing `batch` module.
- `execute/daemon_client.rs`: daemon client connection, module listing, daemon pull/push entry points.
- `execute/remote_shell.rs`: remote-shell process spawning, protocol fallback, transport setup, timeout/bandwidth wiring.

Execution modules should not contain low-level protocol token logic. They should call `remote` and `transfer` modules for those operations.

### `remote/`

Owns remote rsync client behavior independent of command-line parsing:

- `remote/session.rs`: protocol setup, fallback classification, wire protocol selection, session labels.
- `remote/push.rs`: push state machine for protocol 27 and 31.
- `remote/pull.rs`: pull state machine for protocol 27 and 31, including incremental recursion.
- `remote/flist.rs`: local source collection for remote file lists, remote entry sorting, index mapping, hardlink groups, metadata adaptation.
- `remote/send.rs`: serving local sender files to a remote receiver.
- `remote/receive.rs`: receiving remote sender files to local destinations.
- `remote/security.rs`: remote file-list validation, trust-sender boundaries, safe path checks, filter claim validation.
- `remote/daemon_auth.rs`: daemon auth user/password/password-file helpers used by daemon client code.

This module may still live in `rsync-cli` initially, but its APIs should be designed so most of it can later move to a new engine crate.

### `transfer/`

Owns reusable transfer mechanics:

- `transfer/checksum.rs`: remote checksum algorithm selection, builders, final checksums.
- `transfer/delta.rs`: signature requests, delta token generation, literal/copy token helpers.
- `transfer/tokens.rs`: token read/write helpers and apply-to-file logic.
- `transfer/progress.rs`: `FileProgress`, transfer runtime stats, transfer rate labels if not retained in output.
- `transfer/limits.rs`: allocation, basis-copy, signature-table, and file-list budget helpers.

Code here should not depend on `Cli`. If a function needs CLI configuration, pass a small config struct.

### `format/`

Owns user-visible text assembled from plans/actions:

- `format/report.rs`: diagnostics, compact summaries, structured stats.
- `format/actions.rs`: sync action records, itemized codes, action operation labels.
- `format/names.rs`: output name escaping, path label helpers.

The existing `output.rs` remains responsible for stderr routing, log format expansion, info/debug flags, and exit code mapping. After refactor, some current lib.rs formatting helpers may move into either `format/` or `output.rs` depending on whether they are pure output primitives or CLI report assembly.

### `test_support.rs`

Contains private test fixtures shared across module unit tests:

- `TestTransport`
- remote push/pull byte stream builders
- remote fixture entry builders
- temporary directory helpers

This module should be compiled only with `#[cfg(test)]`.

## Crate-Level End State

After the module split stabilizes, move CLI-independent logic into lower-level crates.

Preferred long-term shape:

```text
crates/rsync-engine/
  src/
    local.rs
    remote/
    transfer/
    security.rs

crates/rsync-cli/
  src/
    cli.rs
    options.rs
    plan/
    app.rs
```

Alternative: place protocol-heavy pieces into existing crates:

- `rsync-protocol`: wire primitives, session negotiation, file-list encoding/decoding, mux helpers.
- `rsync-delta`: token generation/application and checksum helpers.
- `rsync-fs`: local filesystem execution primitives.

The engine crate is preferred if the transferred logic needs to coordinate protocol, filesystem, transport, and filter crates without making any one lower-level crate depend upward.

## Public API Compatibility

Keep these existing public entry points stable:

- `rsync_cli::run_from_env`
- `rsync_cli::run_from_env_main`
- `rsync_cli::parse_and_render_result`
- `rsync_cli::parse_and_render`
- `rsync_cli::parse_and_execute`
- `rsync_cli::build_command`
- `rsync_cli::supported_protocol_range`
- `rsync_cli::version_output`
- `rsync_cli::options::*`
- `rsync_cli::output::*`

If internal structs become public only to support tests, prefer moving those tests into the same module or using integration behavior tests instead.

## Migration Plan

### Phase 1: Establish Facade and CLI Boundary

- Create `cli.rs`.
- Move `Cli`, `CliMetadataPolicy`, metadata policy conversion, and `Default for Cli`.
- Update `options.rs` imports from `crate::{Cli, CliMetadataPolicy}` to `crate::cli::{Cli, CliMetadataPolicy}`.
- Re-export `Cli` and `CliMetadataPolicy` from `lib.rs`.
- Move top-level public entry points into `app.rs`.
- Keep behavior unchanged.

Verification:

- `cargo fmt --all -- --check`
- `cargo test -p rsync-cli`

### Phase 2: Split Plan Construction and Rendering

- Create `plan/`.
- Move `TransferPlan`, `TransferMode`, `RemoteWireProtocol`, plan labels, mode selection, diagnostics, and plan rendering.
- Keep `TransferPlan::from_cli` behavior identical.
- Expose only the methods needed by `app` and `execute`.

Verification:

- Existing plan rendering tests pass.
- Add focused plan tests for mode selection and diagnostics if current tests are too broad.

### Phase 3: Split Execution Dispatch

- Create `execute/`.
- Move `execute_or_render` dispatch into `execute/mod.rs` or keep the public wrapper in `app.rs` and delegate to `execute::execute`.
- Move local execution into `execute/local.rs`.
- Move daemon client execution into `execute/daemon_client.rs`.
- Move remote-shell orchestration into `execute/remote_shell.rs`.

Verification:

- Local executor tests pass.
- Daemon client in-memory transport tests pass.
- Remote-shell fallback tests pass.

### Phase 4: Split Remote State Machines

- Create `remote/`.
- Move push protocol 27/31 functions into `remote/push.rs`.
- Move pull protocol 27/31 functions into `remote/pull.rs`.
- Move shared session and fallback helpers into `remote/session.rs`.
- Move file-list collection/adaptation/sorting/indexing into `remote/flist.rs`.
- Move send/receive helpers into `remote/send.rs` and `remote/receive.rs`.
- Move remote path and trust-sender validation into `remote/security.rs`.

Verification:

- Remote push/pull unit tests pass.
- Security regression tests pass.
- Interop tests remain unchanged at call sites.

### Phase 5: Split Transfer Mechanics

- Create `transfer/`.
- Move checksum algorithm enums/builders into `transfer/checksum.rs`.
- Move delta token writer/index/window helpers into `transfer/delta.rs`.
- Move token reader/apply helpers into `transfer/tokens.rs`.
- Move allocation and signature-table budget helpers into `transfer/limits.rs`.
- Move progress/stats runtime structs into `transfer/progress.rs`.

Verification:

- Delta token round-trip tests pass.
- Checksum selection tests pass.
- Oversized allocation rejection tests pass.

### Phase 6: Split Formatting and Tests

- Create `format/`.
- Move action report, itemized output, stats, and output-name helpers.
- Move module-specific unit tests next to their modules.
- Keep CLI behavior tests in `tests/compat` and `tests/interop`.
- Consolidate shared fixtures in `test_support.rs`.

Verification:

- `cargo test -p rsync-cli`
- `cargo test --workspace --all-features`

### Phase 7: Extract Engine Logic

- Create `rsync-engine` only after module APIs have stabilized.
- Move CLI-independent remote and transfer orchestration from `rsync-cli` to `rsync-engine`.
- Keep `rsync-cli` as parser, planner, output renderer, and engine caller.

Verification:

- Full workspace tests.
- Interop tests against upstream rsync.
- Security and stress tests.

## Testing Strategy

Use three test layers:

- Module unit tests for pure helpers and state-machine fragments.
- Crate integration tests for CLI behavior, plan output, local execution, and error mapping.
- Interop/stress/security tests for upstream rsync compatibility, malicious peer handling, and memory-bounded transfers.

During mechanical moves, avoid changing expected output. If a behavior change is needed, land it as a separate commit after the refactor step that exposed the issue.

Important gates:

- `cargo fmt --all -- --check`
- `cargo test -p rsync-cli`
- `cargo test --workspace --all-features`
- `cargo clippy --workspace --all-features -- -D warnings`
- existing interop tests when fixture environment is available

## Risk Management

Main risks:

- Private helper movement can force excessive `pub(crate)` exposure.
- Remote push/pull logic has tight coupling through shared structs and fixture builders.
- Mechanical moves can accidentally change import resolution or cfg-gated Windows behavior.
- Large test movement can hide failures if fixtures are not moved carefully.

Mitigations:

- Move one responsibility at a time.
- Keep each phase behavior-preserving.
- Run targeted tests after every phase.
- Prefer local module tests over widening visibility.
- Create small config/context structs when several modules need the same values.
- Avoid crate extraction until intra-crate module boundaries are stable.

## Completion Criteria

The refactor is complete when:

- `crates/rsync-cli/src/lib.rs` is under 200 lines.
- No single `rsync-cli/src/*.rs` file exceeds 1,500 lines without a documented reason.
- CLI parsing, planning, execution dispatch, remote state machines, transfer mechanics, and formatting have separate ownership.
- `rsync-cli` no longer contains broad wire-level transfer internals except through engine/protocol APIs.
- Existing public entry points remain stable.
- Full workspace tests pass.
- Interop/security/stress tests remain runnable without needing private `lib.rs` fixtures.
