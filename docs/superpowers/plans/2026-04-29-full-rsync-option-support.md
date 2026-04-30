# Full Rsync Option Support Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `rsync-win` to complete upstream rsync command-line option coverage, with implemented behavior where Windows can support it and explicit sidecar/capability/error paths where it cannot.

**Architecture:** Treat rsync compatibility as a layered contract: parse every upstream option first, normalize options into a single transfer plan, then implement behavior by option family across local sync, remote-shell client, daemon client, and daemon server modes. Keep clean-room boundaries between CLI parsing/planning, protocol, transport, filters, portable filesystem behavior, and Windows-native metadata helpers.

**Tech Stack:** Rust 1.76+, `clap` or a custom rsync-compatible parser where clap semantics are insufficient, existing `rsync-cli`, `rsync-protocol`, `rsync-filter`, `rsync-fs`, `rsync-transport`, `rsync-winfs`, upstream rsync documentation, gated interop tests against real upstream rsync/OpenSSH/daemon fixtures, PowerShell release tooling.

---

## Compatibility Target

- Target upstream option surface: rsync client, daemon, internal server, and daemon-server options as documented in the official rsync(1) manpage and NEWS.
- Parsing compatibility means `rsync-win` accepts the same option spellings, short aliases, clustered short flags, negated options, values, repeated flags, and mode-specific options.
- Behavioral compatibility means the option does what upstream rsync does in the supported transfer modes.
- Windows platform gaps must be explicit. If a POSIX feature cannot be represented natively, implement it via remote peer behavior, a documented sidecar, an elevated/admin-only path, or a clear diagnostic.
- Do not claim complete rsync compatibility until every upstream option is either implemented, mode-scoped, or rejected with an rsync-compatible error and documented reason.

## Current Baseline

- The current CLI exposes a subset of rsync options in `crates/rsync-cli/src/lib.rs`.
- Unknown rsync options are rejected by the parser; there is no general passthrough.
- Remote-shell argv generation is a structured whitelist through `RemoteShellOptions`.
- Local Windows sync, remote-shell ordinary-file push/pull, daemon module listing/pull, filters, selected update modes, selected metadata reporting, NTFS sidecar pieces, and hardening tests already exist in partial form.

## File Structure

- Modify `crates/rsync-cli/src/lib.rs`: keep public entry points, then move parsing/planning/output helpers into focused modules as they grow.
- Create `crates/rsync-cli/src/options.rs`: upstream option registry, parser compatibility layer, aliases, value handling, negation handling, and option metadata.
- Create `crates/rsync-cli/src/plan.rs`: option implication, conflicts, mode gating, diagnostics, and construction of `TransferPlan`.
- Create `crates/rsync-cli/src/output.rs`: progress, stats, itemize, out-format, logging, stderr mode, and exit-code mapping.
- Modify `crates/rsync-protocol/src/session.rs`: remote-shell server argv, protocol 31/32 negotiation, delta transfer, compression/checksum negotiation, and remote-option support.
- Modify `crates/rsync-protocol/src/daemon.rs`: daemon client and server protocol support.
- Modify `crates/rsync-filter/src/rule.rs` and `crates/rsync-filter/src/matcher.rs`: full rsync filter grammar and dir-merge semantics.
- Modify `crates/rsync-fs/src/sync.rs`, `walk.rs`, and `metadata.rs`: local file selection, updates, delete timing, backups, sparse/preallocation, hardlinks, symlinks, temp/partial handling, and metadata application.
- Modify `crates/rsync-winfs/src/*`: Windows ACLs, ADS, reparse points, attributes, sparse files, VSS, security descriptors, and sidecar restore.
- Create `tests/interop/rsync_compat.rs`: gated interop matrix against upstream rsync.
- Create `tests/compat/options.rs`: parser and option-registry golden tests.
- Update `README.md`, `docs/COMPATIBILITY.md`, and `docs/ROADMAP.md` only after behavior is implemented and verified.

## Chunk 1: Build the Upstream Option Registry

### Task 1: Capture Upstream Rsync Option Inventory

**Files:**
- Create: `crates/rsync-cli/src/options.rs`
- Create: `tests/compat/options.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-cli/Cargo.toml`

- [x] Add an `OptionSpec` model with fields for long name, short name, aliases, value kind, repeat behavior, negatable form, scope, implication notes, and implementation status.
- [x] Encode every upstream rsync client option from the official option summary.
- [x] Encode daemon/server-only options separately from normal client options.
- [x] Include project-specific options such as `--plan`, `--metadata-policy`, `--fail-on-metadata-loss`, `--protocol-range`, and `--vss` without mixing them into upstream compatibility counts.
- [x] Add a golden test that asserts all expected upstream long options are present in the registry.
- [x] Add a golden test that asserts all expected upstream short options are present in the registry.
- [x] Run `cargo test -p rsync-cli --test options --all-features`.
- [x] Commit: `test: add rsync option inventory registry`.

### Task 2: Add Parser Compatibility Tests Before Rewriting Parsing

**Files:**
- Modify: `tests/compat/options.rs`
- Modify: `crates/rsync-cli/src/options.rs`

- [x] Add tests for clustered short flags such as `-avz`, `-rtgoD`, and `-aAXH`.
- [x] Add tests for short options with attached values such as `-essh`, `-M--fake-super`, and `-B8192`.
- [x] Add tests for long options with `--opt value` and `--opt=value` forms.
- [x] Add tests for negated options such as `--no-D`, `--no-links`, `--no-implied-dirs`, and existing project aliases `--no-o` / `--no-g`.
- [x] Add tests for repeated verbosity and version flags, including rsync's differing `-h` behavior when repeated with `--help`.
- [x] Keep these tests failing until the parser rewrite lands.
- [x] Run `cargo test -p rsync-cli --test options --all-features`.
- [x] Commit: `test: pin rsync parser compatibility cases`.

## Chunk 2: Implement Full Parsing and Planning

### Task 3: Replace the Current Clap-Derive Surface with an Rsync-Compatible Parser

**Files:**
- Modify: `crates/rsync-cli/src/options.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `tests/compat/options.rs`

- [x] Decide whether to keep clap builder mode or implement a small custom parser for rsync-specific edge cases.
- [x] Preserve public helpers `run_from_env`, `parse_and_render`, `parse_and_execute`, and `build_command` where possible.
- [x] Parse all registry options into a structured `ParsedOptions` type.
- [x] Preserve raw operands exactly enough to handle Windows paths, remote-shell operands, daemon operands, and `--`.
- [x] Ensure unknown options fail with an rsync-like diagnostic unless explicitly routed through `--remote-option`.
- [x] Run `cargo test -p rsync-cli --test options --all-features`.
- [x] Run `cargo test -p rsync-cli --all-features`.
- [x] Commit: `feat: parse complete rsync option surface`.

### Task 4: Add Option Implication and Conflict Engine

**Files:**
- Create: `crates/rsync-cli/src/plan.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `tests/compat/options.rs`

- [x] Implement archive expansion: `-a` implies `-rlptgoD`.
- [x] Implement shortcut expansions: `-P`, `-E`, `-F`, `-D`, and other upstream compound forms.
- [x] Implement option disabling through `--no-OPTION`.
- [x] Implement mode gating for local, remote-shell, daemon client, daemon server, and internal server modes.
- [x] Implement conflict diagnostics for incompatible update, delete, temp, metadata, and link modes.
- [x] Add tests for implication order and last-option-wins behavior.
- [x] Run `cargo test -p rsync-cli --test options --all-features`.
- [x] Commit: `feat: normalize rsync options into transfer plans`.

## Chunk 3: Local File Selection and Update Semantics

### Task 5: Implement Path Selection Options

**Files:**
- Modify: `crates/rsync-fs/src/walk.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `crates/rsync-fs/src/walk.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [x] Implement `--relative` / `-R`.
- [x] Implement `--no-implied-dirs`.
- [x] Implement `--dirs` / `-d`, `--old-dirs`, and `--old-d`.
- [x] Implement `--mkpath`.
- [x] Implement `--one-file-system` / `-x` using Windows volume/device identity where available.
- [x] Add local sync tests for each path-selection mode.
- [x] Run `cargo test -p rsync-fs --all-features walk`.
- [x] Run `cargo test -p rsync-cli --all-features relative`.
- [x] Commit: `feat: add rsync path selection modes`.

### Task 6: Implement Update Predicate Options

**Files:**
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `crates/rsync-fs/src/sync.rs`

- [x] Implement `--update` / `-u`.
- [x] Implement `--existing` and `--ignore-existing`.
- [x] Implement `--max-size` and `--min-size`.
- [x] Implement `--modify-window`.
- [x] Implement `--ignore-missing-args` and `--delete-missing-args`.
- [x] Add local tests that compare behavior against an upstream rsync fixture where practical.
- [x] Run `cargo test -p rsync-fs --all-features sync`.
- [x] Commit: `feat: add rsync update predicates`.

## Chunk 4: Delete, Backup, and Temporary File Behavior

### Task 7: Implement Delete Timing Family

**Files:**
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-fs/src/sync.rs`

- [x] Implement `--delete-before`.
- [x] Implement `--delete-during` and map plain `--delete` to the rsync-compatible default.
- [x] Implement `--delete-delay`.
- [x] Implement `--delete-after`.
- [x] Implement `--delete-excluded`.
- [x] Implement `--ignore-errors`, `--force`, and `--max-delete`.
- [x] Add tests for filter protection under each delete timing.
- [x] Run `cargo test -p rsync-fs --all-features delete`.
- [x] Commit: `feat: add rsync delete timing modes`.

### Task 8: Implement Backup and Temp File Options

**Files:**
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-fs/src/sync.rs`

- [x] Implement `--backup` / `-b`.
- [x] Implement `--backup-dir`.
- [x] Implement `--suffix`.
- [x] Implement `--temp-dir` / `-T`.
- [x] Implement `--delay-updates`.
- [x] Implement `--fsync`.
- [x] Verify partial/temp cleanup behavior after transfer failures.
- [x] Run `cargo test -p rsync-fs --all-features backup`.
- [x] Commit: `feat: add rsync backup and temp file modes`.

## Chunk 5: Full Filter Semantics

### Task 9: Complete Filter Input Options

**Files:**
- Modify: `crates/rsync-filter/src/rule.rs`
- Modify: `crates/rsync-filter/src/matcher.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-filter/src/rule.rs`

- [x] Implement `--exclude-from`.
- [x] Implement `--include-from`.
- [x] Ensure `--from0` affects all relevant from-file options.
- [x] Implement `--cvs-exclude` / `-C`.
- [x] Implement `-F` shorthand behavior.
- [x] Add parser tests for blank lines, comments, escaping, and invalid records.
- [x] Run `cargo test -p rsync-filter --all-features`.
- [x] Commit: `feat: add rsync filter input options`.

### Task 10: Complete Filter Rule Grammar

**Files:**
- Modify: `crates/rsync-filter/src/rule.rs`
- Modify: `crates/rsync-filter/src/matcher.rs`
- Test: `crates/rsync-filter/src/rule.rs`
- Test: `crates/rsync-filter/src/matcher.rs`

- [x] Implement include, exclude, hide, show, protect, risk, clear-list, merge, and dir-merge rules.
- [x] Implement sender-side and receiver-side rule modifiers.
- [x] Implement anchoring, directory-only matching, perishable rules, and double-star behavior.
- [x] Add tests mirroring upstream filter examples.
- [x] Run `cargo test -p rsync-filter --all-features`.
- [x] Commit: `feat: complete rsync filter rule grammar`.

## Chunk 6: Links, Hardlinks, Devices, and Special Files

### Task 11: Implement Symlink Mode Family

**Files:**
- Modify: `crates/rsync-fs/src/walk.rs`
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-winfs/src/links.rs`
- Test: `crates/rsync-fs/src/sync.rs`

- [x] Implement `--links` / `-l`.
- [x] Finish `--copy-links` / `-L`.
- [x] Implement `--copy-dirlinks` / `-k`.
- [x] Implement `--keep-dirlinks` / `-K`.
- [x] Finish `--safe-links` and `--copy-unsafe-links`.
- [x] Implement `--munge-links`.
- [x] Add tests for Windows symlink capability errors and remote POSIX symlink behavior.
- [x] Run `cargo test --workspace --all-features links`.
- [x] Commit: `feat: add rsync symlink modes`.

### Task 12: Implement Hardlink Preservation

**Files:**
- Modify: `crates/rsync-fs/src/metadata.rs`
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-winfs/src/links.rs`
- Test: `crates/rsync-fs/src/sync.rs`

- [x] Implement `--hard-links` / `-H` for local Windows volumes where hardlinks are supported.
- [x] Represent hardlink groups in remote file lists.
- [x] Add tests for same-volume hardlinks and cross-volume degradation.
- [x] Run `cargo test --workspace --all-features hard_links`.
- [x] Commit: `feat: preserve hardlink groups`.

### Task 13: Implement Devices and Special Files as Capability-Gated Features

**Files:**
- Modify: `crates/rsync-fs/src/metadata.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Modify: `crates/rsync-winfs/src/sidecar.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [x] Implement option handling for `--devices`, `--specials`, `-D`, `--copy-devices`, and `--write-devices`.
- [x] Use sidecar metadata or explicit diagnostics on Windows when native creation is unavailable.
- [x] Route device/special metadata correctly for remote POSIX peers.
- [x] Add tests for capability reporting and `--fail-on-metadata-loss`.
- [x] Run `cargo test --workspace --all-features devices`.
- [x] Commit: `feat: add device and special file capability handling`.

## Chunk 7: POSIX and Windows Metadata Fidelity

### Task 14: Complete Mode and Chmod Semantics

**Files:**
- Modify: `crates/rsync-core/src/chmod.rs`
- Modify: `crates/rsync-core/src/lib.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-core/src/chmod.rs`

- [x] Implement full rsync `--chmod` symbolic and numeric grammar.
- [x] Implement `--perms`, `--executability` / `-E`, and `--omit-dir-times` / `-O`.
- [x] Preserve existing truthful Windows diagnostics.
- [x] Add upstream example tests for chmod forms.
- [x] Run `cargo test -p rsync-core --all-features chmod`.
- [x] Commit: `feat: complete chunk7 metadata support`.

### Task 15: Implement Owner, Group, and ID Mapping

**Files:**
- Modify: `crates/rsync-core/src/lib.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [x] Implement `--owner`, `--group`, and `--numeric-ids`.
- [x] Implement `--usermap`, `--groupmap`, and `--chown`.
- [x] Implement remote peer ID/name list handling where required by protocol.
- [x] Add Windows sidecar or explicit degradation for local ownership.
- [x] Run `cargo test --workspace --all-features owner groupmap`.
- [x] Commit: `feat: complete chunk7 metadata support`.

### Task 16: Implement ACL, Xattr, Fake-Super, and Time Metadata

**Files:**
- Modify: `crates/rsync-core/src/lib.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-winfs/src/security.rs`
- Modify: `crates/rsync-winfs/src/streams.rs`
- Modify: `crates/rsync-winfs/src/sidecar.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [x] Implement `--acls` / `-A` protocol payload handling.
- [x] Implement `--xattrs` / `-X` protocol payload handling.
- [x] Implement `--fake-super` storage and restore semantics.
- [x] Implement `--atimes` / `-U` and `--crtimes` / `-N` where Windows APIs permit.
- [x] Implement `--omit-link-times` / `-J`.
- [x] Add tests for sidecar roundtrip and remote POSIX peer transfer.
- [x] Run `cargo test --workspace --all-features metadata`.
- [x] Commit: `feat: complete chunk7 metadata support`.

## Chunk 8: Delta Transfer, Checksums, and Compression

### Task 17: Implement Real Delta Transfer

**Files:**
- Modify: `crates/rsync-delta/src/*`
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `crates/rsync-delta/src/lib.rs`

- [x] Wire rolling checksum signatures into local and remote update paths.
- [x] Implement basis file block request and copy-token apply paths.
- [x] Implement `--block-size` / `-B`.
- [x] Keep `--whole-file` / `-W` as an explicit bypass.
- [x] Add large-file delta tests proving less data is sent for small edits.
- [x] Run `cargo test -p rsync-delta --all-features`.
- [x] Run `cargo test -p rsync-cli --all-features delta`.
- [x] Commit: `feat: complete chunk8 delta checksum compression`.

### Task 18: Implement Checksum Negotiation Options

**Files:**
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-core/src/lib.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-protocol/src/session.rs`

- [x] Implement `--checksum-choice` / `--cc`.
- [x] Implement `--checksum-seed`.
- [x] Preserve `--checksum` / `-c` as update predicate behavior.
- [x] Add tests for negotiation success, unsupported lists, and fallback.
- [x] Run `cargo test -p rsync-protocol --all-features checksum`.
- [x] Commit: `feat: complete chunk8 delta checksum compression`.

### Task 19: Implement Compression Options

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-protocol/src/session.rs`

- [x] Implement actual `--compress` / `-z`.
- [x] Implement `--compress-choice` / `--zc`.
- [x] Implement `--compress-level` / `--zl`.
- [x] Implement `--compress-threads` / `--zt` if the selected algorithm supports it.
- [x] Implement `--skip-compress`.
- [x] Add tests for negotiation, compression bypass, and corrupt stream handling.
- [x] Run `cargo test -p rsync-protocol --all-features compress`.
- [x] Commit: `feat: complete chunk8 delta checksum compression`.

## Chunk 9: Remote-Shell Completeness

### Task 20: Add Remote-Shell Transport Options

**Files:**
- Modify: `crates/rsync-transport/src/remote_shell.rs`
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [x] Implement `--rsync-path`.
- [x] Implement `--remote-option` / `-M`.
- [x] Implement `--blocking-io`.
- [x] Implement `--old-args` and `--secluded-args` / `-s`.
- [x] Implement `--ipv4` / `-4` and `--ipv6` / `-6` where transport supports it.
- [x] Add command-construction tests with paths containing spaces and shell metacharacters.
- [x] Run `cargo test -p rsync-cli --all-features remote_shell`.
- [x] Run SSH smoke against `root@192.168.100.181:/root/rsync-test/` with `--rsync-path`, `--blocking-io`, `--ipv4`, `--trust-sender`, and true `--secluded-args` protected arg streaming using paths with spaces/shell metacharacters; cleaned remote and local test directories.
- [x] Commit: `feat: add remote-shell transport options and trust-sender gating` (combined chunk9 commit).

### Task 21: Harden Remote Peer Trust Semantics

**Files:**
- Modify: `crates/rsync-cli/src/lib.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [x] Implement `--trust-sender`.
- [x] Keep strict default remote file-list validation.
- [x] Add malicious peer tests for extra source args, filter violations, absolute paths, parent escapes, reserved Windows names, and case collisions.
- [x] Run `cargo test --workspace --all-features trust_sender`.
- [x] Commit: `feat: add remote-shell transport options and trust-sender gating` (combined chunk9 commit).

## Chunk 10: Daemon Client and Daemon Server

### Task 22: Complete Daemon Client Pull and Push

**Files:**
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `crates/rsync-transport/src/tcp.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `tests/interop/daemon.rs`

- [ ] Finish daemon pull for all implemented file/update/filter/metadata options.
- [ ] Implement daemon push to writable modules.
- [x] Implement `--password-file`, `RSYNC_PASSWORD`, auth user handling, and no-secret logging tests.
- [ ] Implement `--address`, `--port`, `--sockopts`, `--contimeout`, and `--no-motd`.
- [ ] Implement `RSYNC_PROXY` and `RSYNC_CONNECT_PROG` if in scope for full compatibility.
- [x] Run `cargo test -p rsync-cli --test daemon --all-features`.
- [ ] Commit: `feat: complete daemon client mode`.

### Task 23: Implement Daemon Server Mode

**Files:**
- Modify: `crates/rsync-cli/src/options.rs`
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Create: `crates/rsync-cli/src/daemon_server.rs`
- Test: `tests/interop/daemon.rs`

- [ ] Implement `--daemon`.
- [ ] Implement `--config`.
- [ ] Implement `--dparam` / `-M`.
- [ ] Implement `--no-detach`.
- [ ] Implement daemon `--log-file`, `--log-file-format`, `--address`, `--port`, `--sockopts`, `--ipv4`, `--ipv6`, and `--bwlimit`.
- [ ] Add a minimal safe module config parser and explicit unsupported diagnostics for advanced config keys not yet implemented.
- [ ] Add local daemon-server integration tests using a disposable module root.
- [ ] Run `cargo test -p rsync-cli --test daemon --all-features`.
- [ ] Commit: `feat: add rsync daemon server mode`.

## Chunk 11: Output, Logging, and Exit Codes

### Task 24: Implement Rsync Output Controls

**Files:**
- Create: `crates/rsync-cli/src/output.rs`
- Modify: `crates/rsync-cli/src/lib.rs`
- Test: `crates/rsync-cli/src/output.rs`

- [ ] Implement `--verbose` / `-v`, `--quiet` / `-q`, and repeated verbosity levels.
- [ ] Implement `--info` and `--debug`.
- [ ] Implement `--stderr`.
- [ ] Implement `--human-readable` / `-h` and `--8-bit-output` / `-8`.
- [ ] Implement `--progress` and `--out-format`.
- [ ] Preserve existing `--stats` and `--itemize-changes` while aligning field formats with rsync.
- [ ] Run `cargo test -p rsync-cli --all-features output`.
- [ ] Commit: `feat: align rsync output controls`.

### Task 25: Implement Logging and Exit Code Mapping

**Files:**
- Modify: `crates/rsync-cli/src/output.rs`
- Modify: `crates/rsync-cli/src/main.rs`
- Test: `crates/rsync-cli/src/output.rs`

- [ ] Implement `--log-file` and `--log-file-format`.
- [ ] Map errors to rsync-compatible exit codes.
- [ ] Add tests for syntax errors, file IO errors, protocol errors, partial transfer, timeout, and daemon auth failures.
- [ ] Run `cargo test -p rsync-cli --all-features exit_code log_file`.
- [ ] Commit: `feat: add rsync logging and exit codes`.

## Chunk 12: Advanced Transfer Features

### Task 26: Implement Destination Comparison Options

**Files:**
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-fs/src/sync.rs`

- [ ] Implement `--compare-dest`.
- [ ] Implement `--copy-dest`.
- [ ] Implement `--link-dest`.
- [ ] Add tests for relative and absolute comparison directories.
- [ ] Run `cargo test -p rsync-fs --all-features dest`.
- [ ] Commit: `feat: add compare copy and link dest modes`.

### Task 27: Implement Sparse, Preallocation, Fuzzy, and Copy-As

**Files:**
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-winfs/src/metadata.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-fs/src/sync.rs`

- [ ] Implement `--sparse` / `-S`.
- [ ] Implement `--preallocate`.
- [ ] Implement `--fuzzy` / `-y`.
- [ ] Implement `--copy-as` and `--super` capability behavior.
- [ ] Add Windows-specific tests for sparse/preallocation where APIs permit.
- [ ] Run `cargo test --workspace --all-features sparse fuzzy`.
- [ ] Commit: `feat: add advanced file allocation modes`.

### Task 28: Implement Batch Mode

**Files:**
- Modify: `crates/rsync-protocol/src/session.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Create: `crates/rsync-cli/src/batch.rs`
- Test: `crates/rsync-cli/src/batch.rs`

- [ ] Implement `--write-batch`.
- [ ] Implement `--only-write-batch`.
- [ ] Implement `--read-batch`.
- [ ] Record options, filters, file-list metadata, checksums, and token streams needed for replay.
- [ ] Add tests for writing and replaying a batch against a changed destination.
- [ ] Run `cargo test -p rsync-cli --all-features batch`.
- [ ] Commit: `feat: add rsync batch mode`.

## Chunk 13: Resource Limits and Operational Controls

### Task 29: Implement Bandwidth, Timeout, and Stop Options

**Files:**
- Modify: `crates/rsync-transport/src/lib.rs`
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `crates/rsync-cli/src/lib.rs`

- [ ] Implement `--bwlimit`.
- [ ] Implement `--timeout`.
- [ ] Implement `--stop-after`.
- [ ] Implement `--stop-at`.
- [ ] Implement `--max-alloc`.
- [ ] Add deterministic tests with fake clocks or injectable throttlers.
- [ ] Run `cargo test --workspace --all-features limits`.
- [ ] Commit: `feat: add rsync operational limits`.

### Task 30: Implement Remaining Compatibility Toggles

**Files:**
- Modify: `crates/rsync-cli/src/options.rs`
- Modify: `crates/rsync-cli/src/plan.rs`
- Test: `tests/compat/options.rs`

- [ ] Implement `--protocol` mode negotiation gating.
- [ ] Implement `--iconv` or explicit platform-scoped diagnostic if charset conversion is unavailable.
- [ ] Implement `--open-noatime` with capability fallback.
- [ ] Implement `--outbuf`.
- [ ] Implement `--early-input`.
- [x] Ensure all registry options have a non-placeholder implementation status.
- [x] Run `cargo test -p rsync-cli --test options --all-features`.
- [ ] Commit: `feat: handle remaining rsync compatibility toggles`.

## Chunk 14: Interop, Security, and Release Gates

### Task 31: Add Upstream Rsync Interop Matrix

**Files:**
- Create: `tests/interop/rsync_compat.rs`
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`

- [x] Add gated fixture variables for upstream rsync over SSH.
- [x] Add optional fixture variables for older rsync-compatible peers, macOS stock rsync, openrsync, Cygwin/MSYS2, and daemon server fixtures.
- [x] Add smoke cases for every option family, grouped so unsupported external fixtures skip cleanly.
- [x] Run `cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture` with at least one upstream fixture.
- [ ] Commit: `test: add upstream rsync compatibility matrix`.

### Task 32: Add Security and Fuzz Regression Suites

**Files:**
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `crates/rsync-protocol/src/session.rs`
- Create: `tests/security/remote_peer.rs`

- [x] Add malicious file-list tests for parent escapes, absolute paths, Windows prefixes, reserved names, trailing dots/spaces, Unicode normalization collisions, excessive counts, and excessive path lengths.
- [ ] Add malformed token stream tests for overrun, underrun, bad checksum, unsupported multiplex frames, and corrupt compression frames.
- [ ] Add symlink/hardlink race tests where feasible.
- [x] Run `cargo test --workspace --all-features security`.
- [ ] Commit: `test: add full compatibility security regressions`.

### Task 33: Update Documentation and Compatibility Claims

**Files:**
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/ROADMAP.md`

- [ ] Generate a table of all upstream options with status: implemented, remote-only, daemon-only, sidecar, capability-gated, or explicit error.
- [x] Document Windows-specific behavior for POSIX metadata, device files, symlinks, hardlinks, ACLs, xattrs, VSS, ADS, and reparse points.
- [x] Document interop fixture requirements.
- [ ] Remove outdated "development subset" claims only after tests prove full parsing and option-family behavior.
- [x] Run `cargo test --workspace --all-features`.
- [ ] Commit: `docs: document full rsync compatibility status`.

### Task 34: Final Release Gate

**Files:**
- Modify: `scripts/package-release.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`

- [x] Ensure CI runs parser golden tests, workspace tests, clippy, formatting, and package smoke tests.
- [x] Add release package smoke test for `rsync-win.exe --version`, `--help`, and a disposable local sync.
- [x] Verify release zip contains executable, licenses, README, compatibility matrix, third-party notices, and option status table.
- [x] Run final local verification:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
cargo bench -p rsync-fs --bench local_sync
```

- [ ] Run gated interop verification with configured upstream rsync/daemon fixtures.
- [ ] Commit: `ci: gate release on full compatibility checks`.

## Go/No-Go Gates

1. Do not implement broad behavior changes before Chunk 1 and Chunk 2 make the full option surface measurable.
2. Do not mark an option implemented just because it parses; it must have behavior tests or an explicit capability/error path.
3. Do not pass unknown options through to remote rsync except through documented `--remote-option` semantics.
4. Do not claim `-a` compatibility until symlink, permission, owner, group, device, special, and time components are either implemented or truthfully degraded.
5. Do not enable daemon server mode outside controlled roots until auth, module config, path validation, and logging are tested.
6. Do not ship complete compatibility without at least one real upstream rsync interop fixture passing the smoke matrix.

## Verification Matrix

Run after each chunk:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
```

Run before compatibility milestone tags:

```powershell
cargo bench -p rsync-fs --bench local_sync
$env:RSYNC_WIN_SSH_TARGET = "user@host"
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
$env:RSYNC_WIN_DAEMON_URL = "rsync://host:873"
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

## Completion Criteria

- Every upstream rsync client long option is present in the registry and accepted by the parser.
- Every upstream rsync client short option and supported short-option cluster form is accepted.
- Every daemon/server option is accepted in the correct mode and rejected in incorrect modes with useful diagnostics.
- The option status table has no unknown or unclassified entries.
- Common upstream workflows pass against real upstream rsync over local, SSH, and daemon transports.
- Windows-specific limitations are represented through sidecar, capability-gated behavior, or explicit errors instead of silent loss.
