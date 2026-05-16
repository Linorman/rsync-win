# Rsync-Win 下一步发行级开发计划 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐当前开发版距离 Windows rsync 发行版仍缺失的功能、互操作证据、安全门禁和发布工程，使后续版本可以被诚实地定位为 release-grade Windows rsync-compatible distribution。

**Architecture:** 不重做已经通过的本地同步、基础打包和现有模块拆分工作。计划只处理当前仍未完成或仍被文档标为 experimental、planned、portable-only、best-effort 的 release blocker，并要求每个 blocker 都以测试或发布门禁关闭。

**Tech Stack:** Rust 2021, Cargo workspace, Windows MSVC, PowerShell, GitHub Actions, upstream rsync over SSH, upstream rsync daemon fixtures, NTFS capability tests.

---

## 当前起点

以下能力已经存在，不再作为本计划任务重复开发：

- Windows/MSVC 下 `cargo test --workspace --all-features` 可以通过。
- `cargo fmt --all -- --check` 和 `cargo clippy --workspace --all-features -- -D warnings` 可以通过。
- `scripts/package-release.ps1` 可以生成 zip 和 sha256，并验证 `--version`、`--help`、本地 sync smoke、delete/filter smoke。
- 本地 portable sync 已覆盖普通文件、目录、递归、mtime、删除、filter、files-from、update modes、partial/inplace/append-verify、部分 NTFS sidecar。
- `docs/COMPATIBILITY.md` 和 `docs/OPTION-STATUS.md` 已经保守记录当前能力。

本计划只处理下一步缺口：

- 外部 upstream rsync/daemon 互操作不能在 release 中静默 skip。
- remote-shell push 仍拒绝 `--delete + --files-from`。
- remote-shell push 仍缺少完整 sender-side incremental recursion。
- remote-shell/daemon 执行路径仍只允许 `--metadata-policy=portable`。
- `--remove-source-files` 和 `--prune-empty-dirs` 仍是 Planned。
- daemon server 仍是安全模块子集，配置兼容和发布承诺不足。
- NTFS-native/VSS 仍需要发行级能力探测和端到端验证。
- 安全/fuzz/大规模性能门禁还没有成为 release blocker。
- Windows 发行包还缺少签名、依赖清单、安装渠道和完整 release audit。

## Target File Structure

### Interop Release Gate

- Modify: `tests/common/mod.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/interop/daemon.rs`
- Modify: `.github/workflows/release.yml`
- Create: `scripts/run-release-interop.ps1`
- Create: `scripts/write-release-fixture-report.ps1`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/RELEASE-NOTES-TEMPLATE.md`

### Remote Shell Gaps

- Modify: `crates/rsync-cli/src/app/tests/remote.rs`
- Modify: `crates/rsync-cli/src/plan/diagnostics.rs`
- Modify: `crates/rsync-cli/src/plan/remote_args.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-cli/src/remote/flist.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/stress/large_tree.rs`

### Metadata And Planned Options

- Modify: `crates/rsync-cli/src/app/tests/local.rs`
- Modify: `crates/rsync-cli/src/app/tests/remote.rs`
- Modify: `crates/rsync-cli/src/plan/diagnostics.rs`
- Modify: `crates/rsync-cli/src/execute/local.rs`
- Modify: `crates/rsync-cli/src/execute/remote_shell.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/COMPATIBILITY.md`

### Daemon And Windows Fidelity

- Modify: `crates/rsync-cli/src/daemon_server/mod.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `crates/rsync-winfs/src/metadata.rs`
- Modify: `crates/rsync-winfs/src/security.rs`
- Modify: `crates/rsync-winfs/src/streams.rs`
- Modify: `crates/rsync-winfs/src/vss.rs`
- Modify: `tests/interop/daemon.rs`
- Create: `tests/interop/ntfs_native.rs`
- Modify: `crates/rsync-cli/Cargo.toml`

### Release Hardening

- Modify: `tests/security/remote_peer.rs`
- Create: `tests/fuzz/rsync_protocol_fuzz.rs`
- Create: `tests/fuzz/README.md`
- Create: `scripts/run-release-benchmarks.ps1`
- Create: `scripts/generate-sbom.ps1`
- Create: `scripts/sign-release.ps1`
- Modify: `scripts/package-release.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `tests/compat/release_readiness.rs`
- Create: `docs/RELEASE-CHECKLIST.md`

---

### Task 1: 让外部互操作成为 Release 必跑门禁

**Files:**
- Modify: `tests/common/mod.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/interop/daemon.rs`
- Create: `scripts/run-release-interop.ps1`
- Create: `scripts/write-release-fixture-report.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: 添加 release-required fixture helper**

在 `tests/common/mod.rs` 中添加：

```rust
pub fn release_interop_required() -> bool {
    std::env::var("RSYNC_WIN_RELEASE_INTEROP_REQUIRED")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub fn skip_or_fail_external_test(name: &str, reason: Option<&str>) {
    let detail = reason.unwrap_or("external fixture is not configured");
    if release_interop_required() {
        panic!("release interop fixture `{name}` is required but unavailable: {detail}");
    }
    skip_external_test(name, Some(detail));
}
```

- [ ] **Step 2: 替换 SSH fixture skip 分支**

在 `tests/interop/rsync_compat.rs` 的 `ssh_fixture_from_env` 中，把缺失目标或缺失 `ssh` 的分支改为：

```rust
skip_or_fail_external_test(name, Some(missing_message));
return None;
```

缺失 `ssh` 工具时使用：

```rust
skip_or_fail_external_test(name, tools.ssh.reason());
return None;
```

- [ ] **Step 3: 替换 daemon fixture skip 分支**

在 `tests/interop/daemon.rs` 中，对 `RSYNC_WIN_DAEMON_URL`、module、auth user、password-file、writable module 的缺失分支使用同一个 helper。release-required 模式下必须 panic，普通开发模式仍 skip。

- [ ] **Step 4: 新增 release interop runner**

创建 `scripts/run-release-interop.ps1`：

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$env:RSYNC_WIN_RELEASE_INTEROP_REQUIRED = "1"

cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

- [ ] **Step 5: 新增 fixture report**

创建 `scripts/write-release-fixture-report.ps1`：

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$vars = @(
    "RSYNC_WIN_SSH_TARGET",
    "RSYNC_WIN_SSH_PROTOCOL27_TARGET",
    "RSYNC_WIN_MACOS_RSYNC_TARGET",
    "RSYNC_WIN_OPENRSYNC_TARGET",
    "RSYNC_WIN_CYGWIN_TARGET",
    "RSYNC_WIN_MSYS2_TARGET",
    "RSYNC_WIN_DAEMON_URL",
    "RSYNC_WIN_DAEMON_MODULE",
    "RSYNC_WIN_DAEMON_PATH",
    "RSYNC_WIN_DAEMON_AUTH_MODULE",
    "RSYNC_WIN_DAEMON_AUTH_PATH",
    "RSYNC_WIN_DAEMON_WRITABLE_MODULE",
    "RSYNC_WIN_DAEMON_USER",
    "RSYNC_WIN_DAEMON_PASSWORD_FILE"
)

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null
$lines = @("# Release Fixture Report", "")
foreach ($name in $vars) {
    $value = [Environment]::GetEnvironmentVariable($name)
    $state = if ([string]::IsNullOrWhiteSpace($value)) { "missing" } else { "configured" }
    $lines += "- ${name}: ${state}"
}

if (-not [string]::IsNullOrWhiteSpace($env:RSYNC_WIN_SSH_TARGET)) {
    $version = & ssh -o BatchMode=yes -o ConnectTimeout=10 $env:RSYNC_WIN_SSH_TARGET "rsync --version | head -n 1" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $lines += "- upstream ssh rsync: $($version -join ' ')"
    } else {
        $lines += "- upstream ssh rsync: version probe failed"
    }
}

$lines | Set-Content -Path $OutputPath -Encoding utf8
```

- [ ] **Step 6: 接入 release workflow**

在 `.github/workflows/release.yml` 的测试步骤之后、build 之前加入：

```yaml
      - name: Release fixture report
        shell: pwsh
        run: .\scripts\write-release-fixture-report.ps1 -OutputPath dist\release-fixtures.md

      - name: Required release interop
        shell: pwsh
        run: .\scripts\run-release-interop.ps1
```

- [ ] **Step 7: 验证 release-required 缺失 fixture 会失败**

运行：

```powershell
$env:RSYNC_WIN_RELEASE_INTEROP_REQUIRED = "1"
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
Remove-Item Env:\RSYNC_WIN_RELEASE_INTEROP_REQUIRED
```

Expected: 第一条测试在没有配置 `RSYNC_WIN_SSH_TARGET` 时失败，并输出缺失 fixture 名称。

- [ ] **Step 8: 验证普通开发模式仍可 skip**

运行：

```powershell
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
```

Expected: 未配置 fixture 时测试通过并打印 skip 原因。

- [ ] **Step 9: 更新兼容矩阵**

在 `docs/COMPATIBILITY.md` 的 Release Support Matrix 中把 upstream rsync 目标改为：

```markdown
| Upstream rsync versions | upstream rsync 3.4.x and 3.2.x over SSH are release-grade targets. A release-grade build must run the external fixture matrix with `RSYNC_WIN_RELEASE_INTEROP_REQUIRED=1`; preview builds may skip unavailable fixtures. |
```

- [ ] **Step 10: 提交**

```powershell
git add tests/common/mod.rs tests/interop/rsync_compat.rs tests/interop/daemon.rs scripts/run-release-interop.ps1 scripts/write-release-fixture-report.ps1 .github/workflows/release.yml docs/COMPATIBILITY.md
git commit -m "test: require external interop for release builds"
```

---

### Task 2: 修复 Remote Push 的 `--delete + --files-from`

**Files:**
- Modify: `crates/rsync-cli/src/app/tests/remote.rs`
- Modify: `crates/rsync-cli/src/plan/diagnostics.rs`
- Modify: `crates/rsync-cli/src/plan/remote_args.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: 写失败的计划层测试**

在 `crates/rsync-cli/src/app/tests/remote.rs` 中新增：

```rust
#[test]
fn remote_push_delete_with_files_from_is_supported() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-rt",
        "--delete",
        "--files-from=list.txt",
        "src/",
        "host:/dest/",
    ]);

    assert!(output.contains("remote direction: upload"));
    assert!(output.contains("files-from: list.txt"));
    assert!(!output.contains("remote-shell push does not yet support --delete together with --files-from"));
}
```

- [ ] **Step 2: 运行测试确认当前失败**

```powershell
cargo test -p rsync-cli remote_push_delete_with_files_from_is_supported --all-features
```

Expected: 当前失败，因为 `ensure_remote_execution_options_supported` 仍拒绝该组合。

- [ ] **Step 3: 删除硬拒绝**

从 `crates/rsync-cli/src/plan/diagnostics.rs` 删除：

```rust
if plan.remote_direction == Some(TransferDirection::Push)
    && cli.delete
    && cli.files_from.is_some()
{
    bail!(
        "remote-shell push does not yet support --delete together with --files-from because receiver-side files-from semantics are not implemented"
    );
}
```

- [ ] **Step 4: 确保 sender file-list 只包含 files-from 选择**

在 `crates/rsync-cli/src/remote/push.rs` 中定位本地 file-list 收集入口。确认它使用 `load_files_from(cli)` 的结果。如果当前路径没有传递 files-from，新增参数传递，使 sender 只发送 files-from 指定的文件和必要父目录。

新增断言测试应覆盖：

```rust
assert!(output.contains("files-from: list.txt"));
assert!(output.contains("remote --server argv:"));
```

- [ ] **Step 5: 保护 receiver 上不在 files-from 中的路径**

在 `crates/rsync-cli/src/plan/remote_args.rs` 中，为 push receiver argv 添加 delete 保护规则。规则要求：

- files-from 选中路径可以被更新。
- files-from 必要父目录保留。
- 未选中路径不能因为 `--delete` 被删除。

计划层输出必须仍包含 delete mode，并且不再出现拒绝诊断。

- [ ] **Step 6: 加 upstream manifest 互操作用例**

在 `tests/interop/rsync_compat.rs` 的 push case 列表中加入：

```rust
PushManifestCase {
    name: "push-delete-files-from",
    win_options: vec![
        "-rt".to_string(),
        "--delete".to_string(),
        "--files-from".to_string(),
        push_files_from_arg.clone(),
    ],
    upstream_options: vec![
        "-rt".to_string(),
        "--delete".to_string(),
        format!("--files-from={remote_push_files_from}"),
    ],
    win_sources: vec![local_source_arg.clone()],
    upstream_sources: vec![remote_source_arg.clone()],
    prepopulate: vec![
        ("stale.txt", "delete-me"),
        ("drop.tmp", "receiver-protected"),
    ],
}
```

- [ ] **Step 7: 更新兼容文档**

在 `docs/COMPATIBILITY.md` 的 Hardening Status 中把：

```markdown
Remote push routes include/exclude/filter rules to the remote receiver for delete protection; `--files-from` is not routed to the receiver yet.
```

改为：

```markdown
Remote push routes include/exclude/filter and files-from selection to the remote receiver so delete protection is scoped to the selected sender set.
```

- [ ] **Step 8: 验证**

```powershell
cargo test -p rsync-cli remote_push_delete_with_files_from_is_supported --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test --workspace --all-features
```

Expected: 本地测试通过；外部 fixture 未配置时普通模式 skip，release-required 模式必须真实通过。

- [ ] **Step 9: 提交**

```powershell
git add crates/rsync-cli/src/app/tests/remote.rs crates/rsync-cli/src/plan/diagnostics.rs crates/rsync-cli/src/plan/remote_args.rs crates/rsync-cli/src/remote/push.rs tests/interop/rsync_compat.rs docs/COMPATIBILITY.md
git commit -m "feat(remote): support push delete with files-from"
```

---

### Task 3: 实现 Remote Push 的 Sender-Side Incremental Recursion

**Files:**
- Modify: `crates/rsync-cli/src/app/tests/remote.rs`
- Modify: `crates/rsync-cli/src/plan/mod.rs`
- Modify: `crates/rsync-cli/src/plan/remote_args.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `tests/stress/large_tree.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`

- [ ] **Step 1: 写计划层失败测试**

在 `crates/rsync-cli/src/app/tests/remote.rs` 新增：

```rust
#[test]
fn remote_push_inc_recursive_does_not_force_no_inc_recursive() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-r",
        "--inc-recursive",
        "src/",
        "host:/dest/",
    ]);

    assert!(output.contains("remote direction: upload"));
    assert!(output.contains("incremental recursion: true"));
    assert!(!output.contains("--no-inc-recursive"));
    assert!(!output.contains("W_INC_RECURSIVE_PUSH_DISABLED"));
}
```

- [ ] **Step 2: 运行测试确认当前失败**

```powershell
cargo test -p rsync-cli remote_push_inc_recursive_does_not_force_no_inc_recursive --all-features
```

Expected: 当前失败，因为 push 路径仍警告并强制 upstream receiver 使用 `--no-inc-recursive`。

- [ ] **Step 3: 修正 TransferPlan incremental_recursion**

在 `crates/rsync-cli/src/plan/mod.rs` 中，把 `incremental_recursion` 从只允许 remote pull 改为：

```rust
let incremental_recursion =
    requested_incremental_recursion && remote_direction.is_some();
```

删除或改写 `W_INC_RECURSIVE_PUSH_DISABLED` 警告，使它只在协议不支持时出现。

- [ ] **Step 4: 修正 remote argv**

在 `crates/rsync-cli/src/plan/remote_args.rs` 中，确保 push 使用 protocol 31 且 `plan.incremental_recursion` 为 true 时不添加 `--no-inc-recursive`。

同时保留显式 `--no-inc-recursive` 的用户选择：

```rust
if cli.no_inc_recursive {
    argv.push("--no-inc-recursive".to_string());
}
```

- [ ] **Step 5: 扩展 file-list batch writer**

在 `crates/rsync-protocol/src/flist.rs` 中增加测试，证明 batched file-list 与单次 file-list 编码的条目等价，并且 batch index 连续。

测试名：

```rust
#[test]
fn protocol31_incremental_push_batches_round_trip_with_stable_indexes() {
    // build entries, write batches, read batches, assert paths and indexes are stable
}
```

- [ ] **Step 6: 更新 push session**

在 `crates/rsync-cli/src/remote/push.rs` 中，发送 file-list 时使用增量 batch 终止标记，而不是先完整 materialize 全量 file-list。保留现有 max entry 和 max path 限制。

- [ ] **Step 7: 添加 stress test**

在 `tests/stress/large_tree.rs` 中新增：

```rust
#[test]
fn protocol31_push_incremental_recursion_streams_large_file_list() {
    let temp = FixtureTempDir::new("rsync-win-inc-recursive-push").unwrap();
    let source = temp.path().join("source");
    create_many_small_files(&source, 2_000).unwrap();

    let output = rsync_cli::parse_and_render([
        "rsync-win",
        "--plan",
        "-r",
        "--inc-recursive",
        source.to_string_lossy().as_ref(),
        "host:/dest/",
    ]);

    assert!(output.contains("incremental recursion: true"));
    assert!(!output.contains("--no-inc-recursive"));
}
```

- [ ] **Step 8: 添加 upstream 互操作 case**

在 `tests/interop/rsync_compat.rs` push matrix 加入 `--inc-recursive` case，使用嵌套目录和至少 100 个文件，比对 upstream manifest。

- [ ] **Step 9: 更新文档和选项状态**

在 `docs/COMPATIBILITY.md` 删除 remote push sender-side incremental recursion 未实现条目。
在 `docs/OPTION-STATUS.md` 把 `--inc-recursive` 描述改为：

```markdown
| Partially implemented by mode | `--i-r`, `--inc-recursive`, `--no-i-r`, `--no-inc-recursive` (protocol 31 remote pull and push; older protocol fallback remains best-effort) |
```

- [ ] **Step 10: 验证**

```powershell
cargo test -p rsync-cli remote_push_inc_recursive_does_not_force_no_inc_recursive --all-features
cargo test -p rsync-cli --test large_tree --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
```

- [ ] **Step 11: 提交**

```powershell
git add crates/rsync-cli/src/app/tests/remote.rs crates/rsync-cli/src/plan crates/rsync-cli/src/remote/push.rs crates/rsync-protocol/src/flist.rs tests/stress/large_tree.rs tests/interop/rsync_compat.rs docs/COMPATIBILITY.md docs/OPTION-STATUS.md
git commit -m "feat(remote): support incremental recursion for push"
```

---

### Task 4: 放开并验证 Remote/Daemon 的 POSIX Metadata 执行子集

**Files:**
- Modify: `crates/rsync-cli/src/app/tests/remote.rs`
- Modify: `crates/rsync-cli/src/app/tests/daemon.rs`
- Modify: `crates/rsync-cli/src/plan/diagnostics.rs`
- Modify: `crates/rsync-cli/src/remote/push.rs`
- Modify: `crates/rsync-cli/src/remote/flist.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-protocol/src/flist.rs`
- Modify: `tests/interop/rsync_compat.rs`
- Modify: `tests/interop/daemon.rs`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`

- [ ] **Step 1: 写 remote POSIX 计划层测试**

在 `crates/rsync-cli/src/app/tests/remote.rs` 新增：

```rust
#[test]
fn remote_push_allows_posix_metadata_policy_for_supported_upload_subset() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--metadata-policy=posix",
        "-rt",
        "--perms",
        "--executability",
        "--chmod=F755,D755",
        "src/",
        "host:/dest/",
    ]);

    assert!(output.contains("metadata policy: posix"));
    assert!(output.contains("remote direction: upload"));
    assert!(!output.contains("remote-shell MVP currently supports only --metadata-policy=portable"));
}
```

- [ ] **Step 2: 写 daemon POSIX 计划层测试**

在 `crates/rsync-cli/src/app/tests/daemon.rs` 新增：

```rust
#[test]
fn daemon_push_allows_posix_metadata_policy_for_supported_upload_subset() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--metadata-policy=posix",
        "-rt",
        "--perms",
        "--chmod=F755,D755",
        "src/",
        "rsync://host/module/dest/",
    ]);

    assert!(output.contains("metadata policy: posix"));
    assert!(output.contains("daemon direction: upload"));
    assert!(!output.contains("daemon client MVP currently supports only --metadata-policy=portable"));
}
```

- [ ] **Step 3: 运行测试确认当前失败**

```powershell
cargo test -p rsync-cli remote_push_allows_posix_metadata_policy_for_supported_upload_subset --all-features
cargo test -p rsync-cli daemon_push_allows_posix_metadata_policy_for_supported_upload_subset --all-features
```

Expected: 当前失败，因为执行 gate 仍 portable-only。

- [ ] **Step 4: 调整执行 gate**

在 `crates/rsync-cli/src/plan/diagnostics.rs` 中，把 remote 和 daemon 的 metadata policy 检查改为：

```rust
if cli.metadata_policy == CliMetadataPolicy::NtfsNative {
    bail!("remote and daemon execution do not support --metadata-policy=ntfs-native; use local Windows sync for NTFS-native metadata");
}
```

保留 VSS 在 remote/daemon 中拒绝。

- [ ] **Step 5: 限定 POSIX 支持子集**

在同一文件中新增检查：remote/daemon upload 支持 `--perms`、`--executability`、`--chmod`、`--numeric-ids`、`--usermap`、`--groupmap`、`--chown`；`--acls`、`--xattrs`、`--fake-super` 仍必须输出诊断，除非本任务同时实现并通过互操作测试。

- [ ] **Step 6: 确认 file-list metadata 编码**

在 `crates/rsync-cli/src/remote/flist.rs` 和 `crates/rsync-protocol/src/flist.rs` 中确认 outgoing file-list 包含：

- mode bits
- executability inference
- chmod application
- uid/gid mapping fields where protocol supports them

如果已有编码只在 plan 中存在，把 `--chmod` 应用移动到实际 sender file-list 构造路径。

- [ ] **Step 7: 增加 upstream SSH mode manifest case**

在 `tests/interop/rsync_compat.rs` 新增 push case：本地创建 `run.sh` 和 `plain.txt`，运行 `--metadata-policy=posix -rt --perms --executability --chmod=F755,D755`，远端通过 `stat -c "%a %n"` 收集 manifest，与 upstream rsync 对照。

- [ ] **Step 8: 增加 daemon upload case**

在 `tests/interop/daemon.rs` 新增 local daemon-server push，用 `--metadata-policy=posix -rt --perms --chmod=F755,D755` 上传普通文件，断言传输成功并且日志不出现 NTFS-native 承诺。

- [ ] **Step 9: 更新文档**

在 `docs/COMPATIBILITY.md` 写明 remote/daemon POSIX metadata 的发行级支持边界：

```markdown
Remote and daemon upload paths support the tested POSIX mode/executability/chmod subset. POSIX ACL, xattr, and fake-super fidelity remain sidecar/reporting behavior unless an interop fixture explicitly verifies peer restoration.
```

- [ ] **Step 10: 验证**

```powershell
cargo test -p rsync-cli remote_push_allows_posix_metadata_policy_for_supported_upload_subset --all-features
cargo test -p rsync-cli daemon_push_allows_posix_metadata_policy_for_supported_upload_subset --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
cargo test --workspace --all-features
```

- [ ] **Step 11: 提交**

```powershell
git add crates/rsync-cli/src/app/tests/remote.rs crates/rsync-cli/src/app/tests/daemon.rs crates/rsync-cli/src/plan/diagnostics.rs crates/rsync-cli/src/remote crates/rsync-cli/src/execute/daemon_client.rs crates/rsync-protocol/src/flist.rs tests/interop docs/COMPATIBILITY.md docs/OPTION-STATUS.md
git commit -m "feat(metadata): enable POSIX upload metadata subset"
```

---

### Task 5: 实现 `--remove-source-files`

**Files:**
- Modify: `crates/rsync-cli/src/options.rs`
- Modify: `crates/rsync-cli/src/cli.rs`
- Modify: `crates/rsync-cli/src/plan/mod.rs`
- Modify: `crates/rsync-cli/src/app/tests/local.rs`
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: 把 CLI 字段从 planned 接入执行计划**

在 `crates/rsync-cli/src/cli.rs` 加字段：

```rust
#[arg(skip)]
pub(crate) remove_source_files: bool,
```

在 `Default for Cli` 中设为 `false`。

- [ ] **Step 2: 解析 option**

在 `crates/rsync-cli/src/options.rs` 的 `apply_long_option` 中加入：

```rust
"remove-source-files" => cli.remove_source_files = true,
```

在 `apply_negated_option` 中加入：

```rust
"remove-source-files" => cli.remove_source_files = false,
```

- [ ] **Step 3: 增加计划字段**

在 `TransferPlan` 中加入：

```rust
pub(crate) remove_source_files: bool,
```

在 `TransferPlan::from_cli` 中赋值：

```rust
remove_source_files: cli.remove_source_files,
```

在 plan rendering 中输出：

```rust
output.push_str(&format!("remove source files: {}\n", plan.remove_source_files));
```

- [ ] **Step 4: 写本地执行测试**

在 `crates/rsync-cli/src/app/tests/local.rs` 新增：

```rust
#[test]
fn local_remove_source_files_deletes_only_transferred_files() {
    let temp = FixtureTempDir::new("rsync-win-remove-source-files").unwrap();
    let source = temp.path().join("source");
    let dest = temp.path().join("dest");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("move.txt"), b"move").unwrap();

    let output = parse_and_execute([
        "rsync-win",
        "-r",
        "--remove-source-files",
        source.to_string_lossy().as_ref(),
        dest.to_string_lossy().as_ref(),
    ])
    .unwrap();

    assert!(output.contains("remove source files: true"));
    assert!(!source.join("move.txt").exists());
    assert_eq!(std::fs::read(dest.join("move.txt")).unwrap(), b"move");
    assert!(source.exists(), "rsync --remove-source-files leaves directories");
}
```

- [ ] **Step 5: 实现 sync engine 删除源文件**

在 `crates/rsync-fs/src/sync.rs` 的 successful file write action 后，对成功传输的普通文件调用 source filesystem remove。必须满足：

- dry-run 不删除。
- 目录不删除。
- 未传输或传输失败的文件不删除。
- checksum/quick-check 跳过的文件不删除。

- [ ] **Step 6: 更新 option status**

在 `docs/OPTION-STATUS.md` 中把 `--remove-source-files` 从 Planned 移到 Partially implemented by mode，并说明 local ordinary-file path 已支持，remote/daemon 待互操作证明。

- [ ] **Step 7: 验证**

```powershell
cargo test -p rsync-cli local_remove_source_files_deletes_only_transferred_files --all-features
cargo test -p rsync-fs --all-features
cargo test --workspace --all-features
```

- [ ] **Step 8: 提交**

```powershell
git add crates/rsync-cli/src/options.rs crates/rsync-cli/src/cli.rs crates/rsync-cli/src/plan/mod.rs crates/rsync-cli/src/app/tests/local.rs crates/rsync-fs/src/sync.rs docs/OPTION-STATUS.md docs/COMPATIBILITY.md
git commit -m "feat(local): implement remove-source-files"
```

---

### Task 6: 实现 `--prune-empty-dirs`

**Files:**
- Modify: `crates/rsync-cli/src/options.rs`
- Modify: `crates/rsync-cli/src/cli.rs`
- Modify: `crates/rsync-cli/src/plan/mod.rs`
- Modify: `crates/rsync-cli/src/app/tests/local.rs`
- Modify: `crates/rsync-fs/src/sync.rs`
- Modify: `crates/rsync-filter/src/matcher.rs`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: 添加 CLI 字段**

在 `Cli` 中加入：

```rust
#[arg(skip)]
pub(crate) prune_empty_dirs: bool,
```

在 default 中设为 `false`。

- [ ] **Step 2: 解析 option**

在 `apply_long_option` 中加入：

```rust
"prune-empty-dirs" => cli.prune_empty_dirs = true,
```

在 `apply_short_option` 中让 `-m` 设置 `prune_empty_dirs = true`。
在 `apply_negated_option` 中加入：

```rust
"prune-empty-dirs" | "m" => cli.prune_empty_dirs = false,
```

- [ ] **Step 3: 加计划字段与输出**

在 `TransferPlan` 中加入：

```rust
pub(crate) prune_empty_dirs: bool,
```

渲染：

```rust
output.push_str(&format!("prune empty dirs: {}\n", plan.prune_empty_dirs));
```

- [ ] **Step 4: 写本地执行测试**

在 `crates/rsync-cli/src/app/tests/local.rs` 新增：

```rust
#[test]
fn local_prune_empty_dirs_skips_directories_that_have_no_sent_files() {
    let temp = FixtureTempDir::new("rsync-win-prune-empty-dirs").unwrap();
    let source = temp.path().join("source");
    let dest = temp.path().join("dest");
    std::fs::create_dir_all(source.join("keep")).unwrap();
    std::fs::create_dir_all(source.join("empty")).unwrap();
    std::fs::create_dir_all(source.join("filtered")).unwrap();
    std::fs::write(source.join("keep/file.txt"), b"keep").unwrap();
    std::fs::write(source.join("filtered/drop.tmp"), b"drop").unwrap();

    parse_and_execute([
        "rsync-win",
        "-r",
        "--prune-empty-dirs",
        "--exclude=*.tmp",
        source.to_string_lossy().as_ref(),
        dest.to_string_lossy().as_ref(),
    ])
    .unwrap();

    assert!(dest.join("keep").is_dir());
    assert!(dest.join("keep/file.txt").is_file());
    assert!(!dest.join("empty").exists());
    assert!(!dest.join("filtered").exists());
}
```

- [ ] **Step 5: 实现目录 prune**

在 `crates/rsync-fs/src/sync.rs` 的 source walk/selection 阶段，递归判断目录是否包含至少一个会发送的文件或保留项。若 `prune_empty_dirs` 为 true，跳过空目录 action。

规则：

- 被 filter 排除后没有发送文件的目录不创建。
- 包含发送文件的父目录必须创建。
- files-from 需要的父目录必须创建。
- delete protection 不应因为 prune 而删除受保护 receiver 目录。

- [ ] **Step 6: 更新文档**

在 `docs/OPTION-STATUS.md` 把 `--prune-empty-dirs` 从 Planned 移到 Partially implemented by mode。
在 `docs/COMPATIBILITY.md` 写明本地 ordinary-file path 支持，remote/daemon 需互操作确认。

- [ ] **Step 7: 验证**

```powershell
cargo test -p rsync-cli local_prune_empty_dirs_skips_directories_that_have_no_sent_files --all-features
cargo test -p rsync-fs --all-features
cargo test --workspace --all-features
```

- [ ] **Step 8: 提交**

```powershell
git add crates/rsync-cli/src/options.rs crates/rsync-cli/src/cli.rs crates/rsync-cli/src/plan/mod.rs crates/rsync-cli/src/app/tests/local.rs crates/rsync-fs/src/sync.rs crates/rsync-filter/src/matcher.rs docs/OPTION-STATUS.md docs/COMPATIBILITY.md
git commit -m "feat(local): implement prune-empty-dirs"
```

---

### Task 7: 提升 Daemon 到发行级普通文件子集

**Files:**
- Modify: `crates/rsync-cli/src/daemon_server/mod.rs`
- Modify: `crates/rsync-cli/src/execute/daemon_client.rs`
- Modify: `crates/rsync-protocol/src/daemon.rs`
- Modify: `tests/interop/daemon.rs`
- Modify: `scripts/package-release.ps1`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: 增加 daemon 外部 release matrix 测试**

在 `tests/interop/daemon.rs` 中确保以下测试在 `RSYNC_WIN_RELEASE_INTEROP_REQUIRED=1` 时不可 skip：

- module listing
- no-auth pull
- authenticated pull
- bad password
- writable push
- read-only push rejection
- connection controls: `--address`, `--port`, `--contimeout`, `--no-motd`

- [ ] **Step 2: 增加 daemon config 拒绝测试**

添加测试：

```rust
#[test]
fn local_daemon_server_rejects_unsupported_config_keys() {
    let temp = FixtureTempDir::new("rsync-win-daemon-unsupported-config").unwrap();
    let config = temp.path().join("rsyncd.conf");
    std::fs::write(
        &config,
        "[module]\npath = /tmp\nuse chroot = yes\n",
    )
    .unwrap();

    let output = Command::new(rsync_win_binary())
        .args(["--daemon", "--no-detach", "--config", config.to_string_lossy().as_ref()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported daemon module config key"));
}
```

- [ ] **Step 3: 确保 daemon 明文风险在执行输出中可见**

在 daemon auth client/server 成功路径输出中加入固定文本：

```text
daemon auth is challenge-response only and does not encrypt transport
```

测试中断言该文本出现在 authenticated pull/push 的输出或诊断中。

- [ ] **Step 4: 扩展 package optional daemon smoke**

在 `scripts/package-release.ps1` 的 daemon optional 区块中，当 `RSYNC_WIN_DAEMON_WRITABLE_MODULE` 配置时，加入 packaged binary push smoke。成功后验证远端文件存在，并尝试清理测试目录。

- [ ] **Step 5: 更新 compatibility**

在 `docs/COMPATIBILITY.md` 中把 daemon release-grade 子集定义为：

```markdown
Daemon release-grade support is limited to ordinary-file module listing, no-auth pull, authenticated pull, bad-password rejection, writable-module push, read-only rejection, connection controls, and the documented safe `rsyncd.conf` key subset. Unsupported daemon config keys fail closed.
```

- [ ] **Step 6: 验证**

```powershell
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
.\scripts\package-release.ps1 -Tag v0.2.0
```

Expected: 本地 daemon-server 测试通过；外部 daemon fixture 在普通模式可 skip，在 release-required 模式必须真实通过。

- [ ] **Step 7: 提交**

```powershell
git add crates/rsync-cli/src/daemon_server/mod.rs crates/rsync-cli/src/execute/daemon_client.rs crates/rsync-protocol/src/daemon.rs tests/interop/daemon.rs scripts/package-release.ps1 docs/COMPATIBILITY.md
git commit -m "feat(daemon): harden release ordinary-file subset"
```

---

### Task 8: NTFS-Native 与 VSS 发行级验证

**Files:**
- Modify: `crates/rsync-winfs/src/metadata.rs`
- Modify: `crates/rsync-winfs/src/security.rs`
- Modify: `crates/rsync-winfs/src/streams.rs`
- Modify: `crates/rsync-winfs/src/vss.rs`
- Modify: `crates/rsync-cli/src/execute/local.rs`
- Create: `tests/interop/ntfs_native.rs`
- Modify: `crates/rsync-cli/Cargo.toml`
- Modify: `docs/VSS-DESIGN.md`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: 添加 Windows capability report**

在 `crates/rsync-winfs/src/metadata.rs` 添加：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsCapabilityReport {
    pub symlinks: bool,
    pub security_descriptors: bool,
    pub alternate_streams: bool,
    pub sparse_ranges: bool,
    pub vss_snapshots: bool,
}

pub fn windows_capability_report() -> WindowsCapabilityReport {
    WindowsCapabilityReport {
        symlinks: crate::links::detect_link_capabilities().file_symlink,
        security_descriptors: crate::security::security_descriptor_available(),
        alternate_streams: crate::streams::alternate_streams_available(),
        sparse_ranges: sparse_ranges_available(),
        vss_snapshots: crate::vss::vss_available(),
    }
}
```

如果这些 helper 尚不存在，在对应模块新增只读 capability probe，失败时返回 `false`，不能 panic。

- [ ] **Step 2: 暴露 CLI capability 输出**

在 local `--metadata-policy=ntfs-native --plan` 输出中增加：

```text
ntfs capabilities: symlinks=<bool>, security=<bool>, ads=<bool>, sparse=<bool>, vss=<bool>
```

- [ ] **Step 3: 增加 ntfs_native integration test**

在 `crates/rsync-cli/Cargo.toml` 添加：

```toml
[[test]]
name = "ntfs_native"
path = "../../tests/interop/ntfs_native.rs"
```

创建 `tests/interop/ntfs_native.rs`，覆盖：

- creation time restore
- readonly/hidden/archive/system safe attribute subset
- named ADS copy
- sparse range restore with `--sparse`
- security descriptor restore only when elevated and `--super`
- VSS dry-run path

- [ ] **Step 4: 添加真实 VSS opt-in 测试**

在同一测试文件中加入：

```rust
#[test]
fn ntfs_native_vss_real_snapshot_requires_opt_in() {
    if std::env::var("RSYNC_WIN_ENABLE_VSS_INTEGRATION").ok().as_deref() != Some("1") {
        eprintln!("skipping real VSS integration: set RSYNC_WIN_ENABLE_VSS_INTEGRATION=1");
        return;
    }
    // create source, run --metadata-policy ntfs-native --vss, assert copied bytes
}
```

- [ ] **Step 5: 更新文档**

在 `docs/VSS-DESIGN.md` 增加：

```markdown
Real VSS integration tests are opt-in through `RSYNC_WIN_ENABLE_VSS_INTEGRATION=1` because they require a Windows host with VSS enabled and sufficient privileges. Release-grade NTFS-native validation must record whether the real VSS test passed or was explicitly waived.
```

- [ ] **Step 6: 验证**

```powershell
cargo test -p rsync-winfs --all-features
cargo test -p rsync-cli --test ntfs_native --all-features -- --nocapture
cargo test --workspace --all-features
```

- [ ] **Step 7: 提交**

```powershell
git add crates/rsync-winfs/src crates/rsync-cli/src/execute/local.rs crates/rsync-cli/Cargo.toml tests/interop/ntfs_native.rs docs/VSS-DESIGN.md docs/COMPATIBILITY.md
git commit -m "test(ntfs): add release native metadata validation"
```

---

### Task 9: 安全 Fuzz 与恶意 Peer 门禁

**Files:**
- Modify: `tests/security/remote_peer.rs`
- Create: `tests/fuzz/rsync_protocol_fuzz.rs`
- Create: `tests/fuzz/README.md`
- Modify: `crates/rsync-cli/Cargo.toml`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/COMPATIBILITY.md`

- [ ] **Step 1: 接入 fuzz smoke test**

在 `crates/rsync-cli/Cargo.toml` 添加：

```toml
[[test]]
name = "rsync_protocol_fuzz"
path = "../../tests/fuzz/rsync_protocol_fuzz.rs"
```

- [ ] **Step 2: 创建 fuzz smoke**

创建 `tests/fuzz/rsync_protocol_fuzz.rs`：

```rust
use std::io::Cursor;

#[test]
#[ignore = "run explicitly in release hardening jobs"]
fn malformed_protocol_inputs_do_not_panic() {
    let inputs = [
        Vec::new(),
        vec![0xff; 1],
        vec![0xff; 1024],
        (0..4096).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
    ];

    for input in inputs {
        std::panic::catch_unwind(|| {
            let mut cursor = Cursor::new(input);
            let _ = rsync_protocol::flist::read_rsync31_file_list(&mut cursor);
        })
        .expect("protocol parser must not panic on malformed input");
    }
}
```

- [ ] **Step 3: 增加 fuzz README**

创建 `tests/fuzz/README.md`：

````markdown
# Fuzz Smoke Tests

These tests feed malformed byte streams into rsync protocol readers and assert that parsers return errors instead of panicking.

Run:

```powershell
cargo test -p rsync-cli --test rsync_protocol_fuzz --all-features -- --ignored
```
````

- [ ] **Step 4: 扩展 malicious peer regressions**

在 `tests/security/remote_peer.rs` 增加以下测试：

- corrupt compressed token stream fails before final file replace
- oversized ACL payload fails before receiver mutation
- oversized xattr payload fails before receiver mutation
- unsupported multiplex tag during final goodbye returns protocol error
- remote file-list with Windows device name remains rejected

- [ ] **Step 5: 接入 CI**

在 `.github/workflows/ci.yml` 的 security regression tests 后加入：

```yaml
      - name: Fuzz smoke
        run: cargo test -p rsync-cli --test rsync_protocol_fuzz --all-features -- --ignored
```

- [ ] **Step 6: 验证**

```powershell
cargo test -p rsync-cli --test security_remote_peer --all-features
cargo test -p rsync-cli --test rsync_protocol_fuzz --all-features -- --ignored
cargo test --workspace --all-features
```

- [ ] **Step 7: 提交**

```powershell
git add tests/security/remote_peer.rs tests/fuzz crates/rsync-cli/Cargo.toml .github/workflows/ci.yml docs/COMPATIBILITY.md
git commit -m "test(security): add release fuzz and malicious peer gates"
```

---

### Task 10: 发行包签名、依赖清单和安装渠道

**Files:**
- Modify: `scripts/package-release.ps1`
- Create: `scripts/generate-sbom.ps1`
- Create: `scripts/sign-release.ps1`
- Create: `scripts/create-scoop-manifest.ps1`
- Modify: `.github/workflows/release.yml`
- Modify: `tests/compat/release_readiness.rs`
- Create: `docs/RELEASE-CHECKLIST.md`
- Modify: `THIRD-PARTY-NOTICES.md`

- [ ] **Step 1: 生成依赖清单**

创建 `scripts/generate-sbom.ps1`：

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$metadata = cargo metadata --format-version 1 | ConvertFrom-Json
$packages = $metadata.packages | Sort-Object name, version
$lines = @("# rsync-win Dependency Inventory", "")
foreach ($package in $packages) {
    $license = if ($package.license) { $package.license } else { "NOASSERTION" }
    $lines += "- $($package.name) $($package.version) - $license"
}
$lines | Set-Content -Path $OutputPath -Encoding utf8
```

- [ ] **Step 2: package-release 包含依赖清单**

在 `scripts/package-release.ps1` 中调用：

```powershell
$dependencyInventory = Join-Path $packageDir "docs\DEPENDENCY-INVENTORY.md"
& (Join-Path $repoRoot "scripts\generate-sbom.ps1") -OutputPath $dependencyInventory
if ($LASTEXITCODE -ne 0) {
    throw "Dependency inventory generation failed."
}
```

并把 `docs\DEPENDENCY-INVENTORY.md` 加入 `$expectedPackageFiles`。

- [ ] **Step 3: 添加签名脚本**

创建 `scripts/sign-release.ps1`：

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Binary not found: $BinaryPath"
}

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    throw "signtool.exe is required for release-grade signing"
}

& $signtool.Source sign /fd SHA256 /tr $TimestampServer /td SHA256 $BinaryPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool signing failed for $BinaryPath"
}
```

- [ ] **Step 4: 添加 Scoop manifest 生成脚本**

创建 `scripts/create-scoop-manifest.ps1`：

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$Tag,

    [Parameter(Mandatory = $true)]
    [string]$ZipUrl,

    [Parameter(Mandatory = $true)]
    [string]$Sha256,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$version = $Tag.TrimStart("v")
$manifest = [ordered]@{
    version = $version
    description = "Native Windows rsync-compatible command line tool"
    homepage = "https://github.com/Linorman/rsync-win"
    license = "MIT OR Apache-2.0"
    architecture = @{
        "64bit" = @{
            url = $ZipUrl
            hash = $Sha256
        }
    }
    bin = "rsync-win.exe"
}

$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding utf8
```

- [ ] **Step 5: 更新 release workflow**

在 `.github/workflows/release.yml` 中：

- package 前运行 signing，若 release-grade signing secret 未配置则失败。
- package 后上传 zip、sha256、fixture report、dependency inventory、scoop manifest。

- [ ] **Step 6: 增加 release readiness assertions**

在 `tests/compat/release_readiness.rs` 增加：

```rust
#[test]
fn release_package_includes_dependency_inventory_and_install_manifest_script() {
    let package = read_repo_file("scripts/package-release.ps1");
    let sign = read_repo_file("scripts/sign-release.ps1");
    let scoop = read_repo_file("scripts/create-scoop-manifest.ps1");

    assert!(package.contains("DEPENDENCY-INVENTORY.md"));
    assert!(sign.contains("signtool.exe"));
    assert!(scoop.contains("\"64bit\""));
    assert!(scoop.contains("rsync-win.exe"));
}
```

- [ ] **Step 7: 创建 release checklist**

创建 `docs/RELEASE-CHECKLIST.md`，列出：

- local test gates
- required external interop gates
- benchmark gates
- package content
- signing status
- dependency inventory
- checksum
- install manifest

- [ ] **Step 8: 验证**

```powershell
cargo test -p rsync-cli --test release_readiness --all-features
.\scripts\generate-sbom.ps1 -OutputPath dist\DEPENDENCY-INVENTORY.md
.\scripts\package-release.ps1 -Tag v0.2.0
```

- [ ] **Step 9: 提交**

```powershell
git add scripts/package-release.ps1 scripts/generate-sbom.ps1 scripts/sign-release.ps1 scripts/create-scoop-manifest.ps1 .github/workflows/release.yml tests/compat/release_readiness.rs docs/RELEASE-CHECKLIST.md THIRD-PARTY-NOTICES.md
git commit -m "build(release): add signing sbom and install manifest"
```

---

### Task 11: 最终 Go/No-Go Release Audit

**Files:**
- Modify: `README.md`
- Modify: `docs/COMPATIBILITY.md`
- Modify: `docs/OPTION-STATUS.md`
- Modify: `docs/RELEASE-NOTES-TEMPLATE.md`
- Modify: `docs/RELEASE-CHECKLIST.md`

- [ ] **Step 1: 运行全部本地门禁**

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p rsync-cli --test options --all-features
cargo test -p rsync-cli --test security_remote_peer --all-features
cargo test -p rsync-cli --test rsync_protocol_fuzz --all-features -- --ignored
```

Expected: 全部通过。

- [ ] **Step 2: 运行全部外部发行门禁**

在配置完整 fixture 的 release host 上运行：

```powershell
.\scripts\write-release-fixture-report.ps1 -OutputPath dist\release-fixtures.md
.\scripts\run-release-interop.ps1
```

Expected: 不出现 skip；Linux upstream rsync 3.4.x/3.2.x SSH matrix 和 daemon matrix 全通过。

- [ ] **Step 3: 运行 benchmark gate**

创建 `scripts/run-release-benchmarks.ps1`：

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$env:RSYNC_WIN_BENCH_ITERS = "1"
cargo bench -p rsync-fs --bench local_sync
cargo bench -p rsync-cli --bench remote_protocol
```

运行：

```powershell
.\scripts\run-release-benchmarks.ps1
```

Expected: benchmark 完成，并把结果写入 `docs/COMPATIBILITY.md` 的 Benchmark Baseline。

- [ ] **Step 4: 生成并审计 release artifact**

```powershell
.\scripts\package-release.ps1 -Tag v1.0.0
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path "dist\rsync-win-v1.0.0-x86_64-pc-windows-msvc.zip"))
try {
    $zip.Entries | ForEach-Object { $_.FullName } | Sort-Object
} finally {
    $zip.Dispose()
}
```

Expected entries:

```text
docs/COMPATIBILITY.md
docs/DEPENDENCY-INVENTORY.md
docs/OPTION-STATUS.md
docs/RELEASE-NOTES-TEMPLATE.md
LICENSE
LICENSE-APACHE
LICENSE-MIT
README.md
rsync-win.exe
THIRD-PARTY-NOTICES.md
```

- [ ] **Step 5: 更新最终 release docs**

在 `README.md`、`docs/COMPATIBILITY.md`、`docs/OPTION-STATUS.md` 中删除已经关闭的 known-not-implemented 条目。保留真实限制：

- daemon auth 不加密。
- arbitrary non-symlink reparse restore 不支持。
- NTFS-native 不是默认模式。
- 非 release matrix peer 仍 best-effort。

- [ ] **Step 6: 记录 go/no-go**

在 `docs/RELEASE-CHECKLIST.md` 中添加候选版本审计记录：

```markdown
## v1.0.0 Candidate Audit

- Local gates: pass
- External interop gates: pass
- Security gates: pass
- Benchmark gates: pass
- Package smoke: pass
- Artifact checksum: <sha256 from generated file>
- Signing: pass
- Dependency inventory: included
- Decision: go
```

- [ ] **Step 7: 提交**

```powershell
git add README.md docs/COMPATIBILITY.md docs/OPTION-STATUS.md docs/RELEASE-NOTES-TEMPLATE.md docs/RELEASE-CHECKLIST.md scripts/run-release-benchmarks.ps1
git commit -m "docs: record release candidate audit"
```

---

## Recommended Execution Order

1. Task 1: 先让 release 环境不能静默跳过外部互操作测试。
2. Task 2: 关闭 remote push `--delete + --files-from` 功能缺口。
3. Task 3: 关闭 remote push sender-side incremental recursion 功能缺口。
4. Task 4: 放开并验证 remote/daemon POSIX metadata 支持子集。
5. Task 5: 实现 `--remove-source-files`。
6. Task 6: 实现 `--prune-empty-dirs`。
7. Task 7: 把 daemon 普通文件子集提升到 release gate。
8. Task 8: 做 NTFS-native/VSS 发行级验证。
9. Task 9: 增加 fuzz 和恶意 peer release gates。
10. Task 10: 完成签名、依赖清单和安装 manifest。
11. Task 11: 执行最终 go/no-go audit。

## Completion Criteria

可以称为 Windows rsync 发行版的条件：

- release workflow 中外部 upstream rsync/daemon fixture 缺失会失败。
- upstream rsync 3.4.x 和 3.2.x over SSH push/pull matrix 真实通过。
- daemon module list、no-auth pull、auth pull、auth failure、writable push、read-only rejection 真实通过。
- remote push 支持 `--delete + --files-from`。
- remote push 支持 protocol 31 sender-side incremental recursion。
- remote/daemon upload 支持经过互操作验证的 POSIX mode/executability/chmod 子集。
- `--remove-source-files` 和 `--prune-empty-dirs` 不再是 Planned。
- NTFS-native local validation 覆盖 creation time、safe attributes、ADS、sparse、security descriptor、VSS dry-run，真实 VSS 测试有 pass 或记录明确 waiver。
- malicious peer 和 fuzz smoke 进入 CI/release gates。
- release package 包含 dependency inventory、checksum、签名状态和 install manifest。
- `README.md`、`docs/COMPATIBILITY.md`、`docs/OPTION-STATUS.md` 中没有超出测试证据的发行承诺。
