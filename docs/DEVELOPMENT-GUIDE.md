# rsync-win 开发文档

本文档描述 `rsync-win` 从当前 `v0.2.0` 受限兼容版本走向发行级 Windows rsync 发行版的工程约束、架构、测试策略和发布门禁。它不替代 `README.md`、`docs/COMPATIBILITY.md`、`docs/OPTION-STATUS.md`，而是作为开发者进入项目后的总纲。

## 当前结论

截至 2026-05-17，本项目可以在 Windows/MSVC 环境中完成本地构建、测试、打包和基础本地同步冒烟验证。当前可作为实验性或预览级 Windows x64 发行包发布，但不能宣称为完整的 rsync Windows 正式发行版。

已验证的本地门禁：

```powershell
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
.\scripts\package-release.ps1 -Tag v0.2.0
.\dist\package\rsync-win.exe --version
.\dist\package\rsync-win.exe --protocol-range
```

当前限制：

- 外部 upstream rsync、SSH、rsync daemon、macOS、openrsync、Cygwin、MSYS2 互操作 fixture 在未设置环境变量时会跳过，不能作为发行级互操作证明。
- `remote-shell` 和 daemon 仍是 ordinary-file 子集，项目文档也标为 experimental。
- 远程和 daemon 执行路径当前只允许 `--metadata-policy=portable`。
- 大量 upstream rsync 选项处于 partially implemented、diagnostic only、parsed only 或 reserved 状态。
- daemon `--password-file` 只是 rsync challenge-response 认证，不提供传输加密。
- 本项目是 clean-room 独立实现，不是 Samba/rsync 官方 Windows 构建。

## 发行级目标

发行级 Windows rsync 版本必须满足以下定义：

1. **普通数据安全可用**：本地 Windows 同步、远程 SSH push/pull、daemon pull/push 在普通文件和目录场景下可靠，不会破坏目标树。
2. **互操作有证据**：固定 upstream rsync 版本矩阵必须在发布门禁中真实运行，不能只依赖自动 skip。
3. **兼容性诚实**：未完整支持的 rsync 选项必须被拒绝、降级报告或清楚标为兼容解析，不能默默产生不同语义。
4. **Windows 行为明确**：NTFS ACL、ADS、VSS、reparse point、case collision、Unicode normalization、long path 和 SMB/ReFS 行为必须有测试或明确限制。
5. **安全默认值保守**：所有来自远端的路径、file-list、token length、checksum、metadata payload 都必须在写入前验证。
6. **发布工件可审计**：zip、checksum、license、第三方声明、兼容矩阵、选项状态和 release notes 必须随包发布。
7. **用户承诺可验证**：README 中的每个能力声明必须能映射到测试、脚本或兼容性文档。

## 非目标

- 不把 daemon challenge-response 描述为加密传输。
- 不把 NTFS ACL 等同于 POSIX ACL。
- 不默认启用 `ntfs-native` 或 VSS。
- 不声称与 Samba/rsync 官方项目存在从属关系。
- 不为了选项数量接受无行为的兼容假象。

## 架构概览

| 路径 | 职责 |
| --- | --- |
| `crates/rsync-cli` | CLI 解析、计划生成、执行分发、本地/远程/daemon orchestration、输出格式化。 |
| `crates/rsync-core` | 诊断、metadata policy、降级报告、通用 rsync 语义类型。 |
| `crates/rsync-delta` | rolling checksum、block signature、匹配和 token apply。 |
| `crates/rsync-filter` | include、exclude、protect、risk、merge-file、files-from 规则。 |
| `crates/rsync-fs` | portable 文件系统模型、本地同步引擎、写入模式、删除模式。 |
| `crates/rsync-protocol` | rsync 协议版本、file-list、session、daemon、wire IO。 |
| `crates/rsync-transport` | SSH 子进程、TCP、proxy、socket option、bandwidth limit。 |
| `crates/rsync-winfs` | Windows path、metadata、security descriptor、ADS、sparse、links、VSS。 |
| `tests/compat` | 选项状态、发布 readiness、文档一致性。 |
| `tests/interop` | upstream rsync、SSH、daemon 和本地 daemon-server fixture。 |
| `tests/security` | 恶意远端、路径逃逸、wire corruption、checksum/length hardening。 |
| `tests/stress` | 大文件、大树、内存预算和流式处理测试。 |
| `scripts/package-release.ps1` | Windows release zip、checksum、打包后冒烟测试。 |

## 执行模式

### Local portable sync

本地模式是当前最稳定的能力。它覆盖普通文件、目录、多源 operand、递归、mtime、删除、过滤、files-from、update predicate、partial/inplace/append-verify、hardlink/symlink 子集和 NTFS 侧车路径。

发行级要求：

- `cargo test -p rsync-fs` 覆盖 portable semantics。
- `cargo test -p rsync-cli local` 覆盖 CLI 到 executor 的集成行为。
- 发布脚本必须继续运行 disposable local sync 和 delete/filter smoke。

### Remote shell over SSH

远程 shell 模式通过本地 SSH 子进程与 upstream rsync `--server` 交互。当前协议 31 优先，保留协议 27 fallback。

发行级要求：

- upstream rsync 3.4.x 和 3.2.x 的真实 push/pull matrix 必须进入 release gate。
- `--delete + --files-from`、sender-side incremental recursion、POSIX metadata 上传语义需要补齐或明确拒绝。
- macOS Homebrew rsync、macOS stock rsync 2.6.9、openrsync、MSYS2/Cygwin 需要分级支持声明。

### Daemon client and server

daemon 支持 module listing、no-auth pull、authenticated pull、writable-module push 和最小 daemon server。认证不是加密。

发行级要求：

- 外部 upstream rsync daemon fixture 必须覆盖 no-auth、auth、writeable、read-only、bad password、module list。
- daemon server 支持的 `rsyncd.conf` key 必须是白名单，不支持 key 必须报错或警告。
- daemon 传输安全文档必须持续强调明文传输风险。

### Metadata policies

| Policy | 发行级定位 |
| --- | --- |
| `portable` | 默认路径，覆盖普通文件和目录，不承诺 POSIX 或 NTFS 完整元数据。 |
| `posix` | 面向 POSIX 远端和 sidecar/reporting。不得声称 Windows 本地能够原生恢复 POSIX owner/group/ACL/xattr。 |
| `ntfs-native` | 明确 opt-in 的 Windows-to-Windows backup-grade 模式，用于 ADS、SDDL、安全属性、sparse、creation time、VSS。 |

## 源码开发工作流

开发前检查：

```powershell
git status --short --branch
cargo metadata --format-version 1 --no-deps
```

常规验证：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
```

专项验证：

```powershell
cargo test -p rsync-cli --test options --all-features
cargo test -p rsync-cli --test security_remote_peer --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
cargo test -p rsync-cli --test large_file --all-features
cargo test -p rsync-cli --test large_tree --all-features
```

发布验证：

```powershell
.\scripts\package-release.ps1 -Tag v0.2.0
Add-Type -AssemblyName System.IO.Compression.FileSystem
```

## 外部互操作 fixture

发行级测试环境必须至少配置：

| 环境变量 | 用途 |
| --- | --- |
| `RSYNC_WIN_SSH_TARGET` | Linux upstream rsync over SSH 主 fixture。 |
| `RSYNC_WIN_SSH_TMP_ROOT` | 远端 disposable 测试目录根。 |
| `RSYNC_WIN_SSH_PROTOCOL27_TARGET` | 协议 27 fallback fixture。 |
| `RSYNC_WIN_MACOS_RSYNC_TARGET` | macOS/Homebrew 或 macOS peer 探测。 |
| `RSYNC_WIN_OPENRSYNC_TARGET` | openrsync peer 探测。 |
| `RSYNC_WIN_CYGWIN_TARGET` | Cygwin rsync peer 探测。 |
| `RSYNC_WIN_MSYS2_TARGET` | MSYS2 rsync peer 探测。 |
| `RSYNC_WIN_DAEMON_URL` | upstream rsync daemon endpoint。 |
| `RSYNC_WIN_DAEMON_MODULE` | no-auth readable module。 |
| `RSYNC_WIN_DAEMON_AUTH_MODULE` | authenticated readable module。 |
| `RSYNC_WIN_DAEMON_WRITABLE_MODULE` | controlled writable module。 |
| `RSYNC_WIN_DAEMON_USER` | daemon auth 用户。 |
| `RSYNC_WIN_DAEMON_PASSWORD_FILE` | daemon auth 密码文件。 |

发行工作流中这些 fixture 不能全部 skip。预览版可以允许 skip，但 release-grade build 必须失败并说明缺失 fixture。

## 测试策略

### 单元测试

- 协议编码、varint、file-list、token、checksum、filter matcher、path validation 必须可 deterministic 测试。
- Windows API 相关测试必须在不可用时报告能力状态，不能误判成功。

### 集成测试

- CLI parser 到 `TransferPlan` 的转换必须覆盖每个 advertised option。
- `parse_and_execute` 必须覆盖本地、remote-shell mock、daemon mock、错误码映射。
- 输出格式、stats、itemized changes、log-file-format 必须有 golden-like assertions。

### 互操作测试

- upstream rsync 作为 oracle，比对 manifest，而不只检查退出码。
- push 和 pull 都要测 `-rt`、`-a --no-o --no-g`、delete/filter、files-from、checksum、partial、inplace、append-verify、compression、多源、空目录、空文件、Unicode、空格文件名。
- daemon fixture 要覆盖 module list、no-auth pull、auth pull、auth failure、writable push、read-only rejection。

### 压力和性能测试

- automated stress 至少覆盖 3 MiB streaming 文件和 100,000 file-list entry。
- benchmark 覆盖 10,000 小文件、100,000 空文件、1 GiB 文件、小编辑大文件、filter-heavy、delete-heavy。
- 发布前记录 benchmark baseline 和运行机器信息。

### 安全测试

- 远端 file-list 必须拒绝 parent escape、absolute path、Windows prefix、reserved name、invalid char、trailing dot/space、Unicode collision。
- token stream 必须拒绝 literal length overrun、underrun、checksum mismatch、unsupported mux tag。
- daemon secrets 和 password-file 不能被日志泄露。

## 发布门禁

发布候选必须通过：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p rsync-cli --test rsync_compat --all-features -- --nocapture
cargo test -p rsync-cli --test daemon --all-features -- --nocapture
.\scripts\package-release.ps1 -Tag <tag>
```

发布包必须包含：

- `rsync-win.exe`
- `README.md`
- `LICENSE`
- `LICENSE-MIT`
- `LICENSE-APACHE`
- `THIRD-PARTY-NOTICES.md`
- `docs/COMPATIBILITY.md`
- `docs/OPTION-STATUS.md`
- `docs/RELEASE-NOTES-TEMPLATE.md`
- `.sha256` checksum

发行级附加要求：

- 代码签名。
- SBOM 或依赖许可清单。
- release notes 明确列出新增、修复、限制、已知风险。
- 兼容矩阵更新到已验证 upstream rsync 版本。
- GitHub release artifact 与本地 package script 输出一致。

## 文档维护规则

修改功能时同步更新：

| 变更 | 必须检查 |
| --- | --- |
| 新增或改变 CLI option | `crates/rsync-cli/src/options.rs`、`docs/OPTION-STATUS.md`、`tests/compat/options.rs`。 |
| 改变 remote-shell 行为 | `docs/COMPATIBILITY.md`、`tests/interop/rsync_compat.rs`、`tests/security/remote_peer.rs`。 |
| 改变 daemon 行为 | `docs/COMPATIBILITY.md`、`tests/interop/daemon.rs`、`scripts/package-release.ps1` optional smoke。 |
| 改变 Windows metadata | `docs/COMPATIBILITY.md`、`docs/VSS-DESIGN.md`、`crates/rsync-winfs` tests。 |
| 改变发布包内容 | `scripts/package-release.ps1`、`tests/compat/release_readiness.rs`、release workflow。 |

## 风险登记

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| 外部互操作测试默认 skip | 发行包缺少真实 peer 证据 | 增加 release-required fixture 模式，缺失时失败。 |
| 选项解析宽于执行语义 | 用户误以为行为等同 upstream rsync | `OPTION-STATUS.md` 保持保守，未执行选项发诊断或拒绝。 |
| Windows metadata 语义复杂 | 备份恢复不完整或误导 | `portable` 默认，`ntfs-native` opt-in，逐项测试和侧车记录。 |
| daemon 明文传输 | 用户误用在不可信网络 | 文档、help、diagnostics 中明确 daemon auth 不加密。 |
| 协议兼容依赖 upstream 行为 | 真实 peer 版本变化导致回归 | 固定 3.4.x/3.2.x fixture，记录版本，manifest 比对。 |
| 大树内存膨胀 | 真实备份任务失败 | incremental recursion、file-list limit、max-alloc、stress gate。 |
| 发布包供应链风险 | 用户无法验证工件 | checksum、签名、license/SBOM、可复现发布脚本。 |

## 里程碑

| 里程碑 | 目标 | 退出标准 |
| --- | --- | --- |
| `v0.2.x-preview` | 修正文档定位，保持现有能力稳定 | 本地门禁、package smoke、限制说明准确。 |
| `v0.3-interop` | 真实 upstream rsync 互操作门禁 | Linux rsync 3.4.x/3.2.x SSH matrix 和 daemon fixture 必跑。 |
| `v0.4-remote-parity` | 补齐远程普通文件常用语义 | remote push `--delete + --files-from`、sender-side incremental recursion、remote stats 稳定。 |
| `v0.5-metadata` | POSIX/NTFS metadata contract 可验证 | `posix` remote upload、fake-super sidecar、`ntfs-native` restore suite 通过。 |
| `v0.6-hardening` | 安全和性能 release gate | fuzz/security/stress/benchmark gate 进入 CI。 |
| `v1.0` | 发行级 Windows rsync-compatible build | release checklist 全通过，文档承诺全部有测试证据。 |
