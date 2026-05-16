# Rsync-Win 当前版本之后的下一阶段开发计划

> 适用前提：`2026-05-17-rsync-win-release-grade-development.md` 中列出的发行级阻塞项已经完成，当前项目已经可以作为可用的 Windows rsync 发行版发布。

本计划不再重复“让项目能成为 Windows 发行版”的基础工作，而是面向下一阶段：让 `rsync-win` 从可发布版本演进为可长期维护、可公开认证、可被企业和自动化系统稳定采用的 Windows rsync 发行产品。

## 目标

下一阶段目标分为四条主线：

1. 建立公开、可复验的兼容性认证体系。
2. 建立正式分发渠道和发布治理流程。
3. 增强 Windows 场景下的可靠性、性能和可观测性。
4. 明确 v1.0 支持边界，减少后续维护成本。

## 非目标

以下内容不放入本阶段：

- 不重新实现 POSIX rsync 的全部历史边缘行为，除非认证矩阵证明它阻塞真实用户。
- 不把项目改造成 Cygwin/MSYS2 封装发行版。
- 不引入后台云服务、遥测或账号体系。
- 不默认改变已经稳定的 CLI 行为；新增行为必须显式启用或有兼容迁移说明。

## 里程碑

### v0.3.0：认证与分发

目标：让用户能确认这个版本“在哪些平台、哪些模式下通过了认证”，并能通过常见 Windows 渠道安装。

交付物：

- `scripts/run-certification.ps1`
- `docs/CERTIFICATION.md`
- `docs/certification/results/*.json`
- `packaging/winget/`
- `packaging/scoop/`
- `packaging/chocolatey/`
- `packaging/msi/`
- `docs/RELEASE-POLICY.md`

完成标准：

- 每个发布包带有同版本认证报告。
- GitHub Release、ZIP、MSI、Scoop、Chocolatey、WinGet 的校验和一致。
- 用户可以通过 ZIP 或至少一个包管理器完成安装、运行 `rsync --version`、执行本地同步。

### v0.4.0：机器可读接口与诊断稳定化

目标：让 CI、备份系统、企业脚本能够稳定解析 rsync-win 的输出和错误。

交付物：

- `--json`
- `--diagnostics-format=text|json`
- `--stats-format=text|json`
- 稳定错误码枚举
- `docs/CLI-CONTRACT.md`
- `tests/cli_contract/`

完成标准：

- 文本输出仍保持人类友好。
- JSON 输出有 schema、快照测试和兼容策略。
- 诊断消息不再只能依赖字符串匹配。

### v0.5.0：可靠性与恢复

目标：提升长时间、大目录、网络不稳定场景下的成功率。

交付物：

- 可选传输恢复日志。
- 可配置重试策略。
- 更明确的 partial 文件恢复语义。
- 中断恢复测试。
- `docs/RELIABILITY.md`

完成标准：

- 本地和远程传输都能在进程中断后安全重跑。
- partial 文件、临时文件和目标文件状态有文档化保证。
- 测试覆盖 Ctrl-C、网络断开、远端异常退出、磁盘空间不足。

### v0.6.0：Windows 深度集成

目标：让 rsync-win 更适合 Windows 服务器和工作站长期使用。

交付物：

- Windows Service 模式管理命令。
- 计划任务示例。
- VSS 场景验证。
- ACL/ADS/属性行为矩阵。
- 事件日志集成。
- `docs/WINDOWS-OPERATIONS.md`

完成标准：

- 用户可以安装、启动、停止、卸载 rsync-win daemon 服务。
- 服务模式有最小权限建议和配置模板。
- Windows 特有元数据行为有可复验测试。

### v1.0.0：长期支持边界

目标：发布 API、CLI、兼容性和维护策略稳定的正式版。

交付物：

- `docs/SUPPORT-POLICY.md`
- `docs/SECURITY.md`
- `docs/BACKWARD-COMPATIBILITY.md`
- v1.0 认证矩阵
- v1.0 迁移指南

完成标准：

- 所有非实验功能都有支持承诺。
- 破坏性变更需要明确的弃用周期。
- 每个发布渠道都能回溯到同一个源码提交、构建日志、SBOM 和签名制品。

## 开发任务

### 1. 建立兼容性认证系统

目的：把“能跑”升级为“通过哪些兼容性场景，有证据”。

新增目录：

```text
docs/certification/
docs/certification/results/
tests/certification/
```

新增脚本：

```text
scripts/run-certification.ps1
scripts/render-certification-report.ps1
```

认证矩阵第一版：

| 场景 | 本机 Windows | Linux upstream rsync | macOS rsync | openrsync | Cygwin/MSYS2 rsync | NAS daemon |
| --- | --- | --- | --- | --- | --- | --- |
| local copy | required | required | optional | optional | required | not applicable |
| local delete | required | required | optional | optional | required | not applicable |
| pull over remote shell | required | required | required | optional | required | not applicable |
| push over remote shell | required | required | required | optional | required | not applicable |
| daemon pull | required | required | optional | optional | required | required |
| daemon push | required | required | optional | optional | required | required |
| metadata portable | required | required | required | optional | required | required |
| metadata posix | required | required | optional | optional | required | optional |

报告 JSON 结构：

```json
{
  "schema": 1,
  "project": "rsync-win",
  "version": "0.3.0",
  "commit": "git commit hash",
  "generated_at_utc": "ISO-8601 timestamp",
  "runner": {
    "os": "Windows",
    "arch": "x86_64",
    "rustc": "rustc version",
    "powershell": "PowerShell version"
  },
  "targets": [
    {
      "name": "upstream-linux",
      "rsync_version": "remote rsync version",
      "transport": "ssh",
      "result": "passed"
    }
  ],
  "summary": {
    "passed": 0,
    "failed": 0,
    "skipped": 0
  }
}
```

实现步骤：

- [ ] 增加 `tests/certification/mod.rs`，封装认证用例描述、跳过原因和结果收集。
- [ ] 增加 `scripts/run-certification.ps1`，统一读取环境变量、运行认证测试、输出 JSON。
- [ ] 增加 `scripts/render-certification-report.ps1`，把 JSON 转成 Markdown 表格。
- [ ] 在 release 打包脚本中追加认证报告路径检查。
- [ ] 在 `docs/CERTIFICATION.md` 中说明如何复验同一版本。

验证命令：

```powershell
cargo test --workspace --all-features
.\scripts\run-certification.ps1 -Output docs\certification\results\v0.3.0-local.json
.\scripts\render-certification-report.ps1 -Input docs\certification\results\v0.3.0-local.json -Output docs\certification\v0.3.0.md
```

### 2. 建立正式分发渠道

目的：让普通 Windows 用户无需理解 Rust、Cargo 或源码树即可安装。

优先级：

1. ZIP portable 包继续保留，作为最低依赖发行物。
2. Scoop manifest，适合开发者。
3. WinGet manifest，适合普通 Windows 用户。
4. Chocolatey package，适合企业和老自动化脚本。
5. MSI，适合受控桌面环境。

新增目录：

```text
packaging/scoop/
packaging/winget/
packaging/chocolatey/
packaging/msi/
```

发布脚本扩展：

```text
scripts/package-release.ps1
scripts/generate-package-manifests.ps1
scripts/verify-release-artifacts.ps1
```

每个制品必须包含：

- `rsync.exe`
- `rsync-win.exe` 或当前项目约定的主二进制名
- `README.md`
- `LICENSE`
- `NOTICE`
- `docs/COMPATIBILITY.md`
- `docs/CERTIFICATION.md`
- `SBOM`
- SHA256 校验文件
- 签名或签名状态说明

实现步骤：

- [ ] 增加 `scripts/generate-package-manifests.ps1`，从单一版本号生成 Scoop、WinGet、Chocolatey manifest。
- [ ] 增加 manifest 校验测试，确保 URL、版本号、SHA256 一致。
- [ ] 扩展 release 脚本，打包后自动生成并验证所有 manifest。
- [ ] 增加 MSI 构建说明，先支持本地可复验构建，再接入 CI。
- [ ] 更新 `docs/INSTALL.md`，按 ZIP、Scoop、WinGet、Chocolatey、MSI 排列安装方式。

验证命令：

```powershell
.\scripts\package-release.ps1 -Tag v0.3.0
.\scripts\generate-package-manifests.ps1 -Tag v0.3.0
.\scripts\verify-release-artifacts.ps1 -Tag v0.3.0
```

### 3. 稳定机器可读 CLI 合约

目的：让 rsync-win 可被 CI、备份系统、监控系统安全集成。

新增参数：

```text
--json
--diagnostics-format=text|json
--stats-format=text|json
```

新增文档：

```text
docs/CLI-CONTRACT.md
docs/schemas/diagnostics.schema.json
docs/schemas/stats.schema.json
```

建议错误码分类：

| 类别 | 范围 | 示例 |
| --- | --- | --- |
| CLI 使用错误 | 1000-1099 | 参数互斥、缺少路径 |
| 文件系统错误 | 1100-1199 | 权限、路径不存在、磁盘空间不足 |
| 网络/传输错误 | 1200-1299 | SSH 退出、daemon 断开、协议错误 |
| 元数据错误 | 1300-1399 | ACL、所有者、时间戳恢复失败 |
| 兼容性错误 | 1400-1499 | 远端能力不足、协议不匹配 |
| 内部错误 | 1900-1999 | 不应出现的状态 |

JSON 输出示例：

```json
{
  "schema": 1,
  "level": "error",
  "code": 1203,
  "category": "transport",
  "message": "remote shell exited before file list was complete",
  "retryable": true
}
```

实现步骤：

- [ ] 新增 `crates/rsync-cli/src/output/json.rs`。
- [ ] 将当前诊断消息映射到稳定错误码。
- [ ] 为 `--json` 增加端到端快照测试。
- [ ] 保证普通文本输出不受 `--json` 以外参数影响。
- [ ] 文档化 schema 兼容策略：同一 major 版本只允许新增字段，不允许删除或改变语义。

验证命令：

```powershell
cargo test -p rsync-cli --all-features cli_contract
cargo run -p rsync-win -- --json --version
cargo run -p rsync-win -- --diagnostics-format=json invalid-source invalid-dest
```

### 4. 增加传输恢复和重试能力

目的：长时间同步任务不能因为一次短暂网络波动就需要从头排查。

新增参数：

```text
--retry-count=N
--retry-delay=SECONDS
--resume
--resume-state=PATH
```

恢复状态文件建议：

```json
{
  "schema": 1,
  "session_id": "uuid",
  "created_at_utc": "ISO-8601 timestamp",
  "source": "source path",
  "destination": "destination path",
  "entries": [
    {
      "path": "relative/path",
      "size": 1234,
      "mtime": 0,
      "checksum": "optional checksum",
      "state": "pending"
    }
  ]
}
```

实现步骤：

- [ ] 在 plan 层生成稳定 session id。
- [ ] 在 transfer 层记录已完成、进行中、待重试的 entry。
- [ ] 只在显式 `--resume` 时读取恢复文件。
- [ ] 对 partial 文件采用原子重命名策略。
- [ ] 对远程连接失败实现有限重试，避免无限循环。
- [ ] 在文档中明确哪些失败可恢复，哪些失败必须人工处理。

测试场景：

- [ ] 本地传输中断后重跑。
- [ ] 远程 shell 提前退出后重试。
- [ ] daemon 连接断开后重试。
- [ ] 目标磁盘空间不足时不误报成功。
- [ ] partial 文件大小和校验不匹配时重新传输。

验证命令：

```powershell
cargo test -p rsync-cli --all-features resume retry partial
```

### 5. 建立性能基准和回归门槛

目的：后续优化必须有数字，不能只靠主观感觉。

新增目录：

```text
benches/
docs/performance/
```

基准数据集：

| 数据集 | 规模 | 目的 |
| --- | --- | --- |
| tiny-many | 10000 个小文件 | 目录扫描和元数据开销 |
| medium-mixed | 1GB 混合文件 | 常规备份 |
| large-single | 10GB 单文件 | 大文件复制和校验 |
| deep-tree | 20 层目录 | 路径处理 |
| changed-1-percent | 低变更率 | 增量效率 |

指标：

- 总耗时
- 扫描耗时
- 文件列表构建耗时
- 传输耗时
- 校验耗时
- 峰值内存
- 每秒文件数
- 每秒字节数
- 失败率

实现步骤：

- [ ] 新增 `scripts/generate-benchmark-data.ps1`。
- [ ] 新增 `scripts/run-benchmarks.ps1`。
- [ ] 输出 JSON 和 Markdown 两种报告。
- [ ] 在 CI 中运行小规模基准。
- [ ] 对大规模基准采用手动 release gate。
- [ ] 为 Windows Defender/EDR 影响记录单独字段，避免误判性能回退。

验证命令：

```powershell
.\scripts\generate-benchmark-data.ps1 -Profile tiny-many
.\scripts\run-benchmarks.ps1 -Profile tiny-many -Output docs\performance\tiny-many.json
```

### 6. Windows Service 与运维能力

目的：让 daemon 模式能被服务器管理员长期运行和维护。

新增命令：

```text
rsync-win service install
rsync-win service uninstall
rsync-win service start
rsync-win service stop
rsync-win service status
rsync-win service validate-config
```

新增文档：

```text
docs/WINDOWS-OPERATIONS.md
docs/examples/daemon-service.toml
docs/examples/scheduled-backup.ps1
```

实现步骤：

- [ ] 新增 service 子命令解析。
- [ ] 封装 Windows Service Control Manager 操作。
- [ ] 支持指定配置文件、工作目录、日志目录和运行账号。
- [ ] 输出 Windows Event Log。
- [ ] 提供最小权限运行示例。
- [ ] 增加服务安装和卸载的集成测试说明。

完成标准：

- 服务安装后重启机器仍能自动启动。
- 配置错误时服务不静默失败。
- 日志能定位监听地址、配置文件、认证失败、传输失败。

验证命令：

```powershell
cargo test -p rsync-cli --all-features service
rsync-win service validate-config --config docs\examples\daemon-service.toml
```

### 7. Windows 元数据能力矩阵

目的：让用户清楚知道 ACL、所有者、只读属性、隐藏属性、ADS、reparse point 在不同模式下的行为。

新增文档：

```text
docs/WINDOWS-METADATA.md
docs/metadata-matrix.json
```

矩阵维度：

- 本地复制
- SSH push
- SSH pull
- daemon push
- daemon pull
- portable policy
- posix policy
- Windows-native policy

元数据对象：

- mtime
- atime
- readonly
- hidden
- system
- owner
- group
- DACL
- SACL
- alternate data streams
- symlink
- junction
- mount point

实现步骤：

- [ ] 增加 metadata fixture 生成脚本。
- [ ] 增加需要管理员权限的测试分组。
- [ ] 增加非管理员权限下的降级测试。
- [ ] 把不可支持的行为写成明确差异，而不是隐藏在失败测试中。
- [ ] 在 `docs/COMPATIBILITY.md` 中引用矩阵。

验证命令：

```powershell
cargo test -p rsync-cli --all-features metadata_matrix
```

### 8. 安全与供应链成熟化

目的：降低公开发行后的供应链和协议攻击风险。

新增文档：

```text
docs/SECURITY.md
docs/THREAT-MODEL.md
docs/SUPPLY-CHAIN.md
```

发布要求：

- SBOM
- 源码 tag 签名
- 二进制签名
- checksum
- 构建日志归档
- 依赖审计
- fuzz 报告
- 漏洞披露流程

实现步骤：

- [ ] 固化 `cargo audit` 或等价依赖审计流程。
- [ ] 对协议 parser、path sanitizer、daemon auth 增加持续 fuzz。
- [ ] 对 release 制品增加可复验清单。
- [ ] 明确私钥、签名证书、CI secret 的维护流程。
- [ ] 在 `SECURITY.md` 中写明报告渠道和支持版本。

验证命令：

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-features -- -D warnings
```

### 9. 文档和迁移体验

目的：减少用户从 cwRsync、Cygwin/MSYS2 rsync、WSL rsync 迁移时的摩擦。

新增文档：

```text
docs/MIGRATING-FROM-CWRSYNC.md
docs/MIGRATING-FROM-CYGWIN.md
docs/MIGRATING-FROM-WSL.md
docs/TROUBLESHOOTING.md
docs/RECIPES.md
```

必须覆盖的 recipes：

- 本地目录镜像。
- Windows 到 Linux 服务器备份。
- Linux 到 Windows 拉取。
- daemon 模式只读模块。
- daemon 模式写入模块。
- 保留 Windows ACL。
- 跳过 Windows ACL。
- 低权限账号运行服务。
- 计划任务每日备份。
- CI 中同步构建产物。

实现步骤：

- [ ] 从认证测试中提取真实命令作为文档示例。
- [ ] 每个示例都增加“预期退出码”和“如何验证结果”。
- [ ] 增加常见错误索引。
- [ ] 增加从旧发行版迁移的参数映射表。

验证命令：

```powershell
cargo test -p rsync-cli --test release_readiness --all-features
```

### 10. 发布治理和维护策略

目的：避免 v1.0 之后每次修复都变成临时决策。

新增文档：

```text
docs/RELEASE-POLICY.md
docs/SUPPORT-POLICY.md
docs/BACKWARD-COMPATIBILITY.md
docs/MAINTAINER-CHECKLIST.md
```

建议策略：

- `v0.x`：允许有限 CLI 调整，但必须在 changelog 中写明。
- `v1.x`：默认保持 CLI 和 JSON schema 兼容。
- 安全修复：支持最近两个 minor。
- 普通 bugfix：支持当前 minor。
- 实验功能：必须在帮助和文档中标注。
- 弃用功能：至少跨一个 minor 后移除。

发布检查清单：

- [ ] 所有测试通过。
- [ ] 认证报告更新。
- [ ] 性能基准无重大回退。
- [ ] 文档版本号一致。
- [ ] manifest SHA256 一致。
- [ ] SBOM 生成。
- [ ] 制品签名。
- [ ] release notes 包含兼容性说明。
- [ ] 支持版本矩阵更新。

验证命令：

```powershell
.\scripts\verify-release-artifacts.ps1 -Tag v0.3.0
```

## 推荐执行顺序

1. 先做 Task 1 和 Task 2，因为它们决定后续每个版本的可信度和安装体验。
2. 再做 Task 3，因为机器可读合约会影响自动化用户，越早稳定越好。
3. 接着做 Task 4 和 Task 5，用恢复能力和性能数据支撑大规模使用。
4. 然后做 Task 6 和 Task 7，覆盖 Windows 服务器和元数据高级场景。
5. 最后做 Task 8、Task 9、Task 10，为 v1.0 的维护边界收口。

## 风险

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| 包管理器审核周期不可控 | 发布节奏受阻 | ZIP 和 GitHub Release 作为主发布渠道，包管理器作为延迟同步渠道 |
| Windows Service 权限复杂 | 用户容易配置失败 | 提供最小权限模板和 `validate-config` |
| JSON 合约过早冻结 | 后续扩展受限 | schema 只承诺新增字段兼容，复杂对象保留扩展字段 |
| 性能优化破坏兼容性 | 传输结果不可信 | 所有优化必须先过认证测试，再看 benchmark |
| 元数据行为依赖权限 | 同一命令不同机器结果不同 | 文档和测试都区分管理员/非管理员模式 |

## 本阶段完成定义

下一阶段完成时，项目应满足：

- 用户能从公开发布页下载或通过包管理器安装。
- 用户能看到当前版本的认证矩阵和复验方法。
- 自动化系统能使用稳定 JSON 输出判断成功、失败、重试。
- 长时间传输有明确恢复策略。
- Windows daemon 能作为服务运行。
- 安全、支持、兼容性、发布策略都有文档化承诺。
- v1.0 之前剩余工作只剩明确取舍，而不是基础能力缺口。
