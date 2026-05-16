# rsync-win Option Status

This table is maintained from the current `rsync-cli` option registry by execution support level. It is conservative: an option is "fully implemented" only when parsed behavior is connected to tested execution behavior in each documented supported mode where that option applies.

## Upstream Client Options

| Support level | Options |
| --- | --- |
| Fully implemented | `--8-bit-output`, `--debug`, `--help`, `--human-readable`, `--info`, `--itemize-changes`, `--log-file`, `--log-file-format`, `--msgs2stderr`, `--no-msgs2stderr`, `--out-format`, `--P`, `--progress`, `--quiet`, `--stats`, `--stderr`, `--verbose`, `--version` |
| Partially implemented by mode | `--i-r`, `--inc-recursive`, `--no-i-r`, `--no-inc-recursive` (protocol 31 remote pull; remote-shell push streams local file-list batches but remains forced to upstream `--no-inc-recursive`) |
| Partially implemented by mode | `--acls`, `--address`, `--append`, `--append-verify`, `--archive`, `--atimes`, `--backup`, `--backup-dir`, `--block-size`, `--bwlimit`, `--cc`, `--checksum`, `--checksum-choice`, `--checksum-seed`, `--chmod`, `--chown`, `--compare-dest`, `--compress`, `--compress-choice`, `--compress-level`, `--compression-choice`, `--contimeout`, `--copy-dest`, `--copy-devices`, `--copy-dirlinks`, `--copy-links`, `--copy-unsafe-links`, `--crtimes`, `--cvs-exclude`, `--D`, `--del`, `--delay-updates`, `--delete`, `--delete-after`, `--delete-before`, `--delete-delay`, `--delete-during`, `--delete-excluded`, `--delete-missing-args`, `--devices`, `--dirs`, `--dry-run`, `--early-input`, `--exclude`, `--exclude-from`, `--executability`, `--existing`, `--F`, `--fake-super`, `--files-from`, `--filter`, `--force`, `--from0`, `--fsync`, `--fuzzy`, `--group`, `--groupmap`, `--hard-links`, `--ignore-errors`, `--ignore-existing`, `--ignore-missing-args`, `--ignore-non-existing`, `--ignore-times`, `--include`, `--include-from`, `--inplace`, `--ipv4`, `--ipv6`, `--keep-dirlinks`, `--link-dest`, `--links`, `--list-only`, `--max-alloc`, `--max-delete`, `--max-size`, `--min-size`, `--mkpath`, `--modify-window`, `--munge-links`, `--no-implied-dirs`, `--no-motd`, `--numeric-ids`, `--old-args`, `--old-d`, `--old-dirs`, `--omit-dir-times`, `--omit-link-times`, `--one-file-system`, `--only-write-batch`, `--outbuf`, `--owner`, `--partial`, `--partial-dir`, `--password-file`, `--perms`, `--port`, `--preallocate`, `--protocol`, `--protect-args`, `--read-batch`, `--recursive`, `--relative`, `--remote-option`, `--rsh`, `--rsync-path`, `--safe-links`, `--secluded-args`, `--size-only`, `--skip-compress`, `--sockopts`, `--sparse`, `--specials`, `--stop-after`, `--stop-at`, `--suffix`, `--super`, `--temp-dir`, `--time-limit`, `--timeout`, `--times`, `--trust-sender`, `--update`, `--usermap`, `--whole-file`, `--write-batch`, `--write-devices`, `--xattrs`, `--zc`, `--zl` |
| Diagnostic/reporting only | `--blocking-io`, `--copy-as`, `--iconv`, `--open-noatime` |
| Parsed for compatibility only | `--compress-threads`, `--zt` |
| Planned | `--prune-empty-dirs`, `--remove-source-files` |

## Daemon And Project Options

| Scope | Fully implemented | Partially implemented by mode | Diagnostic/reporting only | Parsed for compatibility only | Planned |
| --- | --- | --- | --- | --- | --- |
| Daemon/server | none | `--address`, `--bwlimit`, `--config`, `--daemon`, `--dparam`, `--help`, `--ipv4`, `--ipv6`, `--log-file`, `--log-file-format`, `--no-detach`, `--port`, `--sockopts`, `--verbose` | none | none | none |
| Project-specific | none | `--fail-on-metadata-loss`, `--metadata-policy`, `--plan`, `--protocol-range`, `--vss` | none | none | none |

## Status Meanings

| Support level | Meaning |
| --- | --- |
| Fully implemented | Parsed and covered by tested execution behavior in every documented supported mode where the option applies. |
| Partially implemented by mode | Parsed and connected to real behavior in at least one supported mode, but not yet verified or complete across all applicable local, remote-shell, and daemon paths. |
| Diagnostic/reporting only | Accepted for compatibility and surfaced in plan output or diagnostics, but not applied to transfer semantics. |
| Parsed for compatibility only | Accepted by the parser to avoid rejecting upstream command lines, but not advertised as behavioral compatibility. |
| Planned | Accepted or reserved for future implementation and not counted as current execution support. |
