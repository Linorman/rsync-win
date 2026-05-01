# rsync-win Option Status

This table is maintained from the current `rsync-cli` option registry by status family. It is conservative: `implemented` means parsed and connected to current local, remote-shell, daemon-client, sidecar, or reporting behavior; `explicit diagnostic` means accepted for compatibility but intentionally not applied; `planned diagnostic` means accepted and reported as unsupported until the implementation lands.

## Upstream Client Options

| Status | Options |
| --- | --- |
| Implemented | `--8-bit-output`, `--acls`, `--address`, `--append`, `--append-verify`, `--archive`, `--atimes`, `--backup`, `--backup-dir`, `--block-size`, `--blocking-io`, `--cc`, `--checksum`, `--checksum-choice`, `--checksum-seed`, `--chmod`, `--chown`, `--compare-dest`, `--compress`, `--compress-choice`, `--compress-level`, `--compress-threads`, `--compression-choice`, `--contimeout`, `--copy-as`, `--copy-dest`, `--copy-devices`, `--copy-dirlinks`, `--copy-links`, `--copy-unsafe-links`, `--crtimes`, `--cvs-exclude`, `--D`, `--debug`, `--del`, `--delay-updates`, `--delete`, `--delete-after`, `--delete-before`, `--delete-delay`, `--delete-during`, `--delete-excluded`, `--delete-missing-args`, `--devices`, `--dirs`, `--dry-run`, `--exclude`, `--exclude-from`, `--executability`, `--existing`, `--F`, `--fake-super`, `--files-from`, `--filter`, `--force`, `--from0`, `--fsync`, `--fuzzy`, `--group`, `--groupmap`, `--hard-links`, `--help`, `--human-readable`, `--ignore-errors`, `--ignore-existing`, `--ignore-missing-args`, `--ignore-non-existing`, `--ignore-times`, `--include`, `--include-from`, `--info`, `--inplace`, `--ipv4`, `--ipv6`, `--itemize-changes`, `--keep-dirlinks`, `--link-dest`, `--links`, `--list-only`, `--log-file`, `--log-file-format`, `--max-delete`, `--max-size`, `--min-size`, `--mkpath`, `--modify-window`, `--msgs2stderr`, `--munge-links`, `--no-implied-dirs`, `--no-motd`, `--no-msgs2stderr`, `--numeric-ids`, `--old-args`, `--old-d`, `--old-dirs`, `--omit-dir-times`, `--omit-link-times`, `--one-file-system`, `--only-write-batch`, `--out-format`, `--owner`, `--P`, `--partial`, `--partial-dir`, `--password-file`, `--perms`, `--port`, `--preallocate`, `--progress`, `--protect-args`, `--quiet`, `--read-batch`, `--recursive`, `--relative`, `--remote-option`, `--rsh`, `--rsync-path`, `--safe-links`, `--secluded-args`, `--size-only`, `--skip-compress`, `--sockopts`, `--sparse`, `--specials`, `--stats`, `--stderr`, `--suffix`, `--super`, `--temp-dir`, `--times`, `--trust-sender`, `--update`, `--usermap`, `--verbose`, `--version`, `--whole-file`, `--write-batch`, `--write-devices`, `--xattrs`, `--zc`, `--zl`, `--zt` |
| Explicit diagnostic | none |
| Planned diagnostic | `--bwlimit`, `--early-input`, `--i-r`, `--iconv`, `--inc-recursive`, `--max-alloc`, `--no-i-r`, `--no-inc-recursive`, `--open-noatime`, `--outbuf`, `--protocol`, `--prune-empty-dirs`, `--remove-source-files`, `--stop-after`, `--stop-at`, `--time-limit`, `--timeout` |

## Daemon And Project Options

| Scope | Implemented | Planned diagnostic |
| --- | --- | --- |
| Daemon/server | `--address`, `--bwlimit`, `--config`, `--daemon`, `--dparam`, `--help`, `--ipv4`, `--ipv6`, `--log-file`, `--log-file-format`, `--no-detach`, `--port`, `--sockopts`, `--verbose` | none |
| Project-specific | `--fail-on-metadata-loss`, `--metadata-policy`, `--plan`, `--protocol-range`, `--vss` | none |

## Status Meanings

| Status | Meaning |
| --- | --- |
| Implemented | The option is parsed and has tested behavior in at least one supported mode, or a tested sidecar/reporting path where Windows cannot apply native POSIX semantics. |
| Explicit diagnostic | The option is accepted to preserve rsync command-line compatibility, but the current transfer path emits a documented limitation instead of silently pretending to apply it. |
| Planned diagnostic | The option is accepted and surfaced as unsupported/deferred. It is not counted as behavioral compatibility. |
