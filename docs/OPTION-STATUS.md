# rsync-win Option Status

This table is maintained from the current `rsync-cli` option registry by status family. It is conservative: `implemented` means parsed and connected to current local, remote-shell, daemon-client, sidecar, or reporting behavior; `explicit diagnostic` means accepted for compatibility but intentionally not applied; `planned diagnostic` means accepted and reported as unsupported until the implementation lands.

## Upstream Client Options

| Status | Options |
| --- | --- |
| Implemented | `--acls`, `--address`, `--append`, `--append-verify`, `--archive`, `--atimes`, `--backup`, `--backup-dir`, `--block-size`, `--blocking-io`, `--cc`, `--checksum`, `--checksum-choice`, `--checksum-seed`, `--chmod`, `--chown`, `--compress`, `--compress-choice`, `--compress-level`, `--compress-threads`, `--compression-choice`, `--contimeout`, `--copy-devices`, `--copy-dirlinks`, `--copy-links`, `--copy-unsafe-links`, `--crtimes`, `--cvs-exclude`, `--D`, `--del`, `--delay-updates`, `--delete`, `--delete-after`, `--delete-before`, `--delete-delay`, `--delete-during`, `--delete-excluded`, `--delete-missing-args`, `--devices`, `--dirs`, `--dry-run`, `--exclude`, `--exclude-from`, `--executability`, `--existing`, `--F`, `--fake-super`, `--files-from`, `--filter`, `--force`, `--from0`, `--fsync`, `--group`, `--groupmap`, `--hard-links`, `--help`, `--human-readable`, `--ignore-errors`, `--ignore-existing`, `--ignore-missing-args`, `--ignore-non-existing`, `--ignore-times`, `--include`, `--include-from`, `--inplace`, `--ipv4`, `--ipv6`, `--itemize-changes`, `--keep-dirlinks`, `--links`, `--list-only`, `--max-delete`, `--max-size`, `--min-size`, `--mkpath`, `--modify-window`, `--munge-links`, `--no-implied-dirs`, `--no-motd`, `--numeric-ids`, `--old-args`, `--old-d`, `--old-dirs`, `--omit-dir-times`, `--omit-link-times`, `--one-file-system`, `--owner`, `--P`, `--partial`, `--partial-dir`, `--password-file`, `--perms`, `--port`, `--progress`, `--protect-args`, `--recursive`, `--relative`, `--remote-option`, `--rsh`, `--rsync-path`, `--safe-links`, `--secluded-args`, `--size-only`, `--skip-compress`, `--sockopts`, `--specials`, `--stats`, `--suffix`, `--temp-dir`, `--times`, `--trust-sender`, `--update`, `--usermap`, `--verbose`, `--version`, `--whole-file`, `--write-devices`, `--xattrs`, `--zc`, `--zl`, `--zt` |
| Explicit diagnostic | none |
| Planned diagnostic | `--8-bit-output`, `--bwlimit`, `--compare-dest`, `--copy-as`, `--copy-dest`, `--debug`, `--early-input`, `--fuzzy`, `--i-r`, `--iconv`, `--inc-recursive`, `--info`, `--link-dest`, `--log-file`, `--log-file-format`, `--max-alloc`, `--msgs2stderr`, `--no-i-r`, `--no-inc-recursive`, `--no-msgs2stderr`, `--only-write-batch`, `--open-noatime`, `--out-format`, `--outbuf`, `--preallocate`, `--protocol`, `--prune-empty-dirs`, `--quiet`, `--read-batch`, `--remove-source-files`, `--sparse`, `--stderr`, `--stop-after`, `--stop-at`, `--super`, `--time-limit`, `--timeout`, `--write-batch` |

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
