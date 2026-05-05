# VSS Snapshot Source Design Note

`--vss` is an explicit local Windows source mode. It is accepted only with `--metadata-policy=ntfs-native` so snapshot reads are never enabled by default or implied by portable/POSIX compatibility options.

The implementation keeps VSS isolated from ordinary file IO:

- The local executor validates `--metadata-policy=ntfs-native --vss` before mutation.
- `rsync-winfs::VssSnapshot` creates a runtime shadow copy for each source root through Windows VSS/WMI.
- Source operands are mapped to their snapshot device paths before the portable sync engine walks or reads them.
- The original source paths are still used for user-facing summaries and NTFS sidecar capture.
- Shadow copies are deleted by `Drop` after transfer completion or failure.
- Snapshot creation and path mapping failures stop the transfer before receiver mutation.

This design keeps the portable filesystem abstraction free of direct VSS calls while making the byte source explicit at the local executor boundary.
