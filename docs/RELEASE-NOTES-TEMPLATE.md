# rsync-win {{TAG}}

Windows x64 prebuilt executable for the native Rust rsync-win production-readiness release.

## Capability Status

- Local Windows sync covers the tested ordinary-file and directory subset, including recursion, mtimes, deletion, filters, multiple sources, update modes, bounded local copy buffers, and NTFS-native sidecar capture.
- Remote-shell mode is experimental for ordinary-file push/pull over SSH with protocol 31 preferred and protocol 27 fallback retained for older interop work.
- Daemon mode covers module listing, no-auth pull, authenticated pull, and controlled writable-module flows. Daemon push to writable modules is covered in ordinary-file fixtures. Daemon auth is challenge-response only and is not transport encryption.
- POSIX and NTFS metadata that cannot be faithfully applied are reported as degraded or rejected. `ntfs-native` local Windows sync restores the tested readonly/hidden/archive/system attribute subset, creation time, named ADS payloads, sparse ranges, and security descriptors when explicitly permitted.
- VSS snapshot reads are available only for explicit local `--metadata-policy=ntfs-native --vss` runs on Windows systems where snapshot creation is permitted.

## Known Not Implemented

- Arbitrary non-symlink reparse restore.
- Sender-side remote push incremental recursion and full cross-mode memory-bounded incremental recursion.

Review the packaged `README.md` and `docs/COMPATIBILITY.md` before using this build on important data.
