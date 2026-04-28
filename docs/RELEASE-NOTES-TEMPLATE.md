# rsync-win {{TAG}}

Windows x64 prebuilt executable for the native Rust rsync-win development build.

## Capability Status

- Local Windows sync covers the tested ordinary-file and directory subset, including recursion, mtimes, deletion, filters, multiple sources, update modes, bounded local copy buffers, and NTFS-native sidecar capture.
- Remote-shell mode is experimental for ordinary-file push/pull over SSH with protocol 31 preferred and protocol 27 fallback retained for older interop work.
- Daemon mode is an experimental client MVP for module listing, no-auth ordinary-file pull, and `--password-file` challenge-response auth. Daemon auth is not transport encryption.
- POSIX and NTFS metadata that cannot be faithfully applied are reported as degraded or rejected. `ntfs-native` local Windows sync restores only the tested readonly/hidden/archive/system attribute subset and named ADS payloads.

## Known Not Implemented

- Daemon push.
- VSS snapshot reads.
- NTFS security descriptor restore, sparse range preservation, and arbitrary reparse restore.
- Full memory-bounded incremental recursion.

Review the packaged `README.md` and `docs/COMPATIBILITY.md` before using this build on important data.
