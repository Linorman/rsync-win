# VSS Snapshot Source Design Note

`--vss` remains explicitly rejected until rsync-win has a real snapshot-backed source abstraction.

The future implementation should introduce a source filesystem wrapper that:

- Creates a VSS snapshot before walking source paths.
- Maps each requested source path to its snapshot device path.
- Keeps all file-list, checksum, and literal reads on the snapshot path.
- Releases the snapshot only after transfer completion or failure cleanup.
- Reports snapshot creation, path mapping, and teardown failures as metadata loss when requested.

Do not add direct VSS calls to ordinary file read paths. The portable and ntfs-native source APIs should stay explicit about whether bytes came from the live filesystem or from a snapshot.
