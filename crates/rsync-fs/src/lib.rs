pub mod metadata;
pub mod sync;
pub mod walk;

pub use metadata::{
    default_permissions, path_looks_executable, posix_file_type_bits, FileType, HardlinkId,
    MetadataAction, MetadataDegradation, MetadataFeature, MetadataReport, PortableMetadata,
    POSIX_DIRECTORY_DEFAULT_PERMS, POSIX_FILE_DEFAULT_PERMS, POSIX_FILE_EXECUTABLE_PERMS,
    POSIX_SYMLINK_DEFAULT_PERMS, POSIX_TYPE_DIRECTORY, POSIX_TYPE_REGULAR, POSIX_TYPE_SYMLINK,
};
pub use sync::{
    selected_source_paths, source_relative_paths, sync_sources, sync_tree, DeleteMode,
    DestinationPathPreflight, SourceSelectionOptions, SymlinkMode, SyncAction, SyncOptions,
    SyncReport, UpdateMode,
};
pub use walk::{
    walk_tree, FileWriteMode, FileWriteOptions, FsError, LocalFileSystem, MemoryFileSystem,
    PortableFileSystem, WalkEntry,
};
