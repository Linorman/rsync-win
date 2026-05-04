pub mod drive;
pub mod links;
pub mod metadata;
pub mod path;
pub mod security;
pub mod sidecar;
pub mod streams;
pub mod vss;

pub use drive::{drive_kind_for_path, WindowsDriveKind};
pub use links::{
    classify_reparse_point, detect_link_capabilities, should_traverse_reparse_point,
    LinkCapabilities, ReparsePointKind,
};
pub use metadata::{
    capture_ntfs_native_sidecar, read_windows_metadata, restore_creation_time,
    restore_safe_windows_attributes, WindowsAttributeRestore, WindowsMetadata,
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
    SAFE_RESTORE_ATTRIBUTE_MASK,
};
pub use path::{
    preflight_destination_paths, to_long_path_safe, validate_portable_component,
    validate_portable_relative_path, WindowsPathError,
};
pub use security::{
    capture_security_descriptor_summary, password_file_has_broad_access, SecurityDescriptorSummary,
};
pub use sidecar::{
    parse_ntfs_native_sidecar_manifest, parse_posix_fake_super_sidecar_manifest, NtfsNativeSidecar,
    NtfsNativeSidecarManifest, PosixAclRecord, PosixFakeSuperSidecar,
    PosixFakeSuperSidecarManifest, PosixXattrRecord, SidecarParseError, NTFS_SIDECAR_HEADER,
    POSIX_FAKE_SUPER_SIDECAR_HEADER,
};
pub use streams::{
    copy_alternate_data_streams, enumerate_alternate_data_streams, AlternateDataStream,
    AlternateDataStreamCopyReport,
};
pub use vss::{vss_snapshot_status, VssSnapshot, VssSnapshotStatus};
