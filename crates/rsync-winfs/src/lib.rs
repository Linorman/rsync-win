pub mod drive;
pub mod links;
pub mod metadata;
pub mod path;
pub mod security;
pub mod streams;
pub mod vss;

pub use drive::{drive_kind_for_path, WindowsDriveKind};
pub use links::{
    classify_reparse_point, detect_link_capabilities, should_traverse_reparse_point,
    LinkCapabilities, ReparsePointKind,
};
pub use metadata::{
    capture_ntfs_native_sidecar, read_windows_metadata, NtfsNativeSidecar, WindowsMetadata,
};
pub use path::{
    preflight_destination_paths, to_long_path_safe, validate_portable_component,
    validate_portable_relative_path, WindowsPathError,
};
pub use security::{capture_security_descriptor_summary, SecurityDescriptorSummary};
pub use streams::{enumerate_alternate_data_streams, AlternateDataStream};
pub use vss::{vss_snapshot_status, VssSnapshotStatus};
