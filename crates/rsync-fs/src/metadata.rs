use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Hardlink,
    Device,
    Special,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HardlinkId {
    pub volume: u64,
    pub file: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableMetadata {
    pub file_type: FileType,
    pub len: u64,
    pub modified: Option<SystemTime>,
    pub mode: Option<u32>,
    pub symlink_target: Option<PathBuf>,
    pub hardlink_id: Option<HardlinkId>,
    pub hardlink_count: Option<u64>,
}

pub const POSIX_TYPE_REGULAR: u32 = 0o100000;
pub const POSIX_TYPE_DIRECTORY: u32 = 0o040000;
pub const POSIX_TYPE_SYMLINK: u32 = 0o120000;
pub const POSIX_FILE_DEFAULT_PERMS: u32 = 0o644;
pub const POSIX_FILE_EXECUTABLE_PERMS: u32 = 0o755;
pub const POSIX_DIRECTORY_DEFAULT_PERMS: u32 = 0o755;
pub const POSIX_SYMLINK_DEFAULT_PERMS: u32 = 0o777;

impl PortableMetadata {
    pub fn file(len: u64) -> Self {
        Self {
            file_type: FileType::File,
            len,
            modified: None,
            mode: None,
            symlink_target: None,
            hardlink_id: None,
            hardlink_count: None,
        }
    }

    pub fn directory() -> Self {
        Self {
            file_type: FileType::Directory,
            len: 0,
            modified: None,
            mode: None,
            symlink_target: None,
            hardlink_id: None,
            hardlink_count: None,
        }
    }

    pub fn symlink(target: impl Into<PathBuf>) -> Self {
        Self {
            file_type: FileType::Symlink,
            len: 0,
            modified: None,
            mode: None,
            symlink_target: Some(target.into()),
            hardlink_id: None,
            hardlink_count: None,
        }
    }

    pub fn device() -> Self {
        Self {
            file_type: FileType::Device,
            len: 0,
            modified: None,
            mode: None,
            symlink_target: None,
            hardlink_id: None,
            hardlink_count: None,
        }
    }

    pub fn special() -> Self {
        Self {
            file_type: FileType::Special,
            len: 0,
            modified: None,
            mode: None,
            symlink_target: None,
            hardlink_id: None,
            hardlink_count: None,
        }
    }

    pub fn with_modified(mut self, modified: SystemTime) -> Self {
        self.modified = Some(modified);
        self
    }

    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn posix_mode_for_path(&self, path: Option<&Path>, preserve_executability: bool) -> u32 {
        let file_type_bits = posix_file_type_bits(self.file_type);
        let mut permissions = self
            .mode
            .unwrap_or_else(|| default_permissions(self.file_type));
        permissions &= 0o7777;

        if self.file_type == FileType::File
            && preserve_executability
            && path.is_some_and(path_looks_executable)
        {
            permissions |= 0o111;
        }

        file_type_bits | permissions
    }
}

pub fn posix_file_type_bits(file_type: FileType) -> u32 {
    match file_type {
        FileType::Directory => POSIX_TYPE_DIRECTORY,
        FileType::Symlink => POSIX_TYPE_SYMLINK,
        FileType::File
        | FileType::Hardlink
        | FileType::Device
        | FileType::Special
        | FileType::Other => POSIX_TYPE_REGULAR,
    }
}

pub fn default_permissions(file_type: FileType) -> u32 {
    match file_type {
        FileType::Directory => POSIX_DIRECTORY_DEFAULT_PERMS,
        FileType::Symlink => POSIX_SYMLINK_DEFAULT_PERMS,
        FileType::File
        | FileType::Hardlink
        | FileType::Device
        | FileType::Special
        | FileType::Other => POSIX_FILE_DEFAULT_PERMS,
    }
}

pub fn path_looks_executable(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "bat" | "cmd" | "com" | "exe" | "ps1"
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataFeature {
    Mode,
    Owner,
    Group,
    Acl,
    Xattr,
    Device,
    SpecialFile,
    Symlink,
    Hardlink,
    CreationTime,
    WindowsAttributes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataAction {
    Applied,
    Degraded,
    Ignored,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDegradation {
    pub feature: MetadataFeature,
    pub action: MetadataAction,
    pub message: String,
}

impl MetadataDegradation {
    pub fn new(
        feature: MetadataFeature,
        action: MetadataAction,
        message: impl Into<String>,
    ) -> Self {
        Self {
            feature,
            action,
            message: message.into(),
        }
    }

    pub fn is_loss(&self) -> bool {
        !matches!(self.action, MetadataAction::Applied)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataReport {
    degradations: Vec<MetadataDegradation>,
}

impl MetadataReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, degradation: MetadataDegradation) {
        self.degradations.push(degradation);
    }

    pub fn warn_loss(
        &mut self,
        feature: MetadataFeature,
        action: MetadataAction,
        message: impl Into<String>,
    ) {
        self.push(MetadataDegradation::new(feature, action, message));
    }

    pub fn has_loss(&self) -> bool {
        self.degradations.iter().any(MetadataDegradation::is_loss)
    }

    pub fn degradations(&self) -> &[MetadataDegradation] {
        &self.degradations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_tracks_lossful_metadata_actions() {
        let mut report = MetadataReport::new();
        report.push(MetadataDegradation::new(
            MetadataFeature::Acl,
            MetadataAction::Ignored,
            "portable mode does not preserve ACLs",
        ));

        assert!(report.has_loss());
        assert_eq!(report.degradations().len(), 1);
    }

    #[test]
    fn executability_infers_mode_from_windows_filename_conventions() {
        let metadata = PortableMetadata::file(12);

        for path in ["tool.exe", "run.bat", "run.cmd", "script.ps1"] {
            assert_eq!(
                metadata.posix_mode_for_path(Some(Path::new(path)), true),
                POSIX_TYPE_REGULAR | POSIX_FILE_EXECUTABLE_PERMS,
                "{path}"
            );
        }
        assert_eq!(
            metadata.posix_mode_for_path(Some(Path::new("notes.txt")), true),
            POSIX_TYPE_REGULAR | POSIX_FILE_DEFAULT_PERMS
        );
    }

    #[test]
    fn explicit_mode_overrides_default_permissions() {
        let metadata = PortableMetadata::file(12).with_mode(0o600);

        assert_eq!(
            metadata.posix_mode_for_path(Some(Path::new("tool.exe")), false),
            POSIX_TYPE_REGULAR | 0o600
        );
    }
}
