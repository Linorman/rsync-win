use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Hardlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableMetadata {
    pub file_type: FileType,
    pub len: u64,
    pub modified: Option<SystemTime>,
    pub mode: Option<u32>,
    pub symlink_target: Option<PathBuf>,
}

impl PortableMetadata {
    pub fn file(len: u64) -> Self {
        Self {
            file_type: FileType::File,
            len,
            modified: None,
            mode: None,
            symlink_target: None,
        }
    }

    pub fn directory() -> Self {
        Self {
            file_type: FileType::Directory,
            len: 0,
            modified: None,
            mode: None,
            symlink_target: None,
        }
    }

    pub fn symlink(target: impl Into<PathBuf>) -> Self {
        Self {
            file_type: FileType::Symlink,
            len: 0,
            modified: None,
            mode: None,
            symlink_target: Some(target.into()),
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
}
