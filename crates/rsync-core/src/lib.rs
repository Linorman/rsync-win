pub mod chmod;

use std::path::PathBuf;
use std::str::FromStr;

use thiserror::Error;

pub use chmod::{ChmodFileKind, ChmodRules};

pub type Result<T> = std::result::Result<T, RsyncCoreError>;

#[derive(Debug, Error)]
pub enum RsyncCoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(&'static str),
    #[error("invalid argument `{name}`: {reason}")]
    InvalidArgument { name: &'static str, reason: String },
    #[error("invalid path: {0}")]
    InvalidPath(PathBuf),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MetadataPolicy {
    #[default]
    Portable,
    Posix,
    NtfsNative,
}

impl MetadataPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::Posix => "posix",
            Self::NtfsNative => "ntfs-native",
        }
    }
}

impl std::fmt::Display for MetadataPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MetadataPolicy {
    type Err = RsyncCoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "portable" => Ok(Self::Portable),
            "posix" => Ok(Self::Posix),
            "ntfs-native" => Ok(Self::NtfsNative),
            _ => Err(RsyncCoreError::InvalidArgument {
                name: "metadata-policy",
                reason: format!("expected one of portable, posix, ntfs-native; got `{value}`"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataFeature {
    Symlink,
    SymlinkMtime,
    Permissions,
    Executability,
    Owner,
    Group,
    Device,
    SpecialFile,
    Acl,
    Xattr,
    FakeSuper,
    SecurityDescriptor,
    AlternateDataStream,
    AccessTime,
    CreationTime,
    WindowsAttributes,
    SparseFile,
    ReparsePoint,
    VssSnapshot,
}

impl MetadataFeature {
    pub fn label(self) -> &'static str {
        match self {
            Self::Symlink => "symlink",
            Self::SymlinkMtime => "symlink-mtime",
            Self::Permissions => "permissions",
            Self::Executability => "executability",
            Self::Owner => "owner",
            Self::Group => "group",
            Self::Device => "device",
            Self::SpecialFile => "special-file",
            Self::Acl => "acl",
            Self::Xattr => "xattr",
            Self::FakeSuper => "fake-super",
            Self::SecurityDescriptor => "security-descriptor",
            Self::AlternateDataStream => "alternate-data-stream",
            Self::AccessTime => "access-time",
            Self::CreationTime => "creation-time",
            Self::WindowsAttributes => "windows-attributes",
            Self::SparseFile => "sparse-file",
            Self::ReparsePoint => "reparse-point",
            Self::VssSnapshot => "vss-snapshot",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataAction {
    Applied,
    Stored,
    Degraded,
    Ignored,
    Rejected,
}

impl MetadataAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Stored => "stored",
            Self::Degraded => "degraded",
            Self::Ignored => "ignored",
            Self::Rejected => "rejected",
        }
    }
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
        !matches!(
            self.action,
            MetadataAction::Applied | MetadataAction::Stored
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveComponent {
    Recursive,
    Links,
    Permissions,
    Times,
    Group,
    Owner,
    Devices,
}

impl ArchiveComponent {
    pub fn flag(self) -> &'static str {
        match self {
            Self::Recursive => "-r",
            Self::Links => "-l",
            Self::Permissions => "-p",
            Self::Times => "-t",
            Self::Group => "-g",
            Self::Owner => "-o",
            Self::Devices => "-D",
        }
    }
}

pub fn archive_mode_components() -> [ArchiveComponent; 7] {
    [
        ArchiveComponent::Recursive,
        ArchiveComponent::Links,
        ArchiveComponent::Permissions,
        ArchiveComponent::Times,
        ArchiveComponent::Group,
        ArchiveComponent::Owner,
        ArchiveComponent::Devices,
    ]
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PosixMetadataRequest {
    pub permissions: bool,
    pub owner: bool,
    pub group: bool,
    pub numeric_ids: bool,
    pub chmod: bool,
    pub executability: bool,
    pub symlink_mtime: bool,
    pub acls: bool,
    pub xattrs: bool,
    pub fake_super: bool,
    pub atimes: bool,
    pub crtimes: bool,
    pub omit_dir_times: bool,
    pub user_map: bool,
    pub group_map: bool,
    pub chown: bool,
}

impl PosixMetadataRequest {
    pub fn any(self) -> bool {
        self.permissions
            || self.owner
            || self.group
            || self.numeric_ids
            || self.chmod
            || self.executability
            || self.symlink_mtime
            || self.acls
            || self.xattrs
            || self.fake_super
            || self.atimes
            || self.crtimes
            || self.omit_dir_times
            || self.user_map
            || self.group_map
            || self.chown
    }

    pub fn degradations(self, policy: MetadataPolicy) -> Vec<MetadataDegradation> {
        let mut degradations = Vec::new();
        let policy_label = policy.as_str();

        if self.permissions {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Permissions,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Degraded
                },
                if self.fake_super {
                    "--perms requests POSIX mode preservation; mode bits are stored in the fake-super sidecar".to_string()
                } else {
                    format!(
                        "--perms requests POSIX mode preservation; {policy_label} local transfers record mode intent but do not chmod Windows destinations yet"
                    )
                },
            ));
        }
        if self.chmod {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Permissions,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Degraded
                },
                if self.fake_super {
                    "--chmod requests POSIX mode rewriting; rewritten mode bits are stored in the fake-super sidecar".to_string()
                } else {
                    format!(
                        "--chmod requests POSIX mode rewriting; {policy_label} local transfers report the request but do not apply chmod expressions yet"
                    )
                },
            ));
        }
        if self.executability {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Executability,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Degraded
                },
                if self.fake_super {
                    "--executability mode intent is stored in the fake-super sidecar"
                } else {
                    "--executability is represented in sender mode mapping for remote uploads; local Windows destinations do not apply executable bits"
                },
            ));
        }
        if self.owner {
            let message = if self.fake_super {
                "owner metadata is stored in the fake-super sidecar"
            } else if self.numeric_ids {
                "--numeric-ids requests numeric POSIX owner ids; Windows local transfers do not apply POSIX owners"
            } else {
                "--owner requests POSIX owner preservation; Windows local transfers do not apply POSIX owners"
            };
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Owner,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Ignored
                },
                message,
            ));
        }
        if self.group {
            let message = if self.fake_super {
                "group metadata is stored in the fake-super sidecar"
            } else if self.numeric_ids {
                "--numeric-ids requests numeric POSIX group ids; Windows local transfers do not apply POSIX groups"
            } else {
                "--group requests POSIX group preservation; Windows local transfers do not apply POSIX groups"
            };
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Group,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Ignored
                },
                message,
            ));
        }
        if self.symlink_mtime {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::SymlinkMtime,
                MetadataAction::Degraded,
                "symlink mtime preservation is protocol/platform-dependent and is not applied by the local Windows executor yet",
            ));
        }
        if self.acls {
            let message = if self.fake_super {
                "--acls metadata requested with fake-super; POSIX ACL intent is stored in the fake-super sidecar"
            } else {
                "--acls requests POSIX ACL preservation; Windows local transfers do not apply POSIX ACLs"
            };
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Acl,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Ignored
                },
                message,
            ));
        }
        if self.xattrs {
            let message = if self.fake_super {
                "--xattrs metadata requested with fake-super; POSIX xattr intent is stored in the fake-super sidecar"
            } else {
                "--xattrs requests extended attribute preservation; Windows local transfers do not apply POSIX xattrs"
            };
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Xattr,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Ignored
                },
                message,
            ));
        }
        if self.fake_super {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::FakeSuper,
                MetadataAction::Stored,
                "--fake-super metadata is stored in a Windows sidecar for local transfers",
            ));
        }
        if self.atimes {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::AccessTime,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Degraded
                },
                if self.fake_super {
                    "--atimes intent is stored in the fake-super sidecar"
                } else {
                    "--atimes preservation is platform-dependent and is not applied by the local Windows executor yet"
                },
            ));
        }
        if self.crtimes {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::CreationTime,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Degraded
                },
                if self.fake_super {
                    "--crtimes intent is stored in the fake-super sidecar"
                } else {
                    "--crtimes preservation requires platform-specific creation-time support"
                },
            ));
        }
        if self.omit_dir_times {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Permissions,
                MetadataAction::Applied,
                "--omit-dir-times is applied by not scheduling directory mtime preservation in local planning",
            ));
        }
        if self.user_map || self.chown {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Owner,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Ignored
                },
                if self.fake_super {
                    "owner mapping intent is stored in the fake-super sidecar"
                } else {
                    "owner mapping is meaningful for remote POSIX receivers; local Windows transfers do not apply POSIX owners"
                },
            ));
        }
        if self.group_map || self.chown {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::Group,
                if self.fake_super {
                    MetadataAction::Stored
                } else {
                    MetadataAction::Ignored
                },
                if self.fake_super {
                    "group mapping intent is stored in the fake-super sidecar"
                } else {
                    "group mapping is meaningful for remote POSIX receivers; local Windows transfers do not apply POSIX groups"
                },
            ));
        }

        degradations
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NtfsNativeMetadataRequest {
    pub security_descriptors: bool,
    pub alternate_data_streams: bool,
    pub creation_time: bool,
    pub windows_attributes: bool,
    pub sparse_files: bool,
    pub reparse_points: bool,
    pub vss_snapshot: bool,
}

impl NtfsNativeMetadataRequest {
    pub fn all() -> Self {
        Self {
            security_descriptors: true,
            alternate_data_streams: true,
            creation_time: true,
            windows_attributes: true,
            sparse_files: true,
            reparse_points: true,
            vss_snapshot: false,
        }
    }

    pub fn with_vss(mut self, enabled: bool) -> Self {
        self.vss_snapshot = enabled;
        self
    }

    pub fn degradations(self) -> Vec<MetadataDegradation> {
        let mut degradations = Vec::new();
        if self.security_descriptors {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::SecurityDescriptor,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native captures security descriptor summaries in a sidecar prototype but does not restore them yet",
            ));
        }
        if self.alternate_data_streams {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::AlternateDataStream,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native copies named alternate data stream payloads for local Windows syncs; default data streams remain ordinary file content and unsupported platforms report this as unavailable",
            ));
        }
        if self.creation_time {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::CreationTime,
                MetadataAction::Ignored,
                "metadata-policy=ntfs-native requests creation time preservation; the local executor does not apply creation times yet",
            ));
        }
        if self.windows_attributes {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::WindowsAttributes,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native restores the tested readonly/hidden/archive/system attribute subset and degrades unsupported attribute bits",
            ));
        }
        if self.sparse_files {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::SparseFile,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native detects sparse files but sparse range preservation is not wired into copying yet",
            ));
        }
        if self.reparse_points {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::ReparsePoint,
                MetadataAction::Rejected,
                "metadata-policy=ntfs-native does not preserve arbitrary reparse points yet; unsafe reparse points remain blocked",
            ));
        }
        if self.vss_snapshot {
            degradations.push(MetadataDegradation::new(
                MetadataFeature::VssSnapshot,
                MetadataAction::Rejected,
                "--vss requests snapshot source mode; VSS snapshot creation is not implemented in this build",
            ));
        }

        degradations
    }
}

pub fn archive_mode_degradations(policy: MetadataPolicy) -> Vec<MetadataDegradation> {
    let mut degradations = Vec::new();

    let policy_label = policy.as_str();
    degradations.push(MetadataDegradation::new(
        MetadataFeature::Symlink,
        MetadataAction::Degraded,
        format!("archive mode requests symlink preservation; {policy_label} transfers do not apply symlink preservation in the local executor yet"),
    ));
    degradations.push(MetadataDegradation::new(
        MetadataFeature::Permissions,
        MetadataAction::Degraded,
        format!("archive mode requests POSIX permissions; {policy_label} transfers do not apply POSIX permissions in the local executor yet"),
    ));

    degradations.push(MetadataDegradation::new(
        MetadataFeature::Owner,
        MetadataAction::Ignored,
        "archive mode requests owner preservation; Windows portable transfers do not apply POSIX owners",
    ));
    degradations.push(MetadataDegradation::new(
        MetadataFeature::Group,
        MetadataAction::Ignored,
        "archive mode requests group preservation; Windows portable transfers do not apply POSIX groups",
    ));
    degradations.push(MetadataDegradation::new(
        MetadataFeature::Device,
        MetadataAction::Rejected,
        "archive mode requests device/special files; this implementation does not create device nodes on Windows",
    ));

    degradations
}

pub fn metadata_policy_degradations(policy: MetadataPolicy) -> Vec<MetadataDegradation> {
    match policy {
        MetadataPolicy::Portable => Vec::new(),
        MetadataPolicy::Posix => vec![
            MetadataDegradation::new(
                MetadataFeature::Permissions,
                MetadataAction::Ignored,
                "metadata-policy=posix requests POSIX mode preservation; the local executor does not apply POSIX permissions yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::Owner,
                MetadataAction::Ignored,
                "metadata-policy=posix requests POSIX owner preservation; the local executor does not apply POSIX owners yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::Group,
                MetadataAction::Ignored,
                "metadata-policy=posix requests POSIX group preservation; the local executor does not apply POSIX groups yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::Acl,
                MetadataAction::Ignored,
                "metadata-policy=posix requests POSIX ACL preservation; the local executor does not apply POSIX ACLs yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::Xattr,
                MetadataAction::Ignored,
                "metadata-policy=posix requests extended attribute preservation; the local executor does not apply xattrs yet",
            ),
        ],
        MetadataPolicy::NtfsNative => vec![
            MetadataDegradation::new(
                MetadataFeature::SecurityDescriptor,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native requests NTFS security descriptor preservation; sidecar capture is available but restore is not wired into the local executor yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::AlternateDataStream,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native requests alternate data stream preservation; named ADS payload copy is available for local Windows syncs and unavailable elsewhere",
            ),
            MetadataDegradation::new(
                MetadataFeature::CreationTime,
                MetadataAction::Ignored,
                "metadata-policy=ntfs-native requests creation time preservation; the local executor does not apply creation times yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::WindowsAttributes,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native requests Windows file attribute preservation; the tested readonly/hidden/archive/system subset is restored while unsupported bits are degraded",
            ),
            MetadataDegradation::new(
                MetadataFeature::SparseFile,
                MetadataAction::Degraded,
                "metadata-policy=ntfs-native requests sparse file preservation; sparse detection is available but sparse range restore is not wired into the local executor yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::ReparsePoint,
                MetadataAction::Rejected,
                "metadata-policy=ntfs-native requests reparse point preservation; unsafe reparse points are still rejected",
            ),
        ],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    severity: Severity,
    code: &'static str,
    message: String,
    hint: Option<String>,
}

impl Diagnostic {
    pub fn new(severity: Severity, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity,
            code,
            message: message.into(),
            hint: None,
        }
    }

    pub fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, message)
    }

    pub fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }

    pub fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, code, message)
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    diagnostics: Vec<Diagnostic>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    pub fn info(&mut self, code: &'static str, message: impl Into<String>) {
        self.push(Diagnostic::info(code, message));
    }

    pub fn warn(&mut self, code: &'static str, message: impl Into<String>) {
        self.push(Diagnostic::warning(code, message));
    }

    pub fn error(&mut self, code: &'static str, message: impl Into<String>) {
        self.push(Diagnostic::error(code, message));
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn extend(&mut self, diagnostics: impl IntoIterator<Item = Diagnostic>) {
        self.diagnostics.extend(diagnostics);
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Warning)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
    }

    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_policy_defaults_to_portable() {
        assert_eq!(MetadataPolicy::default(), MetadataPolicy::Portable);
    }

    #[test]
    fn report_tracks_warnings_and_errors() {
        let mut report = Report::new();
        assert!(report.is_empty());
        assert!(!report.has_errors());

        report.info("I000", "discovered environment");
        report.warn("W001", "rsync was not found");
        report.error("E001", "invalid source path");

        assert!(!report.is_empty());
        assert!(report.has_errors());
        assert_eq!(report.diagnostics().len(), 3);
        assert_eq!(report.warnings().count(), 1);
        assert_eq!(report.errors().count(), 1);
    }

    #[test]
    fn diagnostic_can_carry_hint() {
        let diagnostic =
            Diagnostic::warning("W001", "ssh unavailable").with_hint("install OpenSSH client");

        assert_eq!(diagnostic.severity(), Severity::Warning);
        assert_eq!(diagnostic.code(), "W001");
        assert_eq!(diagnostic.message(), "ssh unavailable");
        assert_eq!(diagnostic.hint(), Some("install OpenSSH client"));
    }

    #[test]
    fn parses_metadata_policy_names() {
        assert_eq!(
            "portable".parse::<MetadataPolicy>().unwrap(),
            MetadataPolicy::Portable
        );
        assert_eq!(
            "ntfs-native".parse::<MetadataPolicy>().unwrap(),
            MetadataPolicy::NtfsNative
        );
        assert!("unknown".parse::<MetadataPolicy>().is_err());
    }

    #[test]
    fn archive_mode_reports_unsupported_windows_metadata() {
        let degradations = archive_mode_degradations(MetadataPolicy::Portable);
        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::Owner
                && degradation.action == MetadataAction::Ignored));
        assert!(degradations.iter().any(MetadataDegradation::is_loss));
    }

    #[test]
    fn archive_mode_reports_unimplemented_local_executor_components_for_all_policies() {
        let degradations = archive_mode_degradations(MetadataPolicy::Posix);

        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::Symlink));
        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::Permissions));
    }

    #[test]
    fn posix_metadata_policy_reports_policy_capability_loss() {
        let degradations = metadata_policy_degradations(MetadataPolicy::Posix);

        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::Acl));
        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::Xattr));
        assert!(degradations.iter().all(MetadataDegradation::is_loss));
    }

    #[test]
    fn ntfs_native_metadata_policy_reports_policy_capability_loss() {
        let degradations = metadata_policy_degradations(MetadataPolicy::NtfsNative);

        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::CreationTime));
        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::WindowsAttributes));
        assert!(degradations
            .iter()
            .any(|degradation| degradation.feature == MetadataFeature::AlternateDataStream));
        assert!(degradations.iter().all(MetadataDegradation::is_loss));
    }

    #[test]
    fn posix_request_reports_fake_super_as_stored_sidecar_metadata() {
        let request = PosixMetadataRequest {
            permissions: true,
            owner: true,
            acls: true,
            xattrs: true,
            fake_super: true,
            ..Default::default()
        };

        let degradations = request.degradations(MetadataPolicy::Posix);

        assert!(request.any());
        assert!(degradations.iter().any(|degradation| {
            degradation.feature == MetadataFeature::Acl
                && degradation.action == MetadataAction::Stored
                && !degradation.is_loss()
        }));
        assert!(degradations.iter().any(|degradation| {
            degradation.feature == MetadataFeature::Xattr
                && degradation.action == MetadataAction::Stored
                && !degradation.is_loss()
        }));
        assert!(degradations.iter().any(|degradation| {
            degradation.feature == MetadataFeature::Permissions
                && degradation.action == MetadataAction::Stored
                && !degradation.is_loss()
        }));
    }

    #[test]
    fn numeric_ids_alone_does_not_request_owner_or_group_preservation() {
        let request = PosixMetadataRequest {
            numeric_ids: true,
            ..Default::default()
        };

        let degradations = request.degradations(MetadataPolicy::Portable);

        assert!(request.any());
        assert!(degradations.is_empty());
    }

    #[test]
    fn ntfs_native_request_reports_vss_as_rejected() {
        let degradations = NtfsNativeMetadataRequest::all()
            .with_vss(true)
            .degradations();

        assert!(degradations.iter().any(|degradation| {
            degradation.feature == MetadataFeature::VssSnapshot
                && degradation.action == MetadataAction::Rejected
        }));
    }
}
