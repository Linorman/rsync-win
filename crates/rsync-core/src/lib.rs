use std::path::PathBuf;
use std::str::FromStr;

use thiserror::Error;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataPolicy {
    Portable,
    Posix,
    NtfsNative,
}

impl Default for MetadataPolicy {
    fn default() -> Self {
        Self::Portable
    }
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
    Permissions,
    Owner,
    Group,
    Device,
    SpecialFile,
    Acl,
    Xattr,
    CreationTime,
    WindowsAttributes,
}

impl MetadataFeature {
    pub fn label(self) -> &'static str {
        match self {
            Self::Symlink => "symlink",
            Self::Permissions => "permissions",
            Self::Owner => "owner",
            Self::Group => "group",
            Self::Device => "device",
            Self::SpecialFile => "special-file",
            Self::Acl => "acl",
            Self::Xattr => "xattr",
            Self::CreationTime => "creation-time",
            Self::WindowsAttributes => "windows-attributes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataAction {
    Applied,
    Degraded,
    Ignored,
    Rejected,
}

impl MetadataAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Applied => "applied",
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
        !matches!(self.action, MetadataAction::Applied)
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
                MetadataFeature::Acl,
                MetadataAction::Ignored,
                "metadata-policy=ntfs-native requests NTFS security descriptor preservation; the local executor does not apply security descriptors yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::Xattr,
                MetadataAction::Ignored,
                "metadata-policy=ntfs-native requests alternate data stream preservation; the local executor does not copy ADS data yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::CreationTime,
                MetadataAction::Ignored,
                "metadata-policy=ntfs-native requests creation time preservation; the local executor does not apply creation times yet",
            ),
            MetadataDegradation::new(
                MetadataFeature::WindowsAttributes,
                MetadataAction::Ignored,
                "metadata-policy=ntfs-native requests Windows file attribute preservation; the local executor does not apply Windows attributes yet",
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
        assert!(degradations.iter().all(MetadataDegradation::is_loss));
    }
}
