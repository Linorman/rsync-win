use super::prelude::*;
pub(crate) fn append_diagnostics(output: &mut String, report: &Report) {
    for diagnostic in report.diagnostics() {
        output.push_str(&format!(
            "- [{}] {}: {}\n",
            severity_label(diagnostic.severity()),
            diagnostic.code(),
            diagnostic.message()
        ));
        if let Some(hint) = diagnostic.hint() {
            output.push_str(&format!("  hint: {hint}\n"));
        }
    }
}

pub(crate) fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

pub(crate) fn update_mode_label(mode: UpdateMode) -> &'static str {
    match mode {
        UpdateMode::QuickCheck => "quick-check",
        UpdateMode::Checksum => "checksum",
        UpdateMode::SizeOnly => "size-only",
        UpdateMode::IgnoreTimes => "ignore-times",
    }
}

pub(crate) fn delete_mode_label(mode: DeleteMode) -> &'static str {
    match mode {
        DeleteMode::None => "none",
        DeleteMode::Before => "before",
        DeleteMode::During => "during",
        DeleteMode::Delay => "delay",
        DeleteMode::After => "after",
    }
}

pub(crate) fn file_write_mode_label(mode: FileWriteMode) -> &'static str {
    match mode {
        FileWriteMode::Atomic => "atomic",
        FileWriteMode::InPlace => "inplace",
    }
}

pub(crate) fn symlink_mode_label(mode: SymlinkMode) -> &'static str {
    match mode {
        SymlinkMode::Skip => "skip",
        SymlinkMode::Preserve => "preserve",
        SymlinkMode::CopyAll => "copy-links",
        SymlinkMode::CopyDirLinks => "copy-dirlinks",
        SymlinkMode::CopyUnsafe => "copy-unsafe-links",
        SymlinkMode::SafeOnly => "safe-links",
        SymlinkMode::Munge => "munge-links",
    }
}
