use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use rsync_core::{MetadataFeature, Report, Severity};
use rsync_fs::{DeleteMode, FileWriteMode, SymlinkMode, SyncAction, UpdateMode};
use rsync_protocol::WireFileType;

use crate::cli::Cli;
use crate::output;
use crate::remote::flist::RemoteSourceEntry;
use crate::ProgressLog;
pub(crate) fn format_bytes(bytes: u64) -> String {
    output::format_bytes_human(bytes)
}

pub(crate) fn transfer_rate_label(bytes: u64, elapsed: Duration) -> String {
    output::transfer_rate_label(bytes, elapsed)
}

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

pub(crate) fn append_action_report(output: &mut String, cli: &Cli, actions: &[SyncAction]) {
    append_compact_action_summary(output, actions);

    let expand_actions = cli.dry_run || cli.verbosity > 1;
    if expand_actions {
        output.push_str("actions:\n");
        if actions.is_empty() {
            output.push_str("- no changes\n");
        } else {
            for action in actions {
                append_sync_action(output, action);
            }
        }
    } else {
        append_action_warnings(output, actions);
    }

    append_optional_itemized_changes(output, cli.itemize_changes, actions);
    append_structured_stats(output, cli.stats, actions);
}

pub(crate) fn append_out_format_and_client_log(
    output: &mut String,
    cli: &Cli,
    actions: &[SyncAction],
    client_log: &mut output::TransferLog,
) -> Result<()> {
    for action in actions {
        let record = OutputActionRecord::from_action(action, cli.eight_bit_output);
        if let Some(format) = &cli.out_format {
            output.push_str(&output::render_out_format(
                format,
                &output::OutFormatArgs {
                    filename: &record.name,
                    full_path: &record.full_path,
                    length: record.len,
                    perms: &record.perms,
                    owner: &record.owner,
                    group: &record.group,
                    mtime: record.mtime,
                    itemized: &record.itemized,
                    symlink_target: record.symlink_target.as_deref(),
                    checksum: None,
                },
            ));
            output.push('\n');
        }

        if cli.client_log_file.is_some() {
            let log_format = cli.client_log_file_format.as_deref().unwrap_or("%i %n%L");
            client_log.log_transfer_with_format(
                Some(log_format),
                &output::TransferLogRecord {
                    operation: Some(record.operation),
                    path: Some(record.name.clone()),
                    bytes: Some(record.len),
                    itemized: Some(record.itemized),
                    symlink_target: record.symlink_target,
                    message: record.message,
                },
            )?;
        }
    }
    Ok(())
}

pub(crate) fn append_remote_source_out_format_and_client_log(
    output: &mut String,
    cli: &Cli,
    entries: &[RemoteSourceEntry],
    transferred_entry_indexes: &[usize],
    client_log: &mut output::TransferLog,
) -> Result<()> {
    for entry_index in transferred_entry_indexes {
        let Some(entry) = entries.get(*entry_index) else {
            continue;
        };
        if entry.wire.file_type != WireFileType::File {
            continue;
        }

        let record = OutputRemoteSourceRecord::from_entry(entry, cli.eight_bit_output);
        if let Some(format) = &cli.out_format {
            output.push_str(&output::render_out_format(
                format,
                &output::OutFormatArgs {
                    filename: &record.name,
                    full_path: &record.full_path,
                    length: record.len,
                    perms: &record.perms,
                    owner: &record.owner,
                    group: &record.group,
                    mtime: record.mtime,
                    itemized: &record.itemized,
                    symlink_target: None,
                    checksum: None,
                },
            ));
            output.push('\n');
        }

        if cli.client_log_file.is_some() {
            let log_format = cli.client_log_file_format.as_deref().unwrap_or("%i %n%L");
            client_log.log_transfer_with_format(
                Some(log_format),
                &output::TransferLogRecord {
                    operation: Some(record.operation),
                    path: Some(record.name.clone()),
                    bytes: Some(record.len),
                    itemized: Some(record.itemized),
                    symlink_target: None,
                    message: record.message,
                },
            )?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct OutputActionRecord {
    operation: String,
    name: String,
    full_path: String,
    len: u64,
    perms: String,
    owner: String,
    group: String,
    mtime: i64,
    itemized: String,
    symlink_target: Option<String>,
    message: String,
}

impl OutputActionRecord {
    pub(crate) fn from_action(action: &SyncAction, eight_bit_output: bool) -> Self {
        let path = primary_action_path(action);
        let name = output_name(path, eight_bit_output);
        let full_path = output::escape_output_name(&path.display().to_string(), eight_bit_output);
        let itemized = itemized_code_for_action(action).to_string();
        let len = action_len(action);
        let operation = action_operation(action).to_string();
        let symlink_target = match action {
            SyncAction::CreateSymlink { target, .. } => Some(output::escape_output_name(
                &target.display().to_string(),
                eight_bit_output,
            )),
            _ => None,
        };
        let message = format!("{operation} {name}");

        Self {
            operation,
            name,
            full_path,
            len,
            perms: String::new(),
            owner: String::new(),
            group: String::new(),
            mtime: 0,
            itemized,
            symlink_target,
            message,
        }
    }
}

#[derive(Debug)]
struct OutputRemoteSourceRecord {
    operation: String,
    name: String,
    full_path: String,
    len: u64,
    perms: String,
    owner: String,
    group: String,
    mtime: i64,
    itemized: String,
    message: String,
}

impl OutputRemoteSourceRecord {
    pub(crate) fn from_entry(entry: &RemoteSourceEntry, eight_bit_output: bool) -> Self {
        let raw_name = entry
            .wire
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| entry.wire.path.display().to_string());
        let name = output::escape_output_name(&raw_name, eight_bit_output);
        let full_path =
            output::escape_output_name(&entry.wire.path.display().to_string(), eight_bit_output);
        let operation = "send".to_string();
        let message = format!("{operation} {name}");

        Self {
            operation,
            name,
            full_path,
            len: entry.wire.len,
            perms: String::new(),
            owner: String::new(),
            group: String::new(),
            mtime: entry.wire.mtime_unix,
            itemized: ">f+++++++++".to_string(),
            message,
        }
    }
}

pub(crate) fn primary_action_path(action: &SyncAction) -> &Path {
    match action {
        SyncAction::CreateDir(path)
        | SyncAction::WriteFile { path, .. }
        | SyncAction::WriteFileInPlace { path, .. }
        | SyncAction::AppendFile { path, .. }
        | SyncAction::PreserveMtime(path)
        | SyncAction::DeleteFile(path)
        | SyncAction::DeleteDir(path)
        | SyncAction::ProtectDelete(path)
        | SyncAction::CreateSymlink { path, .. }
        | SyncAction::Warn { path, .. } => path,
        SyncAction::BackupFile { from, .. } => from,
        SyncAction::CreateHardLink { to, .. } => to,
    }
}

pub(crate) fn output_name(path: &Path, eight_bit_output: bool) -> String {
    let display_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    output::escape_output_name(&display_name, eight_bit_output)
}

pub(crate) fn action_len(action: &SyncAction) -> u64 {
    match action {
        SyncAction::WriteFile { len, .. }
        | SyncAction::WriteFileInPlace { len, .. }
        | SyncAction::AppendFile { len, .. } => *len as u64,
        _ => 0,
    }
}

pub(crate) fn action_operation(action: &SyncAction) -> &'static str {
    match action {
        SyncAction::CreateDir(_) => "create-dir",
        SyncAction::WriteFile { .. } => "write",
        SyncAction::WriteFileInPlace { .. } => "write-inplace",
        SyncAction::AppendFile { .. } => "append",
        SyncAction::BackupFile { .. } => "backup",
        SyncAction::PreserveMtime(_) => "preserve-mtime",
        SyncAction::DeleteFile(_) => "delete-file",
        SyncAction::DeleteDir(_) => "delete-dir",
        SyncAction::ProtectDelete(_) => "protect-delete",
        SyncAction::CreateSymlink { .. } => "symlink",
        SyncAction::CreateHardLink { .. } => "hardlink",
        SyncAction::Warn { .. } => "warning",
    }
}

pub(crate) fn itemized_code_for_action(action: &SyncAction) -> &'static str {
    match action {
        SyncAction::CreateDir(_) => "cd+++++++++",
        SyncAction::WriteFile { .. } => ">f+++++++++",
        SyncAction::WriteFileInPlace { .. } => ">f..t.i....",
        SyncAction::AppendFile { .. } => ">f+++++a+++",
        SyncAction::BackupFile { .. } => "bf+++++++++",
        SyncAction::PreserveMtime(_) => ".f..t......",
        SyncAction::DeleteFile(_) | SyncAction::DeleteDir(_) => "*deleting",
        SyncAction::ProtectDelete(_) => ".protect...",
        SyncAction::CreateSymlink { .. } => "cL+++++++++",
        SyncAction::CreateHardLink { .. } => "hf+++++++++",
        SyncAction::Warn { .. } => ".warning...",
    }
}

pub(crate) fn append_compact_action_summary(output: &mut String, actions: &[SyncAction]) {
    if actions.is_empty() {
        output.push_str("changes: none\n");
        return;
    }

    let stats = ActionStats::from_actions(actions);
    let mut parts = vec![format!("{} actions", actions.len())];
    if stats.file_writes > 0 {
        parts.push(format!("{} file writes", stats.file_writes));
    }
    if stats.appended_files > 0 {
        parts.push(format!("{} appends", stats.appended_files));
    }
    if stats.file_write_bytes > 0 {
        parts.push(format!(
            "{} data",
            format_bytes(stats.file_write_bytes as u64)
        ));
    }
    if stats.created_dirs > 0 {
        parts.push(format!("{} dirs", stats.created_dirs));
    }
    let deletes = stats.deleted_files + stats.deleted_dirs;
    if deletes > 0 {
        parts.push(format!("{} deletes", deletes));
    }
    if stats.protected_deletes > 0 {
        parts.push(format!("{} protected", stats.protected_deletes));
    }
    if stats.preserved_mtimes > 0 {
        parts.push(format!("{} mtimes", stats.preserved_mtimes));
    }
    if stats.warnings > 0 {
        parts.push(format!("{} warnings", stats.warnings));
    }
    output.push_str(&format!("changes: {}\n", parts.join(", ")));
}

pub(crate) fn append_action_warnings(output: &mut String, actions: &[SyncAction]) {
    for action in actions {
        if let SyncAction::Warn { path, message } = action {
            output.push_str(&format!("- warning {}: {message}\n", path.display()));
        }
    }
}

pub(crate) fn append_sync_action(output: &mut String, action: &SyncAction) {
    match action {
        SyncAction::CreateDir(path) => {
            output.push_str(&format!("- create-dir {}\n", path.display()));
        }
        SyncAction::WriteFile { path, len } => {
            output.push_str(&format!("- write-file {} {len} bytes\n", path.display()));
        }
        SyncAction::WriteFileInPlace { path, len } => {
            output.push_str(&format!(
                "- write-file-inplace {} {len} bytes\n",
                path.display()
            ));
        }
        SyncAction::AppendFile { path, len } => {
            output.push_str(&format!("- append-file {} {len} bytes\n", path.display()));
        }
        SyncAction::BackupFile { from, to } => {
            output.push_str(&format!(
                "- backup-file {} -> {}\n",
                from.display(),
                to.display()
            ));
        }
        SyncAction::PreserveMtime(path) => {
            output.push_str(&format!("- preserve-mtime {}\n", path.display()));
        }
        SyncAction::DeleteFile(path) => {
            output.push_str(&format!("- delete-file {}\n", path.display()));
        }
        SyncAction::DeleteDir(path) => {
            output.push_str(&format!("- delete-dir {}\n", path.display()));
        }
        SyncAction::ProtectDelete(path) => {
            output.push_str(&format!("- protect-delete {}\n", path.display()));
        }
        SyncAction::CreateSymlink { path, target } => {
            output.push_str(&format!(
                "- create-symlink {} -> {}\n",
                path.display(),
                target.display()
            ));
        }
        SyncAction::CreateHardLink { from, to } => {
            output.push_str(&format!(
                "- create-hardlink {} -> {}\n",
                from.display(),
                to.display()
            ));
        }
        SyncAction::Warn { path, message } => {
            output.push_str(&format!("- warning {}: {message}\n", path.display()));
        }
    }
}

pub(crate) fn log_sync_actions(progress: ProgressLog, actions: &[SyncAction]) {
    if !progress.enabled() {
        return;
    }

    for action in actions {
        match action {
            SyncAction::CreateDir(path) => {
                progress.detail(format!("create dir: {}", path.display()))
            }
            SyncAction::WriteFile { path, len } => progress.info(format!(
                "write: {} ({})",
                path.display(),
                format_bytes(*len as u64)
            )),
            SyncAction::WriteFileInPlace { path, len } => progress.info(format!(
                "write inplace: {} ({})",
                path.display(),
                format_bytes(*len as u64)
            )),
            SyncAction::AppendFile { path, len } => progress.info(format!(
                "append: {} ({})",
                path.display(),
                format_bytes(*len as u64)
            )),
            SyncAction::BackupFile { from, to } => {
                progress.detail(format!("backup: {} -> {}", from.display(), to.display()))
            }
            SyncAction::PreserveMtime(path) => {
                progress.detail(format!("preserve mtime: {}", path.display()));
            }
            SyncAction::DeleteFile(path) => {
                progress.info(format!("delete file: {}", path.display()))
            }
            SyncAction::DeleteDir(path) => progress.info(format!("delete dir: {}", path.display())),
            SyncAction::ProtectDelete(path) => {
                progress.detail(format!("protect delete: {}", path.display()));
            }
            SyncAction::CreateSymlink { path, target } => {
                progress.info(format!(
                    "symlink: {} -> {}",
                    path.display(),
                    target.display()
                ));
            }
            SyncAction::CreateHardLink { from, to } => {
                progress.info(format!("hardlink: {} -> {}", from.display(), to.display()));
            }
            SyncAction::Warn { path, message } => {
                progress.info(format!("warning: {}: {message}", path.display()));
            }
        }
    }
}

pub(crate) fn append_optional_itemized_changes(
    output: &mut String,
    enabled: bool,
    actions: &[SyncAction],
) {
    if !enabled {
        return;
    }

    output.push_str("itemized changes:\n");
    if actions.is_empty() {
        output.push_str("- none\n");
        return;
    }
    for action in actions {
        append_itemized_action(output, action);
    }
}

pub(crate) fn append_itemized_action(output: &mut String, action: &SyncAction) {
    match action {
        SyncAction::CreateDir(path) => {
            output.push_str(&format!("cd+++++++++ {}\n", path.display()));
        }
        SyncAction::WriteFile { path, .. } => {
            output.push_str(&format!(">f+++++++++ {}\n", path.display()));
        }
        SyncAction::WriteFileInPlace { path, .. } => {
            output.push_str(&format!(">f..t.i.... {}\n", path.display()));
        }
        SyncAction::AppendFile { path, .. } => {
            output.push_str(&format!(">f+++++a+++ {}\n", path.display()));
        }
        SyncAction::BackupFile { from, .. } => {
            output.push_str(&format!("bf+++++++++ {}\n", from.display()));
        }
        SyncAction::PreserveMtime(path) => {
            output.push_str(&format!(".f..t...... {}\n", path.display()));
        }
        SyncAction::DeleteFile(path) | SyncAction::DeleteDir(path) => {
            output.push_str(&format!("*deleting   {}\n", path.display()));
        }
        SyncAction::ProtectDelete(path) => {
            output.push_str(&format!(".protect... {}\n", path.display()));
        }
        SyncAction::CreateSymlink { path, .. } => {
            output.push_str(&format!("cL+++++++++ {}\n", path.display()));
        }
        SyncAction::CreateHardLink { to, .. } => {
            output.push_str(&format!("hf+++++++++ {}\n", to.display()));
        }
        SyncAction::Warn { path, .. } => {
            output.push_str(&format!(".warning... {}\n", path.display()));
        }
    }
}

pub(crate) fn append_structured_stats(output: &mut String, enabled: bool, actions: &[SyncAction]) {
    if !enabled {
        return;
    }

    let stats = ActionStats::from_actions(actions);
    output.push_str("structured stats:\n");
    output.push_str(&format!("- actions: {}\n", actions.len()));
    output.push_str(&format!(
        "- file writes: {} ({} bytes)\n",
        stats.file_writes, stats.file_write_bytes
    ));
    output.push_str(&format!("- appended files: {}\n", stats.appended_files));
    output.push_str(&format!("- directories created: {}\n", stats.created_dirs));
    output.push_str(&format!("- mtimes preserved: {}\n", stats.preserved_mtimes));
    output.push_str(&format!("- deleted files: {}\n", stats.deleted_files));
    output.push_str(&format!("- deleted directories: {}\n", stats.deleted_dirs));
    output.push_str(&format!(
        "- protected deletes: {}\n",
        stats.protected_deletes
    ));
    output.push_str(&format!("- warnings: {}\n", stats.warnings));
}

#[derive(Default)]
struct ActionStats {
    file_writes: usize,
    file_write_bytes: usize,
    appended_files: usize,
    created_dirs: usize,
    preserved_mtimes: usize,
    deleted_files: usize,
    deleted_dirs: usize,
    protected_deletes: usize,
    warnings: usize,
}

impl ActionStats {
    pub(crate) fn from_actions(actions: &[SyncAction]) -> Self {
        let mut stats = Self::default();
        for action in actions {
            stats.record(action);
        }
        stats
    }

    pub(crate) fn record(&mut self, action: &SyncAction) {
        match action {
            SyncAction::CreateDir(_) => self.created_dirs += 1,
            SyncAction::WriteFile { len, .. } | SyncAction::WriteFileInPlace { len, .. } => {
                self.file_writes += 1;
                self.file_write_bytes += *len;
            }
            SyncAction::AppendFile { len, .. } => {
                self.appended_files += 1;
                self.file_write_bytes += *len;
            }
            SyncAction::BackupFile { .. } => {}
            SyncAction::PreserveMtime(_) => self.preserved_mtimes += 1,
            SyncAction::DeleteFile(_) => self.deleted_files += 1,
            SyncAction::DeleteDir(_) => self.deleted_dirs += 1,
            SyncAction::ProtectDelete(_) => self.protected_deletes += 1,
            SyncAction::CreateSymlink { .. } | SyncAction::CreateHardLink { .. } => {}
            SyncAction::Warn { .. } => self.warnings += 1,
        }
    }
}

pub(crate) fn metadata_code(feature: MetadataFeature, severity: Severity) -> &'static str {
    match (severity, feature) {
        (Severity::Error, MetadataFeature::Owner) => "E_METADATA_OWNER",
        (Severity::Error, MetadataFeature::Group) => "E_METADATA_GROUP",
        (Severity::Error, MetadataFeature::Device | MetadataFeature::SpecialFile) => {
            "E_METADATA_DEVICE"
        }
        (Severity::Error, MetadataFeature::Symlink) => "E_METADATA_SYMLINK",
        (Severity::Error, MetadataFeature::Permissions) => "E_METADATA_PERMISSIONS",
        (Severity::Error, _) => "E_METADATA_LOSS",
        (_, MetadataFeature::Owner) => "W_METADATA_OWNER",
        (_, MetadataFeature::Group) => "W_METADATA_GROUP",
        (_, MetadataFeature::Device | MetadataFeature::SpecialFile) => "W_METADATA_DEVICE",
        (_, MetadataFeature::Symlink) => "W_METADATA_SYMLINK",
        (_, MetadataFeature::Permissions) => "W_METADATA_PERMISSIONS",
        _ => "W_METADATA_LOSS",
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
