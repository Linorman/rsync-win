use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use crate::metadata::{FileType, HardlinkId, MetadataFeature, PortableMetadata};
use crate::walk::{FileWriteMode, FileWriteOptions, FsError, PortableFileSystem, WalkEntry};
use rsync_filter::{EntryKind, Rule, RuleAction, RuleSet, RuleSide};

pub type DestinationPathPreflight = fn(&[PathBuf]) -> Result<(), FsError>;

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub recursive: bool,
    pub delete: bool,
    pub delete_mode: DeleteMode,
    pub preserve_mtime: bool,
    pub omit_dir_times: bool,
    pub dry_run: bool,
    pub filter_rules: RuleSet,
    pub destination_path_preflight: Option<DestinationPathPreflight>,
    pub update_mode: UpdateMode,
    pub files_from: Option<Vec<PathBuf>>,
    pub file_write_mode: FileWriteMode,
    pub keep_partial: bool,
    pub partial_dir: Option<PathBuf>,
    pub temp_dir: Option<PathBuf>,
    pub delay_updates: bool,
    pub fsync: bool,
    pub append_verify: bool,
    pub symlink_mode: SymlinkMode,
    pub transfer_dirs: bool,
    pub mkpath: bool,
    pub relative_paths: bool,
    pub implied_dirs: bool,
    pub one_file_system: bool,
    pub skip_newer_receiver: bool,
    pub existing_only: bool,
    pub ignore_existing: bool,
    pub max_size: Option<u64>,
    pub min_size: Option<u64>,
    pub modify_window: i64,
    pub ignore_missing_args: bool,
    pub delete_missing_args: bool,
    pub delete_excluded: bool,
    pub ignore_errors: bool,
    pub force_delete: bool,
    pub max_delete: Option<usize>,
    pub backup: bool,
    pub backup_dir: Option<PathBuf>,
    pub backup_suffix: String,
    pub preserve_hard_links: bool,
    pub keep_dirlinks: bool,
    pub preserve_devices: bool,
    pub preserve_specials: bool,
    pub fail_on_metadata_loss: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SourceSelectionOptions<'a> {
    pub recursive: bool,
    pub filter_rules: &'a RuleSet,
    pub files_from: Option<&'a [PathBuf]>,
    pub symlink_mode: SymlinkMode,
    pub one_file_system: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            delete: false,
            delete_mode: DeleteMode::None,
            preserve_mtime: true,
            omit_dir_times: false,
            dry_run: true,
            filter_rules: RuleSet::empty(),
            destination_path_preflight: None,
            update_mode: UpdateMode::QuickCheck,
            files_from: None,
            file_write_mode: FileWriteMode::Atomic,
            keep_partial: false,
            partial_dir: None,
            temp_dir: None,
            delay_updates: false,
            fsync: false,
            append_verify: false,
            symlink_mode: SymlinkMode::Skip,
            transfer_dirs: false,
            mkpath: false,
            relative_paths: false,
            implied_dirs: true,
            one_file_system: false,
            skip_newer_receiver: false,
            existing_only: false,
            ignore_existing: false,
            max_size: None,
            min_size: None,
            modify_window: 0,
            ignore_missing_args: false,
            delete_missing_args: false,
            delete_excluded: false,
            ignore_errors: false,
            force_delete: false,
            max_delete: None,
            backup: false,
            backup_dir: None,
            backup_suffix: "~".to_string(),
            preserve_hard_links: false,
            keep_dirlinks: false,
            preserve_devices: false,
            preserve_specials: false,
            fail_on_metadata_loss: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    QuickCheck,
    Checksum,
    SizeOnly,
    IgnoreTimes,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    #[default]
    None,
    Before,
    During,
    Delay,
    After,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkMode {
    Skip,
    Preserve,
    CopyAll,
    CopyDirLinks,
    CopyUnsafe,
    SafeOnly,
    Munge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    CreateDir(PathBuf),
    WriteFile { path: PathBuf, len: usize },
    WriteFileInPlace { path: PathBuf, len: usize },
    AppendFile { path: PathBuf, len: usize },
    BackupFile { from: PathBuf, to: PathBuf },
    PreserveMtime(PathBuf),
    DeleteFile(PathBuf),
    DeleteDir(PathBuf),
    ProtectDelete(PathBuf),
    CreateSymlink { path: PathBuf, target: PathBuf },
    CreateHardLink { from: PathBuf, to: PathBuf },
    Warn { path: PathBuf, message: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    actions: Vec<SyncAction>,
}

#[derive(Debug, Clone)]
struct DelayedTransfer {
    temp: PathBuf,
    target: PathBuf,
    relative: PathBuf,
    entry: WalkEntry,
}

struct TransferFileContext<'a> {
    dest_root: &'a Path,
    options: &'a SyncOptions,
    delayed_transfers: &'a mut Vec<DelayedTransfer>,
    hardlink_targets: &'a mut BTreeMap<HardlinkId, PathBuf>,
}

#[derive(Debug, Clone, Copy)]
struct RelativeEntryOptions<'a> {
    filter_rules: Option<&'a RuleSet>,
    recursive: bool,
    symlink_mode: SymlinkMode,
    one_file_system: bool,
}

impl SyncReport {
    pub fn push(&mut self, action: SyncAction) {
        self.actions.push(action);
    }

    pub fn actions(&self) -> &[SyncAction] {
        &self.actions
    }

    pub fn warnings(&self) -> impl Iterator<Item = &SyncAction> {
        self.actions
            .iter()
            .filter(|action| matches!(action, SyncAction::Warn { .. }))
    }
}

pub fn sync_tree<F: PortableFileSystem>(
    fs: &mut F,
    source: &Path,
    dest: &Path,
    options: SyncOptions,
) -> Result<SyncReport, FsError> {
    let source_root = fs.resolve_path_for_prefix_check(source)?;
    let dest_root = fs.resolve_path_for_prefix_check(dest)?;
    if source_root == dest_root || dest_root.starts_with(&source_root) {
        return Err(FsError::DestinationInsideSource);
    }

    let source_metadata = fs.metadata(source)?;
    if source_metadata.file_type == FileType::File {
        return sync_single_file(fs, source, source_metadata, dest, &options);
    }

    let mut source_entries = relative_entries(
        fs,
        source,
        Some(&options.filter_rules),
        options.recursive,
        options.symlink_mode,
        options.one_file_system,
    )?;
    if let Some(files_from) = &options.files_from {
        retain_files_from_entries(&mut source_entries, files_from);
    }
    if let Some(preflight) = options.destination_path_preflight {
        let destination_relatives: Vec<_> = source_entries.keys().cloned().collect();
        preflight(&destination_relatives)?;
    }

    let dest_entries = if fs.exists(dest) {
        relative_entries(
            fs,
            dest,
            None,
            options.recursive,
            SymlinkMode::Preserve,
            options.one_file_system,
        )?
    } else {
        BTreeMap::new()
    };
    let mut report = SyncReport::default();

    ensure_missing_destination_parent_allowed(fs, dest, options.mkpath)?;

    if !fs.exists(dest) {
        report.push(SyncAction::CreateDir(dest.to_path_buf()));
        if !options.dry_run {
            fs.create_dir_all(dest)?;
        }
    }

    let delete_mode = options.effective_delete_mode();
    if matches!(delete_mode, DeleteMode::Before | DeleteMode::During) {
        apply_receiver_deletes(
            fs,
            dest,
            &source_entries,
            &dest_entries,
            &options,
            &mut report,
        )?;
    }

    let mut delayed_transfers = Vec::new();
    let mut hardlink_targets = BTreeMap::new();
    let mut directory_mtimes = Vec::new();
    for (relative, entry) in &source_entries {
        let target = dest.join(relative);
        let result = match entry.metadata.file_type {
            FileType::Directory => {
                if !options.recursive && !options.transfer_dirs {
                    report.push(SyncAction::Warn {
                        path: entry.path.clone(),
                        message: "skipping directory because recursive mode is disabled"
                            .to_string(),
                    });
                    continue;
                }
                if !remove_conflicting_target(
                    fs,
                    dest,
                    &target,
                    relative,
                    FileType::Directory,
                    &options,
                    &mut report,
                )? {
                    continue;
                }
                report.push(SyncAction::CreateDir(target.clone()));
                if !options.dry_run {
                    fs.create_dir_all(&target)?;
                }
                directory_mtimes.push((target, entry.clone()));
                Ok(())
            }
            FileType::File => {
                if !remove_conflicting_target(
                    fs,
                    dest,
                    &target,
                    relative,
                    FileType::File,
                    &options,
                    &mut report,
                )? {
                    continue;
                }
                if !file_needs_update(fs, entry, &target, &options)? {
                    remember_hardlink_target(
                        entry,
                        &target,
                        options.preserve_hard_links,
                        &mut hardlink_targets,
                    );
                    preserve_existing_file_mtime(fs, &target, entry, &options, &mut report)?;
                    continue;
                }
                let mut context = TransferFileContext {
                    dest_root: dest,
                    options: &options,
                    delayed_transfers: &mut delayed_transfers,
                    hardlink_targets: &mut hardlink_targets,
                };
                transfer_file(fs, entry, &target, relative, &mut report, &mut context)
            }
            FileType::Symlink => {
                transfer_symlink(fs, entry, dest, &target, relative, &options, &mut report)
            }
            FileType::Hardlink | FileType::Device | FileType::Special | FileType::Other => {
                handle_non_regular_entry(entry, &options, &mut report)
            }
        };
        if let Err(err) = result {
            cleanup_delayed_updates(fs, &delayed_transfers, &options);
            if options.ignore_errors && matches!(delete_mode, DeleteMode::Delay | DeleteMode::After)
            {
                apply_receiver_deletes(
                    fs,
                    dest,
                    &source_entries,
                    &dest_entries,
                    &options,
                    &mut report,
                )?;
            }
            return Err(err);
        }
    }

    if let Err(err) = finish_delayed_updates(fs, dest, &delayed_transfers, &options, &mut report) {
        cleanup_delayed_updates(fs, &delayed_transfers, &options);
        return Err(err);
    }

    if matches!(delete_mode, DeleteMode::Delay | DeleteMode::After) {
        apply_receiver_deletes(
            fs,
            dest,
            &source_entries,
            &dest_entries,
            &options,
            &mut report,
        )?;
    }

    preserve_directory_mtimes(fs, &directory_mtimes, &options, &mut report)?;

    Ok(report)
}

pub fn sync_sources<F: PortableFileSystem>(
    fs: &mut F,
    sources: &[PathBuf],
    dest: &Path,
    options: SyncOptions,
) -> Result<SyncReport, FsError> {
    if sources.is_empty() {
        return Err(FsError::Unsupported("sync requires at least one source"));
    }

    let mut report = SyncReport::default();
    let mut present_sources = Vec::with_capacity(sources.len());
    for source in sources {
        match fs.metadata(source) {
            Ok(_) => present_sources.push(source.clone()),
            Err(FsError::NotFound(_)) if options.delete_missing_args => {
                delete_missing_arg(fs, source, dest, sources.len(), &options, &mut report)?;
            }
            Err(FsError::NotFound(_)) if options.ignore_missing_args => {}
            Err(err) => return Err(err),
        }
    }

    if present_sources.is_empty() {
        return Ok(report);
    }

    if options.relative_paths && options.implied_dirs {
        for source in &present_sources {
            ensure_implied_relative_dirs(fs, source, dest, &options, &mut report)?;
        }
    }

    let child = match present_sources.as_slice() {
        [source] if options.relative_paths => {
            ensure_missing_destination_parent_allowed(fs, dest, options.mkpath)?;
            let mut child_options = options;
            child_options.mkpath = true;
            let target = dest.join(relative_operand_path(source)?);
            sync_tree(fs, source, &target, child_options)
        }
        [source] => sync_tree(fs, source, dest, options),
        _ => sync_multiple_sources(fs, &present_sources, dest, options),
    }?;
    report.actions.extend(child.actions);
    Ok(report)
}

fn ensure_implied_relative_dirs<F: PortableFileSystem>(
    fs: &mut F,
    source: &Path,
    dest: &Path,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    let relative = relative_operand_path(source)?;
    let mut prefix = PathBuf::new();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            continue;
        };
        if components.peek().is_none() {
            break;
        }
        prefix.push(name);
        let target = dest.join(&prefix);
        match fs.metadata(&target) {
            Ok(metadata) if metadata.file_type == FileType::Directory => {}
            Ok(_) => {
                if remove_conflicting_target(
                    fs,
                    dest,
                    &target,
                    &prefix,
                    FileType::Directory,
                    options,
                    report,
                )? {
                    report.push(SyncAction::CreateDir(target.clone()));
                    if !options.dry_run {
                        fs.create_dir_all(&target)?;
                    }
                }
            }
            Err(FsError::NotFound(_)) => {
                report.push(SyncAction::CreateDir(target.clone()));
                if !options.dry_run {
                    fs.create_dir_all(&target)?;
                }
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn sync_multiple_sources<F: PortableFileSystem>(
    fs: &mut F,
    sources: &[PathBuf],
    dest: &Path,
    options: SyncOptions,
) -> Result<SyncReport, FsError> {
    if let Ok(metadata) = fs.metadata(dest) {
        if metadata.file_type != FileType::Directory {
            return Err(FsError::NotDirectory(dest.to_path_buf()));
        }
    }

    let mut targets = Vec::with_capacity(sources.len());
    for source in sources {
        let target = if options.relative_paths {
            dest.join(relative_operand_path(source)?)
        } else {
            batch_target_path(source, dest)?
        };
        let source_root = fs.resolve_path_for_prefix_check(source)?;
        let target_root = fs.resolve_path_for_prefix_check(&target)?;
        if source_root == target_root || target_root.starts_with(&source_root) {
            return Err(FsError::DestinationInsideSource);
        }
        targets.push(target);
    }

    if let Some(preflight) = options.destination_path_preflight {
        let destination_roots: Vec<_> = targets
            .iter()
            .map(|target| destination_preflight_path(target))
            .collect();
        preflight(&destination_roots)?;
    }

    let mut report = SyncReport::default();
    ensure_missing_destination_parent_allowed(fs, dest, options.mkpath)?;
    if !fs.exists(dest) {
        report.push(SyncAction::CreateDir(dest.to_path_buf()));
        if !options.dry_run {
            fs.create_dir_all(dest)?;
        }
    }

    for (source, target) in sources.iter().zip(targets) {
        let mut child_options = options.clone();
        if child_options.relative_paths {
            child_options.mkpath = true;
        }
        let child = sync_tree(fs, source, &target, child_options)?;
        report.actions.extend(child.actions);
    }

    Ok(report)
}

fn batch_target_path(source: &Path, dest: &Path) -> Result<PathBuf, FsError> {
    let file_name = source
        .file_name()
        .ok_or_else(|| FsError::InvalidPortablePath(source.to_path_buf()))?;
    Ok(dest.join(file_name))
}

fn ensure_missing_destination_parent_allowed<F: PortableFileSystem>(
    fs: &F,
    path: &Path,
    mkpath: bool,
) -> Result<(), FsError> {
    if mkpath || fs.exists(path) {
        return Ok(());
    }
    let Some(parent) = non_empty_parent(path) else {
        return Ok(());
    };
    let metadata = fs.metadata(parent)?;
    if metadata.file_type != FileType::Directory {
        return Err(FsError::NotDirectory(parent.to_path_buf()));
    }
    Ok(())
}

fn non_empty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn sync_single_file<F: PortableFileSystem>(
    fs: &mut F,
    source: &Path,
    source_metadata: PortableMetadata,
    dest: &Path,
    options: &SyncOptions,
) -> Result<SyncReport, FsError> {
    let target = match fs.metadata(dest) {
        Ok(metadata) if metadata.file_type == FileType::Directory => {
            let file_name = source
                .file_name()
                .ok_or_else(|| FsError::InvalidPortablePath(source.to_path_buf()))?;
            dest.join(file_name)
        }
        _ => dest.to_path_buf(),
    };

    let mut report = SyncReport::default();
    let entry = WalkEntry {
        path: source.to_path_buf(),
        metadata: source_metadata,
    };
    ensure_missing_destination_parent_allowed(fs, &target, options.mkpath)?;
    if let Some(preflight) = options.destination_path_preflight {
        preflight(&[destination_preflight_path(&target)])?;
    }
    let relative = target
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| destination_preflight_path(&target));
    let dest_root = target.parent().unwrap_or_else(|| Path::new(""));
    if !remove_conflicting_target(
        fs,
        dest_root,
        &target,
        &relative,
        FileType::File,
        options,
        &mut report,
    )? {
        return Ok(report);
    }
    if !file_needs_update(fs, &entry, &target, options)? {
        preserve_existing_file_mtime(fs, &target, &entry, options, &mut report)?;
        return Ok(report);
    }

    let mut delayed_transfers = Vec::new();
    let mut hardlink_targets = BTreeMap::new();
    transfer_file(
        fs,
        &entry,
        &target,
        &relative,
        &mut report,
        &mut TransferFileContext {
            dest_root,
            options,
            delayed_transfers: &mut delayed_transfers,
            hardlink_targets: &mut hardlink_targets,
        },
    )?;
    finish_delayed_updates(fs, dest_root, &delayed_transfers, options, &mut report)?;

    Ok(report)
}

fn transfer_file<F: PortableFileSystem>(
    fs: &mut F,
    entry: &WalkEntry,
    target: &Path,
    relative: &Path,
    report: &mut SyncReport,
    context: &mut TransferFileContext<'_>,
) -> Result<(), FsError> {
    let options = context.options;
    if options.preserve_hard_links {
        if let Some(id) = entry.metadata.hardlink_id {
            if let Some(existing) = context.hardlink_targets.get(&id).cloned() {
                report.push(SyncAction::CreateHardLink {
                    from: existing.clone(),
                    to: target.to_path_buf(),
                });
                if !options.dry_run {
                    backup_receiver_file(fs, context.dest_root, target, relative, options, report)?;
                    remove_existing_file_before_hardlink(fs, target)?;
                    match fs.create_hard_link(&existing, target) {
                        Ok(()) => {
                            preserve_transferred_mtime(fs, target, entry, options, report)?;
                            return Ok(());
                        }
                        Err(err) => {
                            report.push(SyncAction::Warn {
                                path: target.to_path_buf(),
                                message: format!(
                                    "hard link preservation fell back to file copy: {err}"
                                ),
                            });
                        }
                    }
                } else {
                    return Ok(());
                }
            }
        }
    }

    if options.append_verify {
        if let Some(offset) = append_verify_offset(fs, &entry.path, target, entry.metadata.len)? {
            let suffix_len = entry.metadata.len - offset;
            if suffix_len > 0 {
                report.push(SyncAction::AppendFile {
                    path: target.to_path_buf(),
                    len: action_len(suffix_len)?,
                });
                if !options.dry_run {
                    fs.append_file_from(target, &entry.path, offset)?;
                }
            }
            preserve_transferred_mtime(fs, target, entry, options, report)?;
            return Ok(());
        }
    }

    let action = match options.file_write_mode {
        FileWriteMode::Atomic => SyncAction::WriteFile {
            path: target.to_path_buf(),
            len: action_len(entry.metadata.len)?,
        },
        FileWriteMode::InPlace => SyncAction::WriteFileInPlace {
            path: target.to_path_buf(),
            len: action_len(entry.metadata.len)?,
        },
    };
    report.push(action);
    if !options.dry_run {
        if options.delay_updates {
            let temp = delayed_update_path(context.dest_root, relative, options);
            fs.copy_file_with_options(&entry.path, &temp, &delayed_file_write_options(options))?;
            context.delayed_transfers.push(DelayedTransfer {
                temp,
                target: target.to_path_buf(),
                relative: relative.to_path_buf(),
                entry: entry.clone(),
            });
            return Ok(());
        }
        backup_receiver_file(fs, context.dest_root, target, relative, options, report)?;
        fs.copy_file_with_options(&entry.path, target, &file_write_options(options))?;
    }
    remember_hardlink_target(
        entry,
        target,
        options.preserve_hard_links,
        context.hardlink_targets,
    );
    preserve_transferred_mtime(fs, target, entry, options, report)
}

fn remember_hardlink_target(
    entry: &WalkEntry,
    target: &Path,
    preserve_hard_links: bool,
    hardlink_targets: &mut BTreeMap<HardlinkId, PathBuf>,
) {
    if preserve_hard_links {
        if let Some(id) = entry.metadata.hardlink_id {
            hardlink_targets
                .entry(id)
                .or_insert_with(|| target.to_path_buf());
        }
    }
}

fn remove_existing_file_before_hardlink<F: PortableFileSystem>(
    fs: &mut F,
    target: &Path,
) -> Result<(), FsError> {
    match fs.metadata(target) {
        Ok(metadata) if metadata.file_type != FileType::Directory => fs.remove_file(target),
        Ok(_) | Err(FsError::NotFound(_)) => Ok(()),
        Err(err) => Err(err),
    }
}

fn transfer_symlink<F: PortableFileSystem>(
    fs: &mut F,
    entry: &WalkEntry,
    dest_root: &Path,
    target: &Path,
    relative: &Path,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    let Some(link_target) = entry.metadata.symlink_target.as_deref() else {
        report.push(SyncAction::Warn {
            path: entry.path.clone(),
            message: "symlink has no recorded target".to_string(),
        });
        return Ok(());
    };
    let target_kind = fs
        .metadata_follow(&entry.path)
        .map(|metadata| metadata.file_type)
        .unwrap_or(FileType::File);
    let link_target = match options.symlink_mode {
        SymlinkMode::Munge => munge_symlink_target(link_target),
        _ => link_target.to_path_buf(),
    };

    if !remove_conflicting_target(
        fs,
        dest_root,
        target,
        relative,
        FileType::Symlink,
        options,
        report,
    )? {
        return Ok(());
    }

    report.push(SyncAction::CreateSymlink {
        path: target.to_path_buf(),
        target: link_target.clone(),
    });
    if !options.dry_run {
        if fs
            .metadata(target)
            .is_ok_and(|metadata| metadata.file_type != FileType::Directory)
        {
            let _ = fs.remove_file(target);
        }
        fs.create_symlink(target, &link_target, target_kind)?;
    }
    preserve_transferred_mtime(fs, target, entry, options, report)
}

fn munge_symlink_target(target: &Path) -> PathBuf {
    PathBuf::from(format!("/rsyncd-munged/{}", target.to_string_lossy()))
}

fn handle_non_regular_entry(
    entry: &WalkEntry,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    let (feature, requested, label) = match entry.metadata.file_type {
        FileType::Device => (MetadataFeature::Device, options.preserve_devices, "device"),
        FileType::Special => (
            MetadataFeature::SpecialFile,
            options.preserve_specials,
            "special file",
        ),
        _ => {
            report.push(SyncAction::Warn {
                path: entry.path.clone(),
                message: format!(
                    "{:?} is not copied by portable ordinary-file sync",
                    entry.metadata.file_type
                ),
            });
            return Ok(());
        }
    };
    let message = if requested {
        format!("{label} metadata cannot be preserved by portable sync")
    } else {
        format!("skipping {label}; preservation was not requested")
    };
    if requested && options.fail_on_metadata_loss {
        return Err(FsError::Unsupported(match feature {
            MetadataFeature::Device => "device metadata cannot be preserved by portable sync",
            MetadataFeature::SpecialFile => {
                "special file metadata cannot be preserved by portable sync"
            }
            _ => "metadata cannot be preserved by portable sync",
        }));
    }
    report.push(SyncAction::Warn {
        path: entry.path.clone(),
        message,
    });
    Ok(())
}

fn append_verify_offset<F: PortableFileSystem>(
    fs: &F,
    source: &Path,
    target: &Path,
    source_len: u64,
) -> Result<Option<u64>, FsError> {
    let Ok(target_metadata) = fs.metadata(target) else {
        return Ok(None);
    };
    if target_metadata.file_type != FileType::File || target_metadata.len > source_len {
        return Ok(None);
    }

    if fs.file_prefix_matches(source, target)? {
        Ok(Some(target_metadata.len))
    } else {
        Ok(None)
    }
}

fn action_len(len: u64) -> Result<usize, FsError> {
    usize::try_from(len)
        .map_err(|_| FsError::Unsupported("file length exceeds this platform's address size"))
}

fn file_write_options(options: &SyncOptions) -> FileWriteOptions {
    FileWriteOptions {
        mode: options.file_write_mode,
        keep_partial: options.keep_partial,
        partial_dir: options.partial_dir.clone(),
        temp_dir: options.temp_dir.clone(),
        fsync: options.fsync,
    }
}

fn delayed_file_write_options(options: &SyncOptions) -> FileWriteOptions {
    FileWriteOptions {
        mode: FileWriteMode::Atomic,
        keep_partial: options.keep_partial,
        partial_dir: options.partial_dir.clone(),
        temp_dir: None,
        fsync: options.fsync,
    }
}

fn delayed_update_path(dest_root: &Path, relative: &Path, options: &SyncOptions) -> PathBuf {
    let root = match &options.temp_dir {
        Some(temp_dir) if temp_dir.is_absolute() => temp_dir.clone(),
        Some(temp_dir) => dest_root.join(temp_dir),
        None => dest_root.join(".~tmp~"),
    };
    root.join(relative)
}

fn finish_delayed_updates<F: PortableFileSystem>(
    fs: &mut F,
    dest_root: &Path,
    delayed_transfers: &[DelayedTransfer],
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    for transfer in delayed_transfers {
        backup_receiver_file(
            fs,
            dest_root,
            &transfer.target,
            &transfer.relative,
            options,
            report,
        )?;
        fs.rename_file(&transfer.temp, &transfer.target)?;
        preserve_transferred_mtime(fs, &transfer.target, &transfer.entry, options, report)?;
    }
    Ok(())
}

fn cleanup_delayed_updates<F: PortableFileSystem>(
    fs: &mut F,
    delayed_transfers: &[DelayedTransfer],
    options: &SyncOptions,
) {
    if options.keep_partial || options.partial_dir.is_some() {
        return;
    }
    for transfer in delayed_transfers {
        let _ = fs.remove_file(&transfer.temp);
    }
}

fn preserve_transferred_mtime<F: PortableFileSystem>(
    fs: &mut F,
    target: &Path,
    source: &WalkEntry,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    if !options.preserve_mtime {
        return Ok(());
    }
    if options.omit_dir_times && source.metadata.file_type == FileType::Directory {
        return Ok(());
    }
    let Some(modified) = source.metadata.modified else {
        return Ok(());
    };
    report.push(SyncAction::PreserveMtime(target.to_path_buf()));
    if !options.dry_run {
        fs.set_mtime(target, modified)?;
    }
    Ok(())
}

fn preserve_directory_mtimes<F: PortableFileSystem>(
    fs: &mut F,
    directories: &[(PathBuf, WalkEntry)],
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    for (target, entry) in directories.iter().rev() {
        preserve_transferred_mtime(fs, target, entry, options, report)?;
    }
    Ok(())
}

fn file_needs_update<F: PortableFileSystem>(
    fs: &F,
    source: &WalkEntry,
    target: &Path,
    options: &SyncOptions,
) -> Result<bool, FsError> {
    if options
        .max_size
        .is_some_and(|max| source.metadata.len > max)
    {
        return Ok(false);
    }
    if options
        .min_size
        .is_some_and(|min| source.metadata.len < min)
    {
        return Ok(false);
    }

    let Ok(target_metadata) = fs.metadata(target) else {
        return Ok(!options.existing_only);
    };
    if target_metadata.file_type != FileType::File {
        return Ok(true);
    }
    if options.ignore_existing {
        return Ok(false);
    }
    if options.skip_newer_receiver
        && source
            .metadata
            .modified
            .zip(target_metadata.modified)
            .is_some_and(|(source_mtime, target_mtime)| target_mtime > source_mtime)
    {
        return Ok(false);
    }

    match options.update_mode {
        UpdateMode::IgnoreTimes => Ok(true),
        UpdateMode::SizeOnly => Ok(source.metadata.len != target_metadata.len),
        UpdateMode::QuickCheck => Ok(source.metadata.len != target_metadata.len
            || match source.metadata.modified.zip(target_metadata.modified) {
                Some((source_mtime, target_mtime)) => {
                    !mtimes_equal(source_mtime, target_mtime, options.modify_window)
                }
                None => true,
            }),
        UpdateMode::Checksum => Ok(!fs.files_equal(&source.path, target)?),
    }
}

fn preserve_existing_file_mtime<F: PortableFileSystem>(
    fs: &mut F,
    target: &Path,
    source: &WalkEntry,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    if !options.preserve_mtime {
        return Ok(());
    }
    let Some(source_mtime) = source.metadata.modified else {
        return Ok(());
    };
    let Ok(target_metadata) = fs.metadata(target) else {
        return Ok(());
    };
    if target_metadata.modified == Some(source_mtime) {
        return Ok(());
    }

    report.push(SyncAction::PreserveMtime(target.to_path_buf()));
    if !options.dry_run {
        fs.set_mtime(target, source_mtime)?;
    }
    Ok(())
}

fn retain_files_from_entries(entries: &mut BTreeMap<PathBuf, WalkEntry>, files_from: &[PathBuf]) {
    entries.retain(|relative, _| files_from_matches(relative, files_from));
}

fn files_from_matches(relative: &Path, files_from: &[PathBuf]) -> bool {
    files_from.iter().any(|selected| {
        relative == selected || relative.starts_with(selected) || selected.starts_with(relative)
    })
}

pub fn source_relative_paths<F: PortableFileSystem>(
    fs: &F,
    source: &Path,
    filter_rules: &RuleSet,
) -> Result<Vec<PathBuf>, FsError> {
    Ok(relative_entries(
        fs,
        source,
        Some(filter_rules),
        true,
        SymlinkMode::Preserve,
        false,
    )?
    .into_keys()
    .collect())
}

pub fn selected_source_paths<F: PortableFileSystem>(
    fs: &F,
    sources: &[PathBuf],
    options: SourceSelectionOptions<'_>,
) -> Result<Vec<PathBuf>, FsError> {
    if sources.is_empty() {
        return Err(FsError::Unsupported("sync requires at least one source"));
    }

    let mut paths = Vec::new();
    for source in sources {
        paths.extend(selected_single_source_paths(fs, source, options)?);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn selected_single_source_paths<F: PortableFileSystem>(
    fs: &F,
    source: &Path,
    options: SourceSelectionOptions<'_>,
) -> Result<Vec<PathBuf>, FsError> {
    let metadata = fs.metadata(source)?;
    let mut paths = Vec::new();
    if matches!(metadata.file_type, FileType::File | FileType::Directory) {
        paths.push(source.to_path_buf());
    }
    if metadata.file_type != FileType::Directory {
        return Ok(paths);
    }

    let mut entries = relative_entries(
        fs,
        source,
        Some(options.filter_rules),
        options.recursive,
        options.symlink_mode,
        options.one_file_system,
    )?;
    if let Some(files_from) = options.files_from {
        retain_files_from_entries(&mut entries, files_from);
    }

    paths.extend(entries.into_values().filter_map(|entry| {
        let selected = match entry.metadata.file_type {
            FileType::File => true,
            FileType::Directory => options.recursive,
            FileType::Symlink
            | FileType::Hardlink
            | FileType::Device
            | FileType::Special
            | FileType::Other => false,
        };
        selected.then_some(entry.path)
    }));
    Ok(paths)
}

fn remove_conflicting_target<F: PortableFileSystem>(
    fs: &mut F,
    dest_root: &Path,
    target: &Path,
    relative: &Path,
    source_type: FileType,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<bool, FsError> {
    let Ok(target_metadata) = fs.metadata(target) else {
        return Ok(true);
    };

    if options.keep_dirlinks
        && source_type == FileType::Directory
        && target_metadata.file_type == FileType::Symlink
        && fs
            .metadata_follow(target)
            .is_ok_and(|metadata| metadata.file_type == FileType::Directory)
    {
        return Ok(true);
    }

    if target_metadata.file_type == source_type {
        return Ok(true);
    }

    match target_metadata.file_type {
        FileType::Directory => {
            if !options.force_delete
                && options.effective_delete_mode() == DeleteMode::None
                && !fs.list(target)?.is_empty()
            {
                report.push(SyncAction::ProtectDelete(target.to_path_buf()));
                return Ok(false);
            }
            report.push(SyncAction::DeleteDir(target.to_path_buf()));
            if !options.dry_run {
                fs.remove_dir_all(target)?;
            }
        }
        _ => {
            backup_receiver_file(fs, dest_root, target, relative, options, report)?;
            report.push(SyncAction::DeleteFile(target.to_path_buf()));
            if !options.dry_run {
                fs.remove_file(target)?;
            }
        }
    }

    Ok(true)
}

fn relative_entries<F: PortableFileSystem>(
    fs: &F,
    root: &Path,
    filter_rules: Option<&RuleSet>,
    recursive: bool,
    symlink_mode: SymlinkMode,
    one_file_system: bool,
) -> Result<BTreeMap<PathBuf, WalkEntry>, FsError> {
    let mut entries = BTreeMap::new();
    let options = RelativeEntryOptions {
        filter_rules,
        recursive,
        symlink_mode,
        one_file_system,
    };
    collect_relative_entries(fs, root, root, Path::new(""), options, &mut entries)?;
    Ok(entries)
}

fn collect_relative_entries<F: PortableFileSystem>(
    fs: &F,
    root: &Path,
    current: &Path,
    relative_root: &Path,
    options: RelativeEntryOptions<'_>,
    entries: &mut BTreeMap<PathBuf, WalkEntry>,
) -> Result<(), FsError> {
    let directory_rules = load_dir_merge_rules(fs, current, options.filter_rules)?;
    let active_filter_rules = directory_rules.as_ref().or(options.filter_rules);
    for original_entry in fs.list(current)? {
        let name = original_entry
            .path
            .file_name()
            .ok_or_else(|| FsError::InvalidPortablePath(original_entry.path.clone()))?;
        let relative = relative_root.join(name);
        let Some(entry) = apply_symlink_mode(fs, original_entry, options.symlink_mode)? else {
            continue;
        };
        if options.one_file_system && !fs.same_file_system(root, &entry.path)? {
            continue;
        }
        if active_filter_rules.is_some_and(|rules| {
            sender_path_is_filtered(rules, &relative, entry.metadata.file_type)
        }) {
            continue;
        }
        let should_recurse = options.recursive && entry.metadata.file_type == FileType::Directory;
        let child_root = if should_recurse {
            Some(
                followed_directory_walk_path(&entry, options.symlink_mode)?
                    .unwrap_or_else(|| entry.path.clone()),
            )
        } else {
            None
        };
        let child_relative = relative.clone();
        entries.insert(relative, entry);
        if let Some(child_root) = child_root {
            let child_options = RelativeEntryOptions {
                filter_rules: active_filter_rules,
                ..options
            };
            collect_relative_entries(
                fs,
                root,
                &child_root,
                &child_relative,
                child_options,
                entries,
            )?;
        }
    }
    Ok(())
}

fn load_dir_merge_rules<F: PortableFileSystem>(
    fs: &F,
    current: &Path,
    inherited: Option<&RuleSet>,
) -> Result<Option<RuleSet>, FsError> {
    let Some(inherited) = inherited else {
        return Ok(None);
    };

    let mut merged = inherited.clone();
    let mut loaded_any = false;
    for rule in inherited.rules() {
        if rule.action() != RuleAction::DirMerge {
            continue;
        }
        let merge_file = current.join(rule.pattern().raw());
        let bytes = match fs.read_file(&merge_file) {
            Ok(bytes) => bytes,
            Err(FsError::NotFound(_)) => continue,
            Err(err) => return Err(err),
        };
        let parsed = Rule::parse_filter_file(&bytes, false, RuleAction::Exclude)
            .map_err(|_| FsError::Unsupported("invalid dir-merge filter file"))?;
        for parsed_rule in parsed {
            merged.push(parsed_rule);
        }
        loaded_any = true;
    }

    Ok(loaded_any.then_some(merged))
}

fn apply_symlink_mode<F: PortableFileSystem>(
    fs: &F,
    mut entry: WalkEntry,
    symlink_mode: SymlinkMode,
) -> Result<Option<WalkEntry>, FsError> {
    if entry.metadata.file_type != FileType::Symlink {
        return Ok(Some(entry));
    }

    let target = entry.metadata.symlink_target.clone();
    match symlink_mode {
        SymlinkMode::Skip => Ok(None),
        SymlinkMode::Preserve | SymlinkMode::Munge => Ok(Some(entry)),
        SymlinkMode::SafeOnly => {
            if target.as_deref().is_some_and(is_unsafe_symlink_target) {
                Ok(None)
            } else {
                Ok(Some(entry))
            }
        }
        SymlinkMode::CopyAll => {
            entry.metadata = followed_file_metadata_or_other(fs, &entry.path)?;
            entry.metadata.symlink_target = target;
            Ok(Some(entry))
        }
        SymlinkMode::CopyDirLinks => {
            let followed = followed_file_metadata_or_other(fs, &entry.path)?;
            if followed.file_type == FileType::Directory {
                entry.metadata = followed;
                entry.metadata.symlink_target = target;
            }
            Ok(Some(entry))
        }
        SymlinkMode::CopyUnsafe => {
            if target.as_deref().is_some_and(is_unsafe_symlink_target) {
                entry.metadata = followed_file_metadata_or_other(fs, &entry.path)?;
                entry.metadata.symlink_target = target;
            }
            Ok(Some(entry))
        }
    }
}

fn followed_file_metadata_or_other<F: PortableFileSystem>(
    fs: &F,
    path: &Path,
) -> Result<PortableMetadata, FsError> {
    let mut metadata = fs.metadata_follow(path)?;
    if !matches!(metadata.file_type, FileType::File | FileType::Directory) {
        metadata.file_type = FileType::Other;
    }
    metadata.symlink_target = None;
    Ok(metadata)
}

fn followed_directory_walk_path(
    entry: &WalkEntry,
    symlink_mode: SymlinkMode,
) -> Result<Option<PathBuf>, FsError> {
    if entry.metadata.file_type != FileType::Directory {
        return Ok(None);
    }
    let Some(target) = entry.metadata.symlink_target.as_deref() else {
        return Ok(None);
    };
    let should_follow = match symlink_mode {
        SymlinkMode::CopyAll | SymlinkMode::CopyDirLinks => true,
        SymlinkMode::CopyUnsafe => is_unsafe_symlink_target(target),
        SymlinkMode::Skip | SymlinkMode::Preserve | SymlinkMode::SafeOnly | SymlinkMode::Munge => {
            false
        }
    };
    if should_follow {
        Ok(Some(resolve_symlink_target(&entry.path, target)))
    } else {
        Ok(None)
    }
}

fn resolve_symlink_target(link_path: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        link_path
            .parent()
            .map(|parent| parent.join(target))
            .unwrap_or_else(|| target.to_path_buf())
    }
}

fn is_unsafe_symlink_target(target: &Path) -> bool {
    target.is_absolute()
        || target
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
}

fn sender_path_is_filtered(rules: &RuleSet, relative: &Path, file_type: FileType) -> bool {
    let mut current = PathBuf::new();
    let mut components = relative.components().peekable();

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return true;
        };
        current.push(name);

        let kind = if components.peek().is_some() {
            EntryKind::Directory
        } else {
            entry_kind(file_type)
        };
        if matches!(
            rules
                .decide_for_side(&filter_path(&current), kind, RuleSide::Sender)
                .action(),
            RuleAction::Exclude | RuleAction::Hide
        ) {
            return true;
        }
    }

    false
}

fn delete_is_protected(
    rules: &RuleSet,
    relative: &Path,
    file_type: FileType,
    delete_excluded: bool,
) -> bool {
    let mut current = PathBuf::new();
    let mut components = relative.components().peekable();

    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return true;
        };
        current.push(name);

        let kind = if components.peek().is_some() {
            EntryKind::Directory
        } else {
            entry_kind(file_type)
        };
        let action = rules
            .decide_for_side(&filter_path(&current), kind, RuleSide::Receiver)
            .action();
        if action == RuleAction::Protect || (action == RuleAction::Exclude && !delete_excluded) {
            return true;
        }
    }

    false
}

fn entry_kind(file_type: FileType) -> EntryKind {
    if file_type == FileType::Directory {
        EntryKind::Directory
    } else {
        EntryKind::File
    }
}

fn filter_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn destination_preflight_path(target: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in target.components() {
        if let Component::Normal(name) = component {
            out.push(name);
        }
    }
    if out.as_os_str().is_empty() {
        target.to_path_buf()
    } else {
        out
    }
}

impl SyncOptions {
    fn effective_delete_mode(&self) -> DeleteMode {
        if self.delete_mode != DeleteMode::None {
            self.delete_mode
        } else if self.delete {
            DeleteMode::During
        } else {
            DeleteMode::None
        }
    }
}

fn apply_receiver_deletes<F: PortableFileSystem>(
    fs: &mut F,
    dest_root: &Path,
    source_entries: &BTreeMap<PathBuf, WalkEntry>,
    dest_entries: &BTreeMap<PathBuf, WalkEntry>,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    if options.effective_delete_mode() == DeleteMode::None {
        return Ok(());
    }

    let source_relatives: BTreeSet<_> = source_entries.keys().cloned().collect();
    let mut delete_entries: Vec<_> = dest_entries
        .iter()
        .filter(|(relative, _)| !source_relatives.contains(*relative))
        .map(|(relative, entry)| (relative.clone(), entry.clone()))
        .collect();
    delete_entries.sort_by(|left, right| {
        right
            .0
            .components()
            .count()
            .cmp(&left.0.components().count())
            .then_with(|| right.0.cmp(&left.0))
    });

    let mut deleted = 0_usize;
    for (relative, entry) in delete_entries {
        if !fs.exists(&entry.path) {
            continue;
        }
        if options
            .files_from
            .as_ref()
            .is_some_and(|files_from| !files_from_matches(&relative, files_from))
        {
            report.push(SyncAction::ProtectDelete(entry.path.clone()));
            continue;
        }
        if delete_is_protected(
            &options.filter_rules,
            &relative,
            entry.metadata.file_type,
            options.delete_excluded,
        ) {
            report.push(SyncAction::ProtectDelete(entry.path.clone()));
            continue;
        }
        if let Some(limit) = options.max_delete {
            if deleted >= limit {
                return Err(FsError::MaxDeleteExceeded { limit });
            }
        }

        delete_receiver_entry(
            fs,
            dest_root,
            &entry.path,
            &relative,
            entry.metadata.file_type,
            options,
            report,
        )?;
        deleted += 1;
    }

    Ok(())
}

fn delete_receiver_entry<F: PortableFileSystem>(
    fs: &mut F,
    dest_root: &Path,
    path: &Path,
    relative: &Path,
    file_type: FileType,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    match file_type {
        FileType::Directory => {
            report.push(SyncAction::DeleteDir(path.to_path_buf()));
            if !options.dry_run {
                fs.remove_dir_all(path)?;
            }
        }
        _ => {
            backup_receiver_file(fs, dest_root, path, relative, options, report)?;
            report.push(SyncAction::DeleteFile(path.to_path_buf()));
            if !options.dry_run {
                fs.remove_file(path)?;
            }
        }
    }
    Ok(())
}

fn delete_missing_arg<F: PortableFileSystem>(
    fs: &mut F,
    source: &Path,
    dest: &Path,
    source_count: usize,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    let target = if source_count > 1
        || fs
            .metadata(dest)
            .is_ok_and(|meta| meta.file_type == FileType::Directory)
    {
        batch_target_path(source, dest)?
    } else {
        dest.to_path_buf()
    };
    let Ok(metadata) = fs.metadata(&target) else {
        return Ok(());
    };
    let relative = target
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| destination_preflight_path(&target));
    if metadata.file_type == FileType::Directory
        && !options.force_delete
        && options.effective_delete_mode() == DeleteMode::None
        && !fs.list(&target)?.is_empty()
    {
        report.push(SyncAction::ProtectDelete(target));
        return Ok(());
    }
    delete_receiver_entry(
        fs,
        dest,
        &target,
        &relative,
        metadata.file_type,
        options,
        report,
    )
}

fn backup_receiver_file<F: PortableFileSystem>(
    fs: &mut F,
    dest_root: &Path,
    target: &Path,
    relative: &Path,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    if !options.backup {
        return Ok(());
    }
    let Ok(metadata) = fs.metadata(target) else {
        return Ok(());
    };
    if metadata.file_type != FileType::File {
        return Ok(());
    }

    let backup_path = backup_path_for(dest_root, target, relative, options);
    report.push(SyncAction::BackupFile {
        from: target.to_path_buf(),
        to: backup_path.clone(),
    });
    if !options.dry_run {
        fs.copy_file_with_options(target, &backup_path, &FileWriteOptions::default())?;
    }
    Ok(())
}

fn backup_path_for(
    dest_root: &Path,
    target: &Path,
    relative: &Path,
    options: &SyncOptions,
) -> PathBuf {
    let base = if let Some(backup_dir) = &options.backup_dir {
        if backup_dir.is_absolute() {
            backup_dir.join(relative)
        } else {
            dest_root.join(backup_dir).join(relative)
        }
    } else {
        target.to_path_buf()
    };
    append_suffix(base, &options.backup_suffix)
}

fn append_suffix(path: PathBuf, suffix: &str) -> PathBuf {
    if suffix.is_empty() {
        return path;
    }
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

fn mtimes_equal(left: std::time::SystemTime, right: std::time::SystemTime, window: i64) -> bool {
    if window < 0 {
        return left == right;
    }
    match left.duration_since(right) {
        Ok(diff) => diff.as_secs() <= window as u64,
        Err(err) => err.duration().as_secs() <= window as u64,
    }
}

fn relative_operand_path(path: &Path) -> Result<PathBuf, FsError> {
    let mut out = PathBuf::new();
    let mut saw_normal = false;
    for component in path.components() {
        if let Component::Normal(name) = component {
            out.push(name);
            saw_normal = true;
        }
    }
    if saw_normal {
        Ok(out)
    } else {
        Err(FsError::InvalidPortablePath(path.to_path_buf()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::walk::{LocalFileSystem, MemoryFileSystem};
    use rsync_filter::Rule;

    #[test]
    fn dry_run_reports_copy_without_mutating_destination() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"a").unwrap();
        fs.add_dir("dst").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(report.actions().contains(&SyncAction::WriteFile {
            path: "dst/a.txt".into(),
            len: 1,
        }));
        assert!(!fs.exists(Path::new("dst/a.txt")));
    }

    #[test]
    fn memory_sync_copies_files_and_deletes_extra_entries() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"a").unwrap();
        fs.add_file("dst/old.txt", b"old").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: true,
                delete: true,
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/a.txt")).unwrap(), b"a");
        assert!(!fs.exists(Path::new("dst/old.txt")));
    }

    #[test]
    fn syncs_single_file_to_destination_file() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("source.txt", b"file").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("source.txt"),
            Path::new("dest.txt"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dest.txt")).unwrap(), b"file");
        assert!(report.actions().contains(&SyncAction::WriteFile {
            path: PathBuf::from("dest.txt"),
            len: 4,
        }));
    }

    #[test]
    fn single_file_sync_runs_destination_preflight_before_write() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("source.txt", b"file").unwrap();

        let err = sync_tree(
            &mut fs,
            Path::new("source.txt"),
            Path::new("NUL"),
            SyncOptions {
                dry_run: false,
                destination_path_preflight: Some(reject_nul_component),
                ..SyncOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(err, FsError::DestinationPathPreflight(_)));
        assert!(!fs.exists(Path::new("NUL")));
    }

    #[test]
    fn syncs_single_file_into_existing_destination_directory() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("source.txt", b"file").unwrap();
        fs.add_dir("dest").unwrap();

        sync_tree(
            &mut fs,
            Path::new("source.txt"),
            Path::new("dest"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dest/source.txt")).unwrap(), b"file");
    }

    #[test]
    fn non_recursive_sync_skips_source_directories() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/top.txt", b"top").unwrap();
        fs.add_file("src/nested/file.txt", b"nested").unwrap();
        fs.add_dir("dst").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: false,
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/top.txt")).unwrap(), b"top");
        assert!(!fs.exists(Path::new("dst/nested/file.txt")));
        assert!(report
            .warnings()
            .any(|action| matches!(action, SyncAction::Warn { path, .. } if path == Path::new("src/nested"))));
    }

    #[test]
    fn quick_check_skips_files_with_matching_size_and_mtime() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"same").unwrap();
        fs.add_file("dst/a.txt", b"same").unwrap();
        fs.set_mtime(Path::new("src/a.txt"), modified).unwrap();
        fs.set_mtime(Path::new("dst/a.txt"), modified).unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(!report
            .actions()
            .iter()
            .any(|action| matches!(action, SyncAction::WriteFile { .. })));
    }

    #[test]
    fn checksum_mode_updates_same_size_different_content() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_101);
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"new!").unwrap();
        fs.add_file("dst/a.txt", b"old!").unwrap();
        fs.set_mtime(Path::new("src/a.txt"), modified).unwrap();
        fs.set_mtime(Path::new("dst/a.txt"), modified).unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                update_mode: UpdateMode::Checksum,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/a.txt")).unwrap(), b"new!");
    }

    #[test]
    fn checksum_mode_preserves_mtime_when_content_is_unchanged() {
        let source_mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_102);
        let old_dest_mtime = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"same").unwrap();
        fs.add_file("dst/a.txt", b"same").unwrap();
        fs.set_mtime(Path::new("src/a.txt"), source_mtime).unwrap();
        fs.set_mtime(Path::new("dst/a.txt"), old_dest_mtime)
            .unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: true,
                update_mode: UpdateMode::Checksum,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(report
            .actions()
            .contains(&SyncAction::PreserveMtime(PathBuf::from("dst/a.txt"))));
        assert_eq!(
            fs.metadata(Path::new("dst/a.txt")).unwrap().modified,
            Some(source_mtime)
        );
    }

    #[test]
    fn omit_dir_times_preserves_file_mtimes_but_not_directory_mtimes() {
        let source_file_mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_200);
        let source_dir_mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_300);
        let old_dest_dir_mtime = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let mut fs = MemoryFileSystem::new();
        fs.add_dir("src/sub").unwrap();
        fs.add_file("src/sub/file.txt", b"content").unwrap();
        fs.add_dir("dst/sub").unwrap();
        fs.set_mtime(Path::new("src/sub"), source_dir_mtime)
            .unwrap();
        fs.set_mtime(Path::new("src/sub/file.txt"), source_file_mtime)
            .unwrap();
        fs.set_mtime(Path::new("dst/sub"), old_dest_dir_mtime)
            .unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: true,
                omit_dir_times: true,
                update_mode: UpdateMode::IgnoreTimes,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(report
            .actions()
            .contains(&SyncAction::PreserveMtime(PathBuf::from(
                "dst/sub/file.txt"
            ))));
        assert!(!report
            .actions()
            .contains(&SyncAction::PreserveMtime(PathBuf::from("dst/sub"))));
        assert_eq!(
            fs.metadata(Path::new("dst/sub/file.txt")).unwrap().modified,
            Some(source_file_mtime)
        );
        assert_ne!(
            fs.metadata(Path::new("dst/sub")).unwrap().modified,
            Some(source_dir_mtime)
        );
    }

    #[test]
    fn append_verify_appends_when_destination_is_source_prefix() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"abcdef").unwrap();
        fs.add_file("dst/a.txt", b"abc").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                append_verify: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/a.txt")).unwrap(), b"abcdef");
        assert!(report.actions().contains(&SyncAction::AppendFile {
            path: PathBuf::from("dst/a.txt"),
            len: 3,
        }));
        assert!(!report
            .actions()
            .iter()
            .any(|action| matches!(action, SyncAction::WriteFile { .. })));
    }

    #[test]
    fn inplace_mode_reports_inplace_write() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"new").unwrap();
        fs.add_file("dst/a.txt", b"old").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                file_write_mode: FileWriteMode::InPlace,
                update_mode: UpdateMode::IgnoreTimes,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/a.txt")).unwrap(), b"new");
        assert!(report
            .actions()
            .iter()
            .any(|action| matches!(action, SyncAction::WriteFileInPlace { path, len } if path == Path::new("dst/a.txt") && *len == 3)));
    }

    #[test]
    fn copy_links_copies_file_symlink_referent() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/target.txt", b"target").unwrap();
        fs.add_symlink("src/link.txt", "target.txt").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                symlink_mode: SymlinkMode::CopyAll,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/link.txt")).unwrap(), b"target");
    }

    #[test]
    fn copy_links_copies_directory_symlink_referent_under_link_name() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/real/file.txt", b"target").unwrap();
        fs.add_symlink("src/linkdir", "real").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: true,
                dry_run: false,
                preserve_mtime: false,
                symlink_mode: SymlinkMode::CopyAll,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.read_file(Path::new("dst/linkdir/file.txt")).unwrap(),
            b"target"
        );
    }

    #[test]
    fn safe_links_skips_unsafe_sender_symlinks() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("secret.txt", b"secret").unwrap();
        fs.add_symlink("src/unsafe.txt", "../secret.txt").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                symlink_mode: SymlinkMode::SafeOnly,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(!fs.exists(Path::new("dst/unsafe.txt")));
    }

    #[test]
    fn default_mode_skips_sender_symlinks() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/target.txt", b"target").unwrap();
        fs.add_symlink("src/link.txt", "target.txt").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(!fs.exists(Path::new("dst/link.txt")));
        assert_eq!(
            fs.read_file(Path::new("dst/target.txt")).unwrap(),
            b"target"
        );
    }

    #[test]
    fn links_mode_preserves_symlink_targets() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/target.txt", b"target").unwrap();
        fs.add_symlink("src/link.txt", "target.txt").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                symlink_mode: SymlinkMode::Preserve,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        let metadata = fs.metadata(Path::new("dst/link.txt")).unwrap();
        assert_eq!(metadata.file_type, FileType::Symlink);
        assert_eq!(
            metadata.symlink_target.as_deref(),
            Some(Path::new("target.txt"))
        );
        assert!(report.actions().iter().any(|action| matches!(
            action,
            SyncAction::CreateSymlink { path, target }
                if path == Path::new("dst/link.txt") && target == Path::new("target.txt")
        )));
    }

    #[test]
    fn links_mode_reports_filesystem_symlink_capability_errors() {
        let mut fs = FailingCopyFileSystem::new(PathBuf::from("__copy_never_fails__"));
        fs.inner.add_file("src/target.txt", b"target").unwrap();
        fs.inner.add_symlink("src/link.txt", "target.txt").unwrap();

        let err = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                symlink_mode: SymlinkMode::Preserve,
                ..SyncOptions::default()
            },
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("creating symlinks is unsupported by this filesystem"));
    }

    #[test]
    fn munge_links_preserves_link_as_safe_munged_target() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("secret.txt", b"secret").unwrap();
        fs.add_symlink("src/link.txt", "../secret.txt").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                symlink_mode: SymlinkMode::Munge,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        let metadata = fs.metadata(Path::new("dst/link.txt")).unwrap();
        assert_eq!(metadata.file_type, FileType::Symlink);
        assert_eq!(
            metadata.symlink_target.as_deref(),
            Some(Path::new("/rsyncd-munged/../secret.txt"))
        );
    }

    #[test]
    fn copy_dirlinks_only_follows_directory_symlinks() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/real-dir/file.txt", b"dir").unwrap();
        fs.add_file("src/file-target.txt", b"file").unwrap();
        fs.add_symlink("src/linkdir", "real-dir").unwrap();
        fs.add_symlink("src/linkfile.txt", "file-target.txt")
            .unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: true,
                dry_run: false,
                preserve_mtime: false,
                symlink_mode: SymlinkMode::CopyDirLinks,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.read_file(Path::new("dst/linkdir/file.txt")).unwrap(),
            b"dir"
        );
        assert_eq!(
            fs.metadata(Path::new("dst/linkfile.txt"))
                .unwrap()
                .file_type,
            FileType::Symlink
        );
    }

    #[test]
    fn keep_dirlinks_reuses_receiver_directory_symlink() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/linkdir/file.txt", b"new").unwrap();
        fs.add_dir("dst/real").unwrap();
        fs.add_symlink("dst/linkdir", "real").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: true,
                dry_run: false,
                preserve_mtime: false,
                keep_dirlinks: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.metadata(Path::new("dst/linkdir")).unwrap().file_type,
            FileType::Symlink
        );
        assert_eq!(
            fs.read_file(Path::new("dst/real/file.txt")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn hard_links_mode_preserves_memory_hardlink_groups() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/original.txt", b"same").unwrap();
        fs.add_hardlink("src/original.txt", "src/alias.txt")
            .unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                preserve_hard_links: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        let original = fs.metadata(Path::new("dst/original.txt")).unwrap();
        let alias = fs.metadata(Path::new("dst/alias.txt")).unwrap();
        assert_eq!(original.hardlink_id, alias.hardlink_id);
        assert!(report.actions().iter().any(|action| matches!(
            action,
            SyncAction::CreateHardLink { from, to }
                if (from == Path::new("dst/original.txt") && to == Path::new("dst/alias.txt"))
                    || (from == Path::new("dst/alias.txt") && to == Path::new("dst/original.txt"))
        )));
    }

    #[test]
    fn hard_links_mode_falls_back_to_file_copy_when_link_creation_fails() {
        let mut fs = FailingCopyFileSystem::new(PathBuf::from("__copy_never_fails__"));
        fs.inner.add_file("src/original.txt", b"same").unwrap();
        fs.inner
            .add_hardlink("src/original.txt", "src/alias.txt")
            .unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                preserve_hard_links: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.inner.read_file(Path::new("dst/original.txt")).unwrap(),
            b"same"
        );
        assert_eq!(
            fs.inner.read_file(Path::new("dst/alias.txt")).unwrap(),
            b"same"
        );
        assert!(report.actions().iter().any(|action| matches!(
            action,
            SyncAction::Warn { message, .. }
                if message.contains("hard link preservation fell back to file copy")
        )));
    }

    #[test]
    fn device_and_special_file_options_warn_or_error_in_portable_sync() {
        let mut fs = MemoryFileSystem::new();
        fs.add_device("src/null").unwrap();
        fs.add_special("src/socket").unwrap();

        let warn_report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst-warn"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                preserve_devices: true,
                preserve_specials: true,
                fail_on_metadata_loss: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();
        assert_eq!(warn_report.warnings().count(), 2);

        let err = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst-error"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                preserve_devices: true,
                preserve_specials: true,
                fail_on_metadata_loss: true,
                ..SyncOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, FsError::Unsupported(message) if message.contains("device")));
    }

    #[test]
    fn files_from_limits_sender_entries_and_protects_other_deletes() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/keep.txt", b"keep").unwrap();
        fs.add_file("src/skip.txt", b"skip").unwrap();
        fs.add_file("dst/old.txt", b"old").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                delete: true,
                dry_run: false,
                preserve_mtime: false,
                files_from: Some(vec![PathBuf::from("keep.txt")]),
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/keep.txt")).unwrap(), b"keep");
        assert!(!fs.exists(Path::new("dst/skip.txt")));
        assert_eq!(fs.read_file(Path::new("dst/old.txt")).unwrap(), b"old");
        assert!(report
            .actions()
            .contains(&SyncAction::ProtectDelete(PathBuf::from("dst/old.txt"))));
    }

    #[test]
    fn sync_sources_batches_multiple_sources_under_destination() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/one.txt", b"one").unwrap();
        fs.add_file("src/dir/two.txt", b"two").unwrap();

        let report = sync_sources(
            &mut fs,
            &[PathBuf::from("src/one.txt"), PathBuf::from("src/dir")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/one.txt")).unwrap(), b"one");
        assert_eq!(fs.read_file(Path::new("dst/dir/two.txt")).unwrap(), b"two");
        assert!(report
            .actions()
            .contains(&SyncAction::CreateDir(PathBuf::from("dst"))));
    }

    #[test]
    fn filters_sender_entries_and_protects_receiver_deletes() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/keep.txt", b"keep").unwrap();
        fs.add_file("src/cache.tmp", b"cache").unwrap();
        fs.add_file("src/sent.bak", b"new-backup").unwrap();
        fs.add_file("dst/cache.tmp", b"old-cache").unwrap();
        fs.add_file("dst/protected.bak", b"backup").unwrap();
        fs.add_file("dst/delete.me", b"delete").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: true,
                delete: true,
                dry_run: false,
                preserve_mtime: false,
                filter_rules: RuleSet::new(vec![
                    Rule::exclude("*.tmp").unwrap(),
                    Rule::protect("*.bak").unwrap(),
                ]),
                destination_path_preflight: None,
                update_mode: UpdateMode::QuickCheck,
                files_from: None,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/keep.txt")).unwrap(), b"keep");
        assert_eq!(
            fs.read_file(Path::new("dst/sent.bak")).unwrap(),
            b"new-backup"
        );
        assert!(!fs.exists(Path::new("dst/delete.me")));
        assert_eq!(
            fs.read_file(Path::new("dst/cache.tmp")).unwrap(),
            b"old-cache"
        );
        assert_eq!(
            fs.read_file(Path::new("dst/protected.bak")).unwrap(),
            b"backup"
        );
        assert!(report
            .actions()
            .contains(&SyncAction::ProtectDelete(PathBuf::from("dst/cache.tmp"))));
        assert!(report
            .actions()
            .contains(&SyncAction::ProtectDelete(PathBuf::from(
                "dst/protected.bak"
            ))));
    }

    #[test]
    fn dir_merge_filter_files_apply_to_directory_descendants() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/.rsync-filter", b"- *.tmp\n").unwrap();
        fs.add_file("src/keep.txt", b"keep").unwrap();
        fs.add_file("src/drop.tmp", b"drop").unwrap();
        fs.add_file("src/nested/.rsync-filter", b"- secret.*\n")
            .unwrap();
        fs.add_file("src/nested/visible.txt", b"visible").unwrap();
        fs.add_file("src/nested/secret.txt", b"secret").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                filter_rules: RuleSet::new(vec![Rule::parse_filter(": .rsync-filter").unwrap()]),
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/keep.txt")).unwrap(), b"keep");
        assert!(!fs.exists(Path::new("dst/drop.tmp")));
        assert_eq!(
            fs.read_file(Path::new("dst/nested/visible.txt")).unwrap(),
            b"visible"
        );
        assert!(!fs.exists(Path::new("dst/nested/secret.txt")));
    }

    #[test]
    fn selected_source_paths_match_filter_and_files_from_selection() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/keep.txt", b"keep").unwrap();
        fs.add_file("src/drop.tmp", b"drop").unwrap();
        fs.add_file("src/dir/keep.dat", b"nested").unwrap();
        fs.add_file("src/dir/drop.tmp", b"nested-drop").unwrap();
        let files_from = vec![PathBuf::from("dir/keep.dat")];

        let paths = selected_source_paths(
            &fs,
            &[PathBuf::from("src")],
            SourceSelectionOptions {
                recursive: true,
                filter_rules: &RuleSet::new(vec![Rule::exclude("*.tmp").unwrap()]),
                files_from: Some(&files_from),
                symlink_mode: SymlinkMode::Preserve,
                one_file_system: false,
            },
        )
        .unwrap();

        assert_eq!(
            paths,
            vec![
                PathBuf::from("src"),
                PathBuf::from("src/dir"),
                PathBuf::from("src/dir/keep.dat"),
            ]
        );
    }

    #[test]
    fn selected_source_paths_skip_nonrecursive_child_directories() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/top.txt", b"top").unwrap();
        fs.add_file("src/nested/file.txt", b"nested").unwrap();

        let paths = selected_source_paths(
            &fs,
            &[PathBuf::from("src")],
            SourceSelectionOptions {
                recursive: false,
                filter_rules: &RuleSet::empty(),
                files_from: None,
                symlink_mode: SymlinkMode::Preserve,
                one_file_system: false,
            },
        )
        .unwrap();

        assert_eq!(
            paths,
            vec![PathBuf::from("src"), PathBuf::from("src/top.txt")]
        );
    }

    #[test]
    fn directory_filter_protects_receiver_delete_descendants() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/keep.txt", b"keep").unwrap();
        fs.add_file("dst/cache/old.txt", b"old").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: true,
                delete: true,
                dry_run: false,
                preserve_mtime: false,
                filter_rules: RuleSet::new(vec![Rule::exclude("cache/").unwrap()]),
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.read_file(Path::new("dst/cache/old.txt")).unwrap(),
            b"old"
        );
        assert!(report
            .actions()
            .contains(&SyncAction::ProtectDelete(PathBuf::from(
                "dst/cache/old.txt"
            ))));
    }

    #[test]
    fn replaces_destination_directory_with_source_file() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/item", b"file").unwrap();
        fs.add_file("dst/item/old.txt", b"old").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                delete: true,
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/item")).unwrap(), b"file");
        assert!(!fs.exists(Path::new("dst/item/old.txt")));
        assert!(report
            .actions()
            .contains(&SyncAction::DeleteDir(PathBuf::from("dst/item"))));
    }

    #[test]
    fn dirs_mode_creates_top_level_directories_without_recursing() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/top.txt", b"top").unwrap();
        fs.add_file("src/nested/file.txt", b"nested").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                recursive: false,
                transfer_dirs: true,
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/top.txt")).unwrap(), b"top");
        assert!(fs.metadata(Path::new("dst/nested")).unwrap().file_type == FileType::Directory);
        assert!(!fs.exists(Path::new("dst/nested/file.txt")));
        assert!(report
            .actions()
            .contains(&SyncAction::CreateDir(PathBuf::from("dst/nested"))));
    }

    #[test]
    fn relative_mode_preserves_operand_path_under_destination() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/nested/file.txt", b"data").unwrap();

        sync_sources(
            &mut fs,
            &[PathBuf::from("src/nested/file.txt")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                relative_paths: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.read_file(Path::new("dst/src/nested/file.txt")).unwrap(),
            b"data"
        );
    }

    #[test]
    fn no_implied_dirs_preserves_receiver_path_elements() {
        let mut implied_fs = MemoryFileSystem::new();
        implied_fs.add_file("src/nested/file.txt", b"data").unwrap();
        implied_fs.add_dir("dst/elsewhere").unwrap();
        implied_fs
            .add_symlink("dst/src/nested", "../elsewhere")
            .unwrap();

        sync_sources(
            &mut implied_fs,
            &[PathBuf::from("src/nested/file.txt")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                relative_paths: true,
                implied_dirs: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            implied_fs
                .metadata(Path::new("dst/src/nested"))
                .unwrap()
                .file_type,
            FileType::Directory
        );

        let mut no_implied_fs = MemoryFileSystem::new();
        no_implied_fs
            .add_file("src/nested/file.txt", b"data")
            .unwrap();
        no_implied_fs.add_dir("dst/elsewhere").unwrap();
        no_implied_fs
            .add_symlink("dst/src/nested", "../elsewhere")
            .unwrap();

        sync_sources(
            &mut no_implied_fs,
            &[PathBuf::from("src/nested/file.txt")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                relative_paths: true,
                implied_dirs: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            no_implied_fs
                .metadata(Path::new("dst/src/nested"))
                .unwrap()
                .file_type,
            FileType::Symlink
        );
    }

    #[test]
    fn update_predicates_skip_newer_existing_and_size_excluded_files() {
        let older = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let newer = older + Duration::from_secs(60);
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/newer-on-dest.txt", b"sender").unwrap();
        fs.add_file("dst/newer-on-dest.txt", b"receiver").unwrap();
        fs.set_mtime(Path::new("src/newer-on-dest.txt"), older)
            .unwrap();
        fs.set_mtime(Path::new("dst/newer-on-dest.txt"), newer)
            .unwrap();
        fs.add_file("src/create-me.txt", b"new").unwrap();
        fs.add_file("src/existing.txt", b"sender").unwrap();
        fs.add_file("dst/existing.txt", b"receiver").unwrap();
        fs.add_file("src/too-large.bin", b"12345").unwrap();
        fs.add_file("src/too-small.bin", b"1").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                skip_newer_receiver: true,
                ignore_existing: true,
                max_size: Some(4),
                min_size: Some(2),
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.read_file(Path::new("dst/newer-on-dest.txt")).unwrap(),
            b"receiver"
        );
        assert_eq!(
            fs.read_file(Path::new("dst/existing.txt")).unwrap(),
            b"receiver"
        );
        assert_eq!(
            fs.read_file(Path::new("dst/create-me.txt")).unwrap(),
            b"new"
        );
        assert!(!fs.exists(Path::new("dst/too-large.bin")));
        assert!(!fs.exists(Path::new("dst/too-small.bin")));
    }

    #[test]
    fn one_file_system_skips_entries_on_other_boundaries() {
        let mut fs = BoundaryFileSystem::default();
        fs.inner.add_file("src/keep.txt", b"keep").unwrap();
        fs.inner.add_file("src/mounted/skip.txt", b"skip").unwrap();
        fs.other_file_system_roots
            .insert(PathBuf::from("src/mounted"));

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                one_file_system: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.inner.read_file(Path::new("dst/keep.txt")).unwrap(),
            b"keep"
        );
        assert!(!fs.inner.exists(Path::new("dst/mounted")));
    }

    #[test]
    fn modify_window_treats_close_mtimes_as_equal() {
        let source_mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let dest_mtime = source_mtime + Duration::from_secs(1);
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"same-size").unwrap();
        fs.add_file("dst/a.txt", b"old-bytes").unwrap();
        fs.set_mtime(Path::new("src/a.txt"), source_mtime).unwrap();
        fs.set_mtime(Path::new("dst/a.txt"), dest_mtime).unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                modify_window: 1,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs.read_file(Path::new("dst/a.txt")).unwrap(), b"old-bytes");
        assert!(!report
            .actions()
            .iter()
            .any(|action| matches!(action, SyncAction::WriteFile { .. })));
    }

    #[test]
    fn existing_skips_receiver_missing_files() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/create-me.txt", b"new").unwrap();
        fs.add_file("src/update-me.txt", b"new").unwrap();
        fs.add_file("dst/update-me.txt", b"old").unwrap();

        sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                existing_only: true,
                update_mode: UpdateMode::IgnoreTimes,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(!fs.exists(Path::new("dst/create-me.txt")));
        assert_eq!(
            fs.read_file(Path::new("dst/update-me.txt")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn missing_arg_options_ignore_or_delete_receiver_paths() {
        let mut ignore_fs = MemoryFileSystem::new();
        ignore_fs.add_file("src/present.txt", b"new").unwrap();
        ignore_fs.add_file("dst/missing.txt", b"old").unwrap();

        sync_sources(
            &mut ignore_fs,
            &[
                PathBuf::from("src/missing.txt"),
                PathBuf::from("src/present.txt"),
            ],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ignore_missing_args: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            ignore_fs.read_file(Path::new("dst/present.txt")).unwrap(),
            b"new"
        );
        assert_eq!(
            ignore_fs.read_file(Path::new("dst/missing.txt")).unwrap(),
            b"old"
        );

        let mut delete_fs = MemoryFileSystem::new();
        delete_fs.add_file("dst/missing.txt", b"old").unwrap();

        let report = sync_sources(
            &mut delete_fs,
            &[PathBuf::from("src/missing.txt")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_missing_args: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(!delete_fs.exists(Path::new("dst/missing.txt")));
        assert!(report
            .actions()
            .contains(&SyncAction::DeleteFile(PathBuf::from("dst/missing.txt"))));
    }

    #[test]
    fn delete_missing_args_requires_force_or_delete_for_nonempty_dirs() {
        let mut protected_fs = MemoryFileSystem::new();
        protected_fs
            .add_file("dst/missing/nested.txt", b"old")
            .unwrap();

        sync_sources(
            &mut protected_fs,
            &[PathBuf::from("src/missing")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_missing_args: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(protected_fs.exists(Path::new("dst/missing/nested.txt")));

        let mut force_fs = MemoryFileSystem::new();
        force_fs.add_file("dst/missing/nested.txt", b"old").unwrap();

        sync_sources(
            &mut force_fs,
            &[PathBuf::from("src/missing")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_missing_args: true,
                force_delete: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(!force_fs.exists(Path::new("dst/missing")));
    }

    #[test]
    fn force_delete_controls_nonempty_dir_replacement() {
        let mut protected_fs = MemoryFileSystem::new();
        protected_fs.add_file("src/conflict", b"new").unwrap();
        protected_fs
            .add_file("dst/conflict/nested.txt", b"old")
            .unwrap();

        let report = sync_sources(
            &mut protected_fs,
            &[PathBuf::from("src/conflict")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(report
            .actions()
            .contains(&SyncAction::ProtectDelete("dst/conflict".into())));
        assert!(protected_fs.exists(Path::new("dst/conflict/nested.txt")));

        let mut force_fs = MemoryFileSystem::new();
        force_fs.add_file("src/conflict", b"new").unwrap();
        force_fs
            .add_file("dst/conflict/nested.txt", b"old")
            .unwrap();

        sync_sources(
            &mut force_fs,
            &[PathBuf::from("src/conflict")],
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                force_delete: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            force_fs.read_file(Path::new("dst/conflict")).unwrap(),
            b"new"
        );
        assert!(!force_fs.exists(Path::new("dst/conflict/nested.txt")));
    }

    #[test]
    fn delete_modes_order_deletions_and_delete_excluded_controls_filter_protection() {
        let mut before_fs = MemoryFileSystem::new();
        before_fs.add_file("src/new.txt", b"new").unwrap();
        before_fs.add_file("dst/old.txt", b"old").unwrap();

        let before = sync_tree(
            &mut before_fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_mode: DeleteMode::Before,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert!(matches!(before.actions()[0], SyncAction::DeleteFile(_)));

        let mut after_fs = MemoryFileSystem::new();
        after_fs.add_file("src/new.txt", b"new").unwrap();
        after_fs.add_file("dst/old.txt", b"old").unwrap();
        let after = sync_tree(
            &mut after_fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_mode: DeleteMode::After,
                ..SyncOptions::default()
            },
        )
        .unwrap();
        assert!(matches!(
            after.actions().last().unwrap(),
            SyncAction::DeleteFile(_)
        ));

        let mut protected_fs = MemoryFileSystem::new();
        protected_fs.add_file("src/keep.txt", b"keep").unwrap();
        protected_fs.add_file("dst/cache.tmp", b"old").unwrap();
        sync_tree(
            &mut protected_fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_mode: DeleteMode::After,
                filter_rules: RuleSet::new(vec![Rule::exclude("*.tmp").unwrap()]),
                ..SyncOptions::default()
            },
        )
        .unwrap();
        assert!(protected_fs.exists(Path::new("dst/cache.tmp")));

        let mut delete_excluded_fs = MemoryFileSystem::new();
        delete_excluded_fs
            .add_file("src/keep.txt", b"keep")
            .unwrap();
        delete_excluded_fs
            .add_file("dst/cache.tmp", b"old")
            .unwrap();
        sync_tree(
            &mut delete_excluded_fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_mode: DeleteMode::After,
                delete_excluded: true,
                filter_rules: RuleSet::new(vec![Rule::exclude("*.tmp").unwrap()]),
                ..SyncOptions::default()
            },
        )
        .unwrap();
        assert!(!delete_excluded_fs.exists(Path::new("dst/cache.tmp")));
    }

    #[test]
    fn max_delete_stops_after_the_configured_limit() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/keep.txt", b"keep").unwrap();
        fs.add_file("dst/one.txt", b"1").unwrap();
        fs.add_file("dst/two.txt", b"2").unwrap();

        let err = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                delete_mode: DeleteMode::Before,
                max_delete: Some(1),
                ..SyncOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(err, FsError::MaxDeleteExceeded { limit: 1 }));
        let remaining = ["dst/one.txt", "dst/two.txt"]
            .into_iter()
            .filter(|path| fs.exists(Path::new(path)))
            .count();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn ignore_errors_still_applies_delete_after_when_transfer_fails() {
        let mut fs = FailingCopyFileSystem::new(PathBuf::from("src/fail.txt"));
        fs.inner.add_file("src/fail.txt", b"new").unwrap();
        fs.inner.add_file("dst/fail.txt", b"old").unwrap();
        fs.inner.add_file("dst/remove.txt", b"extra").unwrap();

        let err = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                update_mode: UpdateMode::IgnoreTimes,
                delete_mode: DeleteMode::After,
                ignore_errors: true,
                ..SyncOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(err, FsError::Unsupported("injected copy failure")));
        assert_eq!(
            fs.inner.read_file(Path::new("dst/fail.txt")).unwrap(),
            b"old"
        );
        assert!(!fs.inner.exists(Path::new("dst/remove.txt")));
    }

    #[test]
    fn backup_options_save_updated_and_deleted_receiver_files() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/update.txt", b"new").unwrap();
        fs.add_file("dst/update.txt", b"old").unwrap();
        fs.add_file("dst/remove.txt", b"gone").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                update_mode: UpdateMode::IgnoreTimes,
                delete_mode: DeleteMode::After,
                backup: true,
                backup_dir: Some(PathBuf::from("backups")),
                backup_suffix: ".bak".to_string(),
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.read_file(Path::new("dst/backups/update.txt.bak"))
                .unwrap(),
            b"old"
        );
        assert_eq!(
            fs.read_file(Path::new("dst/backups/remove.txt.bak"))
                .unwrap(),
            b"gone"
        );
        assert!(report.actions().iter().any(|action| matches!(
            action,
            SyncAction::BackupFile { from, to }
                if from == Path::new("dst/update.txt") && to == Path::new("dst/backups/update.txt.bak")
        )));
    }

    #[test]
    fn mkpath_controls_creation_of_missing_destination_parents() {
        let mut without_mkpath = MemoryFileSystem::new();
        without_mkpath.add_file("src/file.txt", b"data").unwrap();

        let err = sync_sources(
            &mut without_mkpath,
            &[PathBuf::from("src")],
            Path::new("missing/parent/dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(err, FsError::NotFound(path) if path == Path::new("missing/parent")));
        assert!(!without_mkpath.exists(Path::new("missing/parent/dst")));

        let mut with_mkpath = MemoryFileSystem::new();
        with_mkpath.add_file("src/file.txt", b"data").unwrap();
        sync_sources(
            &mut with_mkpath,
            &[PathBuf::from("src")],
            Path::new("missing/parent/dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                mkpath: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            with_mkpath
                .read_file(Path::new("missing/parent/dst/file.txt"))
                .unwrap(),
            b"data"
        );
    }

    #[test]
    fn delay_updates_keeps_receiver_files_unchanged_until_all_transfers_stage() {
        let mut fs = FailingCopyFileSystem::new(PathBuf::from("src/b.txt"));
        fs.inner.add_file("src/a.txt", b"new-a").unwrap();
        fs.inner.add_file("src/b.txt", b"new-b").unwrap();
        fs.inner.add_file("dst/a.txt", b"old-a").unwrap();
        fs.inner.add_file("dst/b.txt", b"old-b").unwrap();

        let err = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                update_mode: UpdateMode::IgnoreTimes,
                delay_updates: true,
                ..SyncOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(err, FsError::Unsupported("injected copy failure")));
        assert_eq!(
            fs.inner.read_file(Path::new("dst/a.txt")).unwrap(),
            b"old-a"
        );
        assert_eq!(
            fs.inner.read_file(Path::new("dst/b.txt")).unwrap(),
            b"old-b"
        );
        assert!(!fs.inner.exists(Path::new("dst/.~tmp~/a.txt")));
    }

    #[test]
    fn replaces_destination_file_with_source_directory() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/item/nested.txt", b"nested").unwrap();
        fs.add_file("dst/item", b"old-file").unwrap();

        let report = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                delete: true,
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(
            fs.read_file(Path::new("dst/item/nested.txt")).unwrap(),
            b"nested"
        );
        assert!(report
            .actions()
            .contains(&SyncAction::DeleteFile(PathBuf::from("dst/item"))));
    }

    #[test]
    fn refuses_destination_inside_source() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/a.txt", b"a").unwrap();

        let err = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("src/dst"),
            SyncOptions::default(),
        )
        .unwrap_err();

        assert!(matches!(err, FsError::DestinationInsideSource));
    }

    #[test]
    fn refuses_destination_inside_source_after_local_canonicalization() {
        let root = unique_temp_dir("rsync-fs-canonical-dest");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("a.txt"), b"a").unwrap();

        let source_operand = source.join("..").join("source");
        let dest_operand = fs::canonicalize(&source).unwrap().join("dest");

        let mut local = LocalFileSystem;
        let err = sync_tree(
            &mut local,
            &source_operand,
            &dest_operand,
            SyncOptions::default(),
        )
        .unwrap_err();

        assert!(matches!(err, FsError::DestinationInsideSource));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn destination_preflight_fails_before_mutating_sync() {
        let mut fs = MemoryFileSystem::new();
        fs.add_file("src/Foo.txt", b"upper").unwrap();
        fs.add_file("src/foo.txt", b"lower").unwrap();
        fs.add_file("dst/existing.txt", b"existing").unwrap();

        let err = sync_tree(
            &mut fs,
            Path::new("src"),
            Path::new("dst"),
            SyncOptions {
                dry_run: false,
                destination_path_preflight: Some(reject_casefold_collisions),
                ..SyncOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(err, FsError::DestinationPathPreflight(_)));
        assert!(!fs.exists(Path::new("dst/Foo.txt")));
        assert!(!fs.exists(Path::new("dst/foo.txt")));
        assert_eq!(
            fs.read_file(Path::new("dst/existing.txt")).unwrap(),
            b"existing"
        );
    }

    #[test]
    fn local_sync_uses_isolated_temp_roots_for_copy_delete_and_mtime() {
        let root = unique_temp_dir("rsync-fs-local-sync");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir_all(&dest).unwrap();
        fs::write(source.join("nested/file.txt"), b"new").unwrap();
        fs::write(dest.join("old.txt"), b"old").unwrap();

        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        filetime::set_file_mtime(
            source.join("nested/file.txt"),
            filetime::FileTime::from_system_time(modified),
        )
        .unwrap();

        let mut local = LocalFileSystem;
        let report = sync_tree(
            &mut local,
            &source,
            &dest,
            SyncOptions {
                delete: true,
                dry_run: false,
                preserve_mtime: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs::read(dest.join("nested/file.txt")).unwrap(), b"new");
        assert!(!dest.join("old.txt").exists());
        assert!(report
            .actions()
            .iter()
            .any(|action| matches!(action, SyncAction::PreserveMtime(path) if path.ends_with("nested/file.txt"))));

        let actual = fs::metadata(dest.join("nested/file.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(actual, modified);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_hardlink_preservation_replaces_existing_receiver_file() {
        let root = unique_temp_dir("rsync-fs-local-hardlinks");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&dest).unwrap();
        fs::write(source.join("original.txt"), b"same").unwrap();
        fs::hard_link(source.join("original.txt"), source.join("alias.txt")).unwrap();
        fs::write(dest.join("original.txt"), b"old-original").unwrap();
        fs::write(dest.join("alias.txt"), b"old-alias").unwrap();

        let mut local = LocalFileSystem;
        sync_tree(
            &mut local,
            &source,
            &dest,
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                update_mode: UpdateMode::IgnoreTimes,
                preserve_hard_links: true,
                ..SyncOptions::default()
            },
        )
        .unwrap();

        assert_eq!(fs::read(dest.join("original.txt")).unwrap(), b"same");
        assert_eq!(fs::read(dest.join("alias.txt")).unwrap(), b"same");
        let original = local.metadata(&dest.join("original.txt")).unwrap();
        let alias = local.metadata(&dest.join("alias.txt")).unwrap();
        assert_eq!(original.hardlink_id, alias.hardlink_id);
        assert!(original.hardlink_id.is_some());

        fs::remove_dir_all(root).unwrap();
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
        path
    }

    fn reject_nul_component(paths: &[PathBuf]) -> Result<(), FsError> {
        if paths.iter().any(|path| {
            path.components()
                .any(|component| matches!(component, Component::Normal(name) if name == "NUL"))
        }) {
            Err(FsError::DestinationPathPreflight(
                "reserved name".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn reject_casefold_collisions(paths: &[PathBuf]) -> Result<(), FsError> {
        let mut seen = BTreeMap::<String, PathBuf>::new();
        for path in paths {
            let key = path.to_string_lossy().to_lowercase();
            if let Some(first) = seen.get(&key) {
                return Err(FsError::DestinationPathPreflight(format!(
                    "collision between {} and {}",
                    first.display(),
                    path.display()
                )));
            }
            seen.insert(key, path.clone());
        }
        Ok(())
    }

    struct FailingCopyFileSystem {
        inner: MemoryFileSystem,
        fail_source: PathBuf,
    }

    impl FailingCopyFileSystem {
        fn new(fail_source: PathBuf) -> Self {
            Self {
                inner: MemoryFileSystem::new(),
                fail_source,
            }
        }
    }

    impl PortableFileSystem for FailingCopyFileSystem {
        fn metadata(&self, path: &Path) -> Result<PortableMetadata, FsError> {
            self.inner.metadata(path)
        }

        fn metadata_follow(&self, path: &Path) -> Result<PortableMetadata, FsError> {
            self.inner.metadata_follow(path)
        }

        fn resolve_path_for_prefix_check(&self, path: &Path) -> Result<PathBuf, FsError> {
            self.inner.resolve_path_for_prefix_check(path)
        }

        fn read_file(&self, path: &Path) -> Result<Vec<u8>, FsError> {
            self.inner.read_file(path)
        }

        fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            self.inner.write_file_atomic(path, bytes)
        }

        fn write_file_direct(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            self.inner.write_file_direct(path, bytes)
        }

        fn write_file_with_options(
            &mut self,
            path: &Path,
            bytes: &[u8],
            options: &FileWriteOptions,
        ) -> Result<(), FsError> {
            self.inner.write_file_with_options(path, bytes, options)
        }

        fn append_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            self.inner.append_file(path, bytes)
        }

        fn copy_file_with_options(
            &mut self,
            source: &Path,
            dest: &Path,
            options: &FileWriteOptions,
        ) -> Result<u64, FsError> {
            if source == self.fail_source {
                return Err(FsError::Unsupported("injected copy failure"));
            }
            self.inner.copy_file_with_options(source, dest, options)
        }

        fn append_file_from(
            &mut self,
            path: &Path,
            source: &Path,
            offset: u64,
        ) -> Result<u64, FsError> {
            self.inner.append_file_from(path, source, offset)
        }

        fn files_equal(&self, left: &Path, right: &Path) -> Result<bool, FsError> {
            self.inner.files_equal(left, right)
        }

        fn file_prefix_matches(&self, path: &Path, prefix: &Path) -> Result<bool, FsError> {
            self.inner.file_prefix_matches(path, prefix)
        }

        fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
            self.inner.create_dir_all(path)
        }

        fn remove_file(&mut self, path: &Path) -> Result<(), FsError> {
            self.inner.remove_file(path)
        }

        fn remove_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
            self.inner.remove_dir_all(path)
        }

        fn list(&self, path: &Path) -> Result<Vec<WalkEntry>, FsError> {
            self.inner.list(path)
        }

        fn set_mtime(&mut self, path: &Path, modified: SystemTime) -> Result<(), FsError> {
            self.inner.set_mtime(path, modified)
        }
    }

    #[derive(Default)]
    struct BoundaryFileSystem {
        inner: MemoryFileSystem,
        other_file_system_roots: BTreeSet<PathBuf>,
    }

    impl PortableFileSystem for BoundaryFileSystem {
        fn metadata(&self, path: &Path) -> Result<PortableMetadata, FsError> {
            self.inner.metadata(path)
        }

        fn metadata_follow(&self, path: &Path) -> Result<PortableMetadata, FsError> {
            self.inner.metadata_follow(path)
        }

        fn resolve_path_for_prefix_check(&self, path: &Path) -> Result<PathBuf, FsError> {
            self.inner.resolve_path_for_prefix_check(path)
        }

        fn read_file(&self, path: &Path) -> Result<Vec<u8>, FsError> {
            self.inner.read_file(path)
        }

        fn write_file_atomic(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            self.inner.write_file_atomic(path, bytes)
        }

        fn write_file_direct(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            self.inner.write_file_direct(path, bytes)
        }

        fn write_file_with_options(
            &mut self,
            path: &Path,
            bytes: &[u8],
            options: &FileWriteOptions,
        ) -> Result<(), FsError> {
            self.inner.write_file_with_options(path, bytes, options)
        }

        fn append_file(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
            self.inner.append_file(path, bytes)
        }

        fn copy_file_with_options(
            &mut self,
            source: &Path,
            dest: &Path,
            options: &FileWriteOptions,
        ) -> Result<u64, FsError> {
            self.inner.copy_file_with_options(source, dest, options)
        }

        fn append_file_from(
            &mut self,
            path: &Path,
            source: &Path,
            offset: u64,
        ) -> Result<u64, FsError> {
            self.inner.append_file_from(path, source, offset)
        }

        fn files_equal(&self, left: &Path, right: &Path) -> Result<bool, FsError> {
            self.inner.files_equal(left, right)
        }

        fn file_prefix_matches(&self, path: &Path, prefix: &Path) -> Result<bool, FsError> {
            self.inner.file_prefix_matches(path, prefix)
        }

        fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
            self.inner.create_dir_all(path)
        }

        fn remove_file(&mut self, path: &Path) -> Result<(), FsError> {
            self.inner.remove_file(path)
        }

        fn remove_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
            self.inner.remove_dir_all(path)
        }

        fn list(&self, path: &Path) -> Result<Vec<WalkEntry>, FsError> {
            self.inner.list(path)
        }

        fn set_mtime(&mut self, path: &Path, modified: SystemTime) -> Result<(), FsError> {
            self.inner.set_mtime(path, modified)
        }

        fn same_file_system(&self, root: &Path, path: &Path) -> Result<bool, FsError> {
            let root_is_other = self
                .other_file_system_roots
                .iter()
                .any(|other| root.starts_with(other));
            let path_is_other = self
                .other_file_system_roots
                .iter()
                .any(|other| path.starts_with(other));
            Ok(root_is_other == path_is_other)
        }
    }
}
