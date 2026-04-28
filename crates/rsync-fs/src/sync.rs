use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use crate::metadata::{FileType, PortableMetadata};
use crate::walk::{FileWriteMode, FileWriteOptions, FsError, PortableFileSystem, WalkEntry};
use rsync_filter::{EntryKind, RuleAction, RuleSet};

pub type DestinationPathPreflight = fn(&[PathBuf]) -> Result<(), FsError>;

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub recursive: bool,
    pub delete: bool,
    pub preserve_mtime: bool,
    pub dry_run: bool,
    pub filter_rules: RuleSet,
    pub destination_path_preflight: Option<DestinationPathPreflight>,
    pub update_mode: UpdateMode,
    pub files_from: Option<Vec<PathBuf>>,
    pub file_write_mode: FileWriteMode,
    pub keep_partial: bool,
    pub partial_dir: Option<PathBuf>,
    pub append_verify: bool,
    pub symlink_mode: SymlinkMode,
}

#[derive(Debug, Clone, Copy)]
pub struct SourceSelectionOptions<'a> {
    pub recursive: bool,
    pub filter_rules: &'a RuleSet,
    pub files_from: Option<&'a [PathBuf]>,
    pub symlink_mode: SymlinkMode,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            delete: false,
            preserve_mtime: true,
            dry_run: true,
            filter_rules: RuleSet::empty(),
            destination_path_preflight: None,
            update_mode: UpdateMode::QuickCheck,
            files_from: None,
            file_write_mode: FileWriteMode::Atomic,
            keep_partial: false,
            partial_dir: None,
            append_verify: false,
            symlink_mode: SymlinkMode::Preserve,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkMode {
    Preserve,
    CopyAll,
    CopyUnsafe,
    SafeOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    CreateDir(PathBuf),
    WriteFile { path: PathBuf, len: usize },
    WriteFileInPlace { path: PathBuf, len: usize },
    AppendFile { path: PathBuf, len: usize },
    PreserveMtime(PathBuf),
    DeleteFile(PathBuf),
    DeleteDir(PathBuf),
    ProtectDelete(PathBuf),
    Warn { path: PathBuf, message: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    actions: Vec<SyncAction>,
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
    )?;
    if let Some(files_from) = &options.files_from {
        retain_files_from_entries(&mut source_entries, files_from);
    }
    if let Some(preflight) = options.destination_path_preflight {
        let destination_relatives: Vec<_> = source_entries.keys().cloned().collect();
        preflight(&destination_relatives)?;
    }

    let dest_entries = if fs.exists(dest) {
        relative_entries(fs, dest, None, options.recursive, SymlinkMode::Preserve)?
    } else {
        BTreeMap::new()
    };
    let mut report = SyncReport::default();

    if !fs.exists(dest) {
        report.push(SyncAction::CreateDir(dest.to_path_buf()));
        if !options.dry_run {
            fs.create_dir_all(dest)?;
        }
    }

    for (relative, entry) in &source_entries {
        let target = dest.join(relative);
        match entry.metadata.file_type {
            FileType::Directory => {
                if !options.recursive {
                    report.push(SyncAction::Warn {
                        path: entry.path.clone(),
                        message: "skipping directory because recursive mode is disabled"
                            .to_string(),
                    });
                    continue;
                }
                remove_conflicting_target(
                    fs,
                    &target,
                    FileType::Directory,
                    options.dry_run,
                    &mut report,
                )?;
                report.push(SyncAction::CreateDir(target.clone()));
                if !options.dry_run {
                    fs.create_dir_all(&target)?;
                }
            }
            FileType::File => {
                remove_conflicting_target(
                    fs,
                    &target,
                    FileType::File,
                    options.dry_run,
                    &mut report,
                )?;
                if !file_needs_update(fs, entry, &target, options.update_mode)? {
                    preserve_existing_file_mtime(fs, &target, entry, &options, &mut report)?;
                    continue;
                }
                transfer_file(fs, entry, &target, &options, &mut report)?;
            }
            FileType::Symlink | FileType::Hardlink | FileType::Other => {
                report.push(SyncAction::Warn {
                    path: entry.path.clone(),
                    message: format!(
                        "{:?} is not copied by portable ordinary-file sync",
                        entry.metadata.file_type
                    ),
                });
            }
        }
    }

    if options.delete {
        let source_relatives: BTreeSet<_> = source_entries.keys().cloned().collect();
        let mut delete_entries: Vec<_> = dest_entries
            .into_iter()
            .filter(|(relative, _)| !source_relatives.contains(relative))
            .collect();
        delete_entries.sort_by(|left, right| {
            right
                .0
                .components()
                .count()
                .cmp(&left.0.components().count())
                .then_with(|| right.0.cmp(&left.0))
        });

        for (_, entry) in delete_entries {
            if !fs.exists(&entry.path) {
                continue;
            }

            let relative = entry
                .path
                .strip_prefix(dest)
                .map_err(|_| FsError::InvalidPortablePath(entry.path.clone()))?;
            if options
                .files_from
                .as_ref()
                .is_some_and(|files_from| !files_from_matches(relative, files_from))
            {
                report.push(SyncAction::ProtectDelete(entry.path.clone()));
                continue;
            }
            if delete_is_protected(&options.filter_rules, relative, entry.metadata.file_type) {
                report.push(SyncAction::ProtectDelete(entry.path.clone()));
                continue;
            }

            match entry.metadata.file_type {
                FileType::Directory => {
                    report.push(SyncAction::DeleteDir(entry.path.clone()));
                    if !options.dry_run {
                        fs.remove_dir_all(&entry.path)?;
                    }
                }
                _ => {
                    report.push(SyncAction::DeleteFile(entry.path.clone()));
                    if !options.dry_run {
                        fs.remove_file(&entry.path)?;
                    }
                }
            }
        }
    }

    Ok(report)
}

pub fn sync_sources<F: PortableFileSystem>(
    fs: &mut F,
    sources: &[PathBuf],
    dest: &Path,
    options: SyncOptions,
) -> Result<SyncReport, FsError> {
    match sources {
        [] => Err(FsError::Unsupported("sync requires at least one source")),
        [source] => sync_tree(fs, source, dest, options),
        _ => sync_multiple_sources(fs, sources, dest, options),
    }
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
        let target = batch_target_path(source, dest)?;
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
    if !fs.exists(dest) {
        report.push(SyncAction::CreateDir(dest.to_path_buf()));
        if !options.dry_run {
            fs.create_dir_all(dest)?;
        }
    }

    for (source, target) in sources.iter().zip(targets) {
        let child = sync_tree(fs, source, &target, options.clone())?;
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
    if let Some(preflight) = options.destination_path_preflight {
        preflight(&[destination_preflight_path(&target)])?;
    }
    remove_conflicting_target(fs, &target, FileType::File, options.dry_run, &mut report)?;
    if !file_needs_update(fs, &entry, &target, options.update_mode)? {
        preserve_existing_file_mtime(fs, &target, &entry, options, &mut report)?;
        return Ok(report);
    }

    transfer_file(fs, &entry, &target, options, &mut report)?;

    Ok(report)
}

fn transfer_file<F: PortableFileSystem>(
    fs: &mut F,
    entry: &WalkEntry,
    target: &Path,
    options: &SyncOptions,
    report: &mut SyncReport,
) -> Result<(), FsError> {
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
        fs.copy_file_with_options(&entry.path, target, &file_write_options(options))?;
    }
    preserve_transferred_mtime(fs, target, entry, options, report)
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
    let Some(modified) = source.metadata.modified else {
        return Ok(());
    };
    report.push(SyncAction::PreserveMtime(target.to_path_buf()));
    if !options.dry_run {
        fs.set_mtime(target, modified)?;
    }
    Ok(())
}

fn file_needs_update<F: PortableFileSystem>(
    fs: &F,
    source: &WalkEntry,
    target: &Path,
    update_mode: UpdateMode,
) -> Result<bool, FsError> {
    let Ok(target_metadata) = fs.metadata(target) else {
        return Ok(true);
    };
    if target_metadata.file_type != FileType::File {
        return Ok(true);
    }

    match update_mode {
        UpdateMode::IgnoreTimes => Ok(true),
        UpdateMode::SizeOnly => Ok(source.metadata.len != target_metadata.len),
        UpdateMode::QuickCheck => Ok(source.metadata.len != target_metadata.len
            || match source.metadata.modified.zip(target_metadata.modified) {
                Some((source_mtime, target_mtime)) => source_mtime != target_mtime,
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
    Ok(
        relative_entries(fs, source, Some(filter_rules), true, SymlinkMode::Preserve)?
            .into_keys()
            .collect(),
    )
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
    )?;
    if let Some(files_from) = options.files_from {
        retain_files_from_entries(&mut entries, files_from);
    }

    paths.extend(entries.into_values().filter_map(|entry| {
        let selected = match entry.metadata.file_type {
            FileType::File => true,
            FileType::Directory => options.recursive,
            FileType::Symlink | FileType::Hardlink | FileType::Other => false,
        };
        selected.then_some(entry.path)
    }));
    Ok(paths)
}

fn remove_conflicting_target<F: PortableFileSystem>(
    fs: &mut F,
    target: &Path,
    source_type: FileType,
    dry_run: bool,
    report: &mut SyncReport,
) -> Result<(), FsError> {
    let Ok(target_metadata) = fs.metadata(target) else {
        return Ok(());
    };

    if target_metadata.file_type == source_type {
        return Ok(());
    }

    match target_metadata.file_type {
        FileType::Directory => {
            report.push(SyncAction::DeleteDir(target.to_path_buf()));
            if !dry_run {
                fs.remove_dir_all(target)?;
            }
        }
        _ => {
            report.push(SyncAction::DeleteFile(target.to_path_buf()));
            if !dry_run {
                fs.remove_file(target)?;
            }
        }
    }

    Ok(())
}

fn relative_entries<F: PortableFileSystem>(
    fs: &F,
    root: &Path,
    filter_rules: Option<&RuleSet>,
    recursive: bool,
    symlink_mode: SymlinkMode,
) -> Result<BTreeMap<PathBuf, WalkEntry>, FsError> {
    let mut entries = BTreeMap::new();
    collect_relative_entries(
        fs,
        root,
        Path::new(""),
        filter_rules,
        recursive,
        symlink_mode,
        &mut entries,
    )?;
    Ok(entries)
}

fn collect_relative_entries<F: PortableFileSystem>(
    fs: &F,
    current: &Path,
    relative_root: &Path,
    filter_rules: Option<&RuleSet>,
    recursive: bool,
    symlink_mode: SymlinkMode,
    entries: &mut BTreeMap<PathBuf, WalkEntry>,
) -> Result<(), FsError> {
    for original_entry in fs.list(current)? {
        let name = original_entry
            .path
            .file_name()
            .ok_or_else(|| FsError::InvalidPortablePath(original_entry.path.clone()))?;
        let relative = relative_root.join(name);
        let Some(entry) = apply_symlink_mode(fs, original_entry, symlink_mode)? else {
            continue;
        };
        if filter_rules.is_some_and(|rules| {
            sender_path_is_filtered(rules, &relative, entry.metadata.file_type)
        }) {
            continue;
        }
        let should_recurse = recursive && entry.metadata.file_type == FileType::Directory;
        let child_root = if should_recurse {
            Some(
                followed_directory_walk_path(&entry, symlink_mode)?
                    .unwrap_or_else(|| entry.path.clone()),
            )
        } else {
            None
        };
        let child_relative = relative.clone();
        entries.insert(relative, entry);
        if let Some(child_root) = child_root {
            collect_relative_entries(
                fs,
                &child_root,
                &child_relative,
                filter_rules,
                recursive,
                symlink_mode,
                entries,
            )?;
        }
    }
    Ok(())
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
        SymlinkMode::Preserve => Ok(Some(entry)),
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
        SymlinkMode::CopyAll => true,
        SymlinkMode::CopyUnsafe => is_unsafe_symlink_target(target),
        SymlinkMode::Preserve | SymlinkMode::SafeOnly => false,
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
            rules.decide(&filter_path(&current), kind).action(),
            RuleAction::Exclude | RuleAction::Protect
        ) {
            return true;
        }
    }

    false
}

fn delete_is_protected(rules: &RuleSet, relative: &Path, file_type: FileType) -> bool {
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
            rules.decide(&filter_path(&current), kind).action(),
            RuleAction::Exclude | RuleAction::Protect
        ) {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
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
}
