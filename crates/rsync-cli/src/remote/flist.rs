use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rsync_core::{ChmodFileKind, ChmodRules};
use rsync_filter::{
    normalize_files_from_records, parse_files_from_bytes, EntryKind, RuleAction, RuleSet, RuleSide,
};
use rsync_fs::{FileType, LocalFileSystem, PortableFileSystem, SymlinkMode, UpdateMode};
use rsync_protocol::{
    estimated_rsync_file_list_entry_alloc, read_multiplexed_i32, read_rsync_index, read_u16_le,
    rsync_plain_md4_checksum_reader, write_rsync_i32, write_rsync_index, write_rsync_long_value,
    write_u16_le, AllocationBudget, FileListBatch, MultiplexReadState, MultiplexedReader,
    MultiplexedWriter, RemoteSessionError, RsyncFileListEntry, RsyncFileListMetadata,
    RsyncFileListOptions, RsyncHardLinkGroup, RsyncIndexState, TransferDirection, WireFileType,
    RSYNC_DIRECTORY_MODE, RSYNC_INDEX_DONE,
};
use rsync_winfs::{read_windows_metadata, WindowsDriveKind};

use crate::cli::Cli;
use crate::output::ProgressLog;
use crate::plan::{check_transfer_deadline, TransferPlan};
use crate::remote::receive::{
    checked_file_index, read_multiplexed_rsync31_index, write_rsync31_done, write_rsync31_index,
};
use crate::transfer::{
    local_basis_signature_request, open_local_file, read_local_file,
    read_remote_block_signatures_from_reader, read_remote_block_signatures_multiplexed,
    read_rsync31_optional_item_attrs, read_sum_head, remote_sum_head_file_len,
    write_append_verify_file_tokens_from_path, write_delta_tokens_from_path,
    write_remote_block_signatures, write_rsync31_optional_item_attrs, write_sum_head,
    DeltaWriteRuntime, FileProgress, RemoteExecutionStats, RemoteFileChecksum, RemoteFinalChecksum,
    RemoteSumHead, RemoteTransferRuntime, REMOTE_FILE_LIST_BATCH_ENTRIES, RSYNC31_MUX_FRAME_SIZE,
    RSYNC_ITEM_TRANSFER,
};
#[derive(Debug, Clone)]
pub(crate) struct RemoteSourceEntry {
    pub(crate) wire: RsyncFileListEntry,
    pub(crate) local_path: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteSourceEntryBatch {
    base_index: usize,
    pub(crate) entries: Vec<RemoteSourceEntry>,
    is_final: bool,
}

impl RemoteSourceEntryBatch {
    pub(crate) fn file_list_batch(&self) -> FileListBatch {
        FileListBatch {
            base_index: self.base_index,
            entries: self
                .entries
                .iter()
                .map(|entry| entry.wire.clone())
                .collect(),
            is_final: self.is_final,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteSourceEntryBatchBuilder {
    max_entries: usize,
    max_alloc: Option<u64>,
    next_base_index: usize,
    current_entries: Vec<RemoteSourceEntry>,
    current_alloc: usize,
}

impl RemoteSourceEntryBatchBuilder {
    pub(crate) fn with_max_alloc(max_entries: usize, max_alloc: Option<u64>) -> Result<Self> {
        if max_entries == 0 {
            bail!("file-list batch size must be greater than zero");
        }

        Ok(Self {
            max_entries,
            max_alloc,
            next_base_index: 0,
            current_entries: Vec::with_capacity(max_entries.min(1024)),
            current_alloc: 0,
        })
    }

    pub(crate) fn push(
        &mut self,
        entry: RemoteSourceEntry,
    ) -> Result<Option<RemoteSourceEntryBatch>> {
        let entry_alloc = estimated_rsync_file_list_entry_alloc(&entry.wire);
        if self.should_flush_before(entry_alloc) {
            let batch = self.emit(false);
            self.push_current(entry, entry_alloc)?;
            return Ok(Some(batch));
        }

        self.push_current(entry, entry_alloc)?;
        if self.current_entries.len() >= self.max_entries {
            Ok(Some(self.emit(false)))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn finish(&mut self) -> RemoteSourceEntryBatch {
        self.emit(true)
    }

    pub(crate) fn should_flush_before(&self, entry_alloc: usize) -> bool {
        if self.current_entries.is_empty() {
            return false;
        }
        if self.current_entries.len() >= self.max_entries {
            return true;
        }
        if let Some(limit) = self.max_alloc.filter(|limit| *limit > 0) {
            return self.current_alloc.saturating_add(entry_alloc) as u64 > limit;
        }
        false
    }

    pub(crate) fn push_current(
        &mut self,
        entry: RemoteSourceEntry,
        entry_alloc: usize,
    ) -> Result<()> {
        AllocationBudget::new(self.max_alloc).check("file-list batch entry", entry_alloc)?;
        self.current_alloc = self.current_alloc.saturating_add(entry_alloc);
        self.current_entries.push(entry);
        Ok(())
    }

    pub(crate) fn emit(&mut self, is_final: bool) -> RemoteSourceEntryBatch {
        let entries = std::mem::take(&mut self.current_entries);
        let base_index = self.next_base_index;
        self.next_base_index += entries.len();
        self.current_alloc = 0;
        RemoteSourceEntryBatch {
            base_index,
            entries,
            is_final,
        }
    }
}

pub(crate) struct LocalSourceCollectContext<'a> {
    fs: &'a LocalFileSystem,
    options: &'a LocalSourceCollectOptions<'a>,
}

pub(crate) struct LocalSourceCollectOptions<'a> {
    pub(crate) recursive: bool,
    pub(crate) filter_rules: &'a RuleSet,
    pub(crate) files_from: Option<&'a [PathBuf]>,
    pub(crate) symlink_mode: SymlinkMode,
    pub(crate) include_checksums: bool,
    pub(crate) preserve_executability: bool,
    pub(crate) preserve_hard_links: bool,
    pub(crate) chmod_rules: Option<&'a ChmodRules>,
}

pub(crate) fn local_source_paths(cli: &Cli) -> Vec<PathBuf> {
    cli.paths[..cli.paths.len() - 1]
        .iter()
        .map(PathBuf::from)
        .collect()
}

pub(crate) fn append_sources_summary(output: &mut String, sources: &[PathBuf]) {
    if sources.len() == 1 {
        output.push_str(&format!("source: {}\n", sources[0].display()));
        return;
    }

    output.push_str(&format!("sources: {}\n", sources.len()));
    for source in sources {
        output.push_str(&format!("- source {}\n", source.display()));
    }
}

pub(crate) fn append_push_destination_summary(
    output: &mut String,
    plan: &TransferPlan,
) -> Result<()> {
    if let Some(daemon) = &plan.daemon_operand {
        let module = daemon
            .module
            .as_ref()
            .context("daemon push requires a module")?;
        let path = daemon
            .path
            .as_ref()
            .map(|path| format!("/{path}"))
            .unwrap_or_else(String::new);
        output.push_str(&format!("destination: {}::{module}{path}\n", daemon.host));
        return Ok(());
    }

    let remote = plan
        .remote_operand
        .as_ref()
        .context("remote operand was not planned")?;
    output.push_str(&format!("destination: {}:{}\n", remote.host, remote.path));
    Ok(())
}

pub(crate) fn append_pull_sources_summary(output: &mut String, plan: &TransferPlan) -> Result<()> {
    if let Some(daemon) = &plan.daemon_operand {
        let module = daemon
            .module
            .as_ref()
            .context("daemon pull requires a module")?;
        let path = daemon
            .path
            .as_ref()
            .map(|path| format!("/{path}"))
            .unwrap_or_else(String::new);
        output.push_str(&format!("source: {}::{module}{path}\n", daemon.host));
        return Ok(());
    }

    let fallback_remote = plan
        .remote_operand
        .as_ref()
        .context("remote operand was not planned")?;
    let sources = if plan.remote_operands.is_empty() {
        std::slice::from_ref(fallback_remote)
    } else {
        plan.remote_operands.as_slice()
    };

    if sources.len() == 1 {
        output.push_str(&format!(
            "source: {}:{}\n",
            sources[0].host, sources[0].path
        ));
        return Ok(());
    }

    output.push_str(&format!("sources: {}\n", sources.len()));
    for source in sources {
        output.push_str(&format!("- source {}:{}\n", source.host, source.path));
    }
    Ok(())
}

pub(crate) fn remote_session_label(plan: &TransferPlan, direction: TransferDirection) -> String {
    let Some(remote) = plan.remote_operand.as_ref() else {
        return "remote".to_string();
    };

    if direction == TransferDirection::Pull && plan.remote_operands.len() > 1 {
        return format!(
            "{} sources from {}",
            plan.remote_operands.len(),
            remote.host
        );
    }

    match direction {
        TransferDirection::Push => format!("to {}:{}", remote.host, remote.path),
        TransferDirection::Pull => format!("from {}:{}", remote.host, remote.path),
    }
}

pub(crate) fn remote_entries_file_summary(entries: &[RemoteSourceEntry]) -> (usize, u64) {
    entries
        .iter()
        .filter(|entry| entry.wire.file_type == WireFileType::File)
        .fold((0_usize, 0_u64), |(count, bytes), entry| {
            (count + 1, bytes + entry.wire.len)
        })
}

pub(crate) fn append_remote_push_quick_check_note(
    output: &mut String,
    plan: &TransferPlan,
    file_count: usize,
    total_file_bytes: u64,
    stats: &RemoteExecutionStats,
) {
    if plan.dry_run
        || plan.update_mode != UpdateMode::QuickCheck
        || file_count == 0
        || total_file_bytes == 0
        || stats.files != 0
        || stats.bytes != 0
    {
        return;
    }

    output.push_str(
        "transfer note: no file data was sent; remote quick-check treated the destination as up-to-date by size and mtime\n",
    );
    output.push_str(
        "hint: if the remote file may be corrupt, rerun with -c/--checksum or --ignore-times to force content verification or retransmission\n",
    );
}

pub(crate) fn log_source_storage_notes(progress: ProgressLog, sources: &[PathBuf]) {
    for note in source_storage_notes(sources) {
        progress.info(note);
    }
}

pub(crate) fn append_source_storage_notes(output: &mut String, sources: &[PathBuf]) {
    for note in source_storage_notes(sources) {
        output.push_str(&format!("{note}\n"));
    }
}

pub(crate) fn source_storage_notes(sources: &[PathBuf]) -> Vec<String> {
    sources
        .iter()
        .filter_map(|source| {
            if rsync_winfs::drive_kind_for_path(source) == Some(WindowsDriveKind::Remote) {
                Some(format!(
                    "source storage: {} is on a Windows network drive; rsync-win reads it while uploading",
                    source.display()
                ))
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn load_files_from(cli: &Cli) -> Result<Option<Vec<PathBuf>>> {
    let Some(path) = &cli.files_from else {
        return Ok(None);
    };

    let bytes = read_local_file(path)?;
    let records = parse_files_from_bytes(&bytes, cli.from0)?;
    let normalized = normalize_files_from_records(records)?;
    Ok(Some(normalized.into_iter().map(PathBuf::from).collect()))
}

pub(crate) fn local_source_collect_options<'a>(
    plan: &'a TransferPlan,
    files_from: Option<&'a [PathBuf]>,
) -> LocalSourceCollectOptions<'a> {
    LocalSourceCollectOptions {
        recursive: plan.recursive,
        filter_rules: &plan.filter_rules,
        files_from,
        symlink_mode: plan.symlink_mode,
        include_checksums: plan.update_mode == UpdateMode::Checksum,
        preserve_executability: plan.preserve_executability,
        preserve_hard_links: plan.hard_links,
        chmod_rules: plan.chmod_rules.as_ref(),
    }
}

pub(crate) fn rsync31_file_list_options_from_plan(
    plan: &TransferPlan,
    include_checksums: bool,
    include_metadata: bool,
    fake_super_uses_xattrs: bool,
) -> RsyncFileListOptions {
    if !include_metadata {
        return RsyncFileListOptions {
            include_checksums,
            ..RsyncFileListOptions::default()
        };
    }

    RsyncFileListOptions {
        include_checksums,
        preserve_owner: plan.preserve_owner,
        preserve_group: plan.preserve_group,
        numeric_ids: plan.numeric_ids,
        acls: plan.preserve_acls,
        xattrs: plan.preserve_xattrs || (fake_super_uses_xattrs && plan.fake_super),
        fake_super: plan.fake_super,
        atimes: plan.atimes,
        crtimes: plan.crtimes,
    }
}

pub(crate) fn collect_local_source_entries(
    sources: &[PathBuf],
    options: &LocalSourceCollectOptions<'_>,
) -> Result<Vec<RemoteSourceEntry>> {
    let mut entries = Vec::new();
    collect_local_source_entries_with_callback(sources, options, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    entries.sort_by(|left, right| left.wire.path.cmp(&right.wire.path));
    Ok(entries)
}

pub(crate) fn collect_local_source_entry_batches<F>(
    sources: &[PathBuf],
    options: &LocalSourceCollectOptions<'_>,
    max_entries: usize,
    max_alloc: Option<u64>,
    mut on_batch: F,
) -> Result<()>
where
    F: FnMut(RemoteSourceEntryBatch) -> Result<()>,
{
    let mut builder = RemoteSourceEntryBatchBuilder::with_max_alloc(max_entries, max_alloc)?;
    collect_local_source_entries_with_callback(sources, options, |entry| {
        if let Some(batch) = builder.push(entry)? {
            on_batch(batch)?;
        }
        Ok(())
    })?;
    on_batch(builder.finish())?;
    Ok(())
}

pub(crate) fn collect_local_push_source_entries_with_batches<F>(
    sources: &[PathBuf],
    options: &LocalSourceCollectOptions<'_>,
    max_alloc: Option<u64>,
    mut on_batch: F,
) -> Result<(Vec<RemoteSourceEntry>, usize)>
where
    F: FnMut(&FileListBatch) -> Result<()>,
{
    let mut entries = Vec::new();
    let mut batch_count = 0_usize;
    let mut total_alloc = 0_usize;
    collect_local_source_entry_batches(
        sources,
        options,
        REMOTE_FILE_LIST_BATCH_ENTRIES,
        max_alloc,
        |batch| {
            let wire_batch = batch.file_list_batch();
            for entry in &wire_batch.entries {
                total_alloc = total_alloc
                    .checked_add(estimated_rsync_file_list_entry_alloc(entry))
                    .context("file-list allocation estimate overflow")?;
                AllocationBudget::new(max_alloc).check("file-list entries", total_alloc)?;
            }
            on_batch(&wire_batch)?;
            entries.extend(batch.entries.iter().cloned());
            batch_count += 1;
            Ok(())
        },
    )?;
    Ok((entries, batch_count))
}

pub(crate) fn collect_local_source_entries_with_callback<F>(
    sources: &[PathBuf],
    options: &LocalSourceCollectOptions<'_>,
    mut on_entry: F,
) -> Result<()>
where
    F: FnMut(RemoteSourceEntry) -> Result<()>,
{
    if sources.len() == 1 {
        return collect_single_local_source_entries_with_callback(
            &sources[0],
            options,
            &mut on_entry,
        );
    }

    collect_batch_local_source_entries_with_callback(sources, options, &mut on_entry)
}

pub(crate) fn collect_single_local_source_entries_with_callback<F>(
    source: &Path,
    options: &LocalSourceCollectOptions<'_>,
    on_entry: &mut F,
) -> Result<()>
where
    F: FnMut(RemoteSourceEntry) -> Result<()>,
{
    let fs = LocalFileSystem;
    let source_metadata =
        remote_sender_metadata(&fs, source, fs.metadata(source)?, options.symlink_mode)?
            .context("source is skipped by link handling")?;

    if source_metadata.file_type == FileType::File {
        let file_name = source
            .file_name()
            .context("source file is missing a file name")?;
        let relative = PathBuf::from(file_name);
        if remote_source_path_is_filtered(options.filter_rules, &relative, WireFileType::File)
            || options
                .files_from
                .is_some_and(|files_from| !files_from_matches(&relative, files_from))
        {
            return Ok(());
        }
        on_entry(RemoteSourceEntry {
            wire: RsyncFileListEntry {
                path: relative.clone(),
                file_type: WireFileType::File,
                len: source_metadata.len,
                mtime_unix: system_time_to_unix(source_metadata.modified),
                mode: remote_wire_mode(
                    &source_metadata,
                    WireFileType::File,
                    &relative,
                    options.preserve_executability,
                    options.chmod_rules,
                ),
                checksum: options
                    .include_checksums
                    .then(|| checksum_local_path(source))
                    .transpose()?,
                hardlink_group: remote_hardlink_group(
                    &source_metadata,
                    options.preserve_hard_links,
                ),
                metadata: remote_file_list_metadata(source),
            },
            local_path: source.to_path_buf(),
        })?;
        return Ok(());
    }

    if source_metadata.file_type != FileType::Directory {
        bail!("remote-shell MVP only transfers ordinary files and directories");
    }

    on_entry(RemoteSourceEntry {
        wire: RsyncFileListEntry {
            path: PathBuf::from("."),
            file_type: WireFileType::Directory,
            len: 0,
            mtime_unix: system_time_to_unix(source_metadata.modified),
            mode: RSYNC_DIRECTORY_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: remote_file_list_metadata(source),
        },
        local_path: source.to_path_buf(),
    })?;

    collect_local_directory_source_entries_with_callback(
        &LocalSourceCollectContext { fs: &fs, options },
        source,
        Path::new(""),
        on_entry,
    )
}

pub(crate) fn collect_batch_local_source_entries_with_callback<F>(
    sources: &[PathBuf],
    options: &LocalSourceCollectOptions<'_>,
    on_entry: &mut F,
) -> Result<()>
where
    F: FnMut(RemoteSourceEntry) -> Result<()>,
{
    let fs = LocalFileSystem;
    for source in sources {
        let file_name = source
            .file_name()
            .with_context(|| format!("source has no file name: {}", source.display()))?;
        let relative = PathBuf::from(file_name);
        let original_metadata = fs.metadata(source)?;
        let Some(metadata) =
            remote_sender_metadata(&fs, source, original_metadata.clone(), options.symlink_mode)?
        else {
            continue;
        };

        let (file_type, mode) = match metadata.file_type {
            FileType::Directory => (
                WireFileType::Directory,
                remote_wire_mode(
                    &metadata,
                    WireFileType::Directory,
                    &relative,
                    options.preserve_executability,
                    options.chmod_rules,
                ),
            ),
            FileType::File => (
                WireFileType::File,
                remote_wire_mode(
                    &metadata,
                    WireFileType::File,
                    &relative,
                    options.preserve_executability,
                    options.chmod_rules,
                ),
            ),
            other => {
                bail!(
                    "remote-shell MVP does not transfer {:?}: {}",
                    other,
                    source.display()
                )
            }
        };

        if remote_source_path_is_filtered(options.filter_rules, &relative, file_type)
            || options
                .files_from
                .is_some_and(|files_from| !files_from_matches(&relative, files_from))
        {
            continue;
        }

        on_entry(RemoteSourceEntry {
            wire: RsyncFileListEntry {
                path: relative.clone(),
                file_type,
                len: if file_type == WireFileType::File {
                    metadata.len
                } else {
                    0
                },
                mtime_unix: system_time_to_unix(metadata.modified),
                mode,
                checksum: (options.include_checksums && file_type == WireFileType::File)
                    .then(|| checksum_local_path(source))
                    .transpose()?,
                hardlink_group: remote_hardlink_group(&metadata, options.preserve_hard_links),
                metadata: remote_file_list_metadata(source),
            },
            local_path: source.clone(),
        })?;

        if options.recursive && file_type == WireFileType::Directory {
            let child_root = remote_followed_directory_path(
                source,
                &original_metadata,
                &metadata,
                options.symlink_mode,
            )
            .unwrap_or_else(|| source.clone());
            collect_local_directory_source_entries_with_callback(
                &LocalSourceCollectContext { fs: &fs, options },
                &child_root,
                &relative,
                on_entry,
            )?;
        }
    }

    Ok(())
}

pub(crate) fn collect_local_directory_source_entries_with_callback<F>(
    ctx: &LocalSourceCollectContext<'_>,
    current: &Path,
    relative_root: &Path,
    on_entry: &mut F,
) -> Result<()>
where
    F: FnMut(RemoteSourceEntry) -> Result<()>,
{
    for entry in ctx.fs.list(current)? {
        let name = entry
            .path
            .file_name()
            .with_context(|| format!("source entry has no file name: {}", entry.path.display()))?;
        let relative = relative_root.join(name);

        let original_path = entry.path.clone();
        let original_metadata = entry.metadata.clone();
        let Some(metadata) = remote_sender_metadata(
            ctx.fs,
            &entry.path,
            entry.metadata,
            ctx.options.symlink_mode,
        )?
        else {
            continue;
        };

        let (file_type, mode) = match metadata.file_type {
            FileType::Directory => (
                WireFileType::Directory,
                remote_wire_mode(
                    &metadata,
                    WireFileType::Directory,
                    &relative,
                    ctx.options.preserve_executability,
                    ctx.options.chmod_rules,
                ),
            ),
            FileType::File => (
                WireFileType::File,
                remote_wire_mode(
                    &metadata,
                    WireFileType::File,
                    &relative,
                    ctx.options.preserve_executability,
                    ctx.options.chmod_rules,
                ),
            ),
            other => {
                bail!(
                    "remote-shell MVP does not transfer {:?}: {}",
                    other,
                    original_path.display()
                )
            }
        };

        if remote_source_path_is_filtered(ctx.options.filter_rules, &relative, file_type)
            || ctx
                .options
                .files_from
                .is_some_and(|files_from| !files_from_matches(&relative, files_from))
        {
            continue;
        }

        on_entry(RemoteSourceEntry {
            wire: RsyncFileListEntry {
                path: relative.clone(),
                file_type,
                len: if file_type == WireFileType::File {
                    metadata.len
                } else {
                    0
                },
                mtime_unix: system_time_to_unix(metadata.modified),
                mode,
                checksum: (ctx.options.include_checksums && file_type == WireFileType::File)
                    .then(|| checksum_local_path(&original_path))
                    .transpose()?,
                hardlink_group: remote_hardlink_group(&metadata, ctx.options.preserve_hard_links),
                metadata: remote_file_list_metadata(&original_path),
            },
            local_path: original_path.clone(),
        })?;
        if ctx.options.recursive && file_type == WireFileType::Directory {
            let child_root = remote_followed_directory_path(
                &original_path,
                &original_metadata,
                &metadata,
                ctx.options.symlink_mode,
            )
            .unwrap_or(original_path);
            collect_local_directory_source_entries_with_callback(
                ctx,
                &child_root,
                &relative,
                on_entry,
            )?;
        }
    }

    Ok(())
}

pub(crate) fn remote_wire_mode(
    metadata: &rsync_fs::PortableMetadata,
    file_type: WireFileType,
    path: &Path,
    preserve_executability: bool,
    chmod_rules: Option<&ChmodRules>,
) -> u32 {
    let mode = match file_type {
        WireFileType::File | WireFileType::Directory | WireFileType::Symlink => {
            metadata.posix_mode_for_path(Some(path), preserve_executability)
        }
    };
    match (chmod_rules, file_type) {
        (Some(rules), WireFileType::File) => rules.apply(mode, ChmodFileKind::File),
        (Some(rules), WireFileType::Directory) => rules.apply(mode, ChmodFileKind::Directory),
        _ => mode,
    }
}

pub(crate) fn remote_hardlink_group(
    metadata: &rsync_fs::PortableMetadata,
    preserve_hard_links: bool,
) -> Option<RsyncHardLinkGroup> {
    if !preserve_hard_links || metadata.file_type != FileType::File {
        return None;
    }
    if metadata.hardlink_count.unwrap_or(1) <= 1 {
        return None;
    }
    metadata.hardlink_id.map(|id| RsyncHardLinkGroup {
        device: id.volume,
        inode: id.file,
    })
}

pub(crate) fn remote_file_list_metadata(path: &Path) -> RsyncFileListMetadata {
    let std_metadata = fs::symlink_metadata(path).ok();
    let (uid, gid) = remote_metadata_ids(std_metadata.as_ref());
    let atime_unix = std_metadata
        .as_ref()
        .and_then(|metadata| metadata.accessed().ok())
        .and_then(system_time_to_unix_option);
    let crtime_unix = read_windows_metadata(path)
        .ok()
        .and_then(|metadata| metadata.creation_time)
        .or_else(|| {
            std_metadata
                .as_ref()
                .and_then(|metadata| metadata.created().ok())
        })
        .and_then(system_time_to_unix_option);

    RsyncFileListMetadata {
        uid,
        gid,
        user_name: None,
        group_name: None,
        atime_unix,
        crtime_unix,
        xattrs: Vec::new(),
    }
}

#[cfg(unix)]
pub(crate) fn remote_metadata_ids(metadata: Option<&fs::Metadata>) -> (Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;

    (
        metadata.map(|metadata| metadata.uid()),
        metadata.map(|metadata| metadata.gid()),
    )
}

#[cfg(not(unix))]
pub(crate) fn remote_metadata_ids(_metadata: Option<&fs::Metadata>) -> (Option<u32>, Option<u32>) {
    (None, None)
}

pub(crate) fn remote_sender_metadata(
    fs: &LocalFileSystem,
    path: &Path,
    metadata: rsync_fs::PortableMetadata,
    symlink_mode: SymlinkMode,
) -> Result<Option<rsync_fs::PortableMetadata>> {
    if metadata.file_type != FileType::Symlink {
        return Ok(Some(metadata));
    }

    match symlink_mode {
        SymlinkMode::Skip => Ok(None),
        SymlinkMode::Preserve => bail!(
            "remote-shell sender cannot preserve symlink metadata yet; use --copy-links for {}",
            path.display()
        ),
        SymlinkMode::SafeOnly => {
            if metadata
                .symlink_target
                .as_deref()
                .is_some_and(is_unsafe_symlink_target)
            {
                Ok(None)
            } else {
                bail!(
                    "remote-shell sender cannot preserve safe symlink metadata yet: {}",
                    path.display()
                )
            }
        }
        SymlinkMode::CopyAll => Ok(Some(followed_remote_sender_metadata(fs, path)?)),
        SymlinkMode::CopyDirLinks => {
            let copied = followed_remote_sender_metadata(fs, path)?;
            if copied.file_type == FileType::Directory {
                Ok(Some(copied))
            } else {
                bail!(
                    "remote-shell sender cannot preserve non-directory symlink metadata yet: {}",
                    path.display()
                )
            }
        }
        SymlinkMode::CopyUnsafe => {
            if metadata
                .symlink_target
                .as_deref()
                .is_some_and(is_unsafe_symlink_target)
            {
                Ok(Some(followed_remote_sender_metadata(fs, path)?))
            } else {
                bail!(
                    "remote-shell sender cannot preserve safe symlink metadata yet: {}",
                    path.display()
                )
            }
        }
        SymlinkMode::Munge => bail!(
            "remote-shell sender cannot munge symlink metadata yet: {}",
            path.display()
        ),
    }
}

pub(crate) fn followed_remote_sender_metadata(
    fs: &LocalFileSystem,
    path: &Path,
) -> Result<rsync_fs::PortableMetadata> {
    let metadata = fs.metadata_follow(path)?;
    if !matches!(metadata.file_type, FileType::File | FileType::Directory) {
        bail!(
            "remote-shell sender can only copy symlink referents that are ordinary files or directories: {}",
            path.display()
        );
    }
    Ok(metadata)
}

pub(crate) fn remote_followed_directory_path(
    link_path: &Path,
    original_metadata: &rsync_fs::PortableMetadata,
    copied_metadata: &rsync_fs::PortableMetadata,
    symlink_mode: SymlinkMode,
) -> Option<PathBuf> {
    if original_metadata.file_type != FileType::Symlink
        || copied_metadata.file_type != FileType::Directory
    {
        return None;
    }
    let target = original_metadata.symlink_target.as_deref()?;
    let should_follow = match symlink_mode {
        SymlinkMode::CopyAll | SymlinkMode::CopyDirLinks => true,
        SymlinkMode::CopyUnsafe => is_unsafe_symlink_target(target),
        SymlinkMode::Skip | SymlinkMode::Preserve | SymlinkMode::SafeOnly | SymlinkMode::Munge => {
            false
        }
    };
    should_follow.then(|| resolve_symlink_target(link_path, target))
}

pub(crate) fn resolve_symlink_target(link_path: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        link_path
            .parent()
            .map(|parent| parent.join(target))
            .unwrap_or_else(|| target.to_path_buf())
    }
}

pub(crate) fn is_unsafe_symlink_target(target: &Path) -> bool {
    target.is_absolute()
        || target
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
}

pub(crate) fn checksum_local_path(path: &Path) -> Result<[u8; 16]> {
    let mut file = open_local_file(path)?;
    rsync_plain_md4_checksum_reader(&mut file)
        .with_context(|| format!("failed to checksum {}", path.display()))
}

fn remote_wire_index(index: usize, offset: i32) -> Result<i32> {
    let index = i32::try_from(index).context("remote file list index exceeded i32 range")?;
    index
        .checked_add(offset)
        .context("remote file list index overflow")
}

fn remote_source_path_is_filtered(
    rules: &RuleSet,
    relative: &Path,
    file_type: WireFileType,
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
            entry_kind_from_wire(file_type)
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

fn files_from_matches(relative: &Path, files_from: &[PathBuf]) -> bool {
    files_from.iter().any(|selected| {
        relative == selected || relative.starts_with(selected) || selected.starts_with(relative)
    })
}

fn entry_kind_from_wire(file_type: WireFileType) -> EntryKind {
    if file_type == WireFileType::Directory {
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

fn read_nonnegative_multiplexed_i32<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    label: &str,
) -> Result<usize> {
    let value = read_multiplexed_i32(transport, mux)?;
    if value < 0 {
        bail!("remote sent negative {label}: {value}");
    }
    Ok(value as usize)
}

fn system_time_to_unix(value: Option<SystemTime>) -> i64 {
    value
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn system_time_to_unix_option(value: SystemTime) -> Option<i64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
}

pub(crate) fn serve_remote_receiver_requests<T: Read + Write>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    entries: &[RemoteSourceEntry],
    checksum_seed: i32,
    dry_run: bool,
    runtime: RemoteTransferRuntime<'_>,
) -> Result<RemoteExecutionStats> {
    let mut phase_markers = 0_usize;
    let mut stats = RemoteExecutionStats::default();

    loop {
        check_transfer_deadline(runtime.stop_deadline)?;
        let index = read_multiplexed_i32(transport, mux)?;
        if index == -1 {
            write_rsync_i32(transport, -1)?;
            transport.flush()?;
            phase_markers += 1;
            if phase_markers >= 2 {
                break;
            }
            continue;
        }

        let entry_index = checked_file_index(index, entries.len())?;
        let entry = &entries[entry_index];
        if entry.wire.file_type != WireFileType::File {
            return Err(RemoteSessionError::NonFileBlockRequest { index: entry_index }.into());
        }

        if dry_run {
            runtime.progress.detail(format!(
                "dry-run upload request for {}",
                entry.wire.path.display()
            ));
            write_rsync_i32(transport, index)?;
            stats.transferred_entry_indexes.push(entry_index);
            stats.files += 1;
            continue;
        }

        let block_count = read_nonnegative_multiplexed_i32(transport, mux, "block count")?;
        let block_len = read_nonnegative_multiplexed_i32(transport, mux, "block length")?;
        let checksum_len = read_nonnegative_multiplexed_i32(transport, mux, "checksum length")?;
        let remainder = read_nonnegative_multiplexed_i32(transport, mux, "remainder length")?;
        let sum_head = RemoteSumHead {
            block_count,
            block_len,
            checksum_len,
            remainder,
        };
        let signatures = read_remote_block_signatures_multiplexed(
            transport,
            mux,
            sum_head,
            RemoteFileChecksum::md4_with_seed(checksum_seed),
            runtime.max_alloc,
        )?;

        write_rsync_i32(transport, index)?;
        write_rsync_i32(transport, block_count as i32)?;
        write_rsync_i32(transport, block_len as i32)?;
        write_rsync_i32(transport, checksum_len as i32)?;
        write_rsync_i32(transport, remainder as i32)?;
        let mut file_progress = FileProgress::start(
            runtime.progress,
            "upload",
            &entry.wire.path,
            Some(entry.wire.len),
        );
        let delta_stats = write_delta_tokens_from_path(
            transport,
            RemoteFileChecksum::md4_with_seed(checksum_seed),
            RemoteFinalChecksum::protocol27(checksum_seed),
            &entry.local_path,
            &signatures,
            DeltaWriteRuntime {
                compression: runtime.compression,
                progress: Some(&mut file_progress),
                max_alloc: runtime.max_alloc,
                stop_deadline: runtime.stop_deadline,
            },
        )?;
        file_progress.finish();
        stats.transferred_entry_indexes.push(entry_index);
        stats.files += 1;
        stats.bytes += delta_stats.literal_bytes;
    }

    write_rsync_long_value(transport, 0)?;
    write_rsync_long_value(transport, stats.bytes)?;
    write_rsync_long_value(
        transport,
        entries
            .iter()
            .filter(|entry| entry.wire.file_type == WireFileType::File)
            .map(|entry| entry.wire.len)
            .sum(),
    )?;
    transport.flush()?;

    let final_ack = read_multiplexed_i32(transport, mux)?;
    if final_ack != -1 {
        return Err(RemoteSessionError::InvalidFinalAck(final_ack).into());
    }

    Ok(stats)
}

pub(crate) fn serve_remote_receiver_requests_protocol31<T: Read + Write>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    entries: &[RemoteSourceEntry],
    dry_run: bool,
    append_verify: bool,
    checksum: RemoteFileChecksum,
    runtime: RemoteTransferRuntime<'_>,
) -> Result<RemoteExecutionStats> {
    let mut read_index_state = RsyncIndexState::default();
    let mut write_index_state = RsyncIndexState::default();
    let mut phase_markers = 0_usize;
    let mut stats = RemoteExecutionStats::default();

    loop {
        check_transfer_deadline(runtime.stop_deadline)?;
        let request = {
            let mut reader = MultiplexedReader::new(transport, mux);
            let index = read_rsync_index(&mut reader, &mut read_index_state)?;
            if index == RSYNC_INDEX_DONE {
                None
            } else {
                let iflags = read_u16_le(&mut reader)?;
                let attrs = read_rsync31_optional_item_attrs(&mut reader, iflags)?;
                if iflags & RSYNC_ITEM_TRANSFER != 0 {
                    let sum_head = read_sum_head(&mut reader)?;
                    // Upstream append mode sends the append basis as a sum head only.
                    let signatures = if append_verify {
                        Vec::new()
                    } else {
                        read_remote_block_signatures_from_reader(
                            &mut reader,
                            sum_head,
                            checksum,
                            runtime.max_alloc,
                        )?
                    };
                    Some((index, iflags, attrs, Some(sum_head), signatures))
                } else {
                    Some((index, iflags, attrs, None, Vec::new()))
                }
            }
        };

        let Some((index, iflags, attrs, sum_head, signatures)) = request else {
            phase_markers += 1;
            if phase_markers > 2 {
                break;
            }
            write_rsync31_index(transport, &mut write_index_state, RSYNC_INDEX_DONE)?;
            continue;
        };

        let entry_index = checked_file_index(index, entries.len())?;
        let entry = &entries[entry_index];
        let wants_transfer = iflags & RSYNC_ITEM_TRANSFER != 0;
        if !wants_transfer {
            let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
            write_rsync_index(&mut writer, &mut write_index_state, index)?;
            write_u16_le(&mut writer, iflags)?;
            write_rsync31_optional_item_attrs(&mut writer, iflags, &attrs)?;
            writer.flush()?;
            continue;
        }
        if entry.wire.file_type != WireFileType::File {
            return Err(RemoteSessionError::NonFileBlockRequest { index: entry_index }.into());
        }
        if dry_run {
            runtime.progress.detail(format!(
                "dry-run upload request for {}",
                entry.wire.path.display()
            ));
            let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
            write_rsync_index(&mut writer, &mut write_index_state, index)?;
            write_u16_le(&mut writer, iflags)?;
            write_rsync31_optional_item_attrs(&mut writer, iflags, &attrs)?;
            writer.flush()?;
            continue;
        }

        let sum_head = sum_head.context("remote protocol 31 transfer request omitted sum head")?;
        let append_prefix_len = if append_verify {
            let prefix_len = remote_sum_head_file_len(sum_head)?;
            let file_len = entry.wire.len;
            if prefix_len as u64 > file_len {
                bail!(
                    "remote append basis is larger than sender file for {}",
                    entry.local_path.display()
                );
            }
            prefix_len
        } else {
            0
        };
        {
            let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
            write_rsync_index(&mut writer, &mut write_index_state, index)?;
            write_u16_le(&mut writer, iflags)?;
            write_rsync31_optional_item_attrs(&mut writer, iflags, &attrs)?;
            write_sum_head(&mut writer, sum_head)?;
            let total = if append_verify {
                entry.wire.len.saturating_sub(append_prefix_len as u64)
            } else {
                entry.wire.len
            };
            let operation = if append_verify {
                "upload append"
            } else {
                "upload"
            };
            let mut file_progress =
                FileProgress::start(runtime.progress, operation, &entry.wire.path, Some(total));
            let literal_bytes = if append_verify {
                write_append_verify_file_tokens_from_path(
                    &mut writer,
                    RemoteFinalChecksum::protocol31_for_algorithm(checksum.algorithm()),
                    &entry.local_path,
                    append_prefix_len,
                    runtime.compression,
                    Some(&mut file_progress),
                    runtime.stop_deadline,
                )?
            } else {
                write_delta_tokens_from_path(
                    &mut writer,
                    checksum,
                    RemoteFinalChecksum::protocol31_for_algorithm(checksum.algorithm()),
                    &entry.local_path,
                    &signatures,
                    DeltaWriteRuntime {
                        compression: runtime.compression,
                        progress: Some(&mut file_progress),
                        max_alloc: runtime.max_alloc,
                        stop_deadline: runtime.stop_deadline,
                    },
                )?
                .literal_bytes
            };
            writer.flush()?;
            file_progress.finish();
            stats.bytes += literal_bytes;
        }
        stats.transferred_entry_indexes.push(entry_index);
        stats.files += 1;
    }

    write_rsync31_index(transport, &mut write_index_state, RSYNC_INDEX_DONE)?;
    let first_goodbye = read_multiplexed_rsync31_index(transport, mux)?;
    if first_goodbye != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(first_goodbye).into());
    }
    write_rsync31_done(transport)?;
    let second_goodbye = read_multiplexed_rsync31_index(transport, mux)?;
    if second_goodbye != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(second_goodbye).into());
    }

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_sender_files<T: Write>(
    transport: &mut T,
    entries: &[RsyncFileListEntry],
    selected_indexes: &BTreeSet<usize>,
    index_offset: i32,
    dry_run: bool,
    dest: &Path,
    block_size: usize,
    whole_file: bool,
    checksum: RemoteFileChecksum,
    max_alloc: Option<u64>,
    stop_deadline: Option<Instant>,
) -> Result<()> {
    for (index, entry) in entries.iter().enumerate() {
        check_transfer_deadline(stop_deadline)?;
        if entry.file_type != WireFileType::File || !selected_indexes.contains(&index) {
            continue;
        }
        write_rsync_i32(transport, remote_wire_index(index, index_offset)?)?;
        if !dry_run {
            let (sum_head, signatures) = local_basis_signature_request(
                &dest.join(&entry.path),
                block_size,
                checksum,
                whole_file,
                max_alloc,
            )?;
            write_sum_head(transport, sum_head)?;
            write_remote_block_signatures(transport, &signatures)?;
        }
    }
    write_rsync_i32(transport, -1)?;
    Ok(())
}
