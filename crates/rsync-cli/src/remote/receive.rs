use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rsync_filter::{EntryKind, RuleAction, RuleSet, RuleSide};
use rsync_fs::{
    walk_tree, FileType, FileWriteMode, FileWriteOptions, LocalFileSystem, PortableFileSystem,
    SyncAction, UpdateMode,
};
use rsync_protocol::{
    read_multiplexed_i32, read_rsync31_file_list_with_metadata, read_rsync_index, read_u16_le,
    read_varlong, write_rsync_index, MultiplexReadState, MultiplexedReader, MultiplexedWriter,
    RemoteSessionError, RsyncFileListEntry, RsyncFileListOptions, RsyncIndexState, WireFileType,
    DEFAULT_MAX_FILE_LIST_ENTRIES, DEFAULT_MAX_FILE_LIST_PATH_LEN, RSYNC_INDEX_DONE,
    RSYNC_INDEX_FLIST_EOF, RSYNC_INDEX_FLIST_OFFSET,
};

use crate::output::ProgressLog;
use crate::plan::*;
use crate::remote::flist::*;
use crate::transfer::*;

pub(crate) struct RemoteReceiveContext<'a> {
    pub(crate) fs: &'a mut LocalFileSystem,
    pub(crate) dest: &'a Path,
    pub(crate) entries: &'a [RsyncFileListEntry],
    pub(crate) index_offset: i32,
    pub(crate) final_checksum: RemoteFinalChecksum,
    pub(crate) dry_run: bool,
    pub(crate) progress: ProgressLog,
    pub(crate) preserve_times: bool,
    pub(crate) file_write_options: FileWriteOptions,
    pub(crate) append_verify: bool,
    pub(crate) compression: Option<&'a RemoteCompressionConfig>,
    pub(crate) max_alloc: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
    pub(crate) actions: &'a mut Vec<SyncAction>,
}

pub(crate) fn receive_remote_sender_files<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    mut ctx: RemoteReceiveContext<'_>,
) -> Result<RemoteExecutionStats> {
    let mut stats = RemoteExecutionStats::default();

    loop {
        check_transfer_deadline(ctx.stop_deadline)?;
        let index = read_multiplexed_i32(transport, mux)?;
        if index == -1 {
            break;
        }
        let entry_index = checked_remote_file_index(index, ctx.entries.len(), ctx.index_offset)?;
        let entry = &ctx.entries[entry_index];
        if entry.file_type != WireFileType::File {
            return Err(RemoteSessionError::NonFileBlockRequest { index: entry_index }.into());
        }
        let target = ctx.dest.join(&entry.path);

        if ctx.dry_run {
            let len = sync_action_len(entry.len)?;
            ctx.actions.push(remote_write_action(&target, len, &ctx));
            stats.files += 1;
            stats.bytes += entry.len;
            continue;
        }

        let _block_count = read_nonnegative_multiplexed_i32(transport, mux, "block count")?;
        let _block_len = read_nonnegative_multiplexed_i32(transport, mux, "block length")?;
        let _checksum_len = read_nonnegative_multiplexed_i32(transport, mux, "checksum length")?;
        let _remainder = read_nonnegative_multiplexed_i32(transport, mux, "remainder length")?;
        let sum_head = RemoteSumHead {
            block_count: _block_count,
            block_len: _block_len,
            checksum_len: _checksum_len,
            remainder: _remainder,
        };

        let temp_path = receive_temp_path(&target);
        let mut file_progress =
            FileProgress::start(ctx.progress, "download", &entry.path, Some(entry.len));
        let bytes = match read_file_tokens_to_path_with_basis(
            transport,
            mux,
            ctx.final_checksum,
            &entry.path,
            &temp_path,
            entry.len,
            Some((&target, sum_head)),
            ctx.compression,
            Some(&mut file_progress),
            ctx.max_alloc,
            ctx.stop_deadline,
        ) {
            Ok(bytes) => {
                file_progress.finish();
                bytes
            }
            Err(err) => {
                remove_local_file_best_effort(&temp_path);
                return Err(err);
            }
        };
        let write_result =
            write_received_file_from_path(&mut ctx, entry, &target, &temp_path, bytes);
        remove_local_file_best_effort(&temp_path);
        write_result?;
        stats.files += 1;
        stats.bytes += bytes;
    }

    Ok(stats)
}

pub(crate) fn receive_remote_sender_files_protocol31<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    mut ctx: RemoteReceiveContext<'_>,
) -> Result<RemoteExecutionStats> {
    let mut read_index_state = RsyncIndexState::default();
    let mut stats = RemoteExecutionStats::default();

    loop {
        check_transfer_deadline(ctx.stop_deadline)?;
        let response = read_protocol31_sender_response(
            transport,
            mux,
            &mut read_index_state,
            ctx.entries,
            false,
            RsyncFileListOptions::default(),
        )?;
        let Protocol31SenderResponse::File {
            index,
            iflags,
            sum_head,
        } = response
        else {
            break;
        };
        let entry_index = checked_remote_file_index(index, ctx.entries.len(), ctx.index_offset)?;
        apply_remote_sender_file_response_protocol31(
            transport,
            mux,
            entry_index,
            iflags,
            sum_head,
            &mut ctx,
            &mut stats,
        )?;
    }

    Ok(stats)
}

pub(crate) enum Protocol31SenderResponse {
    Done,
    FileListEof,
    ExtraFileList {
        entries: Vec<RsyncFileListEntry>,
    },
    File {
        index: i32,
        iflags: u16,
        sum_head: Option<RemoteSumHead>,
    },
}

pub(crate) fn read_protocol31_sender_response<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    read_index_state: &mut RsyncIndexState,
    entries: &[RsyncFileListEntry],
    allow_incremental_flist: bool,
    file_list_options: RsyncFileListOptions,
) -> Result<Protocol31SenderResponse> {
    let mut reader = MultiplexedReader::new(transport, mux);
    let index = read_rsync_index(&mut reader, read_index_state)?;
    if index == RSYNC_INDEX_DONE {
        return Ok(Protocol31SenderResponse::Done);
    }
    if index == RSYNC_INDEX_FLIST_EOF {
        if allow_incremental_flist {
            return Ok(Protocol31SenderResponse::FileListEof);
        }
        return Err(RemoteSessionError::InvalidFileIndex {
            index,
            file_count: entries.len(),
        }
        .into());
    }
    if index <= RSYNC_INDEX_FLIST_OFFSET {
        if !allow_incremental_flist {
            return Err(RemoteSessionError::InvalidFileIndex {
                index,
                file_count: entries.len(),
            }
            .into());
        }
        incremental_parent_index(index, entries)?;
        let entries = read_rsync31_file_list_with_metadata(
            &mut reader,
            DEFAULT_MAX_FILE_LIST_ENTRIES,
            DEFAULT_MAX_FILE_LIST_PATH_LEN,
            file_list_options,
        )?;
        return Ok(Protocol31SenderResponse::ExtraFileList { entries });
    }

    let iflags = read_u16_le(&mut reader)?;
    let _attrs = read_rsync31_optional_item_attrs(&mut reader, iflags)?;
    let sum_head = if iflags & RSYNC_ITEM_TRANSFER != 0 {
        Some(read_sum_head(&mut reader)?)
    } else {
        None
    };
    Ok(Protocol31SenderResponse::File {
        index,
        iflags,
        sum_head,
    })
}

fn incremental_parent_index(index: i32, entries: &[RsyncFileListEntry]) -> Result<usize> {
    let parent_index = RSYNC_INDEX_FLIST_OFFSET
        .checked_sub(index)
        .context("incremental file-list marker overflowed")?;
    if parent_index < 0 {
        bail!("remote sent invalid incremental file-list marker {index}");
    }
    let parent_index = parent_index as usize;
    let Some(parent) = entries.get(parent_index) else {
        bail!(
            "remote sent incremental file-list for parent index {parent_index}, but file list has {} entries",
            entries.len()
        );
    };
    if parent.file_type != WireFileType::Directory {
        bail!(
            "remote sent incremental file-list for non-directory parent `{}`",
            parent.path.display()
        );
    }
    Ok(parent_index)
}

pub(crate) fn apply_remote_sender_file_response_protocol31<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    entry_index: usize,
    iflags: u16,
    sum_head: Option<RemoteSumHead>,
    ctx: &mut RemoteReceiveContext<'_>,
    stats: &mut RemoteExecutionStats,
) -> Result<()> {
    let entry = &ctx.entries[entry_index];
    if entry.file_type != WireFileType::File {
        if iflags & RSYNC_ITEM_TRANSFER != 0 {
            return Err(RemoteSessionError::NonFileBlockRequest { index: entry_index }.into());
        }
        return Ok(());
    }
    let target = ctx.dest.join(&entry.path);

    if iflags & RSYNC_ITEM_TRANSFER == 0 || ctx.dry_run {
        let len = sync_action_len(entry.len)?;
        ctx.actions.push(remote_write_action(&target, len, ctx));
        stats.files += 1;
        stats.bytes += entry.len;
        return Ok(());
    }

    let temp_path = receive_temp_path(&target);
    let mut file_progress =
        FileProgress::start(ctx.progress, "download", &entry.path, Some(entry.len));
    let bytes = match read_file_tokens_to_path_with_basis(
        transport,
        mux,
        ctx.final_checksum,
        &entry.path,
        &temp_path,
        entry.len,
        sum_head.map(|sum_head| (target.as_path(), sum_head)),
        ctx.compression,
        Some(&mut file_progress),
        ctx.max_alloc,
        ctx.stop_deadline,
    ) {
        Ok(bytes) => {
            file_progress.finish();
            bytes
        }
        Err(err) => {
            remove_local_file_best_effort(&temp_path);
            return Err(err);
        }
    };
    let write_result = write_received_file_from_path(ctx, entry, &target, &temp_path, bytes);
    remove_local_file_best_effort(&temp_path);
    write_result?;
    stats.files += 1;
    stats.bytes += bytes;
    Ok(())
}

fn remote_write_action(target: &Path, len: usize, ctx: &RemoteReceiveContext<'_>) -> SyncAction {
    match ctx.file_write_options.mode {
        FileWriteMode::Atomic => SyncAction::WriteFile {
            path: target.to_path_buf(),
            len,
        },
        FileWriteMode::InPlace => SyncAction::WriteFileInPlace {
            path: target.to_path_buf(),
            len,
        },
    }
}

fn write_received_file_from_path(
    ctx: &mut RemoteReceiveContext<'_>,
    entry: &RsyncFileListEntry,
    target: &Path,
    source_path: &Path,
    source_len: u64,
) -> Result<()> {
    if ctx.append_verify {
        if let Some(offset) = append_verify_offset_local(ctx.fs, source_path, target, source_len)? {
            let suffix_len = source_len - offset;
            if suffix_len > 0 {
                ctx.actions.push(SyncAction::AppendFile {
                    path: target.to_path_buf(),
                    len: sync_action_len(suffix_len)?,
                });
                ctx.fs.append_file_from(target, source_path, offset)?;
            }
            preserve_remote_mtime(ctx, entry, target)?;
            return Ok(());
        }
    }

    ctx.actions.push(remote_write_action(
        target,
        sync_action_len(source_len)?,
        ctx,
    ));
    let mut final_write_options = ctx.file_write_options.clone();
    final_write_options.keep_partial = false;
    final_write_options.partial_dir = None;
    final_write_options.temp_dir = None;
    ctx.fs
        .copy_file_with_options(source_path, target, &final_write_options)?;
    preserve_remote_mtime(ctx, entry, target)
}

fn append_verify_offset_local(
    fs: &LocalFileSystem,
    source: &Path,
    target: &Path,
    source_len: u64,
) -> Result<Option<u64>> {
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

fn preserve_remote_mtime(
    ctx: &mut RemoteReceiveContext<'_>,
    entry: &RsyncFileListEntry,
    target: &Path,
) -> Result<()> {
    if !ctx.preserve_times {
        return Ok(());
    }
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(entry.mtime_unix.max(0) as u64);
    ctx.fs.set_mtime(target, modified)?;
    ctx.actions
        .push(SyncAction::PreserveMtime(target.to_path_buf()));
    Ok(())
}

pub(crate) fn delete_local_extras(
    fs: &mut LocalFileSystem,
    dest: &Path,
    entries: &[RsyncFileListEntry],
    filter_rules: &RuleSet,
    files_from: Option<&[PathBuf]>,
    dry_run: bool,
    actions: &mut Vec<SyncAction>,
) -> Result<()> {
    if !fs.exists(dest) {
        return Ok(());
    }

    let keep: BTreeSet<_> = entries
        .iter()
        .filter(|entry| !remote_entry_is_top_dir(entry))
        .map(|entry| entry.path.clone())
        .collect();
    let mut existing = walk_tree(fs, dest)?;
    existing.sort_by(|left, right| {
        right
            .path
            .components()
            .count()
            .cmp(&left.path.components().count())
            .then_with(|| right.path.cmp(&left.path))
    });

    for entry in existing {
        let relative = entry
            .path
            .strip_prefix(dest)
            .with_context(|| format!("destination entry escaped root: {}", entry.path.display()))?
            .to_path_buf();
        if files_from.is_some_and(|files_from| !files_from_matches(&relative, files_from))
            || delete_is_protected(filter_rules, &relative, entry.metadata.file_type)
        {
            actions.push(SyncAction::ProtectDelete(entry.path.clone()));
            continue;
        }
        if keep.contains(&relative) {
            continue;
        }
        match entry.metadata.file_type {
            FileType::Directory => {
                actions.push(SyncAction::DeleteDir(entry.path.clone()));
                if !dry_run {
                    fs.remove_dir_all(&entry.path)?;
                }
            }
            _ => {
                actions.push(SyncAction::DeleteFile(entry.path.clone()));
                if !dry_run {
                    fs.remove_file(&entry.path)?;
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn remote_entry_is_top_dir(entry: &RsyncFileListEntry) -> bool {
    entry.file_type == WireFileType::Directory && entry.path == Path::new(".")
}

pub(crate) fn sort_remote_entries_for_sender_indexes(entries: &mut [RsyncFileListEntry]) {
    let directories: BTreeSet<PathBuf> = entries
        .iter()
        .filter(|entry| entry.file_type == WireFileType::Directory)
        .map(|entry| entry.path.clone())
        .collect();

    entries.sort_by(|left, right| remote_sender_entry_cmp(left, right, &directories));
}

pub(crate) fn sort_remote_source_entries_for_sender_indexes(entries: &mut [RemoteSourceEntry]) {
    let directories: BTreeSet<PathBuf> = entries
        .iter()
        .filter(|entry| entry.wire.file_type == WireFileType::Directory)
        .map(|entry| entry.wire.path.clone())
        .collect();

    entries.sort_by(|left, right| remote_sender_entry_cmp(&left.wire, &right.wire, &directories));
}

fn remote_sender_entry_cmp(
    left: &RsyncFileListEntry,
    right: &RsyncFileListEntry,
    directories: &BTreeSet<PathBuf>,
) -> Ordering {
    if left.path == right.path {
        return Ordering::Equal;
    }
    if remote_entry_is_top_dir(left) {
        return Ordering::Less;
    }
    if remote_entry_is_top_dir(right) {
        return Ordering::Greater;
    }

    let left_components = normal_path_components(&left.path);
    let right_components = normal_path_components(&right.path);
    let shared = left_components.len().min(right_components.len());

    for index in 0..shared {
        let left_component = &left_components[index];
        let right_component = &right_components[index];
        if left_component == right_component {
            continue;
        }

        let left_prefix = path_from_components(&left_components[..=index]);
        let right_prefix = path_from_components(&right_components[..=index]);
        let left_is_directory = directories.contains(&left_prefix);
        let right_is_directory = directories.contains(&right_prefix);
        match (left_is_directory, right_is_directory) {
            (false, true) => return Ordering::Less,
            (true, false) => return Ordering::Greater,
            _ => return left_component.cmp(right_component),
        }
    }

    left_components.len().cmp(&right_components.len())
}

fn normal_path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn path_from_components(components: &[String]) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    path
}

pub(crate) fn selected_remote_entry_indexes(
    entries: &[RsyncFileListEntry],
    filter_rules: &RuleSet,
    files_from: Option<&[PathBuf]>,
) -> BTreeSet<usize> {
    entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            if remote_entry_is_top_dir(entry)
                || (!remote_source_path_is_filtered(filter_rules, &entry.path, entry.file_type)
                    && files_from.map_or(true, |files_from| {
                        files_from_matches(&entry.path, files_from)
                    }))
            {
                Some(index)
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn selected_remote_entries(
    entries: &[RsyncFileListEntry],
    selected_indexes: &BTreeSet<usize>,
) -> Vec<RsyncFileListEntry> {
    entries
        .iter()
        .enumerate()
        .filter(|(index, _)| selected_indexes.contains(index))
        .map(|(_, entry)| entry.clone())
        .collect()
}

pub(crate) fn selected_remote_transfer_indexes(
    fs: &LocalFileSystem,
    dest: &Path,
    entries: &[RsyncFileListEntry],
    selected_indexes: &BTreeSet<usize>,
    update_mode: UpdateMode,
) -> Result<BTreeSet<usize>> {
    let mut transfer_indexes = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        if !selected_indexes.contains(&index) {
            continue;
        }
        if entry.file_type != WireFileType::File {
            transfer_indexes.insert(index);
            continue;
        }
        if remote_file_needs_update(fs, dest, entry, update_mode)? {
            transfer_indexes.insert(index);
        }
    }
    Ok(transfer_indexes)
}

fn remote_file_needs_update(
    fs: &LocalFileSystem,
    dest: &Path,
    entry: &RsyncFileListEntry,
    update_mode: UpdateMode,
) -> Result<bool> {
    let target = dest.join(&entry.path);
    let Ok(target_metadata) = fs.metadata(&target) else {
        return Ok(true);
    };
    if target_metadata.file_type != FileType::File {
        return Ok(true);
    }

    match update_mode {
        UpdateMode::IgnoreTimes => Ok(true),
        UpdateMode::SizeOnly => Ok(entry.len != target_metadata.len),
        UpdateMode::QuickCheck => {
            let remote_mtime = remote_entry_mtime(entry);
            Ok(entry.len != target_metadata.len
                || match remote_mtime.zip(target_metadata.modified) {
                    Some((remote_mtime, target_mtime)) => remote_mtime != target_mtime,
                    None => true,
                })
        }
        UpdateMode::Checksum => {
            let Some(remote_checksum) = entry.checksum else {
                return Ok(true);
            };
            Ok(checksum_local_path(&target)? != remote_checksum)
        }
    }
}

fn remote_entry_mtime(entry: &RsyncFileListEntry) -> Option<SystemTime> {
    (entry.mtime_unix >= 0)
        .then(|| UNIX_EPOCH + std::time::Duration::from_secs(entry.mtime_unix as u64))
}

pub(crate) fn remote_file_index_offset(entries: &[RsyncFileListEntry]) -> i32 {
    let _ = entries;
    0
}

pub(super) fn remote_source_path_is_filtered(
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

pub(super) fn remote_receiver_path_is_filtered(
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
                .decide_for_side(&filter_path(&current), kind, RuleSide::Receiver)
                .action(),
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
            entry_kind_from_fs(file_type)
        };
        if matches!(
            rules
                .decide_for_side(&filter_path(&current), kind, RuleSide::Receiver)
                .action(),
            RuleAction::Exclude | RuleAction::Protect
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

fn entry_kind_from_fs(file_type: FileType) -> EntryKind {
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
pub(crate) fn read_multiplexed_rsync31_index<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
) -> Result<i32> {
    let mut reader = MultiplexedReader::new(transport, mux);
    let mut state = RsyncIndexState::default();
    Ok(read_rsync_index(&mut reader, &mut state)?)
}

pub(crate) fn write_rsync31_done<T: Write>(transport: &mut T) -> Result<()> {
    let mut state = RsyncIndexState::default();
    write_rsync31_index(transport, &mut state, RSYNC_INDEX_DONE)
}

pub(crate) fn write_rsync31_index<T: Write>(
    transport: &mut T,
    state: &mut RsyncIndexState,
    index: i32,
) -> Result<()> {
    let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
    write_rsync_index(&mut writer, state, index)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn checked_file_index(index: i32, file_count: usize) -> Result<usize> {
    if index < 0 || index as usize >= file_count {
        return Err(RemoteSessionError::InvalidFileIndex { index, file_count }.into());
    }
    Ok(index as usize)
}

pub(crate) fn checked_remote_file_index(
    index: i32,
    file_count: usize,
    offset: i32,
) -> Result<usize> {
    let local_index = index
        .checked_sub(offset)
        .ok_or(RemoteSessionError::InvalidFileIndex { index, file_count })?;
    checked_file_index(local_index, file_count)
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

pub(crate) fn read_remote_sender_protocol31_stats<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
) -> Result<()> {
    let mut reader = MultiplexedReader::new(transport, mux);
    for _ in 0..5 {
        let _value = read_varlong(&mut reader, 3)?;
    }
    Ok(())
}

pub(crate) fn system_time_to_unix_nanos(time: SystemTime) -> Option<i128> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    Some(i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos()))
}

pub(crate) fn append_remote_messages(output: &mut String, mux: &MultiplexReadState) {
    if mux.messages().is_empty() {
        return;
    }
    output.push_str("remote messages:\n");
    for message in mux.messages() {
        output.push_str("- ");
        output.push_str(message);
        output.push('\n');
    }
}
