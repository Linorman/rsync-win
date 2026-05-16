use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use rsync_protocol::{
    write_rsync_index, write_u16_le, MultiplexedWriter, RsyncFileListEntry, RsyncIndexState,
    WireFileType, RSYNC_INDEX_DONE,
};

use super::receive::write_rsync31_index;
use crate::plan::check_transfer_deadline;
use crate::transfer::{
    local_basis_signature_request, write_remote_block_signatures, write_sum_head,
    RemoteFileChecksum, RSYNC31_MUX_FRAME_SIZE, RSYNC_ITEM_IS_NEW, RSYNC_ITEM_LOCAL_CHANGE,
    RSYNC_ITEM_TRANSFER,
};

pub(crate) struct RemoteSenderFileRequest<'a> {
    pub(crate) entries: &'a [RsyncFileListEntry],
    pub(crate) selected_indexes: &'a BTreeSet<usize>,
    pub(crate) index_offset: i32,
    pub(crate) dry_run: bool,
    pub(crate) dest: &'a Path,
    pub(crate) block_size: usize,
    pub(crate) whole_file: bool,
    pub(crate) checksum: RemoteFileChecksum,
    pub(crate) max_alloc: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
}

pub(crate) fn request_remote_sender_files_protocol31<T: Write>(
    transport: &mut T,
    request: RemoteSenderFileRequest<'_>,
) -> Result<()> {
    let RemoteSenderFileRequest {
        entries,
        selected_indexes,
        index_offset,
        dry_run,
        dest,
        block_size,
        whole_file,
        checksum,
        max_alloc,
        stop_deadline,
    } = request;
    let mut index_state = RsyncIndexState::default();
    let mut requested_indexes = BTreeSet::new();
    request_remote_sender_file_indexes_protocol31(
        transport,
        entries,
        selected_indexes,
        &mut requested_indexes,
        index_offset,
        dry_run,
        dest,
        block_size,
        whole_file,
        checksum,
        max_alloc,
        stop_deadline,
        &mut index_state,
    )?;
    write_rsync31_index(transport, &mut index_state, RSYNC_INDEX_DONE)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_sender_file_indexes_protocol31<T: Write>(
    transport: &mut T,
    entries: &[RsyncFileListEntry],
    selected_indexes: &BTreeSet<usize>,
    requested_indexes: &mut BTreeSet<usize>,
    index_offset: i32,
    dry_run: bool,
    dest: &Path,
    block_size: usize,
    whole_file: bool,
    checksum: RemoteFileChecksum,
    max_alloc: Option<u64>,
    stop_deadline: Option<Instant>,
    index_state: &mut RsyncIndexState,
) -> Result<usize> {
    let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
    let mut requests = 0_usize;
    for (index, entry) in entries.iter().enumerate() {
        check_transfer_deadline(stop_deadline)?;
        if entry.file_type != WireFileType::File || !selected_indexes.contains(&index) {
            continue;
        }
        if requested_indexes.contains(&index) {
            continue;
        }
        write_rsync_index(
            &mut writer,
            index_state,
            remote_wire_index(index, index_offset)?,
        )?;
        let iflags = if dry_run {
            RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE
        } else {
            RSYNC_ITEM_TRANSFER | RSYNC_ITEM_IS_NEW
        };
        write_u16_le(&mut writer, iflags)?;
        if !dry_run {
            let (sum_head, signatures) = local_basis_signature_request(
                &dest.join(&entry.path),
                block_size,
                checksum,
                whole_file,
                max_alloc,
            )?;
            write_sum_head(&mut writer, sum_head)?;
            write_remote_block_signatures(&mut writer, &signatures)?;
        }
        requested_indexes.insert(index);
        requests += 1;
    }
    writer.flush()?;
    Ok(requests)
}

fn remote_wire_index(index: usize, offset: i32) -> Result<i32> {
    let index = i32::try_from(index).context("remote file list index exceeded i32 range")?;
    index
        .checked_add(offset)
        .context("remote file list index overflow")
}
