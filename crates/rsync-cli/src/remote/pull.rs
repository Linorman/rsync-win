use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rsync_fs::{LocalFileSystem, PortableFileSystem, SyncAction, UpdateMode};
use rsync_protocol::{
    check_rsync_file_list_budget, exchange_remote_shell_mvp_handshake,
    exchange_remote_shell_protocol31_handshake_with_options, read_multiplexed_i32,
    read_multiplexed_long, read_rsync27_file_list_with_options,
    read_rsync31_file_list_with_metadata, write_i32_le, write_rsync_i32, MultiplexReadState,
    MultiplexedReader, MultiplexedWriter, RemoteSessionError, RsyncFileListEntry, RsyncIndexState,
    WireFileType, DEFAULT_MAX_FILE_LIST_ENTRIES, DEFAULT_MAX_FILE_LIST_PATH_LEN, RSYNC_INDEX_DONE,
};

use crate::cli::Cli;
use crate::execute::remote_shell::protocol31_setup_error;
use crate::format::*;
use crate::plan::*;
use crate::remote::flist::*;
use crate::remote::receive::*;
use crate::transfer::*;
use crate::{output, ProgressLog};

pub(crate) fn execute_remote_pull<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    match plan
        .remote_wire_protocol
        .unwrap_or(RemoteWireProtocol::Modern31)
    {
        RemoteWireProtocol::Modern31 => execute_remote_pull_protocol31(cli, plan, transport),
        RemoteWireProtocol::Compat27 => execute_remote_pull_protocol27(cli, plan, transport),
    }
}

pub(crate) fn execute_remote_pull_protocol27<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
    let mut client_log = output::TransferLog::from_cli(cli)?;
    let handshake = exchange_remote_shell_mvp_handshake(transport)?;
    let mut mux = MultiplexReadState::default();

    write_rsync_i32(transport, 0)?;
    transport.flush()?;

    let mut entries = {
        let mut reader = MultiplexedReader::new(transport, &mut mux);
        read_rsync27_file_list_with_options(
            &mut reader,
            DEFAULT_MAX_FILE_LIST_ENTRIES,
            DEFAULT_MAX_FILE_LIST_PATH_LEN,
            plan.update_mode == UpdateMode::Checksum,
        )?
    };
    check_rsync_file_list_budget(&entries, plan.max_alloc)
        .context("remote file-list exceeds allocation budget")?;
    sort_remote_entries_for_sender_indexes(&mut entries);
    validate_remote_file_list_paths(&entries)?;
    let files_from = load_files_from(cli)?;
    validate_remote_sender_claims(plan, &entries, files_from.as_deref())?;
    let selected_indexes =
        selected_remote_entry_indexes(&entries, &plan.filter_rules, files_from.as_deref());
    let selected_entries = selected_remote_entries(&entries, &selected_indexes);
    let index_offset = remote_file_index_offset(&entries);
    let io_error = read_multiplexed_i32(transport, &mut mux)?;
    if io_error != 0 {
        bail!("remote sender reported non-zero I/O error {io_error}");
    }

    let destination_relatives: Vec<_> = selected_entries
        .iter()
        .filter(|entry| !remote_entry_is_top_dir(entry))
        .map(|entry| entry.path.clone())
        .collect();
    windows_destination_path_preflight(&destination_relatives)?;

    let mut fs = LocalFileSystem;
    let mut actions = Vec::<SyncAction>::new();
    if !fs.exists(dest) {
        actions.push(SyncAction::CreateDir(dest.to_path_buf()));
        if !plan.dry_run {
            fs.create_dir_all(dest)?;
        }
    }
    let transfer_indexes =
        selected_remote_transfer_indexes(&fs, dest, &entries, &selected_indexes, plan.update_mode)?;
    if plan.delete {
        delete_local_extras(
            &mut fs,
            dest,
            &selected_entries,
            &plan.filter_rules,
            files_from.as_deref(),
            plan.dry_run,
            &mut actions,
        )?;
    }
    for entry in &selected_entries {
        if remote_entry_is_top_dir(entry) {
            continue;
        }
        if entry.file_type == WireFileType::Directory {
            let target = dest.join(&entry.path);
            actions.push(SyncAction::CreateDir(target.clone()));
            if !plan.dry_run {
                fs.create_dir_all(&target)?;
            }
        }
    }

    request_remote_sender_files(
        transport,
        &entries,
        &transfer_indexes,
        index_offset,
        plan.dry_run,
        dest,
        remote_delta_block_size(plan)?,
        plan.whole_file,
        RemoteFileChecksum::md4_with_seed(handshake.checksum_seed),
        plan.max_alloc,
        plan.stop_deadline,
    )?;
    transport.flush()?;
    let remote_compression = RemoteCompressionConfig::for_plan(plan)?;
    let stats = receive_remote_sender_files(
        transport,
        &mut mux,
        RemoteReceiveContext {
            fs: &mut fs,
            dest,
            entries: &entries,
            index_offset,
            final_checksum: RemoteFinalChecksum::protocol27(handshake.checksum_seed),
            dry_run: plan.dry_run,
            progress: ProgressLog::from_cli(cli),
            preserve_times: plan.preserve_times,
            file_write_options: file_write_options_from_plan(plan),
            append_verify: plan.append_verify,
            compression: remote_compression.as_ref(),
            max_alloc: plan.max_alloc,
            stop_deadline: plan.stop_deadline,
            actions: &mut actions,
        },
    )?;

    write_rsync_i32(transport, -1)?;
    transport.flush()?;
    let phase_ack = read_multiplexed_i32(transport, &mut mux)?;
    if phase_ack != -1 {
        return Err(RemoteSessionError::InvalidPhaseAck(phase_ack).into());
    }

    let _remote_read = read_multiplexed_long(transport, &mut mux)?;
    let _remote_written = read_multiplexed_long(transport, &mut mux)?;
    let _remote_size = read_multiplexed_long(transport, &mut mux)?;
    write_rsync_i32(transport, -1)?;
    transport.flush()?;

    let mut output = String::new();
    if plan.daemon_operand.is_some() {
        output.push_str("rsync-win daemon pull\n");
    } else {
        output.push_str("rsync-win remote-shell pull\n");
    }
    output.push_str("direction: download (remote -> local)\n");
    append_pull_sources_summary(&mut output, plan)?;
    output.push_str(&format!("destination: {}\n", dest.display()));
    output.push_str(&format!(
        "protocol: {} (peer advertised {})\n",
        handshake.selected_protocol.value(),
        handshake.peer_protocol
    ));
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    append_action_report(&mut output, cli, &actions);
    append_out_format_and_client_log(&mut output, cli, &actions, &mut client_log)?;
    output.push_str(&format!("files received: {}\n", stats.files));
    output.push_str(&format!("bytes received: {}\n", stats.bytes));
    append_remote_messages(&mut output, &mux);
    Ok(output)
}

fn execute_remote_pull_protocol31<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    let handshake = exchange_remote_shell_protocol31_handshake_with_options(
        transport,
        protocol31_setup_options_from_plan(plan),
    )
    .map_err(protocol31_setup_error)?;
    execute_remote_pull_protocol31_with_handshake(cli, plan, transport, handshake)
}

pub(crate) fn execute_remote_pull_protocol31_with_handshake<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
    handshake: rsync_protocol::RemoteShellHandshake,
) -> Result<String> {
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
    let mut client_log = output::TransferLog::from_cli(cli)?;
    let mut mux = MultiplexReadState::default();

    {
        let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
        write_i32_le(&mut writer, 0).map_err(protocol31_setup_error)?;
        writer.flush().map_err(protocol31_setup_error)?;
    }

    let mut entries = {
        let mut reader = MultiplexedReader::new(transport, &mut mux);
        read_rsync31_file_list_with_metadata(
            &mut reader,
            DEFAULT_MAX_FILE_LIST_ENTRIES,
            DEFAULT_MAX_FILE_LIST_PATH_LEN,
            rsync31_file_list_options_from_plan(
                plan,
                plan.update_mode == UpdateMode::Checksum,
                plan.daemon_operand.is_some(),
                true,
            ),
        )
        .map_err(protocol31_setup_error)?
    };
    if plan.incremental_recursion {
        return execute_remote_pull_protocol31_incremental_with_entries(
            cli,
            plan,
            transport,
            handshake,
            &mut mux,
            &mut client_log,
            entries,
        );
    }
    check_rsync_file_list_budget(&entries, plan.max_alloc)
        .context("remote file-list exceeds allocation budget")?;
    sort_remote_entries_for_sender_indexes(&mut entries);
    validate_remote_file_list_paths(&entries)?;
    let files_from = load_files_from(cli)?;
    validate_remote_sender_claims(plan, &entries, files_from.as_deref())?;
    let selected_indexes =
        selected_remote_entry_indexes(&entries, &plan.filter_rules, files_from.as_deref());
    let selected_entries = selected_remote_entries(&entries, &selected_indexes);
    let index_offset = remote_file_index_offset(&entries);

    let destination_relatives: Vec<_> = selected_entries
        .iter()
        .filter(|entry| !remote_entry_is_top_dir(entry))
        .map(|entry| entry.path.clone())
        .collect();
    windows_destination_path_preflight(&destination_relatives)?;

    let mut fs = LocalFileSystem;
    let mut actions = Vec::<SyncAction>::new();
    if !fs.exists(dest) {
        actions.push(SyncAction::CreateDir(dest.to_path_buf()));
        if !plan.dry_run {
            fs.create_dir_all(dest)?;
        }
    }
    let transfer_indexes =
        selected_remote_transfer_indexes(&fs, dest, &entries, &selected_indexes, plan.update_mode)?;
    if plan.delete {
        delete_local_extras(
            &mut fs,
            dest,
            &selected_entries,
            &plan.filter_rules,
            files_from.as_deref(),
            plan.dry_run,
            &mut actions,
        )?;
    }
    for entry in &selected_entries {
        if remote_entry_is_top_dir(entry) {
            continue;
        }
        if entry.file_type == WireFileType::Directory {
            let target = dest.join(&entry.path);
            actions.push(SyncAction::CreateDir(target.clone()));
            if !plan.dry_run {
                fs.create_dir_all(&target)?;
            }
        }
    }

    let remote_file_checksum = RemoteFileChecksum::protocol31(
        handshake.checksum_name.as_deref(),
        handshake.checksum_seed,
    )?;
    request_remote_sender_files_protocol31(
        transport,
        RemoteSenderFileRequest {
            entries: &entries,
            selected_indexes: &transfer_indexes,
            index_offset,
            dry_run: plan.dry_run,
            dest,
            block_size: remote_delta_block_size(plan)?,
            whole_file: plan.whole_file,
            checksum: remote_file_checksum,
            max_alloc: plan.max_alloc,
            stop_deadline: plan.stop_deadline,
        },
    )?;
    transport.flush()?;
    let remote_compression = RemoteCompressionConfig::for_plan(plan)?;
    let stats = receive_remote_sender_files_protocol31(
        transport,
        &mut mux,
        RemoteReceiveContext {
            fs: &mut fs,
            dest,
            entries: &entries,
            index_offset,
            final_checksum: RemoteFinalChecksum::protocol31(handshake.checksum_name.as_deref())?,
            dry_run: plan.dry_run,
            progress: ProgressLog::from_cli(cli),
            preserve_times: plan.preserve_times,
            file_write_options: file_write_options_from_plan(plan),
            append_verify: plan.append_verify,
            compression: remote_compression.as_ref(),
            max_alloc: plan.max_alloc,
            stop_deadline: plan.stop_deadline,
            actions: &mut actions,
        },
    )?;

    write_rsync31_done(transport)?;
    let phase_ack = read_multiplexed_rsync31_index(transport, &mut mux)?;
    if phase_ack != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidPhaseAck(phase_ack).into());
    }

    write_rsync31_done(transport)?;
    let sender_done = read_multiplexed_rsync31_index(transport, &mut mux)?;
    if sender_done != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(sender_done).into());
    }

    read_remote_sender_protocol31_stats(transport, &mut mux)?;

    write_rsync31_done(transport)?;
    let goodbye_ack = read_multiplexed_rsync31_index(transport, &mut mux)?;
    if goodbye_ack != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(goodbye_ack).into());
    }
    write_rsync31_done(transport)?;

    let mut output = String::new();
    if plan.daemon_operand.is_some() {
        output.push_str("rsync-win daemon pull\n");
    } else {
        output.push_str("rsync-win remote-shell pull\n");
    }
    output.push_str("direction: download (remote -> local)\n");
    append_pull_sources_summary(&mut output, plan)?;
    output.push_str(&format!("destination: {}\n", dest.display()));
    output.push_str(&format!(
        "protocol: {} (peer advertised {})\n",
        handshake.selected_protocol.value(),
        handshake.peer_protocol
    ));
    if let Some(checksum_name) = &handshake.checksum_name {
        output.push_str(&format!("checksum negotiation: {checksum_name}\n"));
    }
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    append_action_report(&mut output, cli, &actions);
    append_out_format_and_client_log(&mut output, cli, &actions, &mut client_log)?;
    output.push_str(&format!("files received: {}\n", stats.files));
    output.push_str(&format!("bytes received: {}\n", stats.bytes));
    append_remote_messages(&mut output, &mux);
    Ok(output)
}

fn execute_remote_pull_protocol31_incremental_with_entries<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
    handshake: rsync_protocol::RemoteShellHandshake,
    mux: &mut MultiplexReadState,
    client_log: &mut output::TransferLog,
    mut entries: Vec<RsyncFileListEntry>,
) -> Result<String> {
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
    let file_list_options = rsync31_file_list_options_from_plan(
        plan,
        plan.update_mode == UpdateMode::Checksum,
        plan.daemon_operand.is_some(),
        true,
    );
    check_rsync_file_list_budget(&entries, plan.max_alloc)
        .context("remote file-list exceeds allocation budget")?;
    sort_remote_entries_for_sender_indexes(&mut entries);
    validate_remote_file_list_paths(&entries)?;
    let files_from = load_files_from(cli)?;
    validate_remote_sender_claims(plan, &entries, files_from.as_deref())?;

    let mut fs = LocalFileSystem;
    let mut actions = Vec::<SyncAction>::new();
    if !fs.exists(dest) {
        actions.push(SyncAction::CreateDir(dest.to_path_buf()));
        if !plan.dry_run {
            fs.create_dir_all(dest)?;
        }
    }

    let remote_file_checksum = RemoteFileChecksum::protocol31(
        handshake.checksum_name.as_deref(),
        handshake.checksum_seed,
    )?;
    let final_checksum = RemoteFinalChecksum::protocol31(handshake.checksum_name.as_deref())?;
    let remote_compression = RemoteCompressionConfig::for_plan(plan)?;
    let block_size = remote_delta_block_size(plan)?;
    let file_write_options = file_write_options_from_plan(plan);
    let progress = ProgressLog::from_cli(cli);
    let mut requested_indexes = BTreeSet::new();
    let mut write_index_state = RsyncIndexState::default();
    request_remote_pull_incremental_batch_protocol31(
        transport,
        &mut fs,
        dest,
        &entries,
        0,
        plan,
        files_from.as_deref(),
        remote_file_checksum,
        block_size,
        &mut write_index_state,
        &mut requested_indexes,
        &mut actions,
    )?;
    write_rsync31_index(transport, &mut write_index_state, RSYNC_INDEX_DONE)?;
    transport.flush()?;

    let mut read_index_state = RsyncIndexState::default();
    let mut stats = RemoteExecutionStats::default();

    loop {
        check_transfer_deadline(plan.stop_deadline)?;
        let response = read_protocol31_sender_response(
            transport,
            mux,
            &mut read_index_state,
            &entries,
            true,
            file_list_options,
        )?;
        match response {
            Protocol31SenderResponse::Done => break,
            Protocol31SenderResponse::FileListEof => {}
            Protocol31SenderResponse::ExtraFileList {
                entries: extra_entries,
            } => {
                let mut extra_entries = extra_entries;
                sort_remote_entries_for_sender_indexes(&mut extra_entries);
                let batch_start = entries.len();
                entries.extend(extra_entries);
                check_rsync_file_list_budget(&entries, plan.max_alloc)
                    .context("remote file-list exceeds allocation budget")?;
                validate_remote_file_list_paths(&entries)?;
                validate_remote_sender_claims(
                    plan,
                    &entries[batch_start..],
                    files_from.as_deref(),
                )?;
                request_remote_pull_incremental_batch_protocol31(
                    transport,
                    &mut fs,
                    dest,
                    &entries,
                    batch_start,
                    plan,
                    files_from.as_deref(),
                    remote_file_checksum,
                    block_size,
                    &mut write_index_state,
                    &mut requested_indexes,
                    &mut actions,
                )?;
                write_rsync31_index(transport, &mut write_index_state, RSYNC_INDEX_DONE)?;
                transport.flush()?;
            }
            Protocol31SenderResponse::File {
                index,
                iflags,
                sum_head,
            } => {
                let entry_index = checked_remote_file_index(index, entries.len(), 0)?;
                let mut ctx = RemoteReceiveContext {
                    fs: &mut fs,
                    dest,
                    entries: &entries,
                    index_offset: 0,
                    final_checksum,
                    dry_run: plan.dry_run,
                    progress,
                    preserve_times: plan.preserve_times,
                    file_write_options: file_write_options.clone(),
                    append_verify: plan.append_verify,
                    compression: remote_compression.as_ref(),
                    max_alloc: plan.max_alloc,
                    stop_deadline: plan.stop_deadline,
                    actions: &mut actions,
                };
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
        }
    }

    if plan.delete {
        let selected_indexes =
            selected_remote_entry_indexes(&entries, &plan.filter_rules, files_from.as_deref());
        let selected_entries = selected_remote_entries(&entries, &selected_indexes);
        delete_local_extras(
            &mut fs,
            dest,
            &selected_entries,
            &plan.filter_rules,
            files_from.as_deref(),
            plan.dry_run,
            &mut actions,
        )?;
    }

    write_rsync31_done(transport)?;
    let phase_ack = read_multiplexed_rsync31_index(transport, mux)?;
    if phase_ack != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidPhaseAck(phase_ack).into());
    }

    write_rsync31_done(transport)?;
    let sender_done = read_multiplexed_rsync31_index(transport, mux)?;
    if sender_done != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(sender_done).into());
    }

    read_remote_sender_protocol31_stats(transport, mux)?;

    write_rsync31_done(transport)?;
    let goodbye_ack = read_multiplexed_rsync31_index(transport, mux)?;
    if goodbye_ack != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(goodbye_ack).into());
    }
    write_rsync31_done(transport)?;

    let mut output = String::new();
    if plan.daemon_operand.is_some() {
        output.push_str("rsync-win daemon pull\n");
    } else {
        output.push_str("rsync-win remote-shell pull\n");
    }
    output.push_str("direction: download (remote -> local)\n");
    append_pull_sources_summary(&mut output, plan)?;
    output.push_str(&format!("destination: {}\n", dest.display()));
    output.push_str(&format!(
        "protocol: {} (peer advertised {})\n",
        handshake.selected_protocol.value(),
        handshake.peer_protocol
    ));
    if let Some(checksum_name) = &handshake.checksum_name {
        output.push_str(&format!("checksum negotiation: {checksum_name}\n"));
    }
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    append_action_report(&mut output, cli, &actions);
    append_out_format_and_client_log(&mut output, cli, &actions, client_log)?;
    output.push_str(&format!("files received: {}\n", stats.files));
    output.push_str(&format!("bytes received: {}\n", stats.bytes));
    append_remote_messages(&mut output, mux);
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn request_remote_pull_incremental_batch_protocol31<T: Write>(
    transport: &mut T,
    fs: &mut LocalFileSystem,
    dest: &Path,
    entries: &[RsyncFileListEntry],
    batch_start: usize,
    plan: &TransferPlan,
    files_from: Option<&[PathBuf]>,
    remote_file_checksum: RemoteFileChecksum,
    block_size: usize,
    write_index_state: &mut RsyncIndexState,
    requested_indexes: &mut BTreeSet<usize>,
    actions: &mut Vec<SyncAction>,
) -> Result<usize> {
    let selected_indexes = selected_remote_entry_indexes(entries, &plan.filter_rules, files_from);
    let batch_selected_indexes: BTreeSet<_> = selected_indexes
        .iter()
        .copied()
        .filter(|index| *index >= batch_start)
        .collect();

    for index in &batch_selected_indexes {
        let entry = &entries[*index];
        if remote_entry_is_top_dir(entry) || entry.file_type != WireFileType::Directory {
            continue;
        }
        let target = dest.join(&entry.path);
        actions.push(SyncAction::CreateDir(target.clone()));
        if !plan.dry_run {
            fs.create_dir_all(&target)?;
        }
    }

    let transfer_indexes = selected_remote_transfer_indexes(
        fs,
        dest,
        entries,
        &batch_selected_indexes,
        plan.update_mode,
    )?;
    request_remote_sender_file_indexes_protocol31(
        transport,
        entries,
        &transfer_indexes,
        requested_indexes,
        0,
        plan.dry_run,
        dest,
        block_size,
        plan.whole_file,
        remote_file_checksum,
        plan.max_alloc,
        plan.stop_deadline,
        write_index_state,
    )
}
