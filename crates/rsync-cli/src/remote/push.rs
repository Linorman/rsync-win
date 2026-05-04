use std::io::{Read, Write};

use anyhow::{Context, Result};
use rsync_fs::UpdateMode;
use rsync_protocol::{
    exchange_remote_shell_mvp_handshake, exchange_remote_shell_protocol31_handshake_with_options,
    write_i32_le, write_rsync_i32, MultiplexReadState, MultiplexedWriter, RemoteShellHandshake,
    Rsync27FileListWriter, Rsync31FileListWriter,
};

use crate::cli::Cli;
use crate::execute::remote_shell::protocol31_setup_error;
use crate::format::*;
use crate::plan::*;
use crate::remote::flist::*;
use crate::remote::receive::*;
use crate::transfer::*;
use crate::{output, ProgressLog};

pub(crate) fn execute_remote_push<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    match plan
        .remote_wire_protocol
        .unwrap_or(RemoteWireProtocol::Modern31)
    {
        RemoteWireProtocol::Modern31 => execute_remote_push_protocol31(cli, plan, transport),
        RemoteWireProtocol::Compat27 => execute_remote_push_protocol27(cli, plan, transport),
    }
}

pub(crate) fn execute_remote_push_protocol27<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    let progress = ProgressLog::from_cli(cli);
    let mut client_log = output::TransferLog::from_cli(cli)?;
    let sources = local_source_paths(cli);
    log_source_storage_notes(progress, &sources);
    let files_from = load_files_from(cli)?;
    progress.info("building upload file list");
    let collect_options = local_source_collect_options(plan, files_from.as_deref());
    let handshake = exchange_remote_shell_mvp_handshake(transport)?;
    progress.detail(format!(
        "protocol: rsync {}",
        handshake.selected_protocol.value()
    ));
    if plan.delete {
        write_rsync_i32(transport, 0)?;
    }
    let mut file_list_writer = Rsync27FileListWriter::new(plan.update_mode == UpdateMode::Checksum);
    let (entries, batch_count) = collect_local_push_source_entries_with_batches(
        &sources,
        &collect_options,
        plan.max_alloc,
        |batch| {
            file_list_writer.write_batch(transport, &batch.entries)?;
            Ok(())
        },
    )
    .context("local upload file-list batch exceeds allocation budget")?;
    file_list_writer.finish(transport)?;
    write_rsync_i32(transport, 0)?;
    transport.flush()?;
    let (file_count, total_file_bytes) = remote_entries_file_summary(&entries);
    progress.info(format!(
        "upload list: {} files, {}",
        file_count,
        format_bytes(total_file_bytes)
    ));
    progress.detail(format!("upload list entries: {}", entries.len(),));
    progress.detail(format!("upload list batches: {}", batch_count));

    let mut mux = MultiplexReadState::default();
    let remote_compression = RemoteCompressionConfig::for_plan(plan)?;
    let stats = serve_remote_receiver_requests(
        transport,
        &mut mux,
        &entries,
        handshake.checksum_seed,
        plan.dry_run,
        RemoteTransferRuntime {
            compression: remote_compression.as_ref(),
            progress,
            max_alloc: plan.max_alloc,
            stop_deadline: plan.stop_deadline,
        },
    )?;

    let mut output = String::new();
    if plan.daemon_operand.is_some() {
        output.push_str("rsync-win daemon push\n");
    } else {
        output.push_str("rsync-win remote-shell push\n");
    }
    if plan.daemon_operand.is_some() {
        output.push_str("direction: upload (local -> daemon)\n");
    } else {
        output.push_str("direction: upload (local -> remote)\n");
    }
    append_sources_summary(&mut output, &sources);
    append_source_storage_notes(&mut output, &sources);
    append_push_destination_summary(&mut output, plan)?;
    output.push_str(&format!(
        "protocol: {} (peer advertised {})\n",
        handshake.selected_protocol.value(),
        handshake.peer_protocol
    ));
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    output.push_str(&format!("files offered: {}\n", file_count));
    output.push_str(&format!("bytes offered: {}\n", total_file_bytes));
    output.push_str(&format!("files sent: {}\n", stats.files));
    output.push_str(&format!("bytes sent: {}\n", stats.bytes));
    append_remote_push_quick_check_note(&mut output, plan, file_count, total_file_bytes, &stats);
    append_remote_source_out_format_and_client_log(
        &mut output,
        cli,
        &entries,
        &stats.transferred_entry_indexes,
        &mut client_log,
    )?;
    append_remote_messages(&mut output, &mux);
    Ok(output)
}

pub(crate) fn execute_remote_push_protocol31<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    let handshake = exchange_remote_shell_protocol31_handshake_with_options(
        transport,
        protocol31_setup_options_from_plan(plan),
    )
    .map_err(protocol31_setup_error)?;
    execute_remote_push_protocol31_with_handshake(cli, plan, transport, handshake)
}

pub(crate) fn execute_remote_push_protocol31_with_handshake<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
    handshake: RemoteShellHandshake,
) -> Result<String> {
    let progress = ProgressLog::from_cli(cli);
    let mut client_log = output::TransferLog::from_cli(cli)?;
    let sources = local_source_paths(cli);
    log_source_storage_notes(progress, &sources);
    let files_from = load_files_from(cli)?;
    progress.info("building upload file list");
    let collect_options = local_source_collect_options(plan, files_from.as_deref());
    progress.detail(format!(
        "protocol: rsync {}",
        handshake.selected_protocol.value()
    ));
    if plan.delete {
        let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
        write_i32_le(&mut writer, 0).map_err(protocol31_setup_error)?;
        writer.flush().map_err(protocol31_setup_error)?;
    }
    let (mut entries, batch_count) = {
        let mut file_list_bytes = Vec::new();
        let mut file_list_writer = Rsync31FileListWriter::new(rsync31_file_list_options_from_plan(
            plan,
            plan.update_mode == UpdateMode::Checksum,
            true,
            plan.daemon_operand.is_some(),
        ));
        let (collected_entries, collected_batch_count) =
            collect_local_push_source_entries_with_batches(
                &sources,
                &collect_options,
                plan.max_alloc,
                |batch| {
                    file_list_writer
                        .write_batch(&mut file_list_bytes, &batch.entries)
                        .map_err(protocol31_setup_error)?;
                    Ok(())
                },
            )
            .context("local upload file-list batch exceeds allocation budget")?;
        file_list_writer
            .finish(&mut file_list_bytes)
            .map_err(protocol31_setup_error)?;
        let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
        writer
            .write_all(&file_list_bytes)
            .map_err(protocol31_setup_error)?;
        writer.flush().map_err(protocol31_setup_error)?;
        (collected_entries, collected_batch_count)
    };
    if plan.daemon_operand.is_none() {
        sort_remote_source_entries_for_sender_indexes(&mut entries);
    }
    let (file_count, total_file_bytes) = remote_entries_file_summary(&entries);
    progress.info(format!(
        "upload list: {} files, {}",
        file_count,
        format_bytes(total_file_bytes)
    ));
    progress.detail(format!("upload list entries: {}", entries.len(),));
    progress.detail(format!("upload list batches: {}", batch_count));

    let mut mux = MultiplexReadState::default();
    let remote_compression = RemoteCompressionConfig::for_plan(plan)?;
    let remote_file_checksum = RemoteFileChecksum::protocol31(
        handshake.checksum_name.as_deref(),
        handshake.checksum_seed,
    )?;
    let stats = serve_remote_receiver_requests_protocol31(
        transport,
        &mut mux,
        &entries,
        plan.dry_run,
        plan.append_verify,
        remote_file_checksum,
        RemoteTransferRuntime {
            compression: remote_compression.as_ref(),
            progress,
            max_alloc: plan.max_alloc,
            stop_deadline: plan.stop_deadline,
        },
    )?;

    let mut output = String::new();
    if plan.daemon_operand.is_some() {
        output.push_str("rsync-win daemon push\n");
    } else {
        output.push_str("rsync-win remote-shell push\n");
    }
    if plan.daemon_operand.is_some() {
        output.push_str("direction: upload (local -> daemon)\n");
    } else {
        output.push_str("direction: upload (local -> remote)\n");
    }
    append_sources_summary(&mut output, &sources);
    append_source_storage_notes(&mut output, &sources);
    append_push_destination_summary(&mut output, plan)?;
    output.push_str(&format!(
        "protocol: {} (peer advertised {})\n",
        handshake.selected_protocol.value(),
        handshake.peer_protocol
    ));
    if let Some(checksum_name) = &handshake.checksum_name {
        output.push_str(&format!("checksum negotiation: {checksum_name}\n"));
    }
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    output.push_str(&format!("files offered: {}\n", file_count));
    output.push_str(&format!("bytes offered: {}\n", total_file_bytes));
    output.push_str(&format!("files sent: {}\n", stats.files));
    output.push_str(&format!("bytes sent: {}\n", stats.bytes));
    append_remote_push_quick_check_note(&mut output, plan, file_count, total_file_bytes, &stats);
    append_remote_source_out_format_and_client_log(
        &mut output,
        cli,
        &entries,
        &stats.transferred_entry_indexes,
        &mut client_log,
    )?;
    append_remote_messages(&mut output, &mux);
    Ok(output)
}
