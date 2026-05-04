use anyhow::Result;
use clap::CommandFactory;
#[cfg(test)]
use clap::Parser;
use rsync_core::MetadataPolicy;
use rsync_protocol::{
    TransferDirection, MAX_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION, REMOTE_SHELL_MODERN_PROTOCOL,
    REMOTE_SHELL_MVP_PROTOCOL,
};

use crate::cli::Cli;
use crate::execute::daemon_client::execute_daemon_sync;
#[cfg(test)]
pub(crate) use crate::execute::daemon_client::{
    daemon_auth_user, daemon_auth_user_from_vars, daemon_password_from_vars,
    execute_daemon_sync_with_transport, read_password_file,
};
#[cfg(test)]
pub(crate) use crate::execute::local::ntfs_sidecar_root;
use crate::execute::local::{
    execute_local_sync, execute_local_sync_with_batch, execute_read_batch,
};
use crate::execute::remote_shell::execute_remote_shell_sync;
#[cfg(test)]
pub(crate) use crate::execute::remote_shell::{
    protocol31_setup_error, should_fallback_to_protocol27,
};
use crate::format::*;
use crate::plan::*;
#[cfg(test)]
pub(crate) use crate::remote::pull::execute_remote_pull;
#[cfg(test)]
pub(crate) use crate::remote::push::execute_remote_push;
pub(crate) use crate::remote::receive::{
    checked_file_index, delete_local_extras, read_multiplexed_rsync31_index,
    receive_remote_sender_files_protocol31, remote_entry_is_top_dir, remote_file_index_offset,
    request_remote_sender_files_protocol31, selected_remote_entries, selected_remote_entry_indexes,
    selected_remote_transfer_indexes, sort_remote_entries_for_sender_indexes,
    validate_remote_file_list_paths, windows_destination_path_preflight, write_rsync31_done,
    write_rsync31_index, RemoteReceiveContext,
};
use crate::{daemon_server, options};
pub fn run_from_env() -> Result<()> {
    let cli = options::parse_cli(std::env::args_os())?;
    print!("{}", execute_or_render(&cli)?);
    Ok(())
}

/// Entry point for `main()` that propagates exit-code-mapped errors.
pub fn run_from_env_main() -> Result<(), anyhow::Error> {
    run_from_env()
}

pub fn parse_and_render_result<I, T>(args: I) -> Result<String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = options::parse_cli(args)?;
    Ok(render_output(&cli))
}

pub fn parse_and_render<I, T>(args: I) -> String
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    parse_and_render_result(args).unwrap_or_else(|err| format!("rsync-win: {err}\n"))
}

pub fn parse_and_execute<I, T>(args: I) -> Result<String>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = options::parse_cli(args)?;
    execute_or_render(&cli)
}

pub fn build_command() -> clap::Command {
    Cli::command()
}

pub fn supported_protocol_range() -> String {
    format!("{MIN_PROTOCOL_VERSION}-{MAX_PROTOCOL_VERSION}")
}

pub fn version_output() -> String {
    format!(
        "rsync-win {}\nprotocol primitives range: {}\ntransfer execution: local portable sync supported; remote-shell MVP tries protocol {} first with protocol {} compatibility fallback\n",
        env!("CARGO_PKG_VERSION"),
        supported_protocol_range(),
        REMOTE_SHELL_MODERN_PROTOCOL,
        REMOTE_SHELL_MVP_PROTOCOL
    )
}

fn render_output(cli: &Cli) -> String {
    if cli.help {
        return help_output();
    }

    if cli.version {
        return version_output();
    }

    if cli.protocol_range {
        return format!("{}\n", supported_protocol_range());
    }

    render_transfer_plan(cli)
}

fn help_output() -> String {
    let mut output = String::new();
    output.push_str("rsync-win\n\n");
    output.push_str("Usage: rsync-win [OPTION...] SRC... [DEST]\n\n");
    output.push_str("Common rsync-compatible options:\n");
    for spec in options::upstream_client_option_specs() {
        output.push_str("  --");
        output.push_str(spec.long);
        if let Some(short) = spec.short {
            output.push_str(&format!(", -{short}"));
        }
        output.push('\n');
    }
    output
}

fn render_transfer_plan(cli: &Cli) -> String {
    let plan = TransferPlan::from_cli(cli);
    render_transfer_plan_with(cli, &plan)
}

fn render_transfer_plan_with(cli: &Cli, plan: &TransferPlan) -> String {
    let mut output = String::new();
    output.push_str("rsync-win development transfer planner\n");
    output.push_str("execution: plan output only; local paths execute when --plan is omitted\n");
    output.push_str(&format!(
        "protocol primitives range: {}\n",
        supported_protocol_range()
    ));
    output.push_str(&format!("transfer mode: {}\n", plan.transfer_mode.label()));
    output.push_str(&format!("metadata policy: {}\n", plan.metadata_policy));
    output.push_str(&format!("recursive: {}\n", plan.recursive));
    output.push_str(&format!(
        "incremental recursion: {}\n",
        plan.incremental_recursion
    ));
    output.push_str(&format!("relative: {}\n", plan.relative));
    output.push_str(&format!("implied dirs: {}\n", plan.implied_dirs));
    output.push_str(&format!("dirs: {}\n", plan.transfer_dirs));
    output.push_str(&format!("mkpath: {}\n", plan.mkpath));
    output.push_str(&format!("one file system: {}\n", plan.one_file_system));
    output.push_str(&format!("preserve times: {}\n", plan.preserve_times));
    output.push_str(&format!("delete: {}\n", plan.delete));
    output.push_str(&format!(
        "delete mode: {}\n",
        delete_mode_label(plan.delete_mode)
    ));
    output.push_str(&format!("delete excluded: {}\n", plan.delete_excluded));
    output.push_str(&format!("ignore errors: {}\n", plan.ignore_errors));
    output.push_str(&format!("force delete: {}\n", plan.force_delete));
    if let Some(max_delete) = plan.max_delete {
        output.push_str(&format!("max delete: {max_delete}\n"));
    }
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    output.push_str(&format!("whole file: {}\n", plan.whole_file));
    if let Some(checksum_choice) = &plan.checksum_choice {
        output.push_str(&format!("checksum choice: {checksum_choice}\n"));
    }
    if let Some(checksum_seed) = plan.checksum_seed {
        output.push_str(&format!("checksum seed: {checksum_seed}\n"));
    }
    output.push_str(&format!("compress: {}\n", plan.compress));
    if let Some(compress_choice) = &plan.compress_choice {
        output.push_str(&format!("compress choice: {compress_choice}\n"));
    }
    if let Some(compress_level) = plan.compress_level {
        output.push_str(&format!("compress level: {compress_level}\n"));
    }
    if let Some(compress_threads) = plan.compress_threads {
        output.push_str(&format!("compress threads: {compress_threads}\n"));
    }
    if !plan.skip_compress.is_empty() {
        output.push_str(&format!(
            "skip compress: {}\n",
            plan.skip_compress.join(",")
        ));
    }
    output.push_str(&format!("verbosity: {}\n", plan.verbosity));
    output.push_str(&format!("quiet: {}\n", cli.quiet));
    output.push_str(&format!("human readable: {}\n", plan.human_readable));
    output.push_str(&format!("progress: {}\n", plan.progress));
    output.push_str(&format!("itemize changes: {}\n", cli.itemize_changes));
    output.push_str(&format!("stats: {}\n", cli.stats));
    if !cli.info_flags.is_empty() {
        output.push_str(&format!("info flags: {}\n", cli.info_flags.join(",")));
    }
    if !cli.debug_flags.is_empty() {
        output.push_str(&format!("debug flags: {}\n", cli.debug_flags.join(",")));
    }
    output.push_str(&format!("msgs2stderr: {}\n", cli.msgs2stderr));
    output.push_str(&format!("no msgs2stderr: {}\n", cli.no_msgs2stderr));
    if let Some(ref mode) = cli.stderr_mode {
        output.push_str(&format!("stderr: {mode}\n"));
    }
    if let Some(ref fmt) = cli.out_format {
        output.push_str(&format!("out format: {fmt}\n"));
    }
    output.push_str(&format!("8-bit output: {}\n", cli.eight_bit_output));
    if let Some(ref path) = cli.client_log_file {
        output.push_str(&format!("client log file: {}\n", path.display()));
    }
    if let Some(ref fmt) = cli.client_log_file_format {
        output.push_str(&format!("client log file format: {fmt}\n"));
    }
    output.push_str(&format!(
        "update mode: {}\n",
        update_mode_label(plan.update_mode)
    ));
    output.push_str(&format!(
        "file write mode: {}\n",
        file_write_mode_label(plan.file_write_mode)
    ));
    if plan.keep_partial {
        output.push_str("partial: true\n");
    }
    if let Some(partial_dir) = &plan.partial_dir {
        output.push_str(&format!("partial-dir: {}\n", partial_dir.display()));
    }
    if let Some(temp_dir) = &plan.temp_dir {
        output.push_str(&format!("temp-dir: {}\n", temp_dir.display()));
    }
    output.push_str(&format!("delay updates: {}\n", plan.delay_updates));
    output.push_str(&format!("fsync: {}\n", plan.fsync));
    output.push_str(&format!("append verify: {}\n", plan.append_verify));
    output.push_str(&format!("append: {}\n", plan.append));
    if let Some(block_size) = plan.block_size {
        output.push_str(&format!("block size: {block_size}\n"));
    }
    output.push_str(&format!(
        "symlink mode: {}\n",
        symlink_mode_label(plan.symlink_mode)
    ));
    output.push_str(&format!("keep dirlinks: {}\n", plan.keep_dirlinks));
    output.push_str(&format!("hard links: {}\n", plan.hard_links));
    output.push_str(&format!("devices: {}\n", plan.preserve_devices));
    output.push_str(&format!("special files: {}\n", plan.preserve_specials));
    output.push_str(&format!(
        "update newer only: {}\n",
        plan.skip_newer_receiver
    ));
    output.push_str(&format!("existing only: {}\n", plan.existing_only));
    output.push_str(&format!("ignore existing: {}\n", plan.ignore_existing));
    if let Some(max_size) = plan.max_size {
        output.push_str(&format!("max size: {max_size}\n"));
    }
    if let Some(min_size) = plan.min_size {
        output.push_str(&format!("min size: {min_size}\n"));
    }
    output.push_str(&format!("modify window: {}\n", plan.modify_window));
    output.push_str(&format!(
        "ignore missing args: {}\n",
        plan.ignore_missing_args
    ));
    output.push_str(&format!(
        "delete missing args: {}\n",
        plan.delete_missing_args
    ));
    output.push_str(&format!("backup: {}\n", plan.backup));
    if let Some(backup_dir) = &plan.backup_dir {
        output.push_str(&format!("backup-dir: {}\n", backup_dir.display()));
    }
    output.push_str(&format!("backup suffix: {}\n", plan.backup_suffix));
    if let Some(rsync_path) = &plan.rsync_path {
        output.push_str(&format!("remote rsync path: {rsync_path}\n"));
    }
    if plan.blocking_io {
        output.push_str("remote shell blocking io: true\n");
    }
    if plan.old_args {
        output.push_str("old args: true\n");
    }
    if plan.secluded_args {
        output.push_str("secluded args: true\n");
    }
    if plan.trust_sender {
        output.push_str("trust sender: true\n");
    }
    if plan.ipv4 {
        output.push_str("address family: ipv4\n");
    } else if plan.ipv6 {
        output.push_str("address family: ipv6\n");
    }
    if !plan.remote_options.is_empty() {
        output.push_str("remote options:");
        for option in &plan.remote_options {
            output.push(' ');
            output.push_str(option);
        }
        output.push('\n');
    }
    output.push_str(&format!(
        "posix metadata: {}\n",
        posix_metadata_summary(plan)
    ));
    if plan.metadata_policy == MetadataPolicy::NtfsNative || plan.vss {
        output.push_str(&format!(
            "ntfs-native metadata: sidecar-capture prototype, vss={}\n",
            plan.vss
        ));
    }
    output.push_str(&format!(
        "filter rules: {}\n",
        plan.filter_rules.rules().len()
    ));
    if let Some(files_from) = &cli.files_from {
        output.push_str(&format!("files-from: {}\n", files_from.display()));
        output.push_str(&format!("from0: {}\n", cli.from0));
    }
    output.push_str(&format!("operands: {}\n", cli.paths.len()));
    if let Some(direction) = plan.remote_direction {
        output.push_str(&format!(
            "remote direction: {} ({})\n",
            transfer_direction_label(direction),
            match direction {
                TransferDirection::Push => "local -> remote",
                TransferDirection::Pull => "remote -> local",
            }
        ));
    }
    if let Some(daemon) = &plan.daemon_operand {
        output.push_str("daemon mode: client\n");
        output.push_str(&format!(
            "daemon endpoint: {}:{}\n",
            daemon.host, daemon.port
        ));
        if let Some(address) = &cli.daemon_address {
            output.push_str(&format!("daemon bind address: {address}\n"));
        }
        if let Some(sockopts) = &cli.daemon_sockopts {
            output.push_str(&format!("daemon socket options: {sockopts}\n"));
        }
        if let Some(timeout) = cli.daemon_connect_timeout_secs {
            output.push_str(&format!("daemon connect timeout: {timeout}s\n"));
        }
        if cli.daemon_no_motd {
            output.push_str("daemon motd: disabled\n");
        }
        if let Some(direction) = plan.daemon_direction {
            output.push_str(&format!(
                "daemon direction: {} ({})\n",
                transfer_direction_label(direction),
                match direction {
                    TransferDirection::Push => "local -> daemon",
                    TransferDirection::Pull => "daemon -> local",
                }
            ));
        }
        if let Some(module) = &daemon.module {
            output.push_str(&format!("daemon module: {module}\n"));
        } else {
            output.push_str("daemon module: <list>\n");
        }
        if let Some(path) = &daemon.path {
            output.push_str(&format!("daemon path: {path}\n"));
        }
        if cli.password_file.is_some() {
            output.push_str("daemon auth: password-file configured\n");
        }
    }
    if plan.transfer_mode == TransferMode::DaemonServer {
        output.push_str("daemon mode: server\n");
        let address = cli.daemon_address.as_deref().unwrap_or("0.0.0.0");
        let port = cli
            .daemon_port
            .unwrap_or(rsync_protocol::DEFAULT_DAEMON_PORT);
        output.push_str(&format!("daemon listen: {address}:{port}\n"));
        if let Some(config) = &cli.daemon_config {
            output.push_str(&format!("daemon config: {}\n", config.display()));
        }
        for param in &cli.daemon_params {
            output.push_str(&format!("daemon dparam: {param}\n"));
        }
        output.push_str(&format!("daemon no detach: {}\n", cli.daemon_no_detach));
        if let Some(sockopts) = &cli.daemon_sockopts {
            output.push_str(&format!("daemon socket options: {sockopts}\n"));
        }
        if let Some(log_file) = &cli.daemon_log_file {
            output.push_str(&format!("daemon log file: {}\n", log_file.display()));
        }
        if let Some(format) = &cli.daemon_log_file_format {
            output.push_str(&format!("daemon log file format: {format}\n"));
        }
        if let Some(bwlimit) = &cli.daemon_bwlimit {
            output.push_str(&format!("daemon bwlimit: {bwlimit}\n"));
        }
    }
    if plan.transfer_mode == TransferMode::InternalServer {
        output.push_str("internal server mode: remote peer\n");
    }

    if let Some(argv) = &plan.remote_server_argv {
        output.push_str("remote --server argv:");
        for arg in argv {
            output.push(' ');
            output.push_str(arg);
        }
        output.push('\n');
    }
    if let Some(args) = &plan.remote_protected_args {
        if !args.is_empty() {
            output.push_str("remote protected args:");
            for arg in args {
                output.push(' ');
                output.push_str(arg);
            }
            output.push('\n');
        }
    }
    if let Some(argv) = &plan.remote_ssh_argv {
        output.push_str("remote ssh argv:");
        for arg in argv {
            output.push(' ');
            output.push_str(arg);
        }
        output.push('\n');
        if let Some(protocol) = plan.remote_wire_protocol {
            output.push_str(&format!(
                "wire protocol: experimental {} ({})\n",
                protocol.label(),
                protocol.protocol_number()
            ));
        }
    }

    // Chunk 12 plan rendering
    if !plan.compare_dest.is_empty() {
        output.push_str("compare dest:");
        for dir in &plan.compare_dest {
            output.push(' ');
            output.push_str(&dir.to_string_lossy());
        }
        output.push('\n');
    }
    if !plan.copy_dest.is_empty() {
        output.push_str("copy dest:");
        for dir in &plan.copy_dest {
            output.push(' ');
            output.push_str(&dir.to_string_lossy());
        }
        output.push('\n');
    }
    if !plan.link_dest.is_empty() {
        output.push_str("link dest:");
        for dir in &plan.link_dest {
            output.push(' ');
            output.push_str(&dir.to_string_lossy());
        }
        output.push('\n');
    }
    if plan.sparse {
        output.push_str("sparse: true\n");
    }
    if plan.preallocate {
        output.push_str("preallocate: true\n");
    }
    if plan.fuzzy {
        output.push_str("fuzzy: true\n");
    }
    if let Some(ref copy_as) = plan.copy_as {
        output.push_str(&format!("copy-as: {copy_as}\n"));
    }
    if plan.super_flag {
        output.push_str("super: true\n");
    }
    if let Some(ref batch) = plan.write_batch {
        output.push_str(&format!("write-batch: {}\n", batch.display()));
    }
    if let Some(ref batch) = plan.only_write_batch {
        output.push_str(&format!("only-write-batch: {}\n", batch.display()));
    }
    if let Some(ref batch) = plan.read_batch {
        output.push_str(&format!("read-batch: {}\n", batch.display()));
    }

    // Chunk 13 rendering
    if let Some(ref bwlimit) = plan.bwlimit_display {
        output.push_str(&format!("bwlimit: {bwlimit}\n"));
    }
    if let Some(timeout) = plan.timeout_secs {
        output.push_str(&format!("timeout: {timeout}s\n"));
    }
    if let Some(stop_after) = plan.stop_after_minutes {
        output.push_str(&format!("stop after: {stop_after} minutes\n"));
    }
    if let Some(time_limit) = plan.time_limit_minutes {
        output.push_str(&format!("time limit: {time_limit} minutes\n"));
    }
    if let Some(ref stop_at) = plan.stop_at {
        output.push_str(&format!("stop at: {stop_at}\n"));
    }
    if let Some(ref max_alloc) = plan.max_alloc_display {
        output.push_str(&format!("max alloc: {max_alloc}\n"));
    }
    if let Some(ref early_input) = plan.early_input {
        output.push_str(&format!("early input: {early_input}\n"));
    }
    if let Some(ref outbuf) = plan.outbuf {
        output.push_str(&format!("outbuf: {outbuf}\n"));
    }
    if let Some(protocol) = plan.protocol_version {
        output.push_str(&format!("protocol: {protocol}\n"));
    }
    if let Some(ref iconv) = plan.iconv {
        output.push_str(&format!("iconv: {iconv}\n"));
    }
    if plan.open_noatime {
        output.push_str("open noatime: true\n");
    }

    if !plan.report.is_empty() {
        output.push_str("diagnostics:\n");
        for diagnostic in plan.report.diagnostics() {
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

    output
}

fn execute_or_render(cli: &Cli) -> Result<String> {
    if cli.help || cli.version || cli.protocol_range || cli.plan {
        return Ok(render_output(cli));
    }

    let plan = TransferPlan::from_cli(cli);
    if plan.report.has_errors() {
        return Ok(render_transfer_plan_with(cli, &plan));
    }

    if plan.transfer_mode == TransferMode::DaemonServer {
        return daemon_server::run(cli);
    }

    if plan.daemon_operand.is_some() {
        return execute_daemon_sync(cli, plan);
    }

    if cli.paths.len() < 2 {
        return Ok(render_transfer_plan_with(cli, &plan));
    }

    if cli.paths.iter().any(|path| is_remote_shell_operand(path)) {
        return execute_remote_shell_sync(cli, plan);
    }

    ensure_local_execution_options_supported(cli)?;

    if let Some(ref batch_file) = plan.read_batch {
        return execute_read_batch(batch_file, &cli.paths, cli.dry_run);
    }

    let batch_mode = plan.only_write_batch.is_some();
    let batch_path = plan
        .write_batch
        .clone()
        .or_else(|| plan.only_write_batch.clone());

    if let Some(path) = batch_path {
        return execute_local_sync_with_batch(cli, plan, &path, batch_mode);
    }

    execute_local_sync(cli, plan)
}

#[cfg(test)]
mod tests;
