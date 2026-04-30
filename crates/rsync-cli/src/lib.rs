use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{ArgAction, CommandFactory, Parser, ValueEnum};
use digest::Digest;
use rsync_core::{
    archive_mode_components, archive_mode_degradations, metadata_policy_degradations,
    ChmodFileKind, ChmodRules, Diagnostic, MetadataDegradation, MetadataFeature, MetadataPolicy,
    NtfsNativeMetadataRequest, PosixMetadataRequest, Report, Severity,
};
use rsync_delta::{BlockSignature, DeltaToken, StrongChecksum};
use rsync_filter::{
    normalize_files_from_records, parse_files_from_bytes, EntryKind, Rule, RuleAction, RuleSet,
    RuleSide,
};
use rsync_fs::{
    selected_source_paths, sync_sources, walk_tree, DeleteMode, FileType, FileWriteMode,
    FileWriteOptions, FsError, LocalFileSystem, PortableFileSystem, SourceSelectionOptions,
    SymlinkMode, SyncAction, SyncOptions, UpdateMode,
};
use rsync_protocol::{
    authenticate_daemon_module, build_remote_shell_argv_for_paths,
    build_remote_shell_invocation_for_paths, build_remote_shell_protocol31_argv_for_paths,
    build_remote_shell_protocol31_invocation_for_paths, exchange_daemon_greeting,
    exchange_protocol31_setup_with_options, exchange_remote_shell_mvp_handshake,
    exchange_remote_shell_protocol31_handshake_with_options, read_i32_le, read_multiplexed_i32,
    read_multiplexed_long, read_rsync27_file_list_with_options,
    read_rsync31_file_list_with_options, read_rsync_index, read_u16_le, read_u8, read_varlong,
    read_vstring, request_module_list, rsync_plain_md4_checksum_reader, select_daemon_module,
    write_daemon_args, write_i32_le,
    write_remote_shell_protected_args, write_rsync27_file_list_with_options,
    write_rsync31_file_list_with_metadata, write_rsync_i32, write_rsync_index,
    write_rsync_long_value, write_u16_le, write_vstring, DaemonModuleSelection, DaemonOperand,
    MultiplexReadState, MultiplexedReader, MultiplexedWriter, Protocol31SetupOptions,
    RemoteDeleteMode, RemoteSessionError, RemoteShellOperand, RemoteShellOptions,
    RsyncDeflatedToken, RsyncDeflatedTokenMode, RsyncDeflatedTokenReader, RsyncDeflatedTokenWriter,
    RsyncFileListEntry, RsyncFileListMetadata, RsyncFileListOptions, RsyncHardLinkGroup,
    RsyncIndexState, RsyncMd4Checksum, SessionError, TransferDirection, WireFileType,
    DEFAULT_MAX_FILE_LIST_ENTRIES, DEFAULT_MAX_FILE_LIST_PATH_LEN, MAX_PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION, REMOTE_SHELL_MODERN_PROTOCOL, REMOTE_SHELL_MVP_PROTOCOL,
    RSYNC_DIRECTORY_MODE, RSYNC_INDEX_DONE,
};
use rsync_transport::remote_shell::{
    build_custom_remote_shell_command_with_options, build_ssh_remote_command_with_options,
    default_ssh_program, spawn_ssh_remote_command, RemoteShellCommandOptions, SshAddressFamily,
    SshRemoteCommand,
};
use rsync_transport::tcp::TcpTransport;
use rsync_winfs::{
    capture_ntfs_native_sidecar, copy_alternate_data_streams, read_windows_metadata,
    restore_safe_windows_attributes, to_long_path_safe, PosixAclRecord, PosixFakeSuperSidecar,
    PosixXattrRecord, WindowsDriveKind,
};

pub mod options;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliMetadataPolicy {
    Portable,
    Posix,
    NtfsNative,
}

impl From<CliMetadataPolicy> for MetadataPolicy {
    fn from(value: CliMetadataPolicy) -> Self {
        match value {
            CliMetadataPolicy::Portable => Self::Portable,
            CliMetadataPolicy::Posix => Self::Posix,
            CliMetadataPolicy::NtfsNative => Self::NtfsNative,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "rsync-win",
    disable_version_flag = true,
    about = "Native Windows rsync development build",
    long_about = "Native Windows rsync development build.\n\nThis build executes local portable syncs and an experimental remote-shell MVP for ordinary files/directories using rsync protocol 31 against modern peers, with protocol 27 compatibility code retained for fallback work."
)]
pub struct Cli {
    #[arg(short = 'V', long, action = ArgAction::SetTrue, help = "Print version")]
    version: bool,

    #[arg(long, help = "Print the supported rsync protocol version range")]
    protocol_range: bool,

    #[arg(long, action = ArgAction::SetTrue, help = "Print the transfer plan without executing it")]
    plan: bool,

    #[arg(short = 'r', long, action = ArgAction::SetTrue, help = "Recurse into directories")]
    recursive: bool,

    #[arg(skip)]
    no_recursive: bool,

    #[arg(short = 't', long = "times", action = ArgAction::SetTrue, help = "Preserve modification times")]
    preserve_times: bool,

    #[arg(skip)]
    no_times: bool,

    #[arg(short = 'a', long = "archive", action = ArgAction::SetTrue, help = "Enable archive mode as -rlptgoD, with unsupported metadata reported")]
    archive: bool,

    #[arg(short = 'n', long = "dry-run", action = ArgAction::SetTrue, help = "Plan actions without writing or deleting")]
    dry_run: bool,

    #[arg(long, action = ArgAction::SetTrue, help = "Delete receiver files that are not present on sender")]
    delete: bool,

    #[arg(skip)]
    delete_mode: DeleteMode,

    #[arg(long = "whole-file", action = ArgAction::SetTrue, help = "Use whole-file transfer planning")]
    whole_file: bool,

    #[arg(short = 'z', long = "compress", action = ArgAction::SetTrue, help = "Enable negotiated rsync compression where the active transfer mode supports it")]
    compress: bool,

    #[arg(skip)]
    compress_choice: Option<String>,

    #[arg(skip)]
    compress_level: Option<u32>,

    #[arg(skip)]
    compress_threads: Option<usize>,

    #[arg(skip)]
    skip_compress: Vec<String>,

    #[arg(skip)]
    quiet: u8,

    #[arg(skip)]
    human_readable: u8,

    #[arg(skip)]
    help: bool,

    #[arg(skip)]
    progress: bool,

    #[arg(skip)]
    relative: bool,

    #[arg(skip)]
    implied_dirs: bool,

    #[arg(skip)]
    transfer_dirs: bool,

    #[arg(skip)]
    mkpath: bool,

    #[arg(skip)]
    one_file_system: bool,

    #[arg(short = 'v', action = ArgAction::Count, help = "Increase verbosity")]
    verbosity: u8,

    #[arg(short = 'i', long = "itemize-changes", action = ArgAction::SetTrue, help = "Print rsync-style itemized changes")]
    itemize_changes: bool,

    #[arg(long = "stats", action = ArgAction::SetTrue, help = "Print structured transfer statistics")]
    stats: bool,

    #[arg(long = "list-only", action = ArgAction::SetTrue, help = "List daemon modules or remote entries without copying")]
    list_only: bool,

    #[arg(long = "metadata-policy", value_enum, default_value_t = CliMetadataPolicy::Portable, help = "Metadata compatibility policy")]
    metadata_policy: CliMetadataPolicy,

    #[arg(long, action = ArgAction::SetTrue, help = "Treat unsupported requested metadata as an error")]
    fail_on_metadata_loss: bool,

    #[arg(short = 'p', long = "perms", action = ArgAction::SetTrue, help = "Request POSIX permission preservation")]
    preserve_permissions: bool,

    #[arg(skip)]
    no_permissions: bool,

    #[arg(short = 'o', long = "owner", action = ArgAction::SetTrue, help = "Request POSIX owner preservation")]
    preserve_owner: bool,

    #[arg(short = 'g', long = "group", action = ArgAction::SetTrue, help = "Request POSIX group preservation")]
    preserve_group: bool,

    #[arg(long = "executability", action = ArgAction::SetTrue, help = "Preserve executable-ness where POSIX mode metadata is supported")]
    executability: bool,

    #[arg(long = "acls", action = ArgAction::SetTrue, help = "Request POSIX ACL preservation")]
    acls: bool,

    #[arg(long = "xattrs", action = ArgAction::SetTrue, help = "Request POSIX extended attribute preservation")]
    xattrs: bool,

    #[arg(long = "fake-super", action = ArgAction::SetTrue, help = "Request fake-super style metadata sidecar storage")]
    fake_super: bool,

    #[arg(skip)]
    atimes: bool,

    #[arg(skip)]
    crtimes: bool,

    #[arg(skip)]
    omit_dir_times: bool,

    #[arg(long = "omit-link-times", action = ArgAction::SetTrue, help = "Do not request symlink mtime preservation")]
    omit_link_times: bool,

    #[arg(long = "vss", action = ArgAction::SetTrue, help = "Request VSS snapshot source mode for ntfs-native transfers")]
    vss: bool,

    #[arg(skip)]
    daemon_server: bool,

    #[arg(skip)]
    internal_server: bool,

    #[arg(skip)]
    internal_sender: bool,

    #[arg(long = "include", help = "Add an include filter pattern")]
    includes: Vec<String>,

    #[arg(long = "exclude", help = "Add an exclude filter pattern")]
    excludes: Vec<String>,

    #[arg(long = "filter", help = "Add an rsync-style filter rule")]
    filters: Vec<String>,

    #[arg(skip)]
    exclude_from: Vec<PathBuf>,

    #[arg(skip)]
    include_from: Vec<PathBuf>,

    #[arg(skip)]
    cvs_exclude: bool,

    #[arg(
        long = "files-from",
        help = "Read the source file list from a newline-delimited or --from0 file"
    )]
    files_from: Option<std::path::PathBuf>,

    #[arg(long = "from0", action = ArgAction::SetTrue, help = "Interpret files-from records as NUL-delimited")]
    from0: bool,

    #[arg(short = 'c', long = "checksum", action = ArgAction::SetTrue, help = "Plan checksum-based updates")]
    checksum: bool,

    #[arg(skip)]
    checksum_choice: Option<String>,

    #[arg(skip)]
    checksum_seed: Option<i32>,

    #[arg(long = "size-only", action = ArgAction::SetTrue, help = "Plan updates using file size only")]
    size_only: bool,

    #[arg(long = "ignore-times", action = ArgAction::SetTrue, help = "Ignore quick-check times during planning")]
    ignore_times: bool,

    #[arg(long = "partial", action = ArgAction::SetTrue, help = "Keep partial files during real transfer execution")]
    partial: bool,

    #[arg(
        long = "partial-dir",
        help = "Directory for partial files during real transfer execution"
    )]
    partial_dir: Option<String>,

    #[arg(long = "inplace", action = ArgAction::SetTrue, help = "Plan in-place updates")]
    inplace: bool,

    #[arg(long = "append-verify", action = ArgAction::SetTrue, help = "Plan append-verify updates")]
    append_verify: bool,

    #[arg(skip)]
    append: bool,

    #[arg(skip)]
    update: bool,

    #[arg(skip)]
    existing: bool,

    #[arg(skip)]
    ignore_existing: bool,

    #[arg(skip)]
    max_size: Option<u64>,

    #[arg(skip)]
    min_size: Option<u64>,

    #[arg(skip)]
    modify_window: i64,

    #[arg(skip)]
    ignore_missing_args: bool,

    #[arg(skip)]
    delete_missing_args: bool,

    #[arg(skip)]
    delete_excluded: bool,

    #[arg(skip)]
    ignore_errors: bool,

    #[arg(skip)]
    force: bool,

    #[arg(skip)]
    max_delete: Option<usize>,

    #[arg(skip)]
    backup: bool,

    #[arg(skip)]
    backup_dir: Option<String>,

    #[arg(skip)]
    suffix: Option<String>,

    #[arg(skip)]
    temp_dir: Option<String>,

    #[arg(skip)]
    delay_updates: bool,

    #[arg(skip)]
    fsync: bool,

    #[arg(long = "numeric-ids", action = ArgAction::SetTrue, help = "Use numeric owner/group ids when supported")]
    numeric_ids: bool,

    #[arg(skip)]
    user_maps: Vec<String>,

    #[arg(skip)]
    group_maps: Vec<String>,

    #[arg(skip)]
    chown: Option<String>,

    #[arg(long = "no-o", alias = "no-owner", action = ArgAction::SetTrue, help = "Disable owner preservation requested by archive mode")]
    no_owner: bool,

    #[arg(long = "no-g", alias = "no-group", action = ArgAction::SetTrue, help = "Disable group preservation requested by archive mode")]
    no_group: bool,

    #[arg(
        long = "chmod",
        help = "Requested chmod expression, reported until implemented"
    )]
    chmod: Option<String>,

    #[arg(
        short = 'e',
        long = "rsh",
        value_name = "COMMAND",
        help = "Specify the remote shell command, e.g. \"ssh -p 10080\""
    )]
    remote_shell: Option<String>,

    #[arg(
        long = "password-file",
        help = "Read rsync daemon password from a local file"
    )]
    password_file: Option<PathBuf>,

    #[arg(long = "copy-links", action = ArgAction::SetTrue, help = "Copy symlink referents")]
    copy_links: bool,

    #[arg(long = "safe-links", action = ArgAction::SetTrue, help = "Ignore unsafe symlinks")]
    safe_links: bool,

    #[arg(long = "copy-unsafe-links", action = ArgAction::SetTrue, help = "Copy unsafe symlink referents")]
    copy_unsafe_links: bool,

    #[arg(skip)]
    copy_dirlinks: bool,

    #[arg(skip)]
    keep_dirlinks: bool,

    #[arg(skip)]
    munge_links: bool,

    #[arg(skip)]
    links: bool,

    #[arg(skip)]
    no_links: bool,

    #[arg(skip)]
    hard_links: bool,

    #[arg(skip)]
    devices: bool,

    #[arg(skip)]
    specials: bool,

    #[arg(skip)]
    no_devices: bool,

    #[arg(skip)]
    no_specials: bool,

    #[arg(skip)]
    copy_devices: bool,

    #[arg(skip)]
    write_devices: bool,

    #[arg(skip)]
    block_size: Option<u64>,

    #[arg(skip)]
    remote_options: Vec<String>,

    #[arg(skip)]
    rsync_path: Option<String>,

    #[arg(skip)]
    blocking_io: bool,

    #[arg(skip)]
    old_args: bool,

    #[arg(skip)]
    secluded_args: bool,

    #[arg(skip)]
    trust_sender: bool,

    #[arg(skip)]
    ipv4: bool,

    #[arg(skip)]
    ipv6: bool,

    #[arg(skip)]
    accepted_unsupported_options: Vec<String>,

    #[arg(help = "Source and destination operands")]
    paths: Vec<String>,
}

pub fn run_from_env() -> Result<()> {
    let cli = options::parse_cli(std::env::args_os())?;
    print!("{}", execute_or_render(&cli)?);
    Ok(())
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
    execute_local_sync(cli, plan)
}

#[derive(Debug, Clone)]
struct RemoteSourceEntry {
    wire: RsyncFileListEntry,
    local_path: PathBuf,
}

struct LocalSourceCollectContext<'a> {
    fs: &'a LocalFileSystem,
    options: &'a LocalSourceCollectOptions<'a>,
}

struct LocalSourceCollectOptions<'a> {
    recursive: bool,
    filter_rules: &'a RuleSet,
    files_from: Option<&'a [PathBuf]>,
    symlink_mode: SymlinkMode,
    include_checksums: bool,
    preserve_executability: bool,
    preserve_hard_links: bool,
    chmod_rules: Option<&'a ChmodRules>,
}

#[derive(Debug, Default, Clone, Copy)]
struct RemoteExecutionStats {
    files: usize,
    bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProgressLog {
    verbosity: u8,
}

impl ProgressLog {
    fn from_cli(cli: &Cli) -> Self {
        Self {
            verbosity: cli.verbosity,
        }
    }

    fn info(self, message: impl AsRef<str>) {
        if self.verbosity > 0 {
            eprintln!("rsync-win: {}", message.as_ref());
        }
    }

    fn detail(self, message: impl AsRef<str>) {
        if self.verbosity > 1 {
            eprintln!("rsync-win: {}", message.as_ref());
        }
    }

    fn enabled(self) -> bool {
        self.verbosity > 0
    }
}

#[derive(Debug)]
struct FileProgress {
    progress: ProgressLog,
    operation: &'static str,
    path: String,
    total: Option<u64>,
    started: Instant,
    last_report: Instant,
    transferred: u64,
}

impl FileProgress {
    fn start(
        progress: ProgressLog,
        operation: &'static str,
        path: &Path,
        total: Option<u64>,
    ) -> Self {
        let now = Instant::now();
        let meter = Self {
            progress,
            operation,
            path: path.display().to_string(),
            total,
            started: now,
            last_report: now,
            transferred: 0,
        };
        if progress.enabled() {
            match total {
                Some(total) => progress.info(format!(
                    "{}: {} ({})",
                    operation,
                    meter.path,
                    format_bytes(total)
                )),
                None => progress.info(format!("{}: {}", operation, meter.path)),
            }
        }
        meter
    }

    fn advance(&mut self, bytes: u64) {
        self.transferred += bytes;
        if !self.progress.enabled() || self.last_report.elapsed() < Duration::from_secs(2) {
            return;
        }

        self.report_progress();
        self.last_report = Instant::now();
    }

    fn finish(&mut self) {
        if self.progress.enabled() {
            self.report_finished();
        }
    }

    fn report_progress(&self) {
        let elapsed = self.started.elapsed();
        let rate = transfer_rate_label(self.transferred, elapsed);
        match self.total {
            Some(total) if total > 0 => {
                let percent = (self.transferred as f64 / total as f64 * 100.0).min(100.0);
                self.progress.info(format!(
                    "{}: {} {} / {} ({:.1}%, {})",
                    self.operation,
                    self.path,
                    format_bytes(self.transferred),
                    format_bytes(total),
                    percent,
                    rate
                ));
            }
            Some(_) | None => self.progress.info(format!(
                "{}: {} {} ({})",
                self.operation,
                self.path,
                format_bytes(self.transferred),
                rate
            )),
        }
    }

    fn report_finished(&self) {
        let elapsed = self.started.elapsed();
        let rate = transfer_rate_label(self.transferred, elapsed);
        match self.total {
            Some(total) if total > 0 => {
                let percent = (self.transferred as f64 / total as f64 * 100.0).min(100.0);
                self.progress.info(format!(
                    "{} done: {} {} / {} ({:.1}%, {}, {:.2}s)",
                    self.operation,
                    self.path,
                    format_bytes(self.transferred),
                    format_bytes(total),
                    percent,
                    rate,
                    elapsed.as_secs_f64()
                ));
            }
            Some(_) | None => self.progress.info(format!(
                "{} done: {} {} ({}, {:.2}s)",
                self.operation,
                self.path,
                format_bytes(self.transferred),
                rate,
                elapsed.as_secs_f64()
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteWireProtocol {
    Compat27,
    Modern31,
}

impl RemoteWireProtocol {
    fn protocol_number(self) -> u32 {
        match self {
            Self::Compat27 => REMOTE_SHELL_MVP_PROTOCOL,
            Self::Modern31 => REMOTE_SHELL_MODERN_PROTOCOL,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Compat27 => "protocol 27 compatibility mode",
            Self::Modern31 => "protocol 31 ordinary-file MVP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferMode {
    Local,
    RemoteShell,
    DaemonClient,
    DaemonServer,
    InternalServer,
}

impl TransferMode {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::RemoteShell => "remote-shell",
            Self::DaemonClient => "daemon-client",
            Self::DaemonServer => "daemon-server",
            Self::InternalServer => "internal-server",
        }
    }
}

fn transfer_direction_label(direction: TransferDirection) -> &'static str {
    match direction {
        TransferDirection::Push => "upload",
        TransferDirection::Pull => "download",
    }
}

const RSYNC31_MUX_FRAME_SIZE: usize = 32 * 1024;
const RSYNC_ITEM_BASIS_TYPE_FOLLOWS: u16 = 1 << 11;
const RSYNC_ITEM_XNAME_FOLLOWS: u16 = 1 << 12;
const RSYNC_ITEM_IS_NEW: u16 = 1 << 13;
const RSYNC_ITEM_LOCAL_CHANGE: u16 = 1 << 14;
const RSYNC_ITEM_TRANSFER: u16 = 1 << 15;

#[derive(Debug, Clone, Copy)]
struct RemoteSumHead {
    block_count: usize,
    block_len: usize,
    checksum_len: usize,
    remainder: usize,
}

#[derive(Debug, Default)]
struct Rsync31ItemAttrs {
    basis_type: Option<u8>,
    xname: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteChecksumAlgorithm {
    Md4,
    Md5,
}

impl RemoteChecksumAlgorithm {
    fn from_protocol31_choice(choice: Option<&str>) -> Result<Self> {
        match choice.map(normalize_checksum_choice).as_deref() {
            None | Some("md4") => Ok(Self::Md4),
            Some("md5") => Ok(Self::Md5),
            Some(other) => bail!("unsupported negotiated checksum algorithm `{other}`"),
        }
    }
}

fn normalize_checksum_choice(choice: &str) -> String {
    choice.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy)]
enum RemoteFileChecksum {
    SeededMd4(i32),
    PlainMd4,
    SeededMd5(i32),
    PlainMd5,
}

impl RemoteFileChecksum {
    fn md4_with_seed(seed: i32) -> Self {
        if seed == 0 {
            Self::PlainMd4
        } else {
            Self::SeededMd4(seed)
        }
    }

    fn protocol31(choice: Option<&str>, seed: i32) -> Result<Self> {
        Ok(
            match RemoteChecksumAlgorithm::from_protocol31_choice(choice)? {
                RemoteChecksumAlgorithm::Md4 => Self::md4_with_seed(seed),
                RemoteChecksumAlgorithm::Md5 if seed == 0 => Self::PlainMd5,
                RemoteChecksumAlgorithm::Md5 => Self::SeededMd5(seed),
            },
        )
    }

    fn algorithm(self) -> RemoteChecksumAlgorithm {
        match self {
            Self::SeededMd4(_) | Self::PlainMd4 => RemoteChecksumAlgorithm::Md4,
            Self::SeededMd5(_) | Self::PlainMd5 => RemoteChecksumAlgorithm::Md5,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RemoteFinalChecksum {
    PlainMd4,
    SeededMd4Prefix(i32),
    PlainMd5,
}

impl RemoteFinalChecksum {
    fn protocol27(seed: i32) -> Self {
        if seed == 0 {
            Self::PlainMd4
        } else {
            Self::SeededMd4Prefix(seed)
        }
    }

    fn protocol31(choice: Option<&str>) -> Result<Self> {
        Ok(Self::protocol31_for_algorithm(
            RemoteChecksumAlgorithm::from_protocol31_choice(choice)?,
        ))
    }

    fn protocol31_for_algorithm(algorithm: RemoteChecksumAlgorithm) -> Self {
        match algorithm {
            RemoteChecksumAlgorithm::Md4 => Self::PlainMd4,
            RemoteChecksumAlgorithm::Md5 => Self::PlainMd5,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct RemoteDeltaStats {
    literal_bytes: u64,
    copied_bytes: u64,
}

#[derive(Debug, Clone)]
struct RemoteCompressionConfig {
    mode: RsyncDeflatedTokenMode,
    level: u32,
    skip_suffixes: Vec<String>,
}

impl RemoteCompressionConfig {
    fn for_plan(plan: &TransferPlan) -> Result<Option<Self>> {
        if !plan.compress {
            return Ok(None);
        }
        let mode =
            RsyncDeflatedTokenMode::from_choice(plan.compress_choice.as_deref()).map_err(|_| {
                anyhow::anyhow!(
                    "unsupported compression choice; rsync-win currently supports zlibx and zlib"
                )
            })?;
        Ok(Some(Self {
            mode,
            level: plan.compress_level.unwrap_or(6).min(9),
            skip_suffixes: plan.skip_compress.clone(),
        }))
    }

    fn remote_choice(&self) -> &'static str {
        self.mode.remote_choice()
    }

    fn level_for_path(&self, path: &Path) -> u32 {
        if self.should_skip_path(path) {
            0
        } else {
            self.level
        }
    }

    fn should_skip_path(&self, path: &Path) -> bool {
        let path = path.to_string_lossy().to_ascii_lowercase();
        self.skip_suffixes
            .iter()
            .map(|suffix| {
                suffix
                    .trim()
                    .trim_start_matches("*.")
                    .trim_start_matches('.')
            })
            .filter(|suffix| !suffix.is_empty())
            .any(|suffix| path.ends_with(&format!(".{}", suffix.to_ascii_lowercase())))
    }
}

fn execute_daemon_sync(cli: &Cli, plan: TransferPlan) -> Result<String> {
    ensure_daemon_execution_options_supported(cli, &plan)?;

    let daemon = plan
        .daemon_operand
        .as_ref()
        .context("daemon operand was not planned")?;
    let progress = ProgressLog::from_cli(cli);
    progress.info(format!(
        "daemon connection started: {}:{}",
        daemon.host, daemon.port
    ));
    let mut transport =
        TcpTransport::connect((daemon.host.as_str(), daemon.port), Duration::from_secs(30))
            .with_context(|| format!("failed to connect to {}:{}", daemon.host, daemon.port))?;
    execute_daemon_sync_with_transport(cli, &plan, &mut transport)
}

fn execute_daemon_sync_with_transport<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    mut transport: &mut T,
) -> Result<String> {
    ensure_daemon_execution_options_supported(cli, plan)?;

    let daemon = plan
        .daemon_operand
        .as_ref()
        .context("daemon operand was not planned")?;
    let progress = ProgressLog::from_cli(cli);
    let greeting = exchange_daemon_greeting(&mut transport, REMOTE_SHELL_MODERN_PROTOCOL)
        .context("failed to exchange daemon greeting")?;
    progress.detail(format!(
        "daemon protocol: {}.{}",
        greeting.peer_protocol, greeting.peer_subprotocol
    ));

    if daemon.module.is_none() {
        let listing =
            request_module_list(&mut transport).context("failed to list daemon modules")?;
        let mut output = String::new();
        output.push_str("rsync-win daemon module list\n");
        output.push_str(&format!("endpoint: {}:{}\n", daemon.host, daemon.port));
        output.push_str(&format!(
            "protocol: {}.{}\n",
            greeting.peer_protocol, greeting.peer_subprotocol
        ));
        if !listing.motd.is_empty() {
            output.push_str("motd:\n");
            for line in listing.motd {
                output.push_str(&format!("- {line}\n"));
            }
        }
        output.push_str("modules:\n");
        if listing.modules.is_empty() {
            output.push_str("- <none>\n");
        } else {
            for module in listing.modules {
                output.push_str(&format!("- {}\t{}\n", module.name, module.comment));
            }
        }
        return Ok(output);
    }

    let module = daemon.module.as_deref().expect("checked module");
    match select_daemon_module(&mut transport, module).context("failed to select daemon module")? {
        DaemonModuleSelection::Ok { .. } => {}
        DaemonModuleSelection::AuthRequired { challenge, motd: _ } => {
            let password_file = cli
                .password_file
                .as_ref()
                .context("daemon module requires auth; pass --password-file")?;
            let password = read_password_file(password_file)?;
            let user = daemon_auth_user(daemon)?;
            authenticate_daemon_module(
                &mut transport,
                &user,
                &password,
                &challenge,
                greeting.auth_checksum,
            )
            .context("daemon authentication failed")?;
        }
    }

    let args = daemon_server_args_for_pull(cli, plan, daemon, greeting.peer_protocol)?;
    progress.detail(format!("daemon args: {} argument(s)", args.len()));
    write_daemon_args(&mut transport, greeting.peer_protocol, &args)
        .context("failed to send daemon server args")?;

    if greeting.peer_protocol >= REMOTE_SHELL_MODERN_PROTOCOL {
        let handshake = exchange_protocol31_setup_with_options(
            transport,
            greeting.peer_protocol,
            protocol31_setup_options_from_plan(plan),
        )
        .context("daemon protocol 31 setup failed")?;
        execute_remote_pull_protocol31_with_handshake(cli, plan, transport, handshake)
    } else {
        execute_remote_pull_protocol27(cli, plan, transport)
    }
}

fn daemon_server_args_for_pull(
    cli: &Cli,
    plan: &TransferPlan,
    daemon: &DaemonOperand,
    protocol: u32,
) -> Result<Vec<String>> {
    let path_arg = daemon_module_path_arg(daemon)?;
    let options = remote_shell_options_from_cli(
        cli,
        TransferDirection::Pull,
        plan.recursive,
        plan.preserve_times,
        plan.symlink_mode,
    );
    let argv = if protocol < REMOTE_SHELL_MODERN_PROTOCOL {
        build_remote_shell_argv_for_paths(&options, &[Path::new(&path_arg)])?
    } else {
        build_remote_shell_protocol31_argv_for_paths(&options, &[Path::new(&path_arg)])?
    };
    Ok(argv.into_iter().skip(1).collect())
}

fn daemon_module_path_arg(daemon: &DaemonOperand) -> Result<String> {
    daemon
        .module
        .as_ref()
        .context("daemon pull requires a module")?;
    Ok(match &daemon.path {
        Some(path) => path.clone(),
        None => ".".to_string(),
    })
}

fn daemon_auth_user(daemon: &DaemonOperand) -> Result<String> {
    if let Some(user) = daemon.user.as_deref() {
        return normalize_daemon_auth_user(user)
            .context("daemon auth username is empty or contains a NUL byte");
    }

    local_daemon_auth_user().context(
        "daemon module requires auth but no username was supplied; use user@host::module or set USER, LOGNAME, or USERNAME",
    )
}

fn local_daemon_auth_user() -> Option<String> {
    daemon_auth_user_from_vars([
        ("USER", std::env::var("USER").ok()),
        ("LOGNAME", std::env::var("LOGNAME").ok()),
        ("USERNAME", std::env::var("USERNAME").ok()),
    ])
}

fn daemon_auth_user_from_vars<I, K>(vars: I) -> Option<String>
where
    I: IntoIterator<Item = (K, Option<String>)>,
{
    vars.into_iter()
        .filter_map(|(_, value)| value)
        .find_map(|value| normalize_daemon_auth_user(&value))
}

fn normalize_daemon_auth_user(value: &str) -> Option<String> {
    let user = value.trim();
    if user.is_empty() || user.as_bytes().contains(&0) {
        None
    } else {
        Some(user.to_string())
    }
}

fn read_password_file(path: &Path) -> Result<String> {
    validate_password_file(path)?;
    let mut password = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon password file {}", path.display()))?;
    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }
    Ok(password)
}

fn validate_password_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect daemon password file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "daemon password file must be a regular file: {}",
            path.display()
        );
    }
    validate_password_file_permissions(path, &metadata)
}

#[cfg(unix)]
fn validate_password_file_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "daemon password file must not be accessible by group or other users: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_password_file_permissions(path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    if rsync_winfs::password_file_has_broad_access(path).with_context(|| {
        format!(
            "failed to inspect daemon password file ACL {}",
            path.display()
        )
    })? {
        bail!(
            "daemon password file must not grant read access to broad Windows principals: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_password_file_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

fn execute_remote_shell_sync(cli: &Cli, plan: TransferPlan) -> Result<String> {
    ensure_remote_execution_options_supported(cli, &plan)?;

    let progress = ProgressLog::from_cli(cli);
    let direction = plan
        .remote_direction
        .context("remote-shell direction was not planned")?;
    let command = plan
        .remote_ssh_command
        .as_ref()
        .context("remote-shell command was not planned")?;
    progress.info(format!(
        "remote-shell {} started: {}",
        transfer_direction_label(direction),
        remote_session_label(&plan, direction)
    ));
    progress.detail(format!("remote command: {}", command.display_command()));

    let mut transport = spawn_ssh_remote_command(command)
        .with_context(|| format!("failed to spawn {}", command.display_command()))?;
    if let Some(protected_args) = &plan.remote_protected_args {
        write_remote_shell_protected_args(&mut transport, protected_args)
            .context("failed to send remote-shell protected args")?;
    }

    let session_result = match direction {
        TransferDirection::Push => execute_remote_push(cli, &plan, &mut transport),
        TransferDirection::Pull => execute_remote_pull(cli, &plan, &mut transport),
    };

    transport.finish_input();
    let child_report = transport
        .wait_with_diagnostics()
        .context("failed to wait for remote-shell child process")?;
    let stderr = String::from_utf8_lossy(&child_report.stderr)
        .trim()
        .to_string();

    let output = match session_result {
        Ok(output) => output,
        Err(err) => {
            if plan.remote_wire_protocol == Some(RemoteWireProtocol::Modern31)
                && should_fallback_to_protocol27(&err)
            {
                return execute_remote_shell_protocol27_fallback(cli, &plan, direction);
            }
            if stderr.is_empty() {
                bail!("remote-shell session failed: {err}");
            }
            bail!("remote-shell session failed: {err}; remote stderr: {stderr}");
        }
    };
    if !child_report.status.success() {
        if stderr.is_empty() {
            bail!("remote rsync exited with status {}", child_report.status);
        }
        bail!(
            "remote rsync exited with status {}; remote stderr: {}",
            child_report.status,
            stderr
        );
    }

    Ok(output)
}

fn execute_remote_shell_protocol27_fallback(
    cli: &Cli,
    plan: &TransferPlan,
    direction: TransferDirection,
) -> Result<String> {
    let (command, protected_args) = build_protocol27_fallback_command(cli, plan, direction)?;
    ProgressLog::from_cli(cli).info(format!(
        "remote-shell protocol 31 was not accepted; retrying {} via {}",
        transfer_direction_label(direction),
        command.display_command()
    ));
    let mut transport = spawn_ssh_remote_command(&command)
        .with_context(|| format!("failed to spawn {}", command.display_command()))?;
    write_remote_shell_protected_args(&mut transport, &protected_args)
        .context("failed to send remote-shell protected args for protocol 27 fallback")?;

    let session_result = match direction {
        TransferDirection::Push => execute_remote_push_protocol27(cli, plan, &mut transport),
        TransferDirection::Pull => execute_remote_pull_protocol27(cli, plan, &mut transport),
    };

    transport.finish_input();
    let child_report = transport
        .wait_with_diagnostics()
        .context("failed to wait for remote-shell child process")?;
    let stderr = String::from_utf8_lossy(&child_report.stderr)
        .trim()
        .to_string();

    let output = match session_result {
        Ok(output) => output,
        Err(err) => {
            if stderr.is_empty() {
                bail!("remote-shell protocol 27 fallback failed: {err}");
            }
            bail!("remote-shell protocol 27 fallback failed: {err}; remote stderr: {stderr}");
        }
    };
    if !child_report.status.success() {
        if stderr.is_empty() {
            bail!(
                "remote rsync protocol 27 fallback exited with status {}",
                child_report.status
            );
        }
        bail!(
            "remote rsync protocol 27 fallback exited with status {}; remote stderr: {}",
            child_report.status,
            stderr
        );
    }

    Ok(output)
}

fn build_protocol27_fallback_command(
    cli: &Cli,
    plan: &TransferPlan,
    direction: TransferDirection,
) -> Result<(SshRemoteCommand, Vec<String>)> {
    let remote = plan
        .remote_operand
        .as_ref()
        .context("remote operand was not planned")?;
    let protocol = RemoteWireProtocol::Compat27;
    debug_assert_eq!(protocol.protocol_number(), REMOTE_SHELL_MVP_PROTOCOL);
    let remote_paths: Vec<PathBuf> =
        if direction == TransferDirection::Pull && !plan.remote_operands.is_empty() {
            plan.remote_operands
                .iter()
                .map(|operand| PathBuf::from(&operand.path))
                .collect()
        } else {
            vec![PathBuf::from(&remote.path)]
        };
    let remote_path_refs: Vec<&Path> = remote_paths.iter().map(PathBuf::as_path).collect();
    let (includes, excludes, filters) = remote_receiver_filter_args_from_cli(cli, direction);
    let remote_compression = RemoteCompressionConfig::for_plan(plan)?;
    let invocation = build_remote_shell_invocation_for_paths(
        &RemoteShellOptions {
            rsync_path: plan
                .rsync_path
                .clone()
                .unwrap_or_else(|| "rsync".to_string()),
            direction,
            secluded_args: plan.secluded_args,
            recursive: plan.recursive,
            preserve_times: plan.preserve_times,
            delete_mode: remote_delete_mode(plan.delete, plan.delete_mode),
            dry_run: plan.dry_run,
            whole_file: plan.whole_file
                && !(direction == TransferDirection::Push && plan.append_verify),
            verbosity: plan.verbosity,
            preserve_permissions: plan.preserve_permissions,
            checksum: plan.update_mode == UpdateMode::Checksum,
            checksum_choice: plan.checksum_choice.clone(),
            checksum_seed: plan.checksum_seed,
            size_only: direction == TransferDirection::Push
                && plan.update_mode == UpdateMode::SizeOnly,
            ignore_times: direction == TransferDirection::Push
                && plan.update_mode == UpdateMode::IgnoreTimes,
            partial: direction == TransferDirection::Push && plan.keep_partial,
            partial_dir: if direction == TransferDirection::Push {
                plan.partial_dir
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
            } else {
                None
            },
            inplace: direction == TransferDirection::Push
                && plan.file_write_mode == FileWriteMode::InPlace,
            append_verify: direction == TransferDirection::Push && plan.append_verify,
            executability: direction == TransferDirection::Push && plan.preserve_executability,
            preserve_owner: direction == TransferDirection::Push && plan.preserve_owner,
            preserve_group: direction == TransferDirection::Push && plan.preserve_group,
            numeric_ids: direction == TransferDirection::Push && plan.numeric_ids,
            user_maps: if direction == TransferDirection::Push {
                plan.user_maps.clone()
            } else {
                Vec::new()
            },
            group_maps: if direction == TransferDirection::Push {
                plan.group_maps.clone()
            } else {
                Vec::new()
            },
            chown: if direction == TransferDirection::Push {
                plan.chown.clone()
            } else {
                None
            },
            chmod: if direction == TransferDirection::Push {
                plan.chmod.clone()
            } else {
                None
            },
            acls: direction == TransferDirection::Push && plan.preserve_acls,
            xattrs: direction == TransferDirection::Push && plan.preserve_xattrs,
            fake_super: direction == TransferDirection::Push && plan.fake_super,
            atimes: direction == TransferDirection::Push && plan.atimes,
            crtimes: direction == TransferDirection::Push && plan.crtimes,
            omit_dir_times: plan.omit_dir_times,
            omit_link_times: plan.omit_link_times,
            preserve_links: direction == TransferDirection::Push
                && plan.symlink_mode == SymlinkMode::Preserve
                && (cli.links || cli.archive),
            copy_links: direction == TransferDirection::Pull
                && plan.symlink_mode == SymlinkMode::CopyAll,
            copy_dirlinks: plan.symlink_mode == SymlinkMode::CopyDirLinks,
            keep_dirlinks: plan.keep_dirlinks,
            safe_links: direction == TransferDirection::Push
                && plan.symlink_mode == SymlinkMode::SafeOnly,
            copy_unsafe_links: direction == TransferDirection::Pull
                && plan.symlink_mode == SymlinkMode::CopyUnsafe,
            munge_links: plan.symlink_mode == SymlinkMode::Munge,
            hard_links: plan.hard_links,
            preserve_devices: plan.preserve_devices,
            preserve_specials: plan.preserve_specials,
            copy_devices: cli.copy_devices,
            write_devices: cli.write_devices,
            block_size: plan.block_size,
            compress: plan.compress,
            compress_choice: remote_compression
                .as_ref()
                .map(|compression| compression.remote_choice().to_string()),
            compress_level: plan.compress_level,
            compress_threads: plan.compress_threads,
            skip_compress: plan.skip_compress.clone(),
            remote_options: plan.remote_options.clone(),
            includes,
            excludes,
            filters,
        },
        &remote_path_refs,
    )?;
    Ok((
        build_remote_transport_command(cli, &remote.host, &invocation.argv)?,
        invocation.protected_args,
    ))
}

fn build_remote_transport_command(
    cli: &Cli,
    host: &str,
    remote_server_argv: &[String],
) -> Result<SshRemoteCommand> {
    let options = remote_shell_command_options_from_cli(cli);
    if let Some(remote_shell) = &cli.remote_shell {
        return Ok(build_custom_remote_shell_command_with_options(
            remote_shell,
            host,
            remote_server_argv,
            options,
        )?);
    }

    Ok(build_ssh_remote_command_with_options(
        default_ssh_program().into_os_string(),
        host,
        remote_server_argv,
        options,
    ))
}

fn remote_shell_command_options_from_cli(cli: &Cli) -> RemoteShellCommandOptions {
    let address_family = if cli.ipv4 {
        Some(SshAddressFamily::Ipv4)
    } else if cli.ipv6 {
        Some(SshAddressFamily::Ipv6)
    } else {
        None
    };
    RemoteShellCommandOptions {
        address_family,
        blocking_io: cli.blocking_io,
        old_args: cli.old_args,
    }
}

fn should_fallback_to_protocol27(err: &anyhow::Error) -> bool {
    if let Some(setup_err) = err.downcast_ref::<Protocol31SetupError>() {
        return should_fallback_to_protocol27_from_setup(&setup_err.source);
    }

    should_fallback_to_protocol27_from_negotiation(err)
}

fn should_fallback_to_protocol27_from_setup(err: &anyhow::Error) -> bool {
    should_fallback_to_protocol27_from_negotiation(err) || is_unexpected_eof(err)
}

fn should_fallback_to_protocol27_from_negotiation(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<RemoteSessionError>(),
        Some(
            RemoteSessionError::UnsupportedProtocol { .. }
                | RemoteSessionError::UnsupportedChecksumNegotiation
                | RemoteSessionError::InvalidChecksumList
                | RemoteSessionError::Session(
                    SessionError::NonProtocolOutput(_)
                        | SessionError::IncompleteProtocolPrefix
                        | SessionError::InvalidProtocolPrefix(_)
                )
        )
    )
}

fn is_unexpected_eof(err: &anyhow::Error) -> bool {
    if let Some(io_error) = err.downcast_ref::<std::io::Error>() {
        return io_error.kind() == std::io::ErrorKind::UnexpectedEof;
    }
    matches!(
        err.downcast_ref::<RemoteSessionError>(),
        Some(RemoteSessionError::Io(io_error))
            if io_error.kind() == std::io::ErrorKind::UnexpectedEof
    )
}

#[derive(Debug)]
struct Protocol31SetupError {
    source: anyhow::Error,
}

impl fmt::Display for Protocol31SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "protocol 31 setup failed: {}", self.source)
    }
}

impl std::error::Error for Protocol31SetupError {}

fn protocol31_setup_error<E>(err: E) -> anyhow::Error
where
    E: Into<anyhow::Error>,
{
    anyhow::Error::new(Protocol31SetupError { source: err.into() })
}

fn execute_remote_push<T: Read + Write>(
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

fn execute_remote_push_protocol27<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    let progress = ProgressLog::from_cli(cli);
    let sources = local_source_paths(cli);
    log_source_storage_notes(progress, &sources);
    let files_from = load_files_from(cli)?;
    progress.info("building upload file list");
    let collect_options = local_source_collect_options(plan, files_from.as_deref());
    let entries = collect_local_source_entries(&sources, &collect_options)?;
    let wire_entries: Vec<_> = entries.iter().map(|entry| entry.wire.clone()).collect();
    let (file_count, total_file_bytes) = remote_entries_file_summary(&entries);
    progress.info(format!(
        "upload list: {} files, {}",
        file_count,
        format_bytes(total_file_bytes)
    ));
    progress.detail(format!("upload list entries: {}", entries.len(),));

    let handshake = exchange_remote_shell_mvp_handshake(transport)?;
    progress.detail(format!(
        "protocol: rsync {}",
        handshake.selected_protocol.value()
    ));
    if plan.delete {
        write_rsync_i32(transport, 0)?;
    }
    write_rsync27_file_list_with_options(
        transport,
        &wire_entries,
        plan.update_mode == UpdateMode::Checksum,
    )?;
    write_rsync_i32(transport, 0)?;
    transport.flush()?;

    let mut mux = MultiplexReadState::default();
    let remote_compression = RemoteCompressionConfig::for_plan(plan)?;
    let stats = serve_remote_receiver_requests(
        transport,
        &mut mux,
        &entries,
        handshake.checksum_seed,
        plan.dry_run,
        remote_compression.as_ref(),
        progress,
    )?;

    let remote = plan
        .remote_operand
        .as_ref()
        .context("remote operand was not planned")?;
    let mut output = String::new();
    output.push_str("rsync-win remote-shell push\n");
    output.push_str("direction: upload (local -> remote)\n");
    append_sources_summary(&mut output, &sources);
    append_source_storage_notes(&mut output, &sources);
    output.push_str(&format!("destination: {}:{}\n", remote.host, remote.path));
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
    append_remote_push_quick_check_note(&mut output, plan, file_count, total_file_bytes, stats);
    append_remote_messages(&mut output, &mux);
    Ok(output)
}

fn execute_remote_push_protocol31<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    let progress = ProgressLog::from_cli(cli);
    let sources = local_source_paths(cli);
    log_source_storage_notes(progress, &sources);
    let files_from = load_files_from(cli)?;
    progress.info("building upload file list");
    let collect_options = local_source_collect_options(plan, files_from.as_deref());
    let entries = collect_local_source_entries(&sources, &collect_options)?;
    let wire_entries: Vec<_> = entries.iter().map(|entry| entry.wire.clone()).collect();
    let (file_count, total_file_bytes) = remote_entries_file_summary(&entries);
    progress.info(format!(
        "upload list: {} files, {}",
        file_count,
        format_bytes(total_file_bytes)
    ));
    progress.detail(format!("upload list entries: {}", entries.len(),));

    let handshake = exchange_remote_shell_protocol31_handshake_with_options(
        transport,
        protocol31_setup_options_from_plan(plan),
    )
    .map_err(protocol31_setup_error)?;
    progress.detail(format!(
        "protocol: rsync {}",
        handshake.selected_protocol.value()
    ));
    if plan.delete {
        let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
        write_i32_le(&mut writer, 0).map_err(protocol31_setup_error)?;
        writer.flush().map_err(protocol31_setup_error)?;
    }
    {
        let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
        write_rsync31_file_list_with_metadata(
            &mut writer,
            &wire_entries,
            RsyncFileListOptions {
                include_checksums: plan.update_mode == UpdateMode::Checksum,
                preserve_owner: plan.preserve_owner,
                preserve_group: plan.preserve_group,
                numeric_ids: plan.numeric_ids,
                acls: plan.preserve_acls,
                xattrs: plan.preserve_xattrs,
                fake_super: plan.fake_super,
                atimes: plan.atimes,
                crtimes: plan.crtimes,
            },
        )
        .map_err(protocol31_setup_error)?;
        writer.flush().map_err(protocol31_setup_error)?;
    }

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
        remote_compression.as_ref(),
        progress,
    )?;

    let remote = plan
        .remote_operand
        .as_ref()
        .context("remote operand was not planned")?;
    let mut output = String::new();
    output.push_str("rsync-win remote-shell push\n");
    output.push_str("direction: upload (local -> remote)\n");
    append_sources_summary(&mut output, &sources);
    append_source_storage_notes(&mut output, &sources);
    output.push_str(&format!("destination: {}:{}\n", remote.host, remote.path));
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
    append_remote_push_quick_check_note(&mut output, plan, file_count, total_file_bytes, stats);
    append_remote_messages(&mut output, &mux);
    Ok(output)
}

fn execute_remote_pull<T: Read + Write>(
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

fn execute_remote_pull_protocol27<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
) -> Result<String> {
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
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

fn execute_remote_pull_protocol31_with_handshake<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    transport: &mut T,
    handshake: rsync_protocol::RemoteShellHandshake,
) -> Result<String> {
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
    let mut mux = MultiplexReadState::default();

    {
        let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
        write_i32_le(&mut writer, 0).map_err(protocol31_setup_error)?;
        writer.flush().map_err(protocol31_setup_error)?;
    }

    let mut entries = {
        let mut reader = MultiplexedReader::new(transport, &mut mux);
        read_rsync31_file_list_with_options(
            &mut reader,
            DEFAULT_MAX_FILE_LIST_ENTRIES,
            DEFAULT_MAX_FILE_LIST_PATH_LEN,
            plan.update_mode == UpdateMode::Checksum,
        )
        .map_err(protocol31_setup_error)?
    };
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
        &entries,
        &transfer_indexes,
        index_offset,
        plan.dry_run,
        dest,
        remote_delta_block_size(plan)?,
        plan.whole_file,
        remote_file_checksum,
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
    output.push_str(&format!("files received: {}\n", stats.files));
    output.push_str(&format!("bytes received: {}\n", stats.bytes));
    append_remote_messages(&mut output, &mux);
    Ok(output)
}

fn execute_local_sync(cli: &Cli, plan: TransferPlan) -> Result<String> {
    let sources = local_source_paths(cli);
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
    let files_from = load_files_from(cli)?;
    let ntfs_files_from = files_from.clone();
    let mut fs = LocalFileSystem;
    let progress = ProgressLog::from_cli(cli);
    progress.info(format!(
        "local sync starting: {} source(s) -> {}",
        sources.len(),
        dest.display()
    ));
    let sync_report = sync_sources(
        &mut fs,
        &sources,
        dest,
        SyncOptions {
            recursive: plan.recursive,
            delete: plan.delete,
            delete_mode: plan.delete_mode,
            preserve_mtime: plan.preserve_times,
            omit_dir_times: plan.omit_dir_times,
            dry_run: plan.dry_run,
            filter_rules: plan.filter_rules.clone(),
            destination_path_preflight: Some(windows_destination_path_preflight),
            update_mode: plan.update_mode,
            files_from,
            file_write_mode: plan.file_write_mode,
            keep_partial: plan.keep_partial,
            partial_dir: plan.partial_dir.clone(),
            temp_dir: plan.temp_dir.clone(),
            delay_updates: plan.delay_updates,
            fsync: plan.fsync,
            append_verify: plan.append_verify,
            symlink_mode: plan.symlink_mode,
            transfer_dirs: plan.transfer_dirs,
            mkpath: plan.mkpath,
            relative_paths: plan.relative,
            implied_dirs: plan.implied_dirs,
            one_file_system: plan.one_file_system,
            skip_newer_receiver: plan.skip_newer_receiver,
            existing_only: plan.existing_only,
            ignore_existing: plan.ignore_existing,
            max_size: plan.max_size,
            min_size: plan.min_size,
            modify_window: plan.modify_window,
            ignore_missing_args: plan.ignore_missing_args,
            delete_missing_args: plan.delete_missing_args,
            delete_excluded: plan.delete_excluded,
            ignore_errors: plan.ignore_errors,
            force_delete: plan.force_delete,
            max_delete: plan.max_delete,
            backup: plan.backup,
            backup_dir: plan.backup_dir.clone(),
            backup_suffix: plan.backup_suffix.clone(),
            preserve_hard_links: plan.hard_links,
            keep_dirlinks: plan.keep_dirlinks,
            preserve_devices: plan.preserve_devices,
            preserve_specials: plan.preserve_specials,
            fail_on_metadata_loss: cli.fail_on_metadata_loss,
        },
    )?;
    log_sync_actions(progress, sync_report.actions());
    progress.info(format!(
        "local sync finished: {} action(s)",
        sync_report.actions().len()
    ));
    let ntfs_sidecars =
        handle_ntfs_native_sidecars(&sources, dest, &plan, ntfs_files_from.as_deref())?;
    let posix_sidecars =
        handle_posix_fake_super_sidecars(&sources, dest, &plan, ntfs_files_from.as_deref())?;

    let mut output = String::new();
    output.push_str("rsync-win local portable sync\n");
    append_sources_summary(&mut output, &sources);
    output.push_str(&format!("destination: {}\n", dest.display()));
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    output.push_str(&format!("metadata policy: {}\n", plan.metadata_policy));
    output.push_str(&format!(
        "posix metadata: {}\n",
        posix_metadata_summary(&plan)
    ));
    if plan.metadata_policy == MetadataPolicy::NtfsNative || plan.vss {
        output.push_str(&format!(
            "ntfs-native metadata: sidecar-capture prototype, vss={}\n",
            plan.vss
        ));
    }
    if let Some(sidecars) = ntfs_sidecars {
        output.push_str(&format!(
            "ntfs sidecars: planned {}, written {}\n",
            sidecars.planned, sidecars.written
        ));
        output.push_str(&format!(
            "ntfs attributes: applied {}, degraded {}\n",
            sidecars.attributes_applied, sidecars.attributes_degraded
        ));
        output.push_str(&format!(
            "ntfs streams: copied {}, degraded {}\n",
            sidecars.streams_copied, sidecars.streams_degraded
        ));
        output.push_str(&format!("ntfs sidecar root: {}\n", sidecars.root.display()));
    }
    if let Some(sidecars) = posix_sidecars {
        output.push_str(&format!(
            "posix sidecars: planned {}, written {}\n",
            sidecars.planned, sidecars.written
        ));
        output.push_str(&format!(
            "posix sidecar root: {}\n",
            sidecars.root.display()
        ));
    }

    if !plan.report.is_empty() {
        output.push_str("diagnostics:\n");
        append_diagnostics(&mut output, &plan.report);
    }

    append_action_report(&mut output, cli, sync_report.actions());

    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NtfsSidecarExecution {
    root: PathBuf,
    planned: usize,
    written: usize,
    attributes_applied: usize,
    attributes_degraded: usize,
    streams_copied: usize,
    streams_degraded: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PosixSidecarExecution {
    root: PathBuf,
    planned: usize,
    written: usize,
}

fn handle_ntfs_native_sidecars(
    sources: &[PathBuf],
    dest: &Path,
    plan: &TransferPlan,
    files_from: Option<&[PathBuf]>,
) -> Result<Option<NtfsSidecarExecution>> {
    if plan.metadata_policy != MetadataPolicy::NtfsNative {
        return Ok(None);
    }

    let fs = LocalFileSystem;
    let sidecar_root = ntfs_sidecar_root(dest);
    let capture_paths = collect_ntfs_sidecar_paths(&fs, sources, plan, files_from)?;
    if plan.dry_run {
        return Ok(Some(NtfsSidecarExecution {
            root: sidecar_root,
            planned: capture_paths.len(),
            written: 0,
            attributes_applied: 0,
            attributes_degraded: 0,
            streams_copied: 0,
            streams_degraded: 0,
        }));
    }

    fs::create_dir_all(&sidecar_root)?;
    let mut written = 0;
    let mut attributes_applied = 0;
    let mut attributes_degraded = 0;
    let mut streams_copied = 0;
    let mut streams_degraded = 0;
    for source_path in &capture_paths {
        let sidecar = capture_ntfs_native_sidecar(source_path, plan.vss)
            .with_context(|| format!("capture NTFS metadata for {}", source_path.display()))?;
        if let Some(target_path) = ntfs_destination_for_source(sources, dest, source_path) {
            if target_path.exists() {
                if sidecar.file_type == FileType::File {
                    let report = copy_alternate_data_streams(source_path, &target_path)
                        .with_context(|| {
                            format!("copy alternate data streams to {}", target_path.display())
                        })?;
                    streams_copied += report.copied;
                    if report.unavailable && !sidecar.streams.is_empty() {
                        streams_degraded += sidecar.streams.len();
                    }
                }
                let restore = restore_safe_windows_attributes(&target_path, sidecar.attributes)
                    .with_context(|| {
                        format!(
                            "restore safe Windows attributes for {}",
                            target_path.display()
                        )
                    })?;
                if restore.applied_mask != 0 {
                    attributes_applied += 1;
                }
                if restore.degraded_mask != 0 || !restore.available {
                    attributes_degraded += 1;
                }
            } else if sidecar.attributes.is_some() {
                attributes_degraded += 1;
                streams_degraded += sidecar.streams.len();
            }
        }
        let relative = ntfs_sidecar_relative_name(sources, source_path);
        let manifest_path = sidecar_root.join(format!("{relative}.ntfs.meta"));
        fs::write(&manifest_path, sidecar.manifest())?;
        written += 1;
    }

    Ok(Some(NtfsSidecarExecution {
        root: sidecar_root,
        planned: capture_paths.len(),
        written,
        attributes_applied,
        attributes_degraded,
        streams_copied,
        streams_degraded,
    }))
}

fn handle_posix_fake_super_sidecars(
    sources: &[PathBuf],
    dest: &Path,
    plan: &TransferPlan,
    files_from: Option<&[PathBuf]>,
) -> Result<Option<PosixSidecarExecution>> {
    if !plan.fake_super
        && !plan.preserve_acls
        && !plan.preserve_xattrs
        && !plan.atimes
        && !plan.crtimes
        && plan.chown.is_none()
        && plan.user_maps.is_empty()
        && plan.group_maps.is_empty()
    {
        return Ok(None);
    }

    let fs = LocalFileSystem;
    let sidecar_root = posix_sidecar_root(dest);
    let capture_paths = collect_ntfs_sidecar_paths(&fs, sources, plan, files_from)?;
    if plan.dry_run {
        return Ok(Some(PosixSidecarExecution {
            root: sidecar_root,
            planned: capture_paths.len(),
            written: 0,
        }));
    }

    fs::create_dir_all(&sidecar_root)?;
    let mut written = 0;
    for source_path in &capture_paths {
        let sidecar = capture_posix_fake_super_sidecar(source_path, plan)
            .with_context(|| format!("capture POSIX sidecar for {}", source_path.display()))?;
        let relative = ntfs_sidecar_relative_name(sources, source_path);
        let manifest_path = sidecar_root.join(format!("{relative}.posix.meta"));
        fs::write(&manifest_path, sidecar.manifest())?;
        written += 1;
    }

    Ok(Some(PosixSidecarExecution {
        root: sidecar_root,
        planned: capture_paths.len(),
        written,
    }))
}

fn capture_posix_fake_super_sidecar(
    path: &Path,
    plan: &TransferPlan,
) -> Result<PosixFakeSuperSidecar> {
    let metadata = read_windows_metadata(path)?;
    let mode = posix_sidecar_mode(&metadata.portable, path, plan);
    let std_metadata = fs::symlink_metadata(path)?;

    Ok(PosixFakeSuperSidecar {
        path: path.to_path_buf(),
        mode: Some(mode),
        uid: None,
        gid: None,
        user_name: plan.chown.as_ref().and_then(|chown| {
            let (user, _) = chown.split_once(':').unwrap_or((chown.as_str(), ""));
            (!user.is_empty()).then(|| user.to_string())
        }),
        group_name: plan.chown.as_ref().and_then(|chown| {
            let (_, group) = chown.split_once(':').unwrap_or(("", ""));
            (!group.is_empty()).then(|| group.to_string())
        }),
        access_time_unix_nanos: plan
            .atimes
            .then(|| {
                std_metadata
                    .accessed()
                    .ok()
                    .and_then(system_time_to_unix_nanos)
            })
            .flatten(),
        creation_time_unix_nanos: plan
            .crtimes
            .then(|| {
                read_windows_metadata(path)
                    .ok()?
                    .creation_time
                    .and_then(system_time_to_unix_nanos)
            })
            .flatten(),
        acls: if plan.preserve_acls {
            vec![PosixAclRecord {
                tag: "windows-security-descriptor".to_string(),
                qualifier: None,
                perms: "stored".to_string(),
            }]
        } else {
            Vec::new()
        },
        xattrs: if plan.preserve_xattrs {
            vec![PosixXattrRecord {
                name: "rsync.%stat".to_string(),
                value_hex: format!("{mode:08x}"),
            }]
        } else {
            Vec::new()
        },
        fake_super: plan.fake_super,
    })
}

fn posix_sidecar_mode(
    metadata: &rsync_fs::PortableMetadata,
    path: &Path,
    plan: &TransferPlan,
) -> u32 {
    let mut mode = metadata.posix_mode_for_path(Some(path), plan.preserve_executability);
    if let Some(chmod_rules) = &plan.chmod_rules {
        let kind = if metadata.file_type == FileType::Directory {
            ChmodFileKind::Directory
        } else {
            ChmodFileKind::File
        };
        mode = chmod_rules.apply(mode, kind);
    }
    mode
}

fn posix_sidecar_root(dest: &Path) -> PathBuf {
    let dest_is_file = fs::metadata(dest)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    if dest_is_file {
        dest.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".rsync-win.fake-super")
    } else {
        dest.join(".rsync-win.fake-super")
    }
}

fn ntfs_destination_for_source(
    sources: &[PathBuf],
    dest: &Path,
    source_path: &Path,
) -> Option<PathBuf> {
    if sources.len() == 1 {
        let source = &sources[0];
        let source_metadata = fs::metadata(source).ok()?;
        if source_path == source {
            if source_metadata.is_file()
                && fs::metadata(dest)
                    .map(|metadata| metadata.is_dir())
                    .unwrap_or(false)
            {
                return source.file_name().map(|name| dest.join(name));
            }
            return Some(dest.to_path_buf());
        }
        return source_path
            .strip_prefix(source)
            .ok()
            .map(|relative| dest.join(relative));
    }

    for source in sources {
        if source_path == source {
            return source.file_name().map(|name| dest.join(name));
        }
        if let Ok(relative) = source_path.strip_prefix(source) {
            return source
                .file_name()
                .map(|name| dest.join(name).join(relative));
        }
    }
    None
}

fn collect_ntfs_sidecar_paths(
    fs: &LocalFileSystem,
    sources: &[PathBuf],
    plan: &TransferPlan,
    files_from: Option<&[PathBuf]>,
) -> Result<Vec<PathBuf>> {
    Ok(selected_source_paths(
        fs,
        sources,
        SourceSelectionOptions {
            recursive: plan.recursive,
            filter_rules: &plan.filter_rules,
            files_from,
            symlink_mode: plan.symlink_mode,
            one_file_system: plan.one_file_system,
        },
    )?)
}

fn ntfs_sidecar_root(dest: &Path) -> PathBuf {
    let dest_is_file = fs::metadata(dest)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    if dest_is_file {
        dest.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".rsync-win.ntfs-native")
    } else {
        dest.join(".rsync-win.ntfs-native")
    }
}

fn ntfs_sidecar_relative_name(sources: &[PathBuf], path: &Path) -> String {
    let relative = sources
        .iter()
        .find_map(|source| {
            if path == source {
                source.file_name().map(PathBuf::from)
            } else {
                path.strip_prefix(source).ok().map(|relative| {
                    source
                        .file_name()
                        .map(|name| PathBuf::from(name).join(relative))
                        .unwrap_or_else(|| relative.to_path_buf())
                })
            }
        })
        .unwrap_or_else(|| path.file_name().map(PathBuf::from).unwrap_or_default());
    let display_name = sanitize_sidecar_name(&relative);
    let hash = stable_sidecar_path_hash(&relative);
    format!("{display_name}--{hash:016x}")
}

fn sanitize_sidecar_name(path: &Path) -> String {
    let mut name = String::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        if !name.is_empty() {
            name.push_str("__");
        }
        for ch in part.to_string_lossy().chars() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                name.push(ch);
            } else {
                name.push('_');
            }
        }
    }
    if name.is_empty() {
        "_root".to_string()
    } else {
        name
    }
}

fn stable_sidecar_path_hash(path: &Path) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        for byte in part.to_string_lossy().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn local_source_paths(cli: &Cli) -> Vec<PathBuf> {
    cli.paths[..cli.paths.len() - 1]
        .iter()
        .map(PathBuf::from)
        .collect()
}

fn append_sources_summary(output: &mut String, sources: &[PathBuf]) {
    if sources.len() == 1 {
        output.push_str(&format!("source: {}\n", sources[0].display()));
        return;
    }

    output.push_str(&format!("sources: {}\n", sources.len()));
    for source in sources {
        output.push_str(&format!("- source {}\n", source.display()));
    }
}

fn append_pull_sources_summary(output: &mut String, plan: &TransferPlan) -> Result<()> {
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

fn remote_session_label(plan: &TransferPlan, direction: TransferDirection) -> String {
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

fn remote_entries_file_summary(entries: &[RemoteSourceEntry]) -> (usize, u64) {
    entries
        .iter()
        .filter(|entry| entry.wire.file_type == WireFileType::File)
        .fold((0_usize, 0_u64), |(count, bytes), entry| {
            (count + 1, bytes + entry.wire.len)
        })
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let value = bytes as f64;
    if value >= GIB {
        format!("{:.2} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.2} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.2} KiB", value / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn transfer_rate_label(bytes: u64, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs_f64();
    if seconds <= f64::EPSILON {
        return "instant".to_string();
    }

    format!("{}/s", format_bytes((bytes as f64 / seconds) as u64))
}

fn append_remote_push_quick_check_note(
    output: &mut String,
    plan: &TransferPlan,
    file_count: usize,
    total_file_bytes: u64,
    stats: RemoteExecutionStats,
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

fn log_source_storage_notes(progress: ProgressLog, sources: &[PathBuf]) {
    for note in source_storage_notes(sources) {
        progress.info(note);
    }
}

fn append_source_storage_notes(output: &mut String, sources: &[PathBuf]) {
    for note in source_storage_notes(sources) {
        output.push_str(&format!("{note}\n"));
    }
}

fn source_storage_notes(sources: &[PathBuf]) -> Vec<String> {
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

fn load_files_from(cli: &Cli) -> Result<Option<Vec<PathBuf>>> {
    let Some(path) = &cli.files_from else {
        return Ok(None);
    };

    let bytes = read_local_file(path)?;
    let records = parse_files_from_bytes(&bytes, cli.from0)?;
    let normalized = normalize_files_from_records(records)?;
    Ok(Some(normalized.into_iter().map(PathBuf::from).collect()))
}

fn local_source_collect_options<'a>(
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

fn collect_local_source_entries(
    sources: &[PathBuf],
    options: &LocalSourceCollectOptions<'_>,
) -> Result<Vec<RemoteSourceEntry>> {
    if sources.len() == 1 {
        return collect_single_local_source_entries(&sources[0], options);
    }

    collect_batch_local_source_entries(sources, options)
}

fn collect_single_local_source_entries(
    source: &Path,
    options: &LocalSourceCollectOptions<'_>,
) -> Result<Vec<RemoteSourceEntry>> {
    let fs = LocalFileSystem;
    let source_metadata =
        remote_sender_metadata(&fs, source, fs.metadata(source)?, options.symlink_mode)?
            .context("source is skipped by link handling")?;
    let mut entries = Vec::new();

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
            return Ok(entries);
        }
        entries.push(RemoteSourceEntry {
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
        });
        return Ok(entries);
    }

    if source_metadata.file_type != FileType::Directory {
        bail!("remote-shell MVP only transfers ordinary files and directories");
    }

    entries.push(RemoteSourceEntry {
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
    });

    collect_local_directory_source_entries(
        &LocalSourceCollectContext { fs: &fs, options },
        source,
        Path::new(""),
        &mut entries,
    )?;

    entries.sort_by(|left, right| left.wire.path.cmp(&right.wire.path));
    Ok(entries)
}

fn collect_batch_local_source_entries(
    sources: &[PathBuf],
    options: &LocalSourceCollectOptions<'_>,
) -> Result<Vec<RemoteSourceEntry>> {
    let fs = LocalFileSystem;
    let mut entries = Vec::new();
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

        entries.push(RemoteSourceEntry {
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
        });

        if options.recursive && file_type == WireFileType::Directory {
            let child_root = remote_followed_directory_path(
                source,
                &original_metadata,
                &metadata,
                options.symlink_mode,
            )
            .unwrap_or_else(|| source.clone());
            collect_local_directory_source_entries(
                &LocalSourceCollectContext { fs: &fs, options },
                &child_root,
                &relative,
                &mut entries,
            )?;
        }
    }

    entries.sort_by(|left, right| left.wire.path.cmp(&right.wire.path));
    Ok(entries)
}

fn collect_local_directory_source_entries(
    ctx: &LocalSourceCollectContext<'_>,
    current: &Path,
    relative_root: &Path,
    entries: &mut Vec<RemoteSourceEntry>,
) -> Result<()> {
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

        entries.push(RemoteSourceEntry {
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
        });
        if ctx.options.recursive && file_type == WireFileType::Directory {
            let child_root = remote_followed_directory_path(
                &original_path,
                &original_metadata,
                &metadata,
                ctx.options.symlink_mode,
            )
            .unwrap_or(original_path);
            collect_local_directory_source_entries(ctx, &child_root, &relative, entries)?;
        }
    }

    Ok(())
}

fn remote_wire_mode(
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

fn remote_hardlink_group(
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

fn remote_file_list_metadata(path: &Path) -> RsyncFileListMetadata {
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
fn remote_metadata_ids(metadata: Option<&fs::Metadata>) -> (Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;

    (
        metadata.map(|metadata| metadata.uid()),
        metadata.map(|metadata| metadata.gid()),
    )
}

#[cfg(not(unix))]
fn remote_metadata_ids(_metadata: Option<&fs::Metadata>) -> (Option<u32>, Option<u32>) {
    (None, None)
}

fn remote_sender_metadata(
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

fn followed_remote_sender_metadata(
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

fn remote_followed_directory_path(
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

fn checksum_local_path(path: &Path) -> Result<[u8; 16]> {
    let mut file = open_local_file(path)?;
    rsync_plain_md4_checksum_reader(&mut file)
        .with_context(|| format!("failed to checksum {}", path.display()))
}

fn serve_remote_receiver_requests<T: Read + Write>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    entries: &[RemoteSourceEntry],
    checksum_seed: i32,
    dry_run: bool,
    compression: Option<&RemoteCompressionConfig>,
    progress: ProgressLog,
) -> Result<RemoteExecutionStats> {
    let mut phase_markers = 0_usize;
    let mut stats = RemoteExecutionStats::default();

    loop {
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
            progress.detail(format!(
                "dry-run upload request for {}",
                entry.wire.path.display()
            ));
            write_rsync_i32(transport, index)?;
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
        )?;

        write_rsync_i32(transport, index)?;
        write_rsync_i32(transport, block_count as i32)?;
        write_rsync_i32(transport, block_len as i32)?;
        write_rsync_i32(transport, checksum_len as i32)?;
        write_rsync_i32(transport, remainder as i32)?;
        let mut file_progress =
            FileProgress::start(progress, "upload", &entry.wire.path, Some(entry.wire.len));
        let delta_stats = write_delta_tokens_from_path(
            transport,
            RemoteFileChecksum::md4_with_seed(checksum_seed),
            RemoteFinalChecksum::protocol27(checksum_seed),
            &entry.local_path,
            &signatures,
            compression,
            Some(&mut file_progress),
        )?;
        file_progress.finish();
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

#[allow(clippy::too_many_arguments)]
fn serve_remote_receiver_requests_protocol31<T: Read + Write>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    entries: &[RemoteSourceEntry],
    dry_run: bool,
    append_verify: bool,
    checksum: RemoteFileChecksum,
    compression: Option<&RemoteCompressionConfig>,
    progress: ProgressLog,
) -> Result<RemoteExecutionStats> {
    let mut read_index_state = RsyncIndexState::default();
    let mut write_index_state = RsyncIndexState::default();
    let mut phase_markers = 0_usize;
    let mut stats = RemoteExecutionStats::default();

    loop {
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
                        read_remote_block_signatures_from_reader(&mut reader, sum_head, checksum)?
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
            progress.detail(format!(
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
                FileProgress::start(progress, operation, &entry.wire.path, Some(total));
            let literal_bytes = if append_verify {
                write_append_verify_file_tokens_from_path(
                    &mut writer,
                    RemoteFinalChecksum::protocol31_for_algorithm(checksum.algorithm()),
                    &entry.local_path,
                    append_prefix_len,
                    compression,
                    Some(&mut file_progress),
                )?
            } else {
                write_delta_tokens_from_path(
                    &mut writer,
                    checksum,
                    RemoteFinalChecksum::protocol31_for_algorithm(checksum.algorithm()),
                    &entry.local_path,
                    &signatures,
                    compression,
                    Some(&mut file_progress),
                )?
                .literal_bytes
            };
            writer.flush()?;
            file_progress.finish();
            stats.bytes += literal_bytes;
        }
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
fn request_remote_sender_files<T: Write>(
    transport: &mut T,
    entries: &[RsyncFileListEntry],
    selected_indexes: &BTreeSet<usize>,
    index_offset: i32,
    dry_run: bool,
    dest: &Path,
    block_size: usize,
    whole_file: bool,
    checksum: RemoteFileChecksum,
) -> Result<()> {
    for (index, entry) in entries.iter().enumerate() {
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
            )?;
            write_sum_head(transport, sum_head)?;
            write_remote_block_signatures(transport, &signatures)?;
        }
    }
    write_rsync_i32(transport, -1)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn request_remote_sender_files_protocol31<T: Write>(
    transport: &mut T,
    entries: &[RsyncFileListEntry],
    selected_indexes: &BTreeSet<usize>,
    index_offset: i32,
    dry_run: bool,
    dest: &Path,
    block_size: usize,
    whole_file: bool,
    checksum: RemoteFileChecksum,
) -> Result<()> {
    let mut index_state = RsyncIndexState::default();
    let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
    for (index, entry) in entries.iter().enumerate() {
        if entry.file_type != WireFileType::File || !selected_indexes.contains(&index) {
            continue;
        }
        write_rsync_index(
            &mut writer,
            &mut index_state,
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
            )?;
            write_sum_head(&mut writer, sum_head)?;
            write_remote_block_signatures(&mut writer, &signatures)?;
        }
    }
    write_rsync_index(&mut writer, &mut index_state, RSYNC_INDEX_DONE)?;
    writer.flush()?;
    Ok(())
}

struct RemoteReceiveContext<'a> {
    fs: &'a mut LocalFileSystem,
    dest: &'a Path,
    entries: &'a [RsyncFileListEntry],
    index_offset: i32,
    final_checksum: RemoteFinalChecksum,
    dry_run: bool,
    progress: ProgressLog,
    preserve_times: bool,
    file_write_options: FileWriteOptions,
    append_verify: bool,
    compression: Option<&'a RemoteCompressionConfig>,
    actions: &'a mut Vec<SyncAction>,
}

fn receive_remote_sender_files<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    mut ctx: RemoteReceiveContext<'_>,
) -> Result<RemoteExecutionStats> {
    let mut stats = RemoteExecutionStats::default();

    loop {
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

fn receive_remote_sender_files_protocol31<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    mut ctx: RemoteReceiveContext<'_>,
) -> Result<RemoteExecutionStats> {
    let mut read_index_state = RsyncIndexState::default();
    let mut stats = RemoteExecutionStats::default();

    loop {
        let response = {
            let mut reader = MultiplexedReader::new(transport, mux);
            let index = read_rsync_index(&mut reader, &mut read_index_state)?;
            if index == RSYNC_INDEX_DONE {
                None
            } else {
                let iflags = read_u16_le(&mut reader)?;
                let _attrs = read_rsync31_optional_item_attrs(&mut reader, iflags)?;
                if iflags & RSYNC_ITEM_TRANSFER != 0 {
                    let sum_head = read_sum_head(&mut reader)?;
                    Some((index, iflags, Some(sum_head)))
                } else {
                    Some((index, iflags, None))
                }
            }
        };

        let Some((index, iflags, sum_head)) = response else {
            break;
        };
        let entry_index = checked_remote_file_index(index, ctx.entries.len(), ctx.index_offset)?;
        let entry = &ctx.entries[entry_index];
        if entry.file_type != WireFileType::File {
            if iflags & RSYNC_ITEM_TRANSFER != 0 {
                return Err(RemoteSessionError::NonFileBlockRequest { index: entry_index }.into());
            }
            continue;
        }
        let target = ctx.dest.join(&entry.path);

        if iflags & RSYNC_ITEM_TRANSFER == 0 || ctx.dry_run {
            let len = sync_action_len(entry.len)?;
            ctx.actions.push(remote_write_action(&target, len, &ctx));
            stats.files += 1;
            stats.bytes += entry.len;
            continue;
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
    ctx.fs
        .copy_file_with_options(source_path, target, &ctx.file_write_options)?;
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

fn delete_local_extras(
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

fn remote_entry_is_top_dir(entry: &RsyncFileListEntry) -> bool {
    entry.file_type == WireFileType::Directory && entry.path == Path::new(".")
}

fn sort_remote_entries_for_sender_indexes(entries: &mut [RsyncFileListEntry]) {
    let directories: BTreeSet<PathBuf> = entries
        .iter()
        .filter(|entry| entry.file_type == WireFileType::Directory)
        .map(|entry| entry.path.clone())
        .collect();

    entries.sort_by(|left, right| remote_sender_entry_cmp(left, right, &directories));
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

fn selected_remote_entry_indexes(
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

fn selected_remote_entries(
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

fn selected_remote_transfer_indexes(
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

fn remote_file_index_offset(entries: &[RsyncFileListEntry]) -> i32 {
    let _ = entries;
    0
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

fn remote_receiver_path_is_filtered(
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

fn read_rsync31_optional_item_attrs<R: Read>(
    reader: &mut R,
    iflags: u16,
) -> Result<Rsync31ItemAttrs> {
    let basis_type = if iflags & RSYNC_ITEM_BASIS_TYPE_FOLLOWS != 0 {
        Some(read_u8(reader)?)
    } else {
        None
    };
    let xname = if iflags & RSYNC_ITEM_XNAME_FOLLOWS != 0 {
        Some(read_vstring(reader, 32 * 1024)?)
    } else {
        None
    };
    Ok(Rsync31ItemAttrs { basis_type, xname })
}

fn write_rsync31_optional_item_attrs<W: Write>(
    writer: &mut W,
    iflags: u16,
    attrs: &Rsync31ItemAttrs,
) -> Result<()> {
    if iflags & RSYNC_ITEM_BASIS_TYPE_FOLLOWS != 0 {
        let basis_type = attrs
            .basis_type
            .context("protocol 31 item flags omitted basis type attribute")?;
        writer.write_all(&[basis_type])?;
    }
    if iflags & RSYNC_ITEM_XNAME_FOLLOWS != 0 {
        let xname = attrs
            .xname
            .as_deref()
            .context("protocol 31 item flags omitted xname attribute")?;
        write_vstring(writer, xname)?;
    }
    Ok(())
}

fn read_sum_head<R: Read>(reader: &mut R) -> Result<RemoteSumHead> {
    Ok(RemoteSumHead {
        block_count: read_nonnegative_i32(reader, "block count")?,
        block_len: read_nonnegative_i32(reader, "block length")?,
        checksum_len: read_nonnegative_i32(reader, "checksum length")?,
        remainder: read_nonnegative_i32(reader, "remainder length")?,
    })
}

fn write_sum_head<W: Write>(writer: &mut W, sum_head: RemoteSumHead) -> Result<()> {
    write_i32_le(writer, sum_head.block_count as i32)?;
    write_i32_le(writer, sum_head.block_len as i32)?;
    write_i32_le(writer, sum_head.checksum_len as i32)?;
    write_i32_le(writer, sum_head.remainder as i32)?;
    Ok(())
}

fn remote_sum_head_file_len(sum_head: RemoteSumHead) -> Result<usize> {
    if sum_head.block_count == 0 {
        return Ok(0);
    }
    if sum_head.block_len == 0 {
        bail!("append basis sum head has zero block length");
    }
    if sum_head.remainder > sum_head.block_len {
        bail!("append basis sum head has a remainder larger than its block length");
    }

    let full_len = sum_head
        .block_count
        .checked_mul(sum_head.block_len)
        .context("append basis length overflow")?;
    if sum_head.remainder == 0 {
        Ok(full_len)
    } else {
        full_len
            .checked_sub(sum_head.block_len - sum_head.remainder)
            .context("append basis length underflow")
    }
}

fn read_remote_block_signatures_multiplexed<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    sum_head: RemoteSumHead,
    checksum: RemoteFileChecksum,
) -> Result<Vec<BlockSignature>> {
    let mut reader = MultiplexedReader::new(transport, mux);
    read_remote_block_signatures_from_reader(&mut reader, sum_head, checksum)
}

fn read_remote_block_signatures_from_reader<R: Read>(
    reader: &mut R,
    sum_head: RemoteSumHead,
    checksum: RemoteFileChecksum,
) -> Result<Vec<BlockSignature>> {
    validate_sum_head(sum_head)?;
    let mut signatures = Vec::with_capacity(sum_head.block_count);
    for index in 0..sum_head.block_count {
        let weak = read_i32_le(reader)? as u32;
        let mut strong = vec![0_u8; sum_head.checksum_len];
        reader.read_exact(&mut strong)?;
        let (offset, len) = block_span(&sum_head, index)?;
        signatures.push(BlockSignature {
            index,
            offset,
            len,
            weak,
            strong: normalize_remote_strong_checksum(strong, checksum, sum_head.checksum_len),
        });
    }
    Ok(signatures)
}

fn normalize_remote_strong_checksum(
    strong: Vec<u8>,
    _checksum: RemoteFileChecksum,
    _checksum_len: usize,
) -> Vec<u8> {
    strong
}

fn write_remote_block_signatures<W: Write>(
    writer: &mut W,
    signatures: &[BlockSignature],
) -> Result<()> {
    for signature in signatures {
        write_i32_le(writer, signature.weak as i32)?;
        writer.write_all(&signature.strong)?;
    }
    Ok(())
}

fn local_basis_signature_request(
    path: &Path,
    block_size: usize,
    checksum: RemoteFileChecksum,
    whole_file: bool,
) -> Result<(RemoteSumHead, Vec<BlockSignature>)> {
    let empty = RemoteSumHead {
        block_count: 0,
        block_len: block_size,
        checksum_len: 16,
        remainder: 0,
    };
    if whole_file {
        return Ok((empty, Vec::new()));
    }
    let Ok(metadata) = fs::metadata(to_long_path_safe(path)) else {
        return Ok((empty, Vec::new()));
    };
    if !metadata.is_file() {
        return Ok((empty, Vec::new()));
    }

    let basis = read_local_file(path)?;
    if basis.is_empty() {
        return Ok((empty, Vec::new()));
    }
    let checksum_len = 16;
    let strong = RsyncStrongChecksum {
        checksum,
        checksum_len,
    };
    let signatures = rsync_delta::generate_signatures_with(&basis, block_size, &strong)?;
    let sum_head = RemoteSumHead {
        block_count: signatures.len(),
        block_len: block_size,
        checksum_len,
        remainder: basis.len() % block_size,
    };
    Ok((sum_head, signatures))
}

fn remote_delta_block_size(plan: &TransferPlan) -> Result<usize> {
    let block_size = plan.block_size.unwrap_or(32 * 1024);
    usize::try_from(block_size)
        .ok()
        .filter(|value| *value > 0)
        .context("remote delta block size must fit usize and be greater than zero")
}

fn write_delta_tokens_from_path<T: Write>(
    transport: &mut T,
    block_checksum: RemoteFileChecksum,
    final_checksum: RemoteFinalChecksum,
    path: &Path,
    signatures: &[BlockSignature],
    compression: Option<&RemoteCompressionConfig>,
    progress: Option<&mut FileProgress>,
) -> Result<RemoteDeltaStats> {
    let bytes = read_local_file(path)?;
    write_delta_tokens_from_bytes_with_checksum(
        transport,
        &bytes,
        block_checksum,
        final_checksum,
        signatures,
        compression.map(|compression| compression.level_for_path(path)),
        progress,
    )
}

fn write_delta_tokens_from_bytes_with_checksum<T: Write>(
    transport: &mut T,
    bytes: &[u8],
    block_checksum: RemoteFileChecksum,
    final_checksum: RemoteFinalChecksum,
    signatures: &[BlockSignature],
    compression_level: Option<u32>,
    mut progress: Option<&mut FileProgress>,
) -> Result<RemoteDeltaStats> {
    if signatures.is_empty() {
        let mut reader = bytes;
        let literal_bytes = write_literal_tokens_from_reader_with_checksum(
            transport,
            &mut reader,
            final_checksum,
            compression_level,
            progress,
        )?;
        return Ok(RemoteDeltaStats {
            literal_bytes,
            copied_bytes: 0,
        });
    }

    let checksum_len = signatures
        .first()
        .map(|signature| signature.strong.len())
        .unwrap_or(16);
    let strong = RsyncStrongChecksum {
        checksum: block_checksum,
        checksum_len,
    };
    let tokens = rsync_delta::generate_delta_with(signatures, bytes, &strong);
    let mut stats = RemoteDeltaStats::default();
    let final_checksum = remote_final_checksum_for_bytes(final_checksum, bytes);
    let mut compressor = compression_level.map(RsyncDeflatedTokenWriter::new);

    for token in tokens {
        match token {
            DeltaToken::Literal(literal) => {
                for chunk in literal.chunks(32 * 1024) {
                    if let Some(compressor) = compressor.as_mut() {
                        compressor.send_literal(transport, chunk)?;
                    } else {
                        write_rsync_i32(transport, chunk.len() as i32)?;
                        transport.write_all(chunk)?;
                    }
                    stats.literal_bytes += chunk.len() as u64;
                    if let Some(progress) = progress.as_deref_mut() {
                        progress.advance(chunk.len() as u64);
                    }
                }
            }
            DeltaToken::Copy { offset, len } => {
                let block_index = signatures
                    .iter()
                    .find(|signature| signature.offset == offset && signature.len == len)
                    .map(|signature| signature.index)
                    .context("delta matcher emitted a copy span without a block signature")?;
                if let Some(compressor) = compressor.as_mut() {
                    compressor.send_copy(transport, block_index)?;
                } else {
                    let token = block_index_to_copy_token(block_index)?;
                    write_rsync_i32(transport, token)?;
                }
                stats.copied_bytes += len as u64;
                if let Some(progress) = progress.as_deref_mut() {
                    progress.advance(len as u64);
                }
            }
        }
    }

    if let Some(compressor) = compressor.as_mut() {
        compressor.finish(transport)?;
    } else {
        write_rsync_i32(transport, 0)?;
    }
    transport.write_all(&final_checksum)?;
    Ok(stats)
}

fn write_append_verify_file_tokens_from_path<T: Write>(
    transport: &mut T,
    checksum: RemoteFinalChecksum,
    path: &Path,
    prefix_len: usize,
    compression: Option<&RemoteCompressionConfig>,
    progress: Option<&mut FileProgress>,
) -> Result<u64> {
    let mut file = open_local_file(path)?;
    write_append_verify_literal_tokens_from_reader_with_checksum(
        transport,
        &mut file,
        checksum,
        prefix_len,
        compression.map(|compression| compression.level_for_path(path)),
        progress,
    )
}

fn write_literal_tokens_from_reader_with_checksum<T: Write, R: Read>(
    transport: &mut T,
    reader: &mut R,
    checksum: RemoteFinalChecksum,
    compression_level: Option<u32>,
    mut progress: Option<&mut FileProgress>,
) -> Result<u64> {
    let mut checksum = remote_final_checksum_builder(checksum);
    let mut buf = [0_u8; 32 * 1024];
    let mut total = 0_u64;
    let mut compressor = compression_level.map(RsyncDeflatedTokenWriter::new);
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        checksum.update(&buf[..read]);
        if let Some(compressor) = compressor.as_mut() {
            compressor.send_literal(transport, &buf[..read])?;
        } else {
            write_rsync_i32(transport, read as i32)?;
            transport.write_all(&buf[..read])?;
        }
        total += read as u64;
        if let Some(progress) = progress.as_deref_mut() {
            progress.advance(read as u64);
        }
    }
    if let Some(compressor) = compressor.as_mut() {
        compressor.finish(transport)?;
    } else {
        write_rsync_i32(transport, 0)?;
    }
    transport.write_all(&checksum.finalize())?;
    Ok(total)
}

fn write_append_verify_literal_tokens_from_reader_with_checksum<T: Write, R: Read>(
    transport: &mut T,
    reader: &mut R,
    checksum: RemoteFinalChecksum,
    prefix_len: usize,
    compression_level: Option<u32>,
    mut progress: Option<&mut FileProgress>,
) -> Result<u64> {
    let mut checksum = remote_final_checksum_builder(checksum);
    let mut buf = [0_u8; 32 * 1024];
    let mut remaining_prefix = prefix_len;
    let mut total = 0_u64;
    let mut compressor = compression_level.map(RsyncDeflatedTokenWriter::new);
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let chunk = &buf[..read];
        checksum.update(chunk);
        let literal = if remaining_prefix >= read {
            remaining_prefix -= read;
            continue;
        } else if remaining_prefix > 0 {
            let offset = remaining_prefix;
            remaining_prefix = 0;
            &chunk[offset..]
        } else {
            chunk
        };
        if let Some(compressor) = compressor.as_mut() {
            compressor.send_literal(transport, literal)?;
        } else {
            write_rsync_i32(transport, literal.len() as i32)?;
            transport.write_all(literal)?;
        }
        total += literal.len() as u64;
        if let Some(progress) = progress.as_deref_mut() {
            progress.advance(literal.len() as u64);
        }
    }
    if remaining_prefix > 0 {
        bail!("append-verify prefix length exceeds source file length");
    }
    if let Some(compressor) = compressor.as_mut() {
        compressor.finish(transport)?;
    } else {
        write_rsync_i32(transport, 0)?;
    }
    transport.write_all(&checksum.finalize())?;
    Ok(total)
}

fn remote_checksum_for_bytes(checksum: RemoteFileChecksum, bytes: &[u8]) -> [u8; 16] {
    let mut checksum = remote_file_checksum_builder(checksum);
    checksum.update(bytes);
    checksum.finalize()
}

fn remote_final_checksum_for_bytes(checksum: RemoteFinalChecksum, bytes: &[u8]) -> [u8; 16] {
    let mut checksum = remote_final_checksum_builder(checksum);
    checksum.update(bytes);
    checksum.finalize()
}

enum RemoteChecksumBuilder {
    Md4(RsyncMd4Checksum),
    Md5 { hasher: md5::Md5, seed: Option<i32> },
}

impl RemoteChecksumBuilder {
    fn md5(seed: Option<i32>, prefix_seed: bool) -> Self {
        let mut hasher = md5::Md5::new();
        if prefix_seed {
            if let Some(seed) = seed {
                hasher.update(seed.to_le_bytes());
            }
        }
        Self::Md5 {
            hasher,
            seed: (!prefix_seed).then_some(seed).flatten(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Md4(checksum) => checksum.update(bytes),
            Self::Md5 { hasher, .. } => hasher.update(bytes),
        }
    }

    fn finalize(self) -> [u8; 16] {
        match self {
            Self::Md4(checksum) => checksum.finalize(),
            Self::Md5 { mut hasher, seed } => {
                if let Some(seed) = seed {
                    hasher.update(seed.to_le_bytes());
                }
                let digest = hasher.finalize();
                let mut out = [0_u8; 16];
                out.copy_from_slice(&digest);
                out
            }
        }
    }
}

fn remote_file_checksum_builder(checksum: RemoteFileChecksum) -> RemoteChecksumBuilder {
    match checksum {
        RemoteFileChecksum::SeededMd4(seed) => {
            RemoteChecksumBuilder::Md4(RsyncMd4Checksum::seeded(seed))
        }
        RemoteFileChecksum::PlainMd4 => RemoteChecksumBuilder::Md4(RsyncMd4Checksum::plain()),
        RemoteFileChecksum::SeededMd5(seed) => RemoteChecksumBuilder::md5(Some(seed), false),
        RemoteFileChecksum::PlainMd5 => RemoteChecksumBuilder::md5(None, false),
    }
}

fn remote_final_checksum_builder(checksum: RemoteFinalChecksum) -> RemoteChecksumBuilder {
    match checksum {
        RemoteFinalChecksum::PlainMd4 => RemoteChecksumBuilder::Md4(RsyncMd4Checksum::plain()),
        RemoteFinalChecksum::SeededMd4Prefix(seed) => {
            RemoteChecksumBuilder::Md4(RsyncMd4Checksum::seeded_prefix(seed))
        }
        RemoteFinalChecksum::PlainMd5 => RemoteChecksumBuilder::md5(None, false),
    }
}

#[derive(Debug, Clone, Copy)]
struct RsyncStrongChecksum {
    checksum: RemoteFileChecksum,
    checksum_len: usize,
}

impl StrongChecksum for RsyncStrongChecksum {
    fn digest(&self, block: &[u8]) -> Vec<u8> {
        let checksum = remote_checksum_for_bytes(self.checksum, block);
        checksum[..self.checksum_len.min(checksum.len())].to_vec()
    }
}

fn validate_sum_head(sum_head: RemoteSumHead) -> Result<()> {
    if sum_head.block_count > 0 && sum_head.block_len == 0 {
        bail!("remote sum head has a zero block length");
    }
    if sum_head.remainder > sum_head.block_len && sum_head.block_count > 0 {
        bail!("remote sum head has a remainder larger than its block length");
    }
    Ok(())
}

fn block_span(sum_head: &RemoteSumHead, block_index: usize) -> Result<(usize, usize)> {
    validate_sum_head(*sum_head)?;
    if block_index >= sum_head.block_count {
        bail!("copy token references missing basis block {block_index}");
    }
    let offset = block_index
        .checked_mul(sum_head.block_len)
        .context("basis block offset overflow")?;
    let is_last = block_index + 1 == sum_head.block_count;
    let len = if is_last && sum_head.remainder != 0 {
        sum_head.remainder
    } else {
        sum_head.block_len
    };
    Ok((offset, len))
}

fn block_index_to_copy_token(block_index: usize) -> Result<i32> {
    let token = i32::try_from(block_index).context("basis block index exceeded i32 range")?;
    token
        .checked_add(1)
        .and_then(|value| value.checked_neg())
        .context("basis block token overflow")
}

fn copy_token_to_block_index(token: i32) -> Result<usize> {
    if token >= 0 {
        bail!("copy token must be negative");
    }
    let raw = token
        .checked_neg()
        .and_then(|value| value.checked_sub(1))
        .context("copy token overflow")?;
    usize::try_from(raw).context("copy token block index did not fit usize")
}

#[allow(clippy::too_many_arguments)]
fn read_file_tokens_to_path_with_basis<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    checksum: RemoteFinalChecksum,
    path: &Path,
    output_path: &Path,
    expected_len: u64,
    basis: Option<(&Path, RemoteSumHead)>,
    compression: Option<&RemoteCompressionConfig>,
    mut progress: Option<&mut FileProgress>,
) -> Result<u64> {
    if let Some(parent) = output_path.parent() {
        create_local_dir_all(parent)?;
    }
    let mut output = create_local_file(output_path)?;
    let basis_bytes = match basis {
        Some((basis_path, sum_head)) if sum_head.block_count > 0 => {
            Some((read_local_file(basis_path)?, sum_head))
        }
        _ => None,
    };
    let mut total = 0_u64;
    let mut buf = [0_u8; 32 * 1024];

    if let Some(compression) = compression {
        let mut token_reader = RsyncDeflatedTokenReader::new(compression.mode);
        loop {
            let token = {
                let mut reader = MultiplexedReader::new(transport, mux);
                token_reader.next_token(&mut reader)?
            };
            match token {
                RsyncDeflatedToken::Literal(literal) => {
                    let next_total = total.checked_add(literal.len() as u64).ok_or(
                        RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: u64::MAX,
                        },
                    )?;
                    if next_total > expected_len {
                        return Err(RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: next_total,
                        }
                        .into());
                    }
                    output.write_all(&literal)?;
                    total = next_total;
                    if let Some(progress) = progress.as_deref_mut() {
                        progress.advance(literal.len() as u64);
                    }
                }
                RsyncDeflatedToken::Copy { block_index } => {
                    let Some((basis_bytes, sum_head)) = basis_bytes.as_ref() else {
                        return Err(RemoteSessionError::UnexpectedToken {
                            token: block_index_to_copy_token(block_index)?,
                            path: path.display().to_string(),
                        }
                        .into());
                    };
                    let (offset, len) = block_span(sum_head, block_index)?;
                    let end = offset
                        .checked_add(len)
                        .context("basis copy token offset overflow")?;
                    let Some(bytes) = basis_bytes.get(offset..end) else {
                        bail!(
                            "remote copy token {} references bytes outside the basis file for {}",
                            block_index_to_copy_token(block_index)?,
                            path.display()
                        );
                    };
                    token_reader.observe_copy_data(bytes)?;
                    let next_total = total.checked_add(bytes.len() as u64).ok_or(
                        RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: u64::MAX,
                        },
                    )?;
                    if next_total > expected_len {
                        return Err(RemoteSessionError::FileLengthExceeded {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: next_total,
                        }
                        .into());
                    }
                    output.write_all(bytes)?;
                    total = next_total;
                    if let Some(progress) = progress.as_deref_mut() {
                        progress.advance(bytes.len() as u64);
                    }
                }
                RsyncDeflatedToken::End => {
                    output.sync_all()?;
                    drop(output);
                    if total != expected_len {
                        return Err(RemoteSessionError::FileLengthShort {
                            path: path.display().to_string(),
                            expected: expected_len,
                            actual: total,
                        }
                        .into());
                    }
                    let mut remote_checksum = [0_u8; 16];
                    read_multiplexed_exact(transport, mux, &mut remote_checksum)?;
                    let local_checksum = remote_file_checksum_for_path(checksum, output_path)?;
                    if remote_checksum != local_checksum {
                        return Err(RemoteSessionError::FileChecksumMismatch {
                            path: path.display().to_string(),
                        }
                        .into());
                    }
                    return Ok(total);
                }
            }
        }
    }

    loop {
        let token = read_multiplexed_i32(transport, mux)?;
        if token > 0 {
            let literal_len = token as u64;
            let next_total =
                total
                    .checked_add(literal_len)
                    .ok_or(RemoteSessionError::FileLengthExceeded {
                        path: path.display().to_string(),
                        expected: expected_len,
                        actual: u64::MAX,
                    })?;
            if next_total > expected_len {
                return Err(RemoteSessionError::FileLengthExceeded {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: next_total,
                }
                .into());
            }

            let mut remaining = token as usize;
            while remaining > 0 {
                let len = buf.len().min(remaining);
                read_multiplexed_exact(transport, mux, &mut buf[..len])?;
                output.write_all(&buf[..len])?;
                remaining -= len;
                total += len as u64;
                if let Some(progress) = progress.as_deref_mut() {
                    progress.advance(len as u64);
                }
            }
        } else if token == 0 {
            output.sync_all()?;
            drop(output);
            if total != expected_len {
                return Err(RemoteSessionError::FileLengthShort {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: total,
                }
                .into());
            }
            let mut remote_checksum = [0_u8; 16];
            read_multiplexed_exact(transport, mux, &mut remote_checksum)?;
            let local_checksum = remote_file_checksum_for_path(checksum, output_path)?;
            if remote_checksum != local_checksum {
                return Err(RemoteSessionError::FileChecksumMismatch {
                    path: path.display().to_string(),
                }
                .into());
            }
            return Ok(total);
        } else {
            let Some((basis_bytes, sum_head)) = basis_bytes.as_ref() else {
                return Err(RemoteSessionError::UnexpectedToken {
                    token,
                    path: path.display().to_string(),
                }
                .into());
            };
            let block_index = copy_token_to_block_index(token)?;
            let (offset, len) = block_span(sum_head, block_index)?;
            let end = offset
                .checked_add(len)
                .context("basis copy token offset overflow")?;
            let Some(bytes) = basis_bytes.get(offset..end) else {
                bail!(
                    "remote copy token {token} references bytes outside the basis file for {}",
                    path.display()
                );
            };
            let next_total = total.checked_add(bytes.len() as u64).ok_or(
                RemoteSessionError::FileLengthExceeded {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: u64::MAX,
                },
            )?;
            if next_total > expected_len {
                return Err(RemoteSessionError::FileLengthExceeded {
                    path: path.display().to_string(),
                    expected: expected_len,
                    actual: next_total,
                }
                .into());
            }
            output.write_all(bytes)?;
            total = next_total;
            if let Some(progress) = progress.as_deref_mut() {
                progress.advance(bytes.len() as u64);
            }
        }
    }
}

fn remote_file_checksum_for_path(checksum: RemoteFinalChecksum, path: &Path) -> Result<[u8; 16]> {
    let mut file = open_local_file(path)?;
    let mut checksum = remote_final_checksum_builder(checksum);
    let mut buf = [0_u8; 32 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("failed to checksum {}", path.display()))?;
        if read == 0 {
            break;
        }
        checksum.update(&buf[..read]);
    }
    Ok(checksum.finalize())
}

fn read_local_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(to_long_path_safe(path))
        .with_context(|| format!("failed to read {}", path.display()))
}

fn open_local_file(path: &Path) -> Result<File> {
    File::open(to_long_path_safe(path))
        .with_context(|| format!("failed to open {}", path.display()))
}

fn create_local_file(path: &Path) -> Result<File> {
    File::create(to_long_path_safe(path))
        .with_context(|| format!("failed to create {}", path.display()))
}

fn create_local_dir_all(path: &Path) -> Result<()> {
    std::fs::create_dir_all(to_long_path_safe(path))
        .with_context(|| format!("failed to create {}", path.display()))
}

fn remove_local_file_best_effort(path: &Path) {
    let _ = std::fs::remove_file(to_long_path_safe(path));
}

fn receive_temp_path(target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "rsync-win".into());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_name = format!(".{file_name}.{}.{}.recv", std::process::id(), nanos);
    target
        .parent()
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}

fn sync_action_len(len: u64) -> Result<usize> {
    usize::try_from(len).context("file length exceeds this platform's address size")
}

fn read_multiplexed_exact<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
    buf: &mut [u8],
) -> Result<()> {
    let mut reader = MultiplexedReader::new(transport, mux);
    reader.read_exact(buf)?;
    Ok(())
}

fn read_multiplexed_rsync31_index<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
) -> Result<i32> {
    let mut reader = MultiplexedReader::new(transport, mux);
    let mut state = RsyncIndexState::default();
    Ok(read_rsync_index(&mut reader, &mut state)?)
}

fn write_rsync31_done<T: Write>(transport: &mut T) -> Result<()> {
    let mut state = RsyncIndexState::default();
    write_rsync31_index(transport, &mut state, RSYNC_INDEX_DONE)
}

fn write_rsync31_index<T: Write>(
    transport: &mut T,
    state: &mut RsyncIndexState,
    index: i32,
) -> Result<()> {
    let mut writer = MultiplexedWriter::new(transport, RSYNC31_MUX_FRAME_SIZE);
    write_rsync_index(&mut writer, state, index)?;
    writer.flush()?;
    Ok(())
}

fn checked_file_index(index: i32, file_count: usize) -> Result<usize> {
    if index < 0 || index as usize >= file_count {
        return Err(RemoteSessionError::InvalidFileIndex { index, file_count }.into());
    }
    Ok(index as usize)
}

fn checked_remote_file_index(index: i32, file_count: usize, offset: i32) -> Result<usize> {
    let local_index = index
        .checked_sub(offset)
        .ok_or(RemoteSessionError::InvalidFileIndex { index, file_count })?;
    checked_file_index(local_index, file_count)
}

fn read_nonnegative_i32<R: Read>(reader: &mut R, label: &str) -> Result<usize> {
    let value = read_i32_le(reader)?;
    if value < 0 {
        bail!("remote sent negative {label}: {value}");
    }
    Ok(value as usize)
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

fn read_remote_sender_protocol31_stats<T: Read>(
    transport: &mut T,
    mux: &mut MultiplexReadState,
) -> Result<()> {
    let mut reader = MultiplexedReader::new(transport, mux);
    for _ in 0..5 {
        let _value = read_varlong(&mut reader, 3)?;
    }
    Ok(())
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

fn system_time_to_unix_nanos(time: SystemTime) -> Option<i128> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    Some(i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos()))
}

fn append_remote_messages(output: &mut String, mux: &MultiplexReadState) {
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

fn windows_destination_path_preflight(paths: &[PathBuf]) -> Result<(), FsError> {
    rsync_winfs::path::preflight_destination_paths(paths)
        .map_err(|err| FsError::DestinationPathPreflight(err.to_string()))
}

fn validate_remote_file_list_paths(entries: &[RsyncFileListEntry]) -> Result<()> {
    let destination_relatives: Vec<_> = entries
        .iter()
        .filter(|entry| !remote_entry_is_top_dir(entry))
        .map(|entry| entry.path.clone())
        .collect();
    windows_destination_path_preflight(&destination_relatives)?;
    Ok(())
}

fn validate_remote_sender_claims(
    plan: &TransferPlan,
    entries: &[RsyncFileListEntry],
    files_from: Option<&[PathBuf]>,
) -> Result<()> {
    if plan.trust_sender {
        return Ok(());
    }
    let allowed_single_file_sources = if plan.old_args {
        Vec::new()
    } else {
        remote_single_file_source_basenames(plan)
    };
    for entry in entries {
        if remote_entry_is_top_dir(entry) {
            continue;
        }
        if !remote_entry_matches_single_file_sources(&entry.path, &allowed_single_file_sources) {
            bail!(
                "remote sender sent unrequested path `{}`; use --trust-sender to accept remote file-list names",
                entry.path.display()
            );
        }
        if remote_source_path_is_filtered(&plan.filter_rules, &entry.path, entry.file_type)
            || remote_receiver_path_is_filtered(&plan.filter_rules, &entry.path, entry.file_type)
        {
            bail!(
                "remote sender sent filtered path `{}`; use --trust-sender to accept remote file-list names",
                entry.path.display()
            );
        }
        if files_from.is_some_and(|files_from| !files_from_matches(&entry.path, files_from)) {
            bail!(
                "remote sender sent path `{}` outside --files-from selection; use --trust-sender to accept remote file-list names",
                entry.path.display()
            );
        }
    }
    Ok(())
}

fn remote_single_file_source_basenames(plan: &TransferPlan) -> Vec<String> {
    if plan.remote_direction != Some(TransferDirection::Pull) {
        return Vec::new();
    }
    plan.remote_operands
        .iter()
        .filter_map(|operand| remote_single_file_source_basename(&operand.path))
        .collect()
}

fn remote_single_file_source_basename(path: &str) -> Option<String> {
    if path.ends_with('/') || path.ends_with('\\') {
        return None;
    }
    let normalized = path.replace('\\', "/");
    let basename = normalized.rsplit('/').next()?.trim();
    if basename.is_empty() || !basename.contains('.') {
        return None;
    }
    Some(basename.to_string())
}

fn remote_entry_matches_single_file_sources(relative: &Path, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let relative = relative.to_string_lossy().replace('\\', "/");
    allowed
        .iter()
        .any(|basename| relative == *basename || relative.starts_with(&format!("{basename}/")))
}

#[derive(Debug)]
struct TransferPlan {
    transfer_mode: TransferMode,
    recursive: bool,
    relative: bool,
    implied_dirs: bool,
    transfer_dirs: bool,
    mkpath: bool,
    one_file_system: bool,
    preserve_times: bool,
    delete: bool,
    delete_mode: DeleteMode,
    delete_excluded: bool,
    ignore_errors: bool,
    force_delete: bool,
    max_delete: Option<usize>,
    dry_run: bool,
    whole_file: bool,
    compress: bool,
    compress_choice: Option<String>,
    compress_level: Option<u32>,
    compress_threads: Option<usize>,
    skip_compress: Vec<String>,
    verbosity: u8,
    progress: bool,
    human_readable: u8,
    update_mode: UpdateMode,
    skip_newer_receiver: bool,
    existing_only: bool,
    ignore_existing: bool,
    max_size: Option<u64>,
    min_size: Option<u64>,
    modify_window: i64,
    ignore_missing_args: bool,
    delete_missing_args: bool,
    file_write_mode: FileWriteMode,
    keep_partial: bool,
    partial_dir: Option<PathBuf>,
    temp_dir: Option<PathBuf>,
    delay_updates: bool,
    fsync: bool,
    append_verify: bool,
    append: bool,
    block_size: Option<u64>,
    checksum_choice: Option<String>,
    checksum_seed: Option<i32>,
    symlink_mode: SymlinkMode,
    keep_dirlinks: bool,
    hard_links: bool,
    preserve_devices: bool,
    preserve_specials: bool,
    preserve_permissions: bool,
    preserve_owner: bool,
    preserve_group: bool,
    preserve_executability: bool,
    preserve_acls: bool,
    preserve_xattrs: bool,
    fake_super: bool,
    atimes: bool,
    crtimes: bool,
    omit_dir_times: bool,
    omit_link_times: bool,
    vss: bool,
    numeric_ids: bool,
    user_maps: Vec<String>,
    group_maps: Vec<String>,
    chown: Option<String>,
    chmod: Option<String>,
    chmod_rules: Option<ChmodRules>,
    metadata_policy: MetadataPolicy,
    filter_rules: RuleSet,
    backup: bool,
    backup_dir: Option<PathBuf>,
    backup_suffix: String,
    remote_options: Vec<String>,
    rsync_path: Option<String>,
    blocking_io: bool,
    old_args: bool,
    secluded_args: bool,
    trust_sender: bool,
    ipv4: bool,
    ipv6: bool,
    remote_server_argv: Option<Vec<String>>,
    remote_protected_args: Option<Vec<String>>,
    remote_ssh_argv: Option<Vec<String>>,
    remote_ssh_command: Option<SshRemoteCommand>,
    remote_operand: Option<RemoteShellOperand>,
    remote_operands: Vec<RemoteShellOperand>,
    remote_direction: Option<TransferDirection>,
    remote_wire_protocol: Option<RemoteWireProtocol>,
    daemon_operand: Option<DaemonOperand>,
    daemon_direction: Option<TransferDirection>,
    report: Report,
}

impl TransferPlan {
    fn from_cli(cli: &Cli) -> Self {
        let metadata_policy = MetadataPolicy::from(cli.metadata_policy);
        let mut report = Report::new();
        let mut recursive = cli.recursive;
        let mut preserve_times = cli.preserve_times;

        if cli.archive {
            recursive = true;
            preserve_times = true;
            report.info(
                "I_ARCHIVE_EXPANSION",
                format!(
                    "archive mode expands to -{}",
                    archive_mode_components()
                        .iter()
                        .map(|component| component.flag().trim_start_matches('-'))
                        .collect::<String>()
                ),
            );
            add_metadata_degradations(
                &mut report,
                archive_mode_degradations_for_cli(cli, metadata_policy),
                cli.fail_on_metadata_loss,
            );
        }
        if cli.no_recursive {
            recursive = false;
        }
        if cli.no_times {
            preserve_times = false;
        }
        add_metadata_degradations(
            &mut report,
            metadata_policy_degradations(metadata_policy),
            cli.fail_on_metadata_loss,
        );
        if cli.vss {
            add_metadata_degradations(
                &mut report,
                NtfsNativeMetadataRequest {
                    vss_snapshot: true,
                    ..Default::default()
                }
                .degradations(),
                cli.fail_on_metadata_loss,
            );
        }
        add_explicit_option_diagnostics(cli, &mut report);
        add_option_conflict_diagnostics(cli, &mut report);

        let filter_rules = build_filter_rules(cli, &mut report);
        let chmod_rules = parse_chmod_rules(cli, &mut report);
        let update_mode = update_mode_from_cli(cli);
        let file_write_mode = if cli.inplace {
            FileWriteMode::InPlace
        } else {
            FileWriteMode::Atomic
        };
        let symlink_mode = symlink_mode_from_cli(cli);
        let explicit_server_mode = cli.daemon_server || cli.internal_server;
        let (daemon_operand, daemon_direction, has_daemon_operand) = if explicit_server_mode {
            (None, None, false)
        } else {
            plan_daemon_operands(cli, &mut report)
        };
        let (
            remote_server_argv,
            remote_protected_args,
            remote_ssh_argv,
            remote_ssh_command,
            remote_operand,
            remote_operands,
            remote_direction,
            remote_wire_protocol,
        ) = if explicit_server_mode || has_daemon_operand {
            (None, None, None, None, None, Vec::new(), None, None)
        } else if cli.paths.len() >= 2 {
            let sources = &cli.paths[..cli.paths.len() - 1];
            let destination = cli.paths.last().expect("checked len");
            let source_remotes: Vec<_> = sources
                .iter()
                .map(|source| parse_remote_shell_operand(source, &mut report))
                .collect();
            let destination_remote = parse_remote_shell_operand(destination, &mut report);
            let any_source_remote = source_remotes.iter().any(Option::is_some);
            if !any_source_remote && destination_remote.is_none() {
                (None, None, None, None, None, Vec::new(), None, None)
            } else if any_source_remote && destination_remote.is_some() {
                report.error(
                    "E_REMOTE_BOTH",
                    "remote-to-remote transfers are not supported by this development build",
                );
                (None, None, None, None, None, Vec::new(), None, None)
            } else if any_source_remote {
                if !source_remotes.iter().all(Option::is_some) {
                    report.error(
                        "E_REMOTE_MIXED_SOURCES",
                        "remote-shell pull sources must all be remote operands from the same host",
                    );
                    (None, None, None, None, None, Vec::new(), None, None)
                } else {
                    let remotes: Vec<_> = source_remotes.into_iter().flatten().collect();
                    let remote = remotes.first().expect("checked remote source");
                    if remotes.iter().any(|operand| operand.host != remote.host) {
                        report.error(
                            "E_REMOTE_HOST_MISMATCH",
                            "remote-shell pull sources must use the same remote host",
                        );
                        (None, None, None, None, None, Vec::new(), None, None)
                    } else {
                        let direction = TransferDirection::Pull;
                        let remote_paths: Vec<PathBuf> = remotes
                            .iter()
                            .map(|operand| PathBuf::from(&operand.path))
                            .collect();
                        let remote_path_refs: Vec<&Path> =
                            remote_paths.iter().map(PathBuf::as_path).collect();
                        match build_remote_shell_protocol31_invocation_for_paths(
                            &remote_shell_options_from_cli(
                                cli,
                                direction,
                                recursive,
                                preserve_times,
                                symlink_mode,
                            ),
                            &remote_path_refs,
                        ) {
                            Ok(invocation) => {
                                match build_remote_transport_command(
                                    cli,
                                    &remote.host,
                                    &invocation.argv,
                                ) {
                                    Ok(ssh_command) => {
                                        report.info(
                                        "I_REMOTE_PROTOCOL31_MVP",
                                        format!(
                                            "remote-shell execution tries protocol {REMOTE_SHELL_MODERN_PROTOCOL} first for the ordinary-file MVP"
                                        ),
                                    );
                                        (
                                            Some(invocation.argv),
                                            Some(invocation.protected_args),
                                            Some(render_ssh_command(&ssh_command)),
                                            Some(ssh_command),
                                            Some(remote.clone()),
                                            remotes,
                                            Some(direction),
                                            Some(RemoteWireProtocol::Modern31),
                                        )
                                    }
                                    Err(err) => {
                                        report.error(
                                            "E_REMOTE_SHELL",
                                            format!("could not parse remote shell command: {err}"),
                                        );
                                        (None, None, None, None, None, Vec::new(), None, None)
                                    }
                                }
                            }
                            Err(err) => {
                                report.error(
                                    "E_REMOTE_ARGV",
                                    format!("could not build remote --server argv: {err}"),
                                );
                                (None, None, None, None, None, Vec::new(), None, None)
                            }
                        }
                    }
                }
            } else {
                let remote = destination_remote
                    .as_ref()
                    .expect("checked remote destination");
                let direction = TransferDirection::Push;
                match build_remote_shell_protocol31_invocation_for_paths(
                    &remote_shell_options_from_cli(
                        cli,
                        direction,
                        recursive,
                        preserve_times,
                        symlink_mode,
                    ),
                    &[Path::new(&remote.path)],
                ) {
                    Ok(invocation) => {
                        match build_remote_transport_command(cli, &remote.host, &invocation.argv) {
                            Ok(ssh_command) => {
                                report.info(
                                    "I_REMOTE_PROTOCOL31_MVP",
                                    format!(
                                        "remote-shell execution tries protocol {REMOTE_SHELL_MODERN_PROTOCOL} first for the ordinary-file MVP"
                                    ),
                                );
                                (
                                    Some(invocation.argv),
                                    Some(invocation.protected_args),
                                    Some(render_ssh_command(&ssh_command)),
                                    Some(ssh_command),
                                    Some(remote.clone()),
                                    vec![remote.clone()],
                                    Some(direction),
                                    Some(RemoteWireProtocol::Modern31),
                                )
                            }
                            Err(err) => {
                                report.error(
                                    "E_REMOTE_SHELL",
                                    format!("could not parse remote shell command: {err}"),
                                );
                                (None, None, None, None, None, Vec::new(), None, None)
                            }
                        }
                    }
                    Err(err) => {
                        report.error(
                            "E_REMOTE_ARGV",
                            format!("could not build remote --server argv: {err}"),
                        );
                        (None, None, None, None, None, Vec::new(), None, None)
                    }
                }
            }
        } else {
            (None, None, None, None, None, Vec::new(), None, None)
        };

        add_metadata_degradations(
            &mut report,
            posix_metadata_degradations_for_plan(
                cli,
                metadata_policy,
                remote_direction,
                daemon_direction,
            ),
            cli.fail_on_metadata_loss,
        );
        let transfer_mode = transfer_mode_from_cli(cli, has_daemon_operand, remote_direction);
        add_mode_gating_diagnostics(cli, transfer_mode, has_daemon_operand, &mut report);

        Self {
            transfer_mode,
            recursive,
            relative: cli.relative,
            implied_dirs: cli.implied_dirs,
            transfer_dirs: cli.transfer_dirs,
            mkpath: cli.mkpath,
            one_file_system: cli.one_file_system,
            preserve_times,
            delete: cli.delete || cli.delete_mode != DeleteMode::None,
            delete_mode: if cli.delete || cli.delete_mode != DeleteMode::None {
                if cli.delete_mode == DeleteMode::None {
                    DeleteMode::During
                } else {
                    cli.delete_mode
                }
            } else {
                DeleteMode::None
            },
            delete_excluded: cli.delete_excluded,
            ignore_errors: cli.ignore_errors,
            force_delete: cli.force,
            max_delete: cli.max_delete,
            dry_run: cli.dry_run,
            whole_file: cli.whole_file,
            compress: cli.compress,
            compress_choice: cli.compress_choice.clone(),
            compress_level: cli.compress_level,
            compress_threads: cli.compress_threads,
            skip_compress: cli.skip_compress.clone(),
            verbosity: cli.verbosity,
            progress: cli.progress,
            human_readable: cli.human_readable,
            update_mode,
            skip_newer_receiver: cli.update,
            existing_only: cli.existing,
            ignore_existing: cli.ignore_existing,
            max_size: cli.max_size,
            min_size: cli.min_size,
            modify_window: cli.modify_window,
            ignore_missing_args: cli.ignore_missing_args,
            delete_missing_args: cli.delete_missing_args,
            file_write_mode,
            keep_partial: cli.partial,
            partial_dir: cli.partial_dir.clone().map(PathBuf::from),
            temp_dir: cli.temp_dir.clone().map(PathBuf::from),
            delay_updates: cli.delay_updates,
            fsync: cli.fsync,
            append_verify: cli.append_verify,
            append: cli.append,
            block_size: cli.block_size,
            checksum_choice: cli.checksum_choice.clone(),
            checksum_seed: cli.checksum_seed,
            symlink_mode,
            keep_dirlinks: cli.keep_dirlinks,
            hard_links: cli.hard_links,
            preserve_devices: (cli.devices || cli.archive || cli.copy_devices || cli.write_devices)
                && !cli.no_devices,
            preserve_specials: (cli.specials || cli.archive) && !cli.no_specials,
            preserve_permissions: cli_preserve_permissions(cli),
            preserve_owner: cli_preserve_owner(cli),
            preserve_group: cli_preserve_group(cli),
            preserve_executability: cli.executability,
            preserve_acls: cli.acls,
            preserve_xattrs: cli.xattrs,
            fake_super: cli.fake_super,
            atimes: cli.atimes,
            crtimes: cli.crtimes,
            omit_dir_times: cli.omit_dir_times,
            omit_link_times: cli.omit_link_times,
            vss: cli.vss,
            numeric_ids: cli.numeric_ids,
            user_maps: cli.user_maps.clone(),
            group_maps: cli.group_maps.clone(),
            chown: cli.chown.clone(),
            chmod: cli.chmod.clone(),
            chmod_rules,
            metadata_policy,
            filter_rules,
            backup: cli.backup,
            backup_dir: cli.backup_dir.clone().map(PathBuf::from),
            backup_suffix: cli.suffix.clone().unwrap_or_else(|| {
                if cli.backup_dir.is_some() {
                    String::new()
                } else {
                    "~".to_string()
                }
            }),
            remote_options: cli.remote_options.clone(),
            rsync_path: cli.rsync_path.clone(),
            blocking_io: cli.blocking_io,
            old_args: cli.old_args,
            secluded_args: cli.secluded_args,
            trust_sender: cli.trust_sender,
            ipv4: cli.ipv4,
            ipv6: cli.ipv6,
            remote_server_argv,
            remote_protected_args,
            remote_ssh_argv,
            remote_ssh_command,
            remote_operand,
            remote_operands,
            remote_direction,
            remote_wire_protocol,
            daemon_operand,
            daemon_direction,
            report,
        }
    }
}

fn transfer_mode_from_cli(
    cli: &Cli,
    has_daemon_operand: bool,
    remote_direction: Option<TransferDirection>,
) -> TransferMode {
    if cli.daemon_server {
        TransferMode::DaemonServer
    } else if cli.internal_server {
        TransferMode::InternalServer
    } else if has_daemon_operand {
        TransferMode::DaemonClient
    } else if remote_direction.is_some() {
        TransferMode::RemoteShell
    } else {
        TransferMode::Local
    }
}

fn add_mode_gating_diagnostics(
    cli: &Cli,
    transfer_mode: TransferMode,
    has_daemon_operand: bool,
    report: &mut Report,
) {
    let has_daemon_syntax =
        has_daemon_operand || cli.paths.iter().any(|path| is_daemon_operand_syntax(path));
    let has_remote_shell_syntax = cli.paths.iter().any(|path| is_remote_shell_operand(path));

    if cli.daemon_server && cli.internal_server {
        report.error(
            "E_MODE_CONFLICT",
            "--daemon and --server select different rsync execution modes",
        );
    }
    if cli.internal_sender && !cli.internal_server {
        report.warn(
            "W_MODE_SCOPED_OPTION",
            "--sender is an internal --server modifier and has no standalone client behavior",
        );
    }
    if has_daemon_syntax && has_remote_shell_syntax {
        report.error(
            "E_MODE_CONFLICT",
            "daemon operands cannot be mixed with remote-shell operands",
        );
    }

    match transfer_mode {
        TransferMode::DaemonServer => {
            report.error(
                "E_UNSUPPORTED_MODE",
                "daemon server mode is parsed and gated but not implemented by this build",
            );
            if has_remote_shell_syntax || has_daemon_syntax || !cli.paths.is_empty() {
                report.error(
                    "E_MODE_CONFLICT",
                    "--daemon server mode does not accept transfer operands",
                );
            }
        }
        TransferMode::InternalServer => {
            report.error(
                "E_UNSUPPORTED_MODE",
                "internal --server mode is reserved for rsync peer execution and is not a public entrypoint in this build",
            );
            if cli.daemon_server {
                report.error(
                    "E_MODE_CONFLICT",
                    "internal --server mode cannot be combined with daemon server mode",
                );
            }
        }
        TransferMode::DaemonClient => {
            if cli.remote_shell.is_some() {
                report.error(
                    "E_MODE_CONFLICT",
                    "daemon client mode does not use --rsh/-e",
                );
            }
        }
        TransferMode::RemoteShell => {
            if cli.password_file.is_some() {
                report.warn(
                    "W_MODE_SCOPED_OPTION",
                    "--password-file applies to rsync daemon authentication, not remote-shell mode",
                );
            }
        }
        TransferMode::Local => {
            if cli.password_file.is_some() {
                report.warn(
                    "W_MODE_SCOPED_OPTION",
                    "--password-file applies to rsync daemon authentication, not local mode",
                );
            }
        }
    }
}

fn plan_daemon_operands(
    cli: &Cli,
    report: &mut Report,
) -> (Option<DaemonOperand>, Option<TransferDirection>, bool) {
    let mut present = false;
    let mut operands = Vec::new();
    for (index, operand) in cli.paths.iter().enumerate() {
        if !is_daemon_operand_syntax(operand) {
            continue;
        }
        present = true;
        match DaemonOperand::parse(operand) {
            Ok(Some(daemon)) => operands.push((index, daemon)),
            Ok(None) => {}
            Err(err) => report.error("E_DAEMON_OPERAND", err.to_string()),
        }
    }

    if !present {
        return (None, None, false);
    }
    if operands.len() != 1 {
        if operands.len() > 1 {
            report.error(
                "E_DAEMON_OPERANDS",
                "daemon client MVP supports one daemon operand per command",
            );
        }
        return (None, None, true);
    }

    let (index, operand) = operands.remove(0);
    if cli.paths.len() == 1 {
        if cli.list_only && operand.module.is_none() {
            return (Some(operand), Some(TransferDirection::Pull), true);
        }
        report.error(
            "E_DAEMON_OPERANDS",
            "daemon commands require --list-only host:: for module listing or daemon source plus a local destination for pull",
        );
        return (Some(operand), None, true);
    }

    if index == 0 && cli.paths.len() == 2 {
        if operand.module.is_none() {
            report.error(
                "E_DAEMON_OPERANDS",
                "daemon pull requires a module, e.g. host::module/path",
            );
            return (Some(operand), None, true);
        }
        return (Some(operand), Some(TransferDirection::Pull), true);
    }

    if index == cli.paths.len() - 1 {
        report.error(
            "E_DAEMON_PUSH_UNSUPPORTED",
            "daemon push is out of scope for this MVP; use a remote-shell destination or pull from a daemon module",
        );
        return (Some(operand), Some(TransferDirection::Push), true);
    }

    report.error(
        "E_DAEMON_OPERANDS",
        "daemon operands cannot be mixed with additional local or remote sources in this MVP",
    );
    (Some(operand), None, true)
}

fn remote_shell_options_from_cli(
    cli: &Cli,
    direction: TransferDirection,
    recursive: bool,
    preserve_times: bool,
    symlink_mode: SymlinkMode,
) -> RemoteShellOptions {
    let (includes, excludes, filters) = remote_receiver_filter_args_from_cli(cli, direction);
    RemoteShellOptions {
        rsync_path: cli
            .rsync_path
            .clone()
            .unwrap_or_else(|| "rsync".to_string()),
        direction,
        secluded_args: cli.secluded_args,
        recursive,
        preserve_times,
        delete_mode: remote_delete_mode_from_cli(cli),
        dry_run: cli.dry_run,
        whole_file: cli.whole_file && !(direction == TransferDirection::Push && cli.append_verify),
        verbosity: cli.verbosity,
        preserve_permissions: cli_preserve_permissions(cli),
        checksum: cli.checksum,
        checksum_choice: cli.checksum_choice.clone(),
        checksum_seed: cli.checksum_seed,
        size_only: direction == TransferDirection::Push && cli.size_only,
        ignore_times: direction == TransferDirection::Push && cli.ignore_times,
        partial: direction == TransferDirection::Push && cli.partial,
        partial_dir: (direction == TransferDirection::Push)
            .then(|| cli.partial_dir.clone())
            .flatten(),
        inplace: direction == TransferDirection::Push && cli.inplace,
        append_verify: direction == TransferDirection::Push && cli.append_verify,
        executability: direction == TransferDirection::Push && cli.executability,
        preserve_owner: direction == TransferDirection::Push && cli_preserve_owner(cli),
        preserve_group: direction == TransferDirection::Push && cli_preserve_group(cli),
        numeric_ids: direction == TransferDirection::Push && cli.numeric_ids,
        user_maps: if direction == TransferDirection::Push {
            cli.user_maps.clone()
        } else {
            Vec::new()
        },
        group_maps: if direction == TransferDirection::Push {
            cli.group_maps.clone()
        } else {
            Vec::new()
        },
        chown: if direction == TransferDirection::Push {
            cli.chown.clone()
        } else {
            None
        },
        chmod: (direction == TransferDirection::Push)
            .then(|| cli.chmod.clone())
            .flatten(),
        acls: direction == TransferDirection::Push && cli.acls,
        xattrs: direction == TransferDirection::Push && cli.xattrs,
        fake_super: direction == TransferDirection::Push && cli.fake_super,
        atimes: direction == TransferDirection::Push && cli.atimes,
        crtimes: direction == TransferDirection::Push && cli.crtimes,
        omit_dir_times: cli.omit_dir_times,
        omit_link_times: cli.omit_link_times,
        preserve_links: direction == TransferDirection::Push
            && symlink_mode == SymlinkMode::Preserve
            && (cli.links || cli.archive),
        copy_links: direction == TransferDirection::Pull && symlink_mode == SymlinkMode::CopyAll,
        copy_dirlinks: symlink_mode == SymlinkMode::CopyDirLinks,
        keep_dirlinks: cli.keep_dirlinks,
        safe_links: direction == TransferDirection::Push && symlink_mode == SymlinkMode::SafeOnly,
        copy_unsafe_links: direction == TransferDirection::Pull
            && symlink_mode == SymlinkMode::CopyUnsafe,
        munge_links: symlink_mode == SymlinkMode::Munge,
        hard_links: cli.hard_links,
        preserve_devices: (cli.devices || cli.archive || cli.copy_devices || cli.write_devices)
            && !cli.no_devices,
        preserve_specials: (cli.specials || cli.archive) && !cli.no_specials,
        copy_devices: cli.copy_devices,
        write_devices: cli.write_devices,
        block_size: cli.block_size,
        compress: cli.compress,
        compress_choice: remote_compress_choice_for_argv(
            cli.compress,
            cli.compress_choice.as_deref(),
        ),
        compress_level: cli.compress_level,
        compress_threads: cli.compress_threads,
        skip_compress: cli.skip_compress.clone(),
        remote_options: cli.remote_options.clone(),
        includes,
        excludes,
        filters,
    }
}

fn remote_compress_choice_for_argv(compress: bool, choice: Option<&str>) -> Option<String> {
    if !compress {
        return None;
    }
    RsyncDeflatedTokenMode::from_choice(choice)
        .map(|mode| mode.remote_choice().to_string())
        .ok()
        .or_else(|| choice.map(str::to_string))
}

fn remote_delete_mode_from_cli(cli: &Cli) -> RemoteDeleteMode {
    remote_delete_mode(cli.delete, cli.delete_mode)
}

fn protocol31_setup_options_from_plan(plan: &TransferPlan) -> Protocol31SetupOptions {
    Protocol31SetupOptions {
        checksum_choices: plan
            .checksum_choice
            .as_deref()
            .map(split_option_list)
            .unwrap_or_else(|| vec!["md4".to_string()]),
        checksum_seed: plan.checksum_seed,
    }
}

fn split_option_list(value: &str) -> Vec<String> {
    value
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn remote_delete_mode(delete: bool, delete_mode: DeleteMode) -> RemoteDeleteMode {
    match if delete_mode != DeleteMode::None {
        delete_mode
    } else if delete {
        DeleteMode::During
    } else {
        DeleteMode::None
    } {
        DeleteMode::None => RemoteDeleteMode::None,
        DeleteMode::Before => RemoteDeleteMode::Before,
        DeleteMode::During => RemoteDeleteMode::During,
        DeleteMode::Delay => RemoteDeleteMode::Delay,
        DeleteMode::After => RemoteDeleteMode::After,
    }
}

fn cli_preserve_permissions(cli: &Cli) -> bool {
    (cli.preserve_permissions || cli.archive) && !cli.no_permissions
}

fn cli_preserve_owner(cli: &Cli) -> bool {
    cli.preserve_owner || (cli.archive && !cli.no_owner)
}

fn cli_preserve_group(cli: &Cli) -> bool {
    cli.preserve_group || (cli.archive && !cli.no_group)
}

fn remote_receiver_filter_args_from_cli(
    cli: &Cli,
    _direction: TransferDirection,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut includes = cli.includes.clone();
    let mut excludes = cli.excludes.clone();
    let mut filters = cli.filters.clone();

    if cli.cvs_exclude {
        excludes.extend(
            CVS_EXCLUDE_PATTERNS
                .iter()
                .map(|pattern| (*pattern).to_string()),
        );
    }
    for path in &cli.include_from {
        add_remote_filter_file_args(
            &mut includes,
            &mut excludes,
            &mut filters,
            path,
            cli.from0,
            RuleAction::Include,
        );
    }
    for path in &cli.exclude_from {
        add_remote_filter_file_args(
            &mut includes,
            &mut excludes,
            &mut filters,
            path,
            cli.from0,
            RuleAction::Exclude,
        );
    }

    (includes, excludes, filters)
}

fn add_remote_filter_file_args(
    includes: &mut Vec<String>,
    excludes: &mut Vec<String>,
    filters: &mut Vec<String>,
    path: &Path,
    from0: bool,
    default_action: RuleAction,
) {
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    let Ok(rules) = Rule::parse_filter_file(&bytes, from0, default_action) else {
        return;
    };
    for rule in rules {
        add_remote_filter_rule_arg(includes, excludes, filters, &rule);
    }
}

fn add_remote_filter_rule_arg(
    includes: &mut Vec<String>,
    excludes: &mut Vec<String>,
    filters: &mut Vec<String>,
    rule: &Rule,
) {
    match rule.action() {
        RuleAction::Include if filter_rule_can_use_short_arg(rule) => {
            includes.push(rule.pattern().raw().to_string());
        }
        RuleAction::Exclude if filter_rule_can_use_short_arg(rule) => {
            excludes.push(rule.pattern().raw().to_string());
        }
        _ => filters.push(format_remote_filter_rule(rule)),
    }
}

fn filter_rule_can_use_short_arg(rule: &Rule) -> bool {
    rule.is_sender_side() && rule.is_receiver_side() && !rule.is_perishable()
}

fn format_remote_filter_rule(rule: &Rule) -> String {
    if rule.action() == RuleAction::ClearList {
        return "!".to_string();
    }

    let mut head = match rule.action() {
        RuleAction::Include => "+".to_string(),
        RuleAction::Exclude => "-".to_string(),
        RuleAction::Hide => "H".to_string(),
        RuleAction::Show => "S".to_string(),
        RuleAction::Protect => "P".to_string(),
        RuleAction::Risk => "R".to_string(),
        RuleAction::ClearList => unreachable!("handled above"),
        RuleAction::Merge => ".".to_string(),
        RuleAction::DirMerge => ":".to_string(),
    };
    let mut modifiers = String::new();
    if rule.is_sender_side() && !rule.is_receiver_side() {
        modifiers.push('s');
    } else if rule.is_receiver_side() && !rule.is_sender_side() {
        modifiers.push('r');
    }
    if rule.is_perishable() {
        modifiers.push('p');
    }
    if !modifiers.is_empty() {
        head.push(',');
        head.push_str(&modifiers);
    }
    format!("{head} {}", rule.pattern().raw())
}

fn update_mode_from_cli(cli: &Cli) -> UpdateMode {
    if cli.ignore_times {
        UpdateMode::IgnoreTimes
    } else if cli.checksum {
        UpdateMode::Checksum
    } else if cli.size_only {
        UpdateMode::SizeOnly
    } else {
        UpdateMode::QuickCheck
    }
}

fn symlink_mode_from_cli(cli: &Cli) -> SymlinkMode {
    if cli.no_links {
        SymlinkMode::Skip
    } else if cli.copy_links {
        SymlinkMode::CopyAll
    } else if cli.copy_dirlinks {
        SymlinkMode::CopyDirLinks
    } else if cli.copy_unsafe_links {
        SymlinkMode::CopyUnsafe
    } else if cli.safe_links {
        SymlinkMode::SafeOnly
    } else if cli.munge_links {
        SymlinkMode::Munge
    } else if cli.links || cli.archive {
        SymlinkMode::Preserve
    } else {
        SymlinkMode::Skip
    }
}

fn file_write_options_from_plan(plan: &TransferPlan) -> FileWriteOptions {
    FileWriteOptions {
        mode: plan.file_write_mode,
        keep_partial: plan.keep_partial,
        partial_dir: plan.partial_dir.clone(),
        temp_dir: plan.temp_dir.clone(),
        fsync: plan.fsync,
    }
}

fn render_ssh_command(command: &SshRemoteCommand) -> Vec<String> {
    std::iter::once(&command.program)
        .chain(command.args.iter())
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

fn parse_remote_shell_operand(operand: &str, report: &mut Report) -> Option<RemoteShellOperand> {
    match RemoteShellOperand::parse(operand) {
        Ok(remote) => remote,
        Err(err) => {
            report.error("E_REMOTE_OPERAND", err.to_string());
            None
        }
    }
}

fn build_filter_rules(cli: &Cli, report: &mut Report) -> RuleSet {
    let mut rules = RuleSet::empty();

    if cli.cvs_exclude {
        for pattern in CVS_EXCLUDE_PATTERNS {
            match Rule::exclude(*pattern) {
                Ok(rule) => rules.push(rule),
                Err(err) => report.error("E_FILTER", format!("invalid CVS exclude pattern: {err}")),
            }
        }
    }
    for pattern in &cli.includes {
        match Rule::include(pattern) {
            Ok(rule) => rules.push(rule),
            Err(err) => report.error("E_FILTER", format!("invalid include pattern: {err}")),
        }
    }
    for path in &cli.include_from {
        add_filter_file_rules(&mut rules, path, cli.from0, RuleAction::Include, report);
    }
    for pattern in &cli.excludes {
        match Rule::exclude(pattern) {
            Ok(rule) => rules.push(rule),
            Err(err) => report.error("E_FILTER", format!("invalid exclude pattern: {err}")),
        }
    }
    for path in &cli.exclude_from {
        add_filter_file_rules(&mut rules, path, cli.from0, RuleAction::Exclude, report);
    }
    for filter in &cli.filters {
        match Rule::parse_filter(filter) {
            Ok(rule) => rules.push(rule),
            Err(err) => report.error("E_FILTER", format!("invalid filter rule: {err}")),
        }
    }

    rules
}

const CVS_EXCLUDE_PATTERNS: &[&str] = &[
    "RCS",
    "SCCS",
    "CVS",
    "CVS.adm",
    "RCSLOG",
    "cvslog.*",
    "tags",
    "TAGS",
    ".make.state",
    ".nse_depinfo",
    "*~",
    "#*",
    ".#*",
    ",*",
    "_$*",
    "*$",
    "*.old",
    "*.bak",
    "*.BAK",
    "*.orig",
    "*.rej",
    ".del-*",
    "*.a",
    "*.olb",
    "*.o",
    "*.obj",
    "*.so",
    "*.exe",
    "*.Z",
    "*.elc",
    "*.ln",
    "core",
    ".svn",
    ".git",
    ".hg",
    ".bzr",
];

fn add_filter_file_rules(
    rules: &mut RuleSet,
    path: &Path,
    from0: bool,
    default_action: RuleAction,
    report: &mut Report,
) {
    match fs::read(path) {
        Ok(bytes) => match Rule::parse_filter_file(&bytes, from0, default_action) {
            Ok(parsed) => {
                for rule in parsed {
                    rules.push(rule);
                }
            }
            Err(err) => report.error(
                "E_FILTER",
                format!("invalid filter file {}: {err}", path.display()),
            ),
        },
        Err(err) => report.error(
            "E_FILTER",
            format!("could not read filter file {}: {err}", path.display()),
        ),
    }
}

fn parse_chmod_rules(cli: &Cli, report: &mut Report) -> Option<ChmodRules> {
    let Some(chmod) = &cli.chmod else {
        return None;
    };
    match chmod.parse::<ChmodRules>() {
        Ok(rules) => Some(rules),
        Err(err) => {
            report.error("E_CHMOD", err.to_string());
            None
        }
    }
}

fn add_metadata_degradations(
    report: &mut Report,
    degradations: Vec<MetadataDegradation>,
    fail_on_loss: bool,
) {
    for degradation in degradations {
        let severity = if fail_on_loss && degradation.is_loss() {
            Severity::Error
        } else {
            Severity::Warning
        };
        let code = metadata_code(degradation.feature, severity);
        let message = format!(
            "{} metadata {}: {}",
            degradation.feature.label(),
            degradation.action.label(),
            degradation.message
        );
        report.push(Diagnostic::new(severity, code, message));
    }
}

fn archive_mode_degradations_for_cli(
    cli: &Cli,
    metadata_policy: MetadataPolicy,
) -> Vec<MetadataDegradation> {
    archive_mode_degradations(metadata_policy)
        .into_iter()
        .filter(|degradation| {
            !(cli.no_permissions && degradation.feature == MetadataFeature::Permissions
                || cli.no_owner && degradation.feature == MetadataFeature::Owner
                || cli.no_group && degradation.feature == MetadataFeature::Group
                || cli.no_devices && degradation.feature == MetadataFeature::Device
                || cli.no_specials && degradation.feature == MetadataFeature::SpecialFile)
        })
        .collect()
}

fn posix_metadata_request_from_cli(cli: &Cli) -> PosixMetadataRequest {
    PosixMetadataRequest {
        permissions: cli_preserve_permissions(cli),
        owner: cli_preserve_owner(cli),
        group: cli_preserve_group(cli),
        numeric_ids: cli.numeric_ids,
        chmod: cli.chmod.is_some(),
        executability: cli.executability,
        symlink_mtime: cli.archive && !cli.omit_link_times,
        acls: cli.acls,
        xattrs: cli.xattrs,
        fake_super: cli.fake_super,
        atimes: cli.atimes,
        crtimes: cli.crtimes,
        omit_dir_times: cli.omit_dir_times,
        user_map: !cli.user_maps.is_empty(),
        group_map: !cli.group_maps.is_empty(),
        chown: cli.chown.is_some(),
    }
}

fn posix_metadata_degradations_for_plan(
    cli: &Cli,
    metadata_policy: MetadataPolicy,
    remote_direction: Option<TransferDirection>,
    daemon_direction: Option<TransferDirection>,
) -> Vec<MetadataDegradation> {
    let mut request = posix_metadata_request_from_cli(cli);

    if daemon_direction.is_none() && remote_direction == Some(TransferDirection::Push) {
        request.chmod = false;
        request.executability = false;
        request.owner = false;
        request.group = false;
        request.acls = false;
        request.xattrs = false;
        request.fake_super = false;
        request.atimes = false;
        request.crtimes = false;
        request.omit_dir_times = false;
        request.user_map = false;
        request.group_map = false;
        request.chown = false;
    }

    request.degradations(metadata_policy)
}

fn posix_metadata_summary(plan: &TransferPlan) -> String {
    let mut parts = Vec::new();
    if plan.preserve_permissions {
        parts.push("perms");
    }
    if plan.preserve_owner {
        parts.push("owner");
    }
    if plan.preserve_group {
        parts.push("group");
    }
    if plan.preserve_executability {
        parts.push("executability");
    }
    if plan.preserve_acls {
        parts.push("acls");
    }
    if plan.preserve_xattrs {
        parts.push("xattrs");
    }
    if plan.hard_links {
        parts.push("hard-links");
    }
    if plan.fake_super {
        parts.push("fake-super");
    }
    if plan.omit_dir_times {
        parts.push("omit-dir-times");
    }
    if plan.atimes {
        parts.push("atimes");
    }
    if plan.crtimes {
        parts.push("crtimes");
    }
    if plan.omit_link_times {
        parts.push("omit-link-times");
    }
    if plan.numeric_ids {
        parts.push("numeric-ids");
    }
    if plan.chmod.is_some() {
        parts.push("chmod");
    }
    if !plan.user_maps.is_empty() {
        parts.push("usermap");
    }
    if !plan.group_maps.is_empty() {
        parts.push("groupmap");
    }
    if plan.chown.is_some() {
        parts.push("chown");
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(",")
    }
}

fn add_explicit_option_diagnostics(cli: &Cli, report: &mut Report) {
    if cli.numeric_ids {
        report.warn(
            "W_UNSUPPORTED_OPTION",
            "--numeric-ids is parsed as an owner/group id mapping modifier; it has no local effect unless owner/group preservation is requested",
        );
    }
    if let Some(chmod) = &cli.chmod {
        if chmod.parse::<ChmodRules>().is_ok() {
            report.info(
                "I_OPTION_PARSED",
                "--chmod is applied to POSIX mode bits for remote uploads; local Windows destinations do not chmod files",
            );
        }
    }

    for (enabled, flag) in [
        (cli.compress, "-z/--compress"),
        (cli.partial, "--partial"),
        (cli.inplace, "--inplace"),
        (cli.append_verify, "--append-verify"),
        (cli.copy_links, "--copy-links"),
        (cli.copy_dirlinks, "--copy-dirlinks"),
        (cli.keep_dirlinks, "--keep-dirlinks"),
        (cli.safe_links, "--safe-links"),
        (cli.copy_unsafe_links, "--copy-unsafe-links"),
        (cli.munge_links, "--munge-links"),
        (cli.hard_links, "--hard-links"),
        (cli.devices, "--devices"),
        (cli.specials, "--specials"),
        (cli.copy_devices, "--copy-devices"),
        (cli.write_devices, "--write-devices"),
        (cli.preserve_permissions, "--perms"),
        (cli.preserve_owner, "--owner"),
        (cli.preserve_group, "--group"),
        (cli.executability, "--executability"),
        (cli.acls, "--acls"),
        (cli.xattrs, "--xattrs"),
        (cli.fake_super, "--fake-super"),
        (cli.atimes, "--atimes"),
        (cli.crtimes, "--crtimes"),
        (cli.omit_dir_times, "--omit-dir-times"),
        (cli.omit_link_times, "--omit-link-times"),
        (cli.vss, "--vss"),
        (cli.no_owner, "--no-o"),
        (cli.no_group, "--no-g"),
    ] {
        if enabled {
            report.info(
                "I_OPTION_PARSED",
                format!("{flag} is represented in the execution plan"),
            );
        }
    }

    for map in &cli.user_maps {
        report.info(
            "I_OPTION_PARSED",
            format!("--usermap={map} is represented in the execution plan"),
        );
    }
    for map in &cli.group_maps {
        report.info(
            "I_OPTION_PARSED",
            format!("--groupmap={map} is represented in the execution plan"),
        );
    }
    if let Some(chown) = &cli.chown {
        report.info(
            "I_OPTION_PARSED",
            format!("--chown={chown} is represented in the execution plan"),
        );
    }

    if let Some(checksum_choice) = &cli.checksum_choice {
        report.info(
            "I_OPTION_PARSED",
            format!("--checksum-choice={checksum_choice} is represented in the execution plan"),
        );
    }
    if let Some(checksum_seed) = cli.checksum_seed {
        report.info(
            "I_OPTION_PARSED",
            format!("--checksum-seed={checksum_seed} is represented in the execution plan"),
        );
    }
    if let Some(compress_choice) = &cli.compress_choice {
        report.info(
            "I_OPTION_PARSED",
            format!("--compress-choice={compress_choice} is represented in the execution plan"),
        );
    }
    if let Some(compress_level) = cli.compress_level {
        report.info(
            "I_OPTION_PARSED",
            format!("--compress-level={compress_level} is represented in the execution plan"),
        );
    }
    if let Some(compress_threads) = cli.compress_threads {
        report.info(
            "I_OPTION_PARSED",
            format!("--compress-threads={compress_threads} is represented in the execution plan"),
        );
    }
    for skip in &cli.skip_compress {
        report.info(
            "I_OPTION_PARSED",
            format!("--skip-compress={skip} is represented in the execution plan"),
        );
    }

    if let Some(remote_shell) = &cli.remote_shell {
        report.info(
            "I_REMOTE_SHELL",
            format!("-e/--rsh remote shell command: {remote_shell}"),
        );
    }
    if let Some(rsync_path) = &cli.rsync_path {
        report.info(
            "I_REMOTE_RSYNC_PATH",
            format!("--rsync-path remote program: {rsync_path}"),
        );
    }
    if cli.blocking_io {
        report.info(
            "I_REMOTE_BLOCKING_IO",
            "--blocking-io requested; child process transport uses blocking stdio",
        );
    }
    if cli.old_args {
        report.info(
            "I_REMOTE_ARGS",
            "--old-args requested; remote filename args use legacy shell splitting and sender arg names are trusted",
        );
    }
    if cli.secluded_args {
        report.info(
            "I_REMOTE_ARGS",
            "--secluded-args requested; remote filename args are sent in the protected pre-handshake arg stream",
        );
    }
    if cli.trust_sender {
        report.info(
            "I_TRUST_SENDER",
            "--trust-sender disables strict sender file-list claim validation but keeps destination path safety checks",
        );
    }
    if cli.ipv4 || cli.ipv6 {
        report.info(
            "I_REMOTE_ADDRESS_FAMILY",
            if cli.ipv4 {
                "--ipv4 selects ssh -4 for remote-shell transport"
            } else {
                "--ipv6 selects ssh -6 for remote-shell transport"
            },
        );
    }

    if let Some(partial_dir) = &cli.partial_dir {
        report.info(
            "I_OPTION_PARSED",
            format!("--partial-dir={partial_dir} is represented in the execution plan"),
        );
    }
    for option in &cli.accepted_unsupported_options {
        report.warn(
            "W_UNIMPLEMENTED_OPTION",
            format!("{option} is accepted for rsync option compatibility but has no behavior in this build yet"),
        );
    }
}

fn add_option_conflict_diagnostics(cli: &Cli, report: &mut Report) {
    if let (Some(min_size), Some(max_size)) = (cli.min_size, cli.max_size) {
        if min_size > max_size {
            report.error(
                "E_OPTION_CONFLICT",
                "--min-size cannot be greater than --max-size",
            );
        }
    }
    if cli.ignore_missing_args && cli.delete_missing_args {
        report.error(
            "E_OPTION_CONFLICT",
            "--ignore-missing-args cannot be combined with --delete-missing-args",
        );
    }
    if cli.inplace && cli.delay_updates {
        report.error(
            "E_OPTION_CONFLICT",
            "--inplace cannot be combined with --delay-updates",
        );
    }
    if cli.inplace && cli.partial_dir.is_some() {
        report.error(
            "E_OPTION_CONFLICT",
            "--inplace and --partial-dir cannot both control the same write path",
        );
    }
    if cli.inplace && cli.temp_dir.is_some() {
        report.error(
            "E_OPTION_CONFLICT",
            "--inplace and --temp-dir cannot both control the same write path",
        );
    }
    if cli.fake_super && cli.metadata_policy == CliMetadataPolicy::NtfsNative {
        report.error(
            "E_OPTION_CONFLICT",
            "--fake-super cannot be combined with --metadata-policy=ntfs-native",
        );
    }
    let link_modes = [
        cli.links,
        cli.copy_links,
        cli.copy_dirlinks,
        cli.copy_unsafe_links,
        cli.safe_links,
        cli.munge_links,
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count();
    if !cli.no_links && link_modes > 1 {
        report.warn(
            "W_OPTION_OVERLAP",
            "multiple symlink transfer modes were requested; rsync-win applies its current precedence while preserving the diagnostic",
        );
    }
    if cli.existing && cli.ignore_existing {
        report.warn(
            "W_OPTION_OVERLAP",
            "--existing and --ignore-existing together leave only receiver-missing files eligible",
        );
    }
}

fn ensure_local_execution_options_supported(cli: &Cli) -> Result<()> {
    if cli.inplace && cli.partial_dir.is_some() {
        bail!("--inplace and --partial-dir cannot both control the same local write path");
    }

    Ok(())
}

fn ensure_remote_execution_options_supported(cli: &Cli, plan: &TransferPlan) -> Result<()> {
    if plan.remote_ssh_command.is_none() {
        bail!("remote-shell execution could not be planned; run with --plan for diagnostics");
    }
    if plan.remote_direction == Some(TransferDirection::Push)
        && cli.paths[..cli.paths.len() - 1]
            .iter()
            .any(|path| is_remote_shell_operand(path))
    {
        bail!("remote-shell push sources must be local paths");
    }

    if plan.remote_direction == Some(TransferDirection::Push)
        && cli.delete
        && cli.files_from.is_some()
    {
        bail!(
            "remote-shell push does not yet support --delete together with --files-from because receiver-side files-from semantics are not implemented"
        );
    }
    if cli.inplace && cli.partial_dir.is_some() {
        bail!("--inplace and --partial-dir cannot both control the same remote-shell write path");
    }
    if cli.metadata_policy != CliMetadataPolicy::Portable {
        bail!("remote-shell MVP currently supports only --metadata-policy=portable");
    }
    if cli.vss {
        bail!(
            "remote-shell execution does not yet support VSS metadata options; run with --plan for diagnostics"
        );
    }
    let _ = RemoteCompressionConfig::for_plan(plan)?;

    Ok(())
}

fn ensure_daemon_execution_options_supported(cli: &Cli, plan: &TransferPlan) -> Result<()> {
    let daemon = plan
        .daemon_operand
        .as_ref()
        .context("daemon execution could not be planned; run with --plan for diagnostics")?;
    if cli.remote_shell.is_some() {
        bail!("daemon client mode does not use --rsh/-e; omit the remote-shell option");
    }
    if plan.daemon_direction != Some(TransferDirection::Pull) {
        bail!("daemon client MVP currently supports module listing and pull only");
    }
    if daemon.module.is_none() && !cli.list_only {
        bail!("daemon module listing requires --list-only host::");
    }
    if daemon.module.is_none() && cli.paths.len() != 1 {
        bail!("daemon module listing takes exactly one daemon operand");
    }
    if daemon.module.is_some() && cli.paths.len() != 2 {
        bail!("daemon pull requires one daemon source and one local destination");
    }
    if cli.list_only && daemon.module.is_some() {
        bail!("daemon --list-only currently supports module listing only; use a destination for pull dry runs");
    }
    if cli.inplace && cli.partial_dir.is_some() {
        bail!("--inplace and --partial-dir cannot both control the same daemon write path");
    }
    if cli.metadata_policy != CliMetadataPolicy::Portable {
        bail!("daemon client MVP currently supports only --metadata-policy=portable");
    }
    if cli.preserve_owner
        || cli.preserve_group
        || cli.acls
        || cli.xattrs
        || cli.fake_super
        || cli.vss
    {
        bail!(
            "daemon execution does not yet support owner/group, ACL, xattr, fake-super, or VSS metadata options; run with --plan for diagnostics"
        );
    }

    Ok(())
}

fn is_daemon_operand_syntax(operand: &str) -> bool {
    operand.starts_with("rsync://") || operand.contains("::")
}

fn is_remote_shell_operand(operand: &str) -> bool {
    if is_daemon_operand_syntax(operand) {
        return false;
    }
    matches!(RemoteShellOperand::parse(operand), Ok(Some(_)) | Err(_))
}

fn append_diagnostics(output: &mut String, report: &Report) {
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

fn append_action_report(output: &mut String, cli: &Cli, actions: &[SyncAction]) {
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

fn append_compact_action_summary(output: &mut String, actions: &[SyncAction]) {
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

fn append_action_warnings(output: &mut String, actions: &[SyncAction]) {
    for action in actions {
        if let SyncAction::Warn { path, message } = action {
            output.push_str(&format!("- warning {}: {message}\n", path.display()));
        }
    }
}

fn append_sync_action(output: &mut String, action: &SyncAction) {
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

fn log_sync_actions(progress: ProgressLog, actions: &[SyncAction]) {
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

fn append_optional_itemized_changes(output: &mut String, enabled: bool, actions: &[SyncAction]) {
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

fn append_itemized_action(output: &mut String, action: &SyncAction) {
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

fn append_structured_stats(output: &mut String, enabled: bool, actions: &[SyncAction]) {
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
    fn from_actions(actions: &[SyncAction]) -> Self {
        let mut stats = Self::default();
        for action in actions {
            stats.record(action);
        }
        stats
    }

    fn record(&mut self, action: &SyncAction) {
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

fn metadata_code(feature: MetadataFeature, severity: Severity) -> &'static str {
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

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

fn update_mode_label(mode: UpdateMode) -> &'static str {
    match mode {
        UpdateMode::QuickCheck => "quick-check",
        UpdateMode::Checksum => "checksum",
        UpdateMode::SizeOnly => "size-only",
        UpdateMode::IgnoreTimes => "ignore-times",
    }
}

fn delete_mode_label(mode: DeleteMode) -> &'static str {
    match mode {
        DeleteMode::None => "none",
        DeleteMode::Before => "before",
        DeleteMode::During => "during",
        DeleteMode::Delay => "delay",
        DeleteMode::After => "after",
    }
}

fn file_write_mode_label(mode: FileWriteMode) -> &'static str {
    match mode {
        FileWriteMode::Atomic => "atomic",
        FileWriteMode::InPlace => "inplace",
    }
}

fn symlink_mode_label(mode: SymlinkMode) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsync_protocol::{write_rsync31_file_list_with_options, RSYNC_REGULAR_FILE_MODE};
    use std::fs;
    use std::io::{Read, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn renders_default_banner() {
        let output = parse_and_render(["rsync-win"]);

        assert!(output.contains("rsync-win development transfer planner"));
        assert!(output.contains("execution: plan output only"));
        assert!(output.contains("protocol primitives range: 20-32"));
    }

    #[test]
    fn renders_protocol_range() {
        let output = parse_and_render(["rsync-win", "--protocol-range"]);

        assert_eq!(output, "20-32\n");
    }

    #[test]
    fn renders_version_with_protocol_range() {
        let output = parse_and_render(["rsync-win", "--version"]);

        assert!(output.contains(&format!("rsync-win {}", env!("CARGO_PKG_VERSION"))));
        assert!(output.contains("protocol primitives range: 20-32"));
        assert!(output.contains(
            "remote-shell MVP tries protocol 31 first with protocol 27 compatibility fallback"
        ));
    }

    #[test]
    fn command_has_version_and_help_output() {
        let mut command = build_command();
        let help = command.render_long_help().to_string();
        assert!(help.contains("Native Windows rsync development build"));
        assert!(help.contains("--version"));
        assert!(help.contains("--protocol-range"));
        assert!(help.contains("--plan"));
        assert!(help.contains("--metadata-policy"));
        assert!(help.contains("--fail-on-metadata-loss"));
    }

    #[test]
    fn archive_mode_reports_unsupported_metadata_without_claiming_success() {
        let output = parse_and_render([
            "rsync-win",
            "-a",
            "--delete",
            "--dry-run",
            "src",
            "host:dest",
        ]);

        assert!(output.contains("archive mode expands to -rlptgoD"));
        assert!(output.contains("[warning] W_METADATA_OWNER"));
        assert!(output.contains("[warning] W_METADATA_GROUP"));
        assert!(output.contains("[warning] W_METADATA_DEVICE"));
        assert!(output.contains(
            "remote --server argv: rsync --server --delete-during --no-inc-recursive --perms --owner --group --links --devices --specials -ntre.LsfxCIvu"
        ));
        assert!(output.contains("[info] I_REMOTE_PROTOCOL31_MVP"));
        assert!(output.contains("wire protocol: experimental protocol 31"));
    }

    #[test]
    fn remote_shell_plan_shows_ssh_command_without_claiming_transfer_execution() {
        let output = parse_and_render([
            "rsync-win",
            "-rt",
            "--whole-file",
            "--plan",
            "src",
            "user@example.test:/tmp/path with spaces",
        ]);

        assert!(output
            .contains("remote --server argv: rsync --server --no-inc-recursive -Wtre.LsfxCIvu"));
        assert!(output.contains(
            "remote ssh argv: ssh -o BatchMode=yes -o ConnectTimeout=10 user@example.test"
        ));
        assert!(output.contains("'/tmp/path with spaces'"));
        assert!(output.contains("wire protocol: experimental protocol 31"));
        assert!(output.contains("[info] I_REMOTE_PROTOCOL31_MVP"));
        assert!(!output.contains("local portable sync"));
    }

    #[test]
    fn remote_shell_plan_accepts_rsync_e_compress_and_no_owner_group() {
        let output = parse_and_render([
            "rsync-win",
            "-avz",
            "--no-o",
            "--no-g",
            "./hunyuan_only_run/",
            "-e",
            "ssh -p 10080",
            "root@118.145.32.132:/mnt/afs/250010150/huozhiyu/VBench-exp/hunyuan_only_run/",
        ]);

        assert!(output.contains("compress: true"));
        assert!(output.contains("remote direction: upload (local -> remote)"));
        assert!(output.contains("remote ssh argv: ssh -p 10080 root@118.145.32.132"));
        assert!(output.contains("[info] I_REMOTE_SHELL"));
        assert!(!output.contains("[warning] W_COMPRESS_UNSUPPORTED"));
        assert!(!output.contains("BatchMode=yes"));
        assert!(!output.contains("W_METADATA_OWNER"));
        assert!(!output.contains("W_METADATA_GROUP"));
    }

    #[test]
    fn literal_token_writer_checksums_while_streaming() {
        let mut output = Vec::new();
        let mut input = &b"abcdef"[..];

        let sent = write_literal_tokens_from_reader_with_checksum(
            &mut output,
            &mut input,
            RemoteFinalChecksum::PlainMd4,
            None,
            None,
        )
        .unwrap();

        assert_eq!(sent, 6);
        assert_eq!(i32::from_le_bytes(output[0..4].try_into().unwrap()), 6);
        assert_eq!(&output[4..10], b"abcdef");
        assert_eq!(i32::from_le_bytes(output[10..14].try_into().unwrap()), 0);
        assert_eq!(
            &output[14..30],
            &rsync_protocol::rsync_plain_md4_checksum(b"abcdef")
        );
    }

    #[test]
    fn delta_token_writer_emits_copy_tokens_for_matching_basis_blocks() {
        let basis = b"AAAABBBBCCCC";
        let target = b"AAAAXXXXCCCC";
        let signatures = test_remote_block_signatures(basis, 4, 16, RemoteFileChecksum::PlainMd4);
        let mut output = Vec::new();

        let stats = write_delta_tokens_from_bytes_with_checksum(
            &mut output,
            target,
            RemoteFileChecksum::PlainMd4,
            RemoteFinalChecksum::PlainMd4,
            &signatures,
            None,
            None,
        )
        .unwrap();

        assert_eq!(stats.literal_bytes, 4);
        assert_eq!(stats.copied_bytes, 8);
        assert_eq!(i32::from_le_bytes(output[0..4].try_into().unwrap()), -1);
        assert_eq!(i32::from_le_bytes(output[4..8].try_into().unwrap()), 4);
        assert_eq!(&output[8..12], b"XXXX");
        assert_eq!(i32::from_le_bytes(output[12..16].try_into().unwrap()), -3);
        assert_eq!(i32::from_le_bytes(output[16..20].try_into().unwrap()), 0);
        assert_eq!(
            &output[20..36],
            &rsync_protocol::rsync_plain_md4_checksum(target)
        );
    }

    #[test]
    fn delta_token_writer_sends_less_literal_data_for_large_small_edit() {
        let block_size = 4096;
        let block_count = 512;
        let mut basis = Vec::with_capacity(block_size * block_count);
        for block in 0..block_count {
            for offset in 0..block_size {
                basis.push(((block * 31 + offset) % 251) as u8);
            }
        }
        let mut target = basis.clone();
        let edit_start = 257 * block_size + 128;
        target[edit_start..edit_start + 256].fill(0x7f);
        let signatures =
            test_remote_block_signatures(&basis, block_size, 16, RemoteFileChecksum::PlainMd4);
        let mut output = Vec::new();

        let stats = write_delta_tokens_from_bytes_with_checksum(
            &mut output,
            &target,
            RemoteFileChecksum::PlainMd4,
            RemoteFinalChecksum::PlainMd4,
            &signatures,
            None,
            None,
        )
        .unwrap();

        assert!(stats.literal_bytes <= block_size as u64);
        assert!(stats.copied_bytes >= (target.len() - block_size) as u64);
        assert!(stats.literal_bytes < target.len() as u64 / 100, "{stats:?}");
    }

    #[test]
    fn delta_token_reader_applies_copy_tokens_from_basis_file() {
        let root = unique_temp_dir("rsync-cli-delta-token-reader");
        let basis = root.join("basis.txt");
        let dest = root.join("dest.txt");
        fs::create_dir_all(&root).unwrap();
        fs::write(&basis, b"AAAABBBBCCCC").unwrap();

        let mut payload = Vec::new();
        write_i32_le(&mut payload, -1).unwrap();
        write_i32_le(&mut payload, 4).unwrap();
        payload.extend_from_slice(b"XXXX");
        write_i32_le(&mut payload, -3).unwrap();
        write_i32_le(&mut payload, 0).unwrap();
        payload.extend_from_slice(&rsync_protocol::rsync_plain_md4_checksum(b"AAAAXXXXCCCC"));
        let mut input = Vec::new();
        append_mux_payload(&mut input, &payload);
        let mut input = &input[..];
        let mut mux = MultiplexReadState::default();

        let bytes = read_file_tokens_to_path_with_basis(
            &mut input,
            &mut mux,
            RemoteFinalChecksum::PlainMd4,
            Path::new("dest.txt"),
            &dest,
            12,
            Some((
                &basis,
                RemoteSumHead {
                    block_count: 3,
                    block_len: 4,
                    checksum_len: 16,
                    remainder: 0,
                },
            )),
            None,
            None,
        )
        .unwrap();

        assert_eq!(bytes, 12);
        assert_eq!(fs::read(&dest).unwrap(), b"AAAAXXXXCCCC");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compressed_delta_tokens_roundtrip_with_copy_tokens() {
        let root = unique_temp_dir("rsync-cli-compressed-delta-token-reader");
        let basis_path = root.join("basis.txt");
        let dest = root.join("dest.txt");
        fs::create_dir_all(&root).unwrap();
        let basis = b"AAAABBBBCCCC";
        let target = b"AAAAXXXXCCCC";
        fs::write(&basis_path, basis).unwrap();
        let signatures = test_remote_block_signatures(basis, 4, 16, RemoteFileChecksum::PlainMd4);
        let mut payload = Vec::new();

        let stats = write_delta_tokens_from_bytes_with_checksum(
            &mut payload,
            target,
            RemoteFileChecksum::PlainMd4,
            RemoteFinalChecksum::PlainMd4,
            &signatures,
            Some(6),
            None,
        )
        .unwrap();
        assert_eq!(stats.literal_bytes, 4);
        assert_eq!(stats.copied_bytes, 8);

        let mut input = Vec::new();
        append_mux_payload(&mut input, &payload);
        let mut input = &input[..];
        let mut mux = MultiplexReadState::default();
        let compression = RemoteCompressionConfig {
            mode: RsyncDeflatedTokenMode::Zlibx,
            level: 6,
            skip_suffixes: Vec::new(),
        };

        let bytes = read_file_tokens_to_path_with_basis(
            &mut input,
            &mut mux,
            RemoteFinalChecksum::PlainMd4,
            Path::new("dest.txt"),
            &dest,
            12,
            Some((
                &basis_path,
                RemoteSumHead {
                    block_count: 3,
                    block_len: 4,
                    checksum_len: 16,
                    remainder: 0,
                },
            )),
            Some(&compression),
            None,
        )
        .unwrap();

        assert_eq!(bytes, 12);
        assert_eq!(fs::read(&dest).unwrap(), target);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn append_verify_token_writer_sends_suffix_but_checksums_whole_file() {
        let mut output = Vec::new();
        let mut input = &b"abcdef"[..];

        let sent = write_append_verify_literal_tokens_from_reader_with_checksum(
            &mut output,
            &mut input,
            RemoteFinalChecksum::PlainMd4,
            3,
            None,
            None,
        )
        .unwrap();

        assert_eq!(sent, 3);
        assert_eq!(i32::from_le_bytes(output[0..4].try_into().unwrap()), 3);
        assert_eq!(&output[4..7], b"def");
        assert_eq!(i32::from_le_bytes(output[7..11].try_into().unwrap()), 0);
        assert_eq!(
            &output[11..27],
            &rsync_protocol::rsync_plain_md4_checksum(b"abcdef")
        );
    }

    #[test]
    fn protocol31_checksum_choice_controls_block_and_final_digest_algorithm() {
        let md5_abc = [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72,
        ];
        let block_checksum = RemoteFileChecksum::protocol31(Some("md5"), 0).unwrap();
        let final_checksum = RemoteFinalChecksum::protocol31(Some("md5")).unwrap();

        assert_eq!(remote_checksum_for_bytes(block_checksum, b"abc"), md5_abc);
        assert_eq!(
            remote_final_checksum_for_bytes(final_checksum, b"abc"),
            md5_abc
        );
        assert_ne!(
            remote_checksum_for_bytes(block_checksum, b"abc"),
            rsync_protocol::rsync_plain_md4_checksum(b"abc")
        );
    }

    #[cfg(windows)]
    #[test]
    fn remote_token_file_io_handles_windows_long_paths() {
        let root = unique_temp_dir("rsync-cli-long-path");
        let mut long_dir = root.clone();
        while long_dir.as_os_str().to_string_lossy().len() < 280 {
            long_dir.push("segment0123456789");
        }
        let source = long_dir.join("source.txt");
        let dest = long_dir.join("dest.txt");
        assert!(source.as_os_str().to_string_lossy().len() > 260);

        std::fs::create_dir_all(to_long_path_safe(&long_dir)).unwrap();
        std::fs::write(to_long_path_safe(&source), b"abc").unwrap();

        let mut upload_tokens = Vec::new();
        assert_eq!(
            write_delta_tokens_from_path(
                &mut upload_tokens,
                RemoteFileChecksum::PlainMd4,
                RemoteFinalChecksum::PlainMd4,
                &source,
                &[],
                None,
                None
            )
            .unwrap()
            .literal_bytes,
            3
        );
        assert_eq!(
            checksum_local_path(&source).unwrap(),
            rsync_protocol::rsync_plain_md4_checksum(b"abc")
        );

        let mut payload = Vec::new();
        write_i32_le(&mut payload, 3).unwrap();
        payload.extend_from_slice(b"abc");
        write_i32_le(&mut payload, 0).unwrap();
        payload.extend_from_slice(&rsync_protocol::rsync_plain_md4_checksum(b"abc"));
        let mut input = Vec::new();
        append_mux_payload(&mut input, &payload);
        let mut input = &input[..];
        let mut mux = MultiplexReadState::default();

        assert_eq!(
            read_file_tokens_to_path_with_basis(
                &mut input,
                &mut mux,
                RemoteFinalChecksum::PlainMd4,
                Path::new("dest.txt"),
                &dest,
                3,
                None,
                None,
                None
            )
            .unwrap(),
            3
        );
        assert_eq!(std::fs::read(to_long_path_safe(&dest)).unwrap(), b"abc");

        std::fs::remove_dir_all(to_long_path_safe(&root)).unwrap();
    }

    #[test]
    fn should_fallback_to_protocol27_accepts_protocol31_setup_errors() {
        let fallback_errors = vec![
            anyhow::Error::new(RemoteSessionError::UnsupportedProtocol {
                negotiated: 30,
                supported: REMOTE_SHELL_MODERN_PROTOCOL,
            }),
            anyhow::Error::new(RemoteSessionError::UnsupportedChecksumNegotiation),
            anyhow::Error::new(RemoteSessionError::InvalidChecksumList),
            anyhow::Error::new(RemoteSessionError::Session(
                SessionError::NonProtocolOutput("banner".to_string()),
            )),
            anyhow::Error::new(RemoteSessionError::Session(
                SessionError::IncompleteProtocolPrefix,
            )),
            anyhow::Error::new(RemoteSessionError::Session(
                SessionError::InvalidProtocolPrefix(0x7273_796e),
            )),
            protocol31_setup_error(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated setup frame",
            )),
            protocol31_setup_error(RemoteSessionError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated handshake",
            ))),
        ];

        for err in fallback_errors {
            assert!(should_fallback_to_protocol27(&err), "{err}");
        }
    }

    #[test]
    fn should_fallback_to_protocol27_rejects_transfer_errors() {
        let non_fallback_errors = vec![
            anyhow::Error::new(RemoteSessionError::InvalidFileIndex {
                index: 99,
                file_count: 1,
            }),
            anyhow::Error::new(RemoteSessionError::NonFileBlockRequest { index: 0 }),
            anyhow::Error::new(RemoteSessionError::FileChecksumMismatch {
                path: "file.txt".to_string(),
            }),
            anyhow::Error::new(RemoteSessionError::InvalidPhaseAck(0)),
            anyhow::Error::new(RemoteSessionError::InvalidFinalAck(0)),
            anyhow::Error::new(RemoteSessionError::UnexpectedToken {
                token: -1,
                path: "file.txt".to_string(),
            }),
            anyhow::Error::new(RemoteSessionError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated transfer",
            ))),
            anyhow::Error::new(RemoteSessionError::Session(
                SessionError::RemoteErrorMessage("remote refused transfer".to_string()),
            )),
        ];

        for err in non_fallback_errors {
            assert!(!should_fallback_to_protocol27(&err), "{err}");
        }
    }

    #[test]
    fn remote_shell_execute_rejects_nonportable_metadata_policy_before_spawning() {
        let err = parse_and_execute([
            "rsync-win",
            "-rt",
            "--metadata-policy",
            "posix",
            "src",
            "user@example.test:/tmp/dest",
        ])
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("remote-shell MVP currently supports only --metadata-policy=portable"));
    }

    #[test]
    fn remote_push_delete_with_filters_routes_receiver_protection() {
        let cli = Cli::parse_from([
            "rsync-win",
            "-rt",
            "--delete",
            "--exclude",
            "*.tmp",
            "src",
            "user@example.test:/tmp/dest",
        ]);
        let plan = TransferPlan::from_cli(&cli);

        ensure_remote_execution_options_supported(&cli, &plan).unwrap();
        let argv = plan.remote_server_argv.as_ref().unwrap();
        assert!(argv.contains(&"--delete-during".to_string()));
        assert!(argv.contains(&"--exclude=*.tmp".to_string()));
    }

    #[test]
    fn remote_shell_execute_allows_chunk7_posix_metadata_options_before_spawning() {
        let cli = options::parse_cli([
            "rsync-win",
            "-r",
            "--owner",
            "--group",
            "--acls",
            "--xattrs",
            "--fake-super",
            "--atimes",
            "--crtimes",
            "--usermap=*:root",
            "--groupmap=*:root",
            "--chown=root:root",
            "src",
            "user@example.test:/tmp/dest",
        ])
        .unwrap();
        let plan = TransferPlan::from_cli(&cli);

        ensure_remote_execution_options_supported(&cli, &plan).unwrap();

        let argv = plan.remote_server_argv.as_ref().unwrap();
        for expected in [
            "--owner",
            "--group",
            "--acls",
            "--xattrs",
            "--fake-super",
            "--atimes",
            "--crtimes",
            "--usermap=*:root",
            "--groupmap=*:root",
            "--chown=root:root",
        ] {
            assert!(argv.contains(&expected.to_string()), "{expected}: {argv:?}");
        }
    }

    #[test]
    fn remote_push_still_rejects_delete_with_files_from() {
        let cli = Cli::parse_from([
            "rsync-win",
            "-rt",
            "--delete",
            "--files-from",
            "list.txt",
            "src",
            "user@example.test:/tmp/dest",
        ]);
        let plan = TransferPlan::from_cli(&cli);

        let err = ensure_remote_execution_options_supported(&cli, &plan).unwrap_err();

        assert!(err.to_string().contains(
            "remote-shell push does not yet support --delete together with --files-from"
        ));
    }

    #[test]
    fn remote_shell_plan_includes_supported_phase5_execution_options() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--size-only",
            "--partial",
            "--partial-dir",
            ".rsync-partial",
            "--plan",
            "src",
            "user@example.test:/tmp/dest",
        ]);

        assert!(output.contains("--size-only"));
        assert!(output.contains("--partial"));
        assert!(output.contains("--partial-dir=.rsync-partial"));
        assert!(output.contains("update mode: size-only"));
        assert!(output.contains("partial: true"));
    }

    #[test]
    fn remote_shell_plan_routes_delete_timing_options() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--delete-after",
            "--plan",
            "src",
            "user@example.test:/tmp/dest",
        ]);
        let server_line = output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(server_line.contains("--delete-after"));
        assert!(!server_line.contains("--delete-before"));
    }

    #[test]
    fn remote_shell_plan_routes_checksum_and_receiver_metadata_options() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "-c",
            "--numeric-ids",
            "--chmod",
            "F600,D700",
            "--plan",
            "src",
            "user@example.test:/tmp/dest",
        ]);
        let server_line = output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(server_line.contains("--checksum"));
        assert!(server_line.contains("--numeric-ids"));
        assert!(server_line.contains("--chmod=F600,D700"));
        assert!(output.contains("update mode: checksum"));
    }

    #[test]
    fn remote_push_chmod_with_fail_on_metadata_loss_keeps_supported_mapping() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--chmod",
            "F600",
            "--fail-on-metadata-loss",
            "--plan",
            "src",
            "user@example.test:/tmp/dest",
        ]);
        let server_line = output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(output.contains("remote direction: upload (local -> remote)"));
        assert!(server_line.contains("--chmod=F600"));
        assert!(!output.contains("[error] E_METADATA_PERMISSIONS"));
    }

    #[test]
    fn remote_push_executability_with_fail_on_metadata_loss_keeps_supported_mapping() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--executability",
            "--fail-on-metadata-loss",
            "--plan",
            "src",
            "user@example.test:/tmp/dest",
        ]);
        let server_line = output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(output.contains("remote direction: upload (local -> remote)"));
        assert!(server_line.contains("--executability"));
        assert!(!output.contains("[error] E_METADATA_LOSS"));
    }

    #[test]
    fn remote_pull_routes_sender_link_options_to_remote_server() {
        let copy_links_output = parse_and_render([
            "rsync-win",
            "-r",
            "--copy-links",
            "--plan",
            "user@example.test:/tmp/source",
            "dest",
        ]);
        let copy_links_server_line = copy_links_output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();
        let copy_unsafe_output = parse_and_render([
            "rsync-win",
            "-r",
            "--copy-unsafe-links",
            "--plan",
            "user@example.test:/tmp/source",
            "dest",
        ]);
        let copy_unsafe_server_line = copy_unsafe_output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(copy_links_server_line.contains("--copy-links"));
        assert!(!copy_links_server_line.contains("--copy-unsafe-links"));
        assert!(copy_unsafe_server_line.contains("--copy-unsafe-links"));
        assert!(!copy_unsafe_server_line.contains("--copy-links"));
    }

    #[test]
    fn remote_pull_plan_accepts_multiple_sources_from_same_host() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--plan",
            "user@example.test:/tmp/one",
            "user@example.test:/tmp/two",
            "dest",
        ]);
        let server_line = output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(output.contains("remote direction: download (remote -> local)"));
        assert!(server_line.contains("--sender"));
        assert!(server_line.contains("--no-inc-recursive"));
        assert!(server_line.ends_with(" . /tmp/one /tmp/two"));
        assert!(!output.contains("[error] E_REMOTE"));
    }

    #[test]
    fn remote_pull_plan_rejects_multiple_hosts() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--plan",
            "one@example.test:/tmp/one",
            "two@example.test:/tmp/two",
            "dest",
        ]);

        assert!(output.contains("[error] E_REMOTE_HOST_MISMATCH"));
        assert!(!output.contains("remote --server argv:"));
    }

    #[test]
    fn remote_pull_sender_index_sort_places_files_before_directory_walks() {
        let mut entries = vec![
            test_remote_entry(".", WireFileType::Directory),
            test_remote_entry("analysis", WireFileType::Directory),
            test_remote_entry("subdir", WireFileType::Directory),
            test_remote_entry("root.txt", WireFileType::File),
            test_remote_entry("analysis/config_overview.json", WireFileType::File),
            test_remote_entry("subdir/a.txt", WireFileType::File),
        ];

        sort_remote_entries_for_sender_indexes(&mut entries);

        let paths: Vec<_> = entries.iter().map(|entry| entry.path.as_path()).collect();
        assert_eq!(
            paths,
            vec![
                Path::new("."),
                Path::new("root.txt"),
                Path::new("analysis"),
                Path::new("analysis/config_overview.json"),
                Path::new("subdir"),
                Path::new("subdir/a.txt"),
            ]
        );
    }

    #[test]
    fn remote_push_routes_append_verify_without_whole_file() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--whole-file",
            "--append-verify",
            "--plan",
            "src",
            "user@example.test:/tmp/dest",
        ]);
        let server_line = output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(server_line.contains("--append-verify"));
        assert!(!server_line.contains("-W"));
        assert!(output.contains("append verify: true"));
    }

    #[test]
    fn remote_pull_keeps_append_verify_on_local_receiver_only() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--append-verify",
            "--plan",
            "user@example.test:/tmp/source",
            "dest",
        ]);
        let server_line = output
            .lines()
            .find(|line| line.starts_with("remote --server argv:"))
            .unwrap();

        assert!(!server_line.contains("--append-verify"));
        assert!(output.contains("append verify: true"));
    }

    #[test]
    fn remote_push_protocol31_dry_run_exchanges_session_bytes() {
        let root = unique_temp_dir("rsync-cli-remote-push-mvp");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--dry-run".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_dry_run_input());

        let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("rsync-win remote-shell push"));
        assert!(output.contains("protocol: 31 (peer advertised 31)"));
        assert!(output.contains("checksum negotiation: md4"));
        assert!(output.contains("files offered: 1"));
        assert!(output.contains("files sent: 0"));
        assert!(transport.written.starts_with(&31_u32.to_le_bytes()));
        assert!(transport
            .written
            .windows("file.txt".len())
            .any(|window| window == b"file.txt"));
        assert!(!output.contains("transfer note: no file data was sent"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_accepts_local_source_with_trailing_forward_separator() {
        let root = unique_temp_dir("rsync-cli-remote-push-trailing-separator");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();
        let source_arg = format!("{}/", source.to_string_lossy());

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--dry-run".to_string(),
            source_arg,
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_dry_run_input());

        let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("files offered: 1"));
        assert!(transport
            .written
            .windows("file.txt".len())
            .any(|window| window == b"file.txt"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_delete_sends_filter_list_terminator_before_file_list() {
        let root = unique_temp_dir("rsync-cli-remote-push-delete-filter-list");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--delete".to_string(),
            "--dry-run".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_dry_run_input());

        let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();
        let payloads = written_protocol31_mux_payloads(&transport.written);

        assert!(output.contains("files offered: 1"));
        assert_eq!(
            payloads.first().map(Vec::as_slice),
            Some(&[0_u8, 0, 0, 0][..])
        );
        assert!(payloads.iter().skip(1).any(|payload| {
            payload
                .windows("file.txt".len())
                .any(|window| window == b"file.txt")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_notes_when_quick_check_skips_all_file_data() {
        let root = unique_temp_dir("rsync-cli-remote-push-quick-check-skip");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_dry_run_input());

        let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("files sent: 0"));
        assert!(output.contains("bytes sent: 0"));
        assert!(output.contains(
            "transfer note: no file data was sent; remote quick-check treated the destination as up-to-date by size and mtime"
        ));
        assert!(output.contains(
            "hint: if the remote file may be corrupt, rerun with -c/--checksum or --ignore-times"
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_append_verify_sends_only_suffix_tokens() {
        let root = unique_temp_dir("rsync-cli-remote-push-append");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"abcdef").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--append-verify".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_append_verify_input());

        let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("files sent: 1"));
        assert!(output.contains("bytes sent: 3"));
        assert!(transport
            .written
            .windows("def".len())
            .any(|window| window == b"def"));
        assert!(!transport
            .written
            .windows("abcdef".len())
            .any(|window| window == b"abcdef"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_rejects_append_basis_larger_than_sender() {
        let root = unique_temp_dir("rsync-cli-remote-push-append-oversize");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"abcdef").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--append-verify".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport =
            TestTransport::with_input(remote_push_append_verify_oversized_basis_input());

        let err = execute_remote_push(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string()
                .contains("remote append basis is larger than sender file"),
            "{err:#}"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_rejects_unsupported_mux_during_transfer() {
        let root = unique_temp_dir("rsync-cli-remote-push-bad-mux-transfer");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_unsupported_mux_input());

        let err = execute_remote_push(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string().contains("unsupported multiplex message"),
            "{err:#}"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_rejects_unsupported_mux_during_final_goodbye() {
        let root = unique_temp_dir("rsync-cli-remote-push-bad-mux-final");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--dry-run".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_final_unsupported_mux_input());

        let err = execute_remote_push(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string().contains("unsupported multiplex message"),
            "{err:#}"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_push_protocol31_filters_local_sender_entries() {
        let root = unique_temp_dir("rsync-cli-remote-push-filter");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();
        fs::write(source.join("skip.tmp"), b"skip").unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--dry-run".to_string(),
            "--exclude".to_string(),
            "*.tmp".to_string(),
            source.to_string_lossy().into_owned(),
            "host:/tmp/dest".to_string(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_push_dry_run_input());

        let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("files offered: 1"));
        assert!(transport
            .written
            .windows("file.txt".len())
            .any(|window| window == b"file.txt"));
        assert!(!transport
            .written
            .windows("skip.tmp".len())
            .any(|window| window == b"skip.tmp"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_protocol31_dry_run_reads_file_list_and_reports_actions() {
        let root = unique_temp_dir("rsync-cli-remote-pull-mvp");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "--dry-run".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_dry_run_input());

        let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("rsync-win remote-shell pull"));
        assert!(output.contains("protocol: 31 (peer advertised 31)"));
        assert!(output.contains("checksum negotiation: md4"));
        assert!(output.contains("write-file"));
        assert!(output.contains("files received: 1"));
        assert!(!dest.join("file.txt").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_rejects_security_file_list_parent_escape_before_writes() {
        let root = unique_temp_dir("rsync-cli-remote-pull-escape");
        let dest = root.join("dest");
        fs::create_dir_all(&root).unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
            test_remote_entry(".", WireFileType::Directory),
            RsyncFileListEntry {
                path: PathBuf::from("../escape.txt"),
                file_type: WireFileType::File,
                len: 3,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ]));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(err.to_string().contains("portable"), "{err:#}");
        assert!(!dest.exists());
        assert!(!root.join("escape.txt").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_rejects_security_absolute_or_prefixed_file_list_paths_before_writes() {
        for (label, wire_path) in [
            ("drive", "C:/escape.txt"),
            ("root", "/escape.txt"),
            ("unc", "//server/share/escape.txt"),
        ] {
            let root = unique_temp_dir(&format!("rsync-cli-remote-pull-{label}-path"));
            let dest = root.join("dest");
            fs::create_dir_all(&root).unwrap();

            let cli = Cli::parse_from(vec![
                "rsync-win".to_string(),
                "host:/tmp/source".to_string(),
                dest.to_string_lossy().into_owned(),
            ]);
            let plan = TransferPlan::from_cli(&cli);
            let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
                test_remote_entry(".", WireFileType::Directory),
                RsyncFileListEntry {
                    path: PathBuf::from(wire_path),
                    file_type: WireFileType::File,
                    len: 3,
                    mtime_unix: 0,
                    mode: RSYNC_REGULAR_FILE_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
            ]));

            let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

            assert!(
                err.to_string()
                    .contains("not a portable relative rsync path"),
                "{wire_path}: {err:#}"
            );
            assert!(
                !dest.exists(),
                "{wire_path}: destination directory was created"
            );
            assert!(
                fs::read_dir(&root).unwrap().next().is_none(),
                "{wire_path}: rejected path left files under test root"
            );

            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn remote_pull_rejects_security_reserved_trailing_and_unicode_paths_before_writes() {
        for (label, wire_path, expected) in [
            ("reserved", "CON.txt", "not a portable relative rsync path"),
            (
                "trailing-dot",
                "dir/bad.",
                "not a portable relative rsync path",
            ),
            (
                "trailing-space",
                "dir/bad ",
                "not a portable relative rsync path",
            ),
        ] {
            let root = unique_temp_dir(&format!("rsync-cli-remote-pull-{label}"));
            let dest = root.join("dest");
            fs::create_dir_all(&root).unwrap();

            let cli = Cli::parse_from(vec![
                "rsync-win".to_string(),
                "host:/tmp/source".to_string(),
                dest.to_string_lossy().into_owned(),
            ]);
            let plan = TransferPlan::from_cli(&cli);
            let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
                test_remote_entry(".", WireFileType::Directory),
                RsyncFileListEntry {
                    path: PathBuf::from(wire_path),
                    file_type: WireFileType::File,
                    len: 3,
                    mtime_unix: 0,
                    mode: RSYNC_REGULAR_FILE_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
            ]));

            let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

            assert!(err.to_string().contains(expected), "{wire_path}: {err:#}");
            assert!(
                !dest.exists(),
                "{wire_path}: destination directory was created"
            );
            assert!(
                fs::read_dir(&root).unwrap().next().is_none(),
                "{wire_path}: rejected path left files under test root"
            );

            fs::remove_dir_all(root).unwrap();
        }

        let root = unique_temp_dir("rsync-cli-remote-pull-unicode-collision");
        let dest = root.join("dest");
        fs::create_dir_all(&root).unwrap();
        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
            test_remote_entry(".", WireFileType::Directory),
            test_remote_entry("caf\u{00e9}.txt", WireFileType::File),
            test_remote_entry("cafe\u{301}.txt", WireFileType::File),
        ]));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string().contains("case/normalization collision"),
            "{err:#}"
        );
        assert!(!dest.exists());
        assert!(fs::read_dir(&root).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trust_sender_default_rejects_remote_filter_violations() {
        let root = unique_temp_dir("rsync-cli-trust-sender-filter-default");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let cli = options::parse_cli(vec![
            "rsync-win".to_string(),
            "--dry-run".to_string(),
            "--exclude".to_string(),
            "*.tmp".to_string(),
            "host:/tmp/source/".to_string(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
            &[
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("skip.tmp", WireFileType::File),
                test_remote_entry("file.txt", WireFileType::File),
            ],
            2,
        ));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string().contains("remote sender sent filtered path"),
            "{err:#}"
        );
        assert!(fs::read_dir(&dest).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trust_sender_default_rejects_unrequested_single_file_entries() {
        let root = unique_temp_dir("rsync-cli-trust-sender-extra-source-default");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let cli = options::parse_cli(vec![
            "rsync-win".to_string(),
            "--dry-run".to_string(),
            "host:/tmp/allowed.txt".to_string(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
            &[
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("other.txt", WireFileType::File),
            ],
            1,
        ));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string()
                .contains("remote sender sent unrequested path"),
            "{err:#}"
        );
        assert!(fs::read_dir(&dest).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_args_trusts_remote_source_arg_names_but_not_filters() {
        let root = unique_temp_dir("rsync-cli-old-args-source-trust");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let cli = options::parse_cli(vec![
            "rsync-win".to_string(),
            "--dry-run".to_string(),
            "--old-args".to_string(),
            "host:/tmp/allowed.txt".to_string(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
            &[
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("other.txt", WireFileType::File),
            ],
            1,
        ));

        let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("files received: 1"), "{output}");
        assert!(fs::read_dir(&dest).unwrap().next().is_none());

        let cli = options::parse_cli(vec![
            "rsync-win".to_string(),
            "--dry-run".to_string(),
            "--old-args".to_string(),
            "--exclude".to_string(),
            "*.tmp".to_string(),
            "host:/tmp/allowed.txt".to_string(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
            &[
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("skip.tmp", WireFileType::File),
            ],
            1,
        ));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string().contains("remote sender sent filtered path"),
            "{err:#}"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn trust_sender_keeps_destination_path_validation_strict() {
        for (label, entries, expected) in [
            (
                "parent",
                vec![
                    test_remote_entry(".", WireFileType::Directory),
                    test_remote_entry("../escape.txt", WireFileType::File),
                ],
                "not a portable relative rsync path",
            ),
            (
                "absolute",
                vec![
                    test_remote_entry(".", WireFileType::Directory),
                    test_remote_entry("/escape.txt", WireFileType::File),
                ],
                "not a portable relative rsync path",
            ),
            (
                "reserved",
                vec![
                    test_remote_entry(".", WireFileType::Directory),
                    test_remote_entry("CON.txt", WireFileType::File),
                ],
                "not a portable relative rsync path",
            ),
            (
                "case-collision",
                vec![
                    test_remote_entry(".", WireFileType::Directory),
                    test_remote_entry("Report.txt", WireFileType::File),
                    test_remote_entry("report.txt", WireFileType::File),
                ],
                "case/normalization collision",
            ),
        ] {
            let root = unique_temp_dir(&format!("rsync-cli-trust-sender-{label}"));
            let dest = root.join("dest");
            fs::create_dir_all(&root).unwrap();

            let cli = options::parse_cli(vec![
                "rsync-win".to_string(),
                "--trust-sender".to_string(),
                "host:/tmp/source/".to_string(),
                dest.to_string_lossy().into_owned(),
            ])
            .unwrap();
            let plan = TransferPlan::from_cli(&cli);
            let mut transport =
                TestTransport::with_input(remote_pull_file_list_only_input(&entries));

            let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

            assert!(err.to_string().contains(expected), "{label}: {err:#}");
            assert!(!dest.exists(), "{label}: destination directory was created");

            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn remote_pull_rejects_security_oversized_literal_stream_without_final_file() {
        let root = unique_temp_dir("rsync-cli-remote-pull-oversize");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_transfer_input(
            "file.txt",
            3,
            &[b"abcdef".as_slice()],
        ));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(err.to_string().contains("exceeding advertised length 3"));
        assert!(!dest.join("file.txt").exists());
        assert!(fs::read_dir(&dest).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_rejects_security_short_literal_stream_without_final_file() {
        let root = unique_temp_dir("rsync-cli-remote-pull-short");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_transfer_input(
            "file.txt",
            6,
            &[b"abc".as_slice()],
        ));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(err.to_string().contains("below advertised length 6"));
        assert!(!dest.join("file.txt").exists());
        assert!(fs::read_dir(&dest).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_rejects_security_checksum_mismatch_without_final_file() {
        let root = unique_temp_dir("rsync-cli-remote-pull-checksum");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_transfer_input_with_checksum(
            "file.txt",
            3,
            &[b"abc".as_slice()],
            [0_u8; 16],
        ));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(err.to_string().contains("checksum mismatch"), "{err:#}");
        assert!(!dest.join("file.txt").exists());
        assert!(fs::read_dir(&dest).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_protocol31_filters_requests_and_protects_delete() {
        let root = unique_temp_dir("rsync-cli-remote-pull-filter");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("skip.tmp"), b"local").unwrap();

        let cli = options::parse_cli(vec![
            "rsync-win".to_string(),
            "--dry-run".to_string(),
            "--trust-sender".to_string(),
            "--delete".to_string(),
            "--exclude".to_string(),
            "*.tmp".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_filter_dry_run_input());

        let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("write-file"));
        assert!(output.contains("protect-delete"));
        assert!(output.contains("files received: 1"));
        assert!(dest.join("skip.tmp").exists());
        let payloads = written_protocol31_mux_payloads(&transport.written);
        assert!(payloads.iter().any(|payload| payload == &[1]));
        assert!(!payloads.iter().any(|payload| payload == &[2]));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_delete_protects_descendants_of_filtered_directories() {
        let root = unique_temp_dir("rsync-cli-remote-delete-protect-dir");
        let dest = root.join("dest");
        fs::create_dir_all(dest.join("cache")).unwrap();
        fs::write(dest.join("cache/old.txt"), b"old").unwrap();
        let mut local = LocalFileSystem;
        let mut actions = Vec::new();

        delete_local_extras(
            &mut local,
            &dest,
            &[],
            &RuleSet::new(vec![Rule::exclude("cache/").unwrap()]),
            None,
            false,
            &mut actions,
        )
        .unwrap();

        assert!(dest.join("cache/old.txt").exists());
        assert!(actions.iter().any(|action| {
            matches!(action, SyncAction::ProtectDelete(path) if path.ends_with("cache/old.txt"))
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_pull_files_from_retains_needed_parent_dirs_only() {
        let entries = vec![
            test_remote_entry(".", WireFileType::Directory),
            test_remote_entry("dir", WireFileType::Directory),
            test_remote_entry("dir/keep.txt", WireFileType::File),
            test_remote_entry("dir/drop.txt", WireFileType::File),
            test_remote_entry("other", WireFileType::Directory),
            test_remote_entry("other/file.txt", WireFileType::File),
        ];
        let files_from = vec![PathBuf::from("dir/keep.txt")];

        let selected =
            selected_remote_entry_indexes(&entries, &RuleSet::empty(), Some(&files_from));
        let selected_paths: Vec<_> = entries
            .iter()
            .enumerate()
            .filter(|(index, _)| selected.contains(index))
            .map(|(_, entry)| entry.path.as_path())
            .collect();

        assert_eq!(
            selected_paths,
            vec![Path::new("."), Path::new("dir"), Path::new("dir/keep.txt")]
        );
    }

    #[test]
    fn daemon_operands_route_to_daemon_plan_without_remote_shell_argv() {
        let output = parse_and_render(["rsync-win", "--plan", "host::module/path", "dest"]);

        assert!(output.contains("daemon mode: client"));
        assert!(output.contains("daemon endpoint: host:873"));
        assert!(output.contains("daemon direction: download (daemon -> local)"));
        assert!(output.contains("daemon module: module"));
        assert!(output.contains("daemon path: path"));
        assert!(!output.contains("E_REMOTE_OPERAND"));
        assert!(!output.contains("remote ssh argv:"));
    }

    #[test]
    fn daemon_url_operands_route_to_daemon_plan() {
        let output = parse_and_render([
            "rsync-win",
            "--plan",
            "rsync://user@example.test:8873/pub/dir",
            "dest",
        ]);

        assert!(output.contains("daemon mode: client"));
        assert!(output.contains("daemon endpoint: example.test:8873"));
        assert!(output.contains("daemon module: pub"));
        assert!(output.contains("daemon path: dir"));
        assert!(!output.contains("remote ssh argv:"));
    }

    #[test]
    fn daemon_module_listing_plan_uses_daemon_mode() {
        let output = parse_and_render(["rsync-win", "--plan", "--list-only", "host::"]);

        assert!(output.contains("daemon mode: client"));
        assert!(output.contains("daemon module: <list>"));
        assert!(!output.contains("remote ssh argv:"));
    }

    #[test]
    fn windows_drive_operands_are_not_daemon_operands() {
        let output = parse_and_render(["rsync-win", "--plan", r"C:\src", "dest"]);

        assert!(!output.contains("daemon mode: client"));
        assert!(!output.contains("remote ssh argv:"));
    }

    #[test]
    fn daemon_password_file_does_not_render_secret_or_path() {
        let output = parse_and_render([
            "rsync-win",
            "--plan",
            "--password-file",
            "secret-password.txt",
            "user@host::module/path",
            "dest",
        ]);

        assert!(output.contains("daemon auth: password-file configured"));
        assert!(!output.contains("secret-password"));
        assert!(!output.contains("remote ssh argv:"));
    }

    #[test]
    fn daemon_auth_user_prefers_operand_and_uses_local_env_fallback_order() {
        let daemon = DaemonOperand::parse("alice@host::module").unwrap().unwrap();

        assert_eq!(daemon_auth_user(&daemon).unwrap(), "alice");
        assert_eq!(
            daemon_auth_user_from_vars([
                ("USER", Some(String::new())),
                ("LOGNAME", Some(" logname ".to_string())),
                ("USERNAME", Some("winuser".to_string())),
            ]),
            Some("logname".to_string())
        );
        assert_eq!(
            daemon_auth_user_from_vars([
                ("USER", Some("bad\0user".to_string())),
                ("LOGNAME", None),
                ("USERNAME", Some("winuser".to_string())),
            ]),
            Some("winuser".to_string())
        );
    }

    #[test]
    fn daemon_password_file_rejects_non_regular_paths() {
        let root = unique_temp_dir("rsync-cli-password-file-dir");
        fs::create_dir_all(&root).unwrap();

        let err = read_password_file(&root).unwrap_err();

        assert!(err.to_string().contains("must be a regular file"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn daemon_password_file_rejects_group_or_other_access() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_temp_dir("rsync-cli-password-file-perms");
        fs::create_dir_all(&root).unwrap();
        let password_file = root.join("pw.txt");
        fs::write(&password_file, "secret\n").unwrap();
        fs::set_permissions(&password_file, fs::Permissions::from_mode(0o644)).unwrap();

        let err = read_password_file(&password_file).unwrap_err();

        assert!(err
            .to_string()
            .contains("must not be accessible by group or other users"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn daemon_module_listing_executes_over_in_memory_transport() {
        let cli = Cli::parse_from(["rsync-win", "--list-only", "host::"]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(
            b"@RSYNCD: 31.0\nhello\npublic\tPublic files\n@RSYNCD: EXIT\n".to_vec(),
        );

        let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("rsync-win daemon module list"));
        assert!(output.contains("endpoint: host:873"));
        assert!(output.contains("- hello"));
        assert!(output.contains("- public\tPublic files"));
        assert_eq!(transport.written, b"@RSYNCD: 31.0 md5 md4\n#list\n");
    }

    #[test]
    fn daemon_no_auth_pull_uses_remote_pull_receive_path() {
        let root = unique_temp_dir("rsync-cli-daemon-pull");
        let dest = root.join("dest");
        let cli = Cli::parse_from([
            "rsync-win",
            "--dry-run",
            "host::module/file.txt",
            &dest.to_string_lossy(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut input = b"@RSYNCD: 31.0\n@RSYNCD: OK\n".to_vec();
        input.extend_from_slice(&daemon_protocol31_setup_input());
        input.extend_from_slice(&daemon_pull_dry_run_input());
        let mut transport = TestTransport::with_input(input);

        let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

        assert!(output.contains("rsync-win daemon pull"));
        assert!(output.contains("source: host::module/file.txt"));
        assert!(output.contains("dry run: true"));
        assert!(transport
            .written
            .starts_with(b"@RSYNCD: 31.0 md5 md4\nmodule\n--server\0--sender\0"));
        assert!(transport
            .written
            .windows(b"file.txt\0".len())
            .any(|window| window == b"file.txt\0"));
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn daemon_password_file_auth_hashes_without_logging_secret() {
        let root = unique_temp_dir("rsync-cli-daemon-auth");
        fs::create_dir_all(&root).unwrap();
        let password_file = root.join("pw.txt");
        let dest = root.join("dest");
        write_test_password_file(&password_file, "secret\n");
        let cli = Cli::parse_from([
            "rsync-win",
            "--dry-run",
            "--password-file",
            &password_file.to_string_lossy(),
            "alice@host::module/file.txt",
            &dest.to_string_lossy(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut input = b"@RSYNCD: 31.0\n@RSYNCD: AUTHREQD challenge\n@RSYNCD: OK\n".to_vec();
        input.extend_from_slice(&daemon_protocol31_setup_input());
        input.extend_from_slice(&daemon_pull_dry_run_input());
        let mut transport = TestTransport::with_input(input);

        let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();
        let written = String::from_utf8_lossy(&transport.written);

        assert!(output.contains("rsync-win daemon pull"));
        assert!(written.contains("alice "));
        assert!(!written.contains("secret"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fail_on_metadata_loss_upgrades_archive_degradations_to_errors() {
        let output =
            parse_and_render(["rsync-win", "-a", "--fail-on-metadata-loss", "src", "dest"]);

        assert!(output.contains("[error] E_METADATA_OWNER"));
        assert!(output.contains("[error] E_METADATA_GROUP"));
        assert!(output.contains("[error] E_METADATA_DEVICE"));
    }

    #[test]
    fn nonportable_metadata_policy_reports_loss_without_archive_mode() {
        let output = parse_and_render([
            "rsync-win",
            "--metadata-policy",
            "ntfs-native",
            "--fail-on-metadata-loss",
            "src",
            "dest",
        ]);

        assert!(output.contains("metadata policy: ntfs-native"));
        assert!(output.contains("[error] E_METADATA_LOSS"));
        assert!(output.contains("metadata-policy=ntfs-native requests NTFS security descriptor"));
        assert!(output.contains("metadata-policy=ntfs-native requests creation time"));
    }

    #[test]
    fn posix_metadata_options_render_plan_and_fail_on_loss() {
        let output = parse_and_render([
            "rsync-win",
            "--metadata-policy",
            "posix",
            "--perms",
            "--owner",
            "--group",
            "--executability",
            "--acls",
            "--xattrs",
            "--fake-super",
            "--fail-on-metadata-loss",
            "src",
            "dest",
        ]);

        assert!(output.contains("metadata policy: posix"));
        assert!(output
            .contains("posix metadata: perms,owner,group,executability,acls,xattrs,fake-super"));
        assert!(output.contains("[error] E_METADATA_OWNER"));
        assert!(output.contains("[error] E_METADATA_GROUP"));
        assert!(output.contains("[error] E_METADATA_PERMISSIONS"));
        assert!(output.contains("fake-super metadata stored"));
        assert!(output.contains("[error] E_METADATA_LOSS"));
        assert!(output.contains("acl metadata stored"));
    }

    #[test]
    fn fake_super_fail_on_metadata_loss_keeps_stored_sidecar_metadata_non_error() {
        let output = parse_and_render([
            "rsync-win",
            "--fake-super",
            "--acls",
            "--xattrs",
            "--fail-on-metadata-loss",
            "src",
            "dest",
        ]);

        assert!(!output.contains("[error] E_METADATA_LOSS"));
        assert!(!output.contains("[error] E_METADATA_PERMISSIONS"));
        assert!(output.contains("fake-super metadata stored"));
        assert!(output.contains("acl metadata stored"));
        assert!(output.contains("xattr metadata stored"));
    }

    #[test]
    fn local_fake_super_writes_posix_sidecar_manifest() {
        let root = unique_temp_dir("rsync-cli-posix-sidecar");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"data").unwrap();

        let output = parse_and_execute([
            "rsync-win",
            "-r",
            "--fake-super",
            "--acls",
            "--xattrs",
            "--atimes",
            "--crtimes",
            "--chmod=u=rw,go=r",
            &source.to_string_lossy(),
            &dest.to_string_lossy(),
        ])
        .unwrap();

        assert!(
            output.contains("posix sidecars: planned 2, written 2"),
            "{output}"
        );
        let sidecar_root = dest.join(".rsync-win.fake-super");
        let manifests: Vec<_> = fs::read_dir(&sidecar_root)
            .unwrap()
            .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect();
        assert!(manifests
            .iter()
            .any(|manifest| manifest.contains("path=") && manifest.contains("file.txt")));
        assert!(manifests
            .iter()
            .any(|manifest| manifest.contains("fake_super=true")));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn numeric_ids_alone_is_reported_without_metadata_loss_error() {
        let output = parse_and_render([
            "rsync-win",
            "--numeric-ids",
            "--fail-on-metadata-loss",
            "src",
            "dest",
        ]);

        assert!(output.contains("posix metadata: numeric-ids"));
        assert!(output.contains("[warning] W_UNSUPPORTED_OPTION"));
        assert!(!output.contains("[error] E_METADATA_OWNER"));
        assert!(!output.contains("[error] E_METADATA_GROUP"));
    }

    #[test]
    fn ntfs_native_plan_reports_sidecar_and_vss_rejection() {
        let output = parse_and_render([
            "rsync-win",
            "--metadata-policy",
            "ntfs-native",
            "--vss",
            "--fail-on-metadata-loss",
            "src",
            "dest",
        ]);

        assert!(output.contains("metadata policy: ntfs-native"));
        assert!(output.contains("ntfs-native metadata: sidecar-capture prototype, vss=true"));
        assert!(output.contains("security-descriptor metadata degraded"));
        assert!(output.contains("alternate-data-stream metadata degraded"));
        assert!(output.contains("[error] E_METADATA_LOSS: vss-snapshot metadata rejected"));
    }

    #[test]
    fn parses_filters_without_executing_transfer() {
        let output = parse_and_render([
            "rsync-win",
            "-r",
            "--include",
            "*.rs",
            "--exclude",
            "target/",
            "--filter",
            "protect *.bak",
            "--files-from",
            "list.txt",
            "--from0",
            "src",
            "dest",
        ]);

        assert!(output.contains("filter rules: 3"));
        assert!(output.contains("files-from: list.txt"));
        assert!(output.contains("from0: true"));
        assert!(output.contains("execution: plan output only"));
    }

    #[test]
    fn local_executor_copies_files_and_deletes_extras() {
        let root = unique_temp_dir("rsync-cli-local-exec");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir_all(&dest).unwrap();
        fs::write(source.join("nested/file.txt"), b"new").unwrap();
        fs::write(dest.join("old.txt"), b"old").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-rt".to_string(),
            "--delete".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert_eq!(fs::read(dest.join("nested/file.txt")).unwrap(), b"new");
        assert!(!dest.join("old.txt").exists());
        assert!(output.contains("rsync-win local portable sync"));
        assert!(output.contains("changes:"));
        assert!(output.contains("file writes"));
        assert!(output.contains("deletes"));
        assert!(!output.contains("actions:\n"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_executor_batches_multiple_sources() {
        let root = unique_temp_dir("rsync-cli-local-batch");
        let file_source = root.join("one.txt");
        let dir_source = root.join("dir");
        let dest = root.join("dest");
        fs::create_dir_all(dir_source.join("nested")).unwrap();
        fs::write(&file_source, b"one").unwrap();
        fs::write(dir_source.join("nested/two.txt"), b"two").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            file_source.to_string_lossy().into_owned(),
            dir_source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert_eq!(fs::read(dest.join("one.txt")).unwrap(), b"one");
        assert_eq!(fs::read(dest.join("dir/nested/two.txt")).unwrap(), b"two");
        assert!(output.contains("sources: 2"));
        assert!(output.contains("changes:"));
        assert!(output.contains("file writes"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_ntfs_native_sync_writes_sidecar_manifests_when_explicit() {
        let root = unique_temp_dir("rsync-cli-ntfs-sidecar");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("file.txt"), b"hello").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--metadata-policy".to_string(),
            "ntfs-native".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let sidecar_root = dest.join(".rsync-win.ntfs-native");
        let sidecar_file = fs::read_dir(&sidecar_root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("source__file.txt--") && name.ends_with(".ntfs.meta")
                    })
            })
            .expect("expected source file sidecar");

        assert!(output.contains("ntfs sidecars: planned"));
        assert!(sidecar_file.exists());
        assert!(fs::read_to_string(sidecar_file)
            .unwrap()
            .contains("rsync-win ntfs-native sidecar v1"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_ntfs_native_sidecar_names_do_not_flatten_to_collisions() {
        let root = unique_temp_dir("rsync-cli-ntfs-sidecar-collision");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(source.join("a")).unwrap();
        fs::write(source.join("a/b.txt"), b"nested").unwrap();
        fs::write(source.join("a__b.txt"), b"flat").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--metadata-policy".to_string(),
            "ntfs-native".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let sidecar_root = dest.join(".rsync-win.ntfs-native");
        let sidecar_names: BTreeSet<_> = fs::read_dir(sidecar_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();

        assert!(output.contains("ntfs sidecars: planned 4, written 4"));
        assert_eq!(sidecar_names.len(), 4);
        assert!(sidecar_names.iter().any(|name| {
            name.starts_with("source__a__b.txt--") && name.ends_with(".ntfs.meta")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_ntfs_native_sidecars_respect_filters() {
        let root = unique_temp_dir("rsync-cli-ntfs-filter");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.txt"), b"keep").unwrap();
        fs::write(source.join("secret.txt"), b"secret").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--metadata-policy".to_string(),
            "ntfs-native".to_string(),
            "--exclude".to_string(),
            "secret.txt".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let sidecar_paths = ntfs_sidecar_source_paths(&dest);
        assert!(output.contains("ntfs sidecars: planned 2, written 2"));
        assert!(sidecar_paths.contains(&source));
        assert!(sidecar_paths.contains(&source.join("keep.txt")));
        assert!(!sidecar_paths.contains(&source.join("secret.txt")));
        assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep");
        assert!(!dest.join("secret.txt").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_ntfs_native_sidecars_respect_files_from() {
        let root = unique_temp_dir("rsync-cli-ntfs-files-from");
        let source = root.join("source");
        let dest = root.join("dest");
        let list = root.join("files.txt");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.txt"), b"keep").unwrap();
        fs::write(source.join("drop.txt"), b"drop").unwrap();
        fs::write(&list, b"keep.txt\n").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--metadata-policy".to_string(),
            "ntfs-native".to_string(),
            "--files-from".to_string(),
            list.to_string_lossy().into_owned(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let sidecar_paths = ntfs_sidecar_source_paths(&dest);
        assert!(output.contains("ntfs sidecars: planned 2, written 2"));
        assert!(sidecar_paths.contains(&source));
        assert!(sidecar_paths.contains(&source.join("keep.txt")));
        assert!(!sidecar_paths.contains(&source.join("drop.txt")));
        assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep");
        assert!(!dest.join("drop.txt").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn local_ntfs_native_sync_restores_safe_windows_attributes() {
        let root = unique_temp_dir("rsync-cli-ntfs-attributes");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        let source_file = source.join("file.txt");
        fs::write(&source_file, b"hello").unwrap();
        rsync_winfs::restore_safe_windows_attributes(
            &source_file,
            Some(rsync_winfs::FILE_ATTRIBUTE_READONLY | rsync_winfs::FILE_ATTRIBUTE_ARCHIVE),
        )
        .unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--metadata-policy".to_string(),
            "ntfs-native".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let dest_file = dest.join("file.txt");
        let dest_metadata = rsync_winfs::read_windows_metadata(&dest_file).unwrap();
        assert!(dest_metadata
            .attributes
            .is_some_and(|attrs| { attrs & rsync_winfs::FILE_ATTRIBUTE_READONLY != 0 }));
        assert!(output.contains("ntfs attributes: applied"));

        rsync_winfs::restore_safe_windows_attributes(
            &source_file,
            Some(rsync_winfs::FILE_ATTRIBUTE_ARCHIVE),
        )
        .unwrap();
        rsync_winfs::restore_safe_windows_attributes(
            &dest_file,
            Some(rsync_winfs::FILE_ATTRIBUTE_ARCHIVE),
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn local_ntfs_native_sync_copies_alternate_stream_payloads() {
        let root = unique_temp_dir("rsync-cli-ntfs-streams");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        let source_file = source.join("file.txt");
        fs::write(&source_file, b"default").unwrap();
        fs::write(
            test_stream_data_path(&source_file, "Zone.Identifier"),
            b"zone",
        )
        .unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--metadata-policy".to_string(),
            "ntfs-native".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let dest_file = dest.join("file.txt");
        assert_eq!(fs::read(&dest_file).unwrap(), b"default");
        assert_eq!(
            fs::read(test_stream_data_path(&dest_file, "Zone.Identifier")).unwrap(),
            b"zone"
        );
        assert!(output.contains("ntfs streams: copied 1, degraded 0"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_executor_honors_files_from_records() {
        let root = unique_temp_dir("rsync-cli-files-from");
        let source = root.join("source");
        let dest = root.join("dest");
        let list = root.join("files.txt");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&dest).unwrap();
        fs::write(source.join("keep.txt"), b"keep").unwrap();
        fs::write(source.join("skip.txt"), b"skip").unwrap();
        fs::write(&list, b"keep.txt\n").unwrap();

        parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--files-from".to_string(),
            list.to_string_lossy().into_owned(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep");
        assert!(!dest.join("skip.txt").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_executor_runs_append_verify_itemize_and_stats() {
        let root = unique_temp_dir("rsync-cli-append-verify");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&dest).unwrap();
        fs::write(source.join("file.txt"), b"abcdef").unwrap();
        fs::write(dest.join("file.txt"), b"abc").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "--append-verify".to_string(),
            "--itemize-changes".to_string(),
            "--stats".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert_eq!(fs::read(dest.join("file.txt")).unwrap(), b"abcdef");
        assert!(output.contains("itemized changes:"));
        assert!(output.contains(">f+++++a+++"));
        assert!(output.contains("structured stats:"));
        assert!(output.contains("- appended files: 1"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_executor_runs_inplace_mode() {
        let root = unique_temp_dir("rsync-cli-inplace");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&dest).unwrap();
        fs::write(source.join("file.txt"), b"new").unwrap();
        fs::write(dest.join("file.txt"), b"old").unwrap();

        let output = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            "-vv".to_string(),
            "--ignore-times".to_string(),
            "--inplace".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();

        assert_eq!(fs::read(dest.join("file.txt")).unwrap(), b"new");
        assert!(output.contains("write-file-inplace"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_executor_rejects_unicode_normalization_collision_before_write() {
        let root = unique_temp_dir("rsync-cli-unicode-preflight");
        let source = root.join("source");
        let dest = root.join("dest");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&dest).unwrap();

        let composed = source.join("caf\u{00e9}.txt");
        let decomposed = source.join("cafe\u{0301}.txt");
        if fs::write(&composed, b"composed").is_err()
            || fs::write(&decomposed, b"decomposed").is_err()
        {
            fs::remove_dir_all(root).unwrap();
            return;
        }
        if fs::read_dir(&source).unwrap().count() < 2 {
            fs::remove_dir_all(root).unwrap();
            return;
        }

        let err = parse_and_execute(vec![
            "rsync-win".to_string(),
            "-r".to_string(),
            source.to_string_lossy().into_owned(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("destination path preflight failed"));
        assert!(err.to_string().contains("case/normalization collision"));
        assert!(fs::read_dir(&dest).unwrap().next().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_executor_preflight_rejects_case_collision_paths() {
        let err = windows_destination_path_preflight(&[
            PathBuf::from("dir/Foo.txt"),
            PathBuf::from("dir/foo.txt"),
        ])
        .unwrap_err();

        assert!(matches!(err, FsError::DestinationPathPreflight(_)));
    }

    #[test]
    fn remote_sender_executability_sets_execute_bits_for_windows_scripts() {
        let root = unique_temp_dir("rsync-cli-executability-mode");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("app.exe"), b"exe").unwrap();
        fs::write(source.join("run.bat"), b"echo hi").unwrap();
        fs::write(source.join("run.cmd"), b"echo hi").unwrap();
        fs::write(source.join("script.ps1"), b"Write-Host hi").unwrap();
        fs::write(source.join("notes.txt"), b"notes").unwrap();
        let filter_rules = RuleSet::empty();
        let options = LocalSourceCollectOptions {
            recursive: true,
            filter_rules: &filter_rules,
            files_from: None,
            symlink_mode: SymlinkMode::Preserve,
            include_checksums: false,
            preserve_executability: true,
            preserve_hard_links: false,
            chmod_rules: None,
        };

        let entries =
            collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();

        for path in ["app.exe", "run.bat", "run.cmd", "script.ps1"] {
            let entry = entries
                .iter()
                .find(|entry| entry.wire.path.as_path() == Path::new(path))
                .unwrap();
            assert_eq!(entry.wire.mode & 0o111, 0o111, "{path}");
        }
        let notes = entries
            .iter()
            .find(|entry| entry.wire.path.as_path() == Path::new("notes.txt"))
            .unwrap();

        assert_eq!(notes.wire.mode & 0o111, 0);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_sender_chmod_applies_numeric_modes_to_remote_file_list() {
        let root = unique_temp_dir("rsync-cli-chmod-mode");
        let source = root.join("source");
        fs::create_dir_all(source.join("dir")).unwrap();
        fs::write(source.join("dir/file.txt"), b"data").unwrap();
        let chmod_rules = "F600,D700".parse::<ChmodRules>().unwrap();
        let filter_rules = RuleSet::empty();
        let options = LocalSourceCollectOptions {
            recursive: true,
            filter_rules: &filter_rules,
            files_from: None,
            symlink_mode: SymlinkMode::Preserve,
            include_checksums: false,
            preserve_executability: false,
            preserve_hard_links: false,
            chmod_rules: Some(&chmod_rules),
        };

        let entries =
            collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();

        let dir = entries
            .iter()
            .find(|entry| entry.wire.path.as_path() == Path::new("dir"))
            .unwrap();
        let file = entries
            .iter()
            .find(|entry| entry.wire.path.as_path() == Path::new("dir/file.txt"))
            .unwrap();

        assert_eq!(dir.wire.mode & 0o7777, 0o700);
        assert_eq!(file.wire.mode & 0o7777, 0o600);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_sender_protect_filter_keeps_source_entries() {
        let root = unique_temp_dir("rsync-cli-protect-sender");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.bak"), b"backup").unwrap();
        let filter_rules = RuleSet::new(vec![Rule::protect("*.bak").unwrap()]);
        let options = LocalSourceCollectOptions {
            recursive: true,
            filter_rules: &filter_rules,
            files_from: None,
            symlink_mode: SymlinkMode::Preserve,
            include_checksums: false,
            preserve_executability: false,
            preserve_hard_links: false,
            chmod_rules: None,
        };

        let entries =
            collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();

        assert!(entries
            .iter()
            .any(|entry| entry.wire.path.as_path() == Path::new("keep.bak")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_sender_marks_hardlink_groups_in_file_list() {
        let root = unique_temp_dir("rsync-cli-remote-hardlink-groups");
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        let original = source.join("original.txt");
        let alias = source.join("alias.txt");
        fs::write(&original, b"same").unwrap();
        if fs::hard_link(&original, &alias).is_err() {
            fs::remove_dir_all(root).unwrap();
            return;
        }
        let filter_rules = RuleSet::empty();
        let options = LocalSourceCollectOptions {
            recursive: true,
            filter_rules: &filter_rules,
            files_from: None,
            symlink_mode: SymlinkMode::Preserve,
            include_checksums: false,
            preserve_executability: false,
            preserve_hard_links: true,
            chmod_rules: None,
        };

        let entries =
            collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();
        let original_entry = entries
            .iter()
            .find(|entry| entry.wire.path.as_path() == Path::new("original.txt"))
            .unwrap();
        let alias_entry = entries
            .iter()
            .find(|entry| entry.wire.path.as_path() == Path::new("alias.txt"))
            .unwrap();

        assert!(original_entry.wire.hardlink_group.is_some());
        assert_eq!(
            original_entry.wire.hardlink_group,
            alias_entry.wire.hardlink_group
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn chmod_accepts_symbolic_forms_in_cli_plan() {
        let output = parse_and_render([
            "rsync-win",
            "--plan",
            "--chmod",
            "u+rw,go-w",
            "src",
            "host:/dest",
        ]);

        assert!(output.contains("posix metadata: chmod"));
        assert!(!output.contains("[error] E_CHMOD"));
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

    fn write_test_password_file(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn test_remote_entry(path: &str, file_type: WireFileType) -> RsyncFileListEntry {
        RsyncFileListEntry {
            path: PathBuf::from(path),
            file_type,
            len: 0,
            mtime_unix: 0,
            mode: match file_type {
                WireFileType::Directory => RSYNC_DIRECTORY_MODE,
                _ => RSYNC_REGULAR_FILE_MODE,
            },
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        }
    }

    #[cfg(windows)]
    fn test_stream_data_path(path: &Path, stream_name: &str) -> PathBuf {
        let mut stream_path = to_long_path_safe(path).into_os_string();
        stream_path.push(format!(":{stream_name}"));
        PathBuf::from(stream_path)
    }

    fn ntfs_sidecar_source_paths(dest: &Path) -> BTreeSet<PathBuf> {
        fs::read_dir(ntfs_sidecar_root(dest))
            .unwrap()
            .map(|entry| {
                let manifest = fs::read_to_string(entry.unwrap().path()).unwrap();
                rsync_winfs::parse_ntfs_native_sidecar_manifest(&manifest)
                    .unwrap()
                    .sidecar
                    .path
            })
            .collect()
    }

    fn test_remote_block_signatures(
        basis: &[u8],
        block_size: usize,
        checksum_len: usize,
        checksum: RemoteFileChecksum,
    ) -> Vec<rsync_delta::BlockSignature> {
        basis
            .chunks(block_size)
            .enumerate()
            .map(|(index, block)| {
                let mut strong = remote_file_checksum_builder(checksum);
                strong.update(block);
                rsync_delta::BlockSignature {
                    index,
                    offset: index * block_size,
                    len: block.len(),
                    weak: rsync_delta::rolling_checksum(block),
                    strong: strong.finalize()[..checksum_len].to_vec(),
                }
            })
            .collect()
    }

    fn remote_push_dry_run_input() -> Vec<u8> {
        let mut input = remote_handshake_input();
        append_mux_payload(
            &mut input,
            &[
                1,
                (RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) as u8,
                ((RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) >> 8) as u8,
            ],
        );
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        input
    }

    fn remote_push_append_verify_input() -> Vec<u8> {
        remote_push_append_verify_input_with_sum_head(RemoteSumHead {
            block_count: 1,
            block_len: 3,
            checksum_len: 2,
            remainder: 0,
        })
    }

    fn remote_push_append_verify_oversized_basis_input() -> Vec<u8> {
        remote_push_append_verify_input_with_sum_head(RemoteSumHead {
            block_count: 3,
            block_len: 3,
            checksum_len: 2,
            remainder: 0,
        })
    }

    fn remote_push_append_verify_input_with_sum_head(sum_head: RemoteSumHead) -> Vec<u8> {
        let mut input = remote_handshake_input();
        let mut request = Vec::new();
        let mut state = RsyncIndexState::default();
        write_rsync_index(&mut request, &mut state, 1).unwrap();
        write_u16_le(
            &mut request,
            RSYNC_ITEM_TRANSFER | RSYNC_ITEM_BASIS_TYPE_FOLLOWS,
        )
        .unwrap();
        request.push(0);
        write_sum_head(&mut request, sum_head).unwrap();
        append_mux_payload(&mut input, &request);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        input
    }

    fn remote_push_unsupported_mux_input() -> Vec<u8> {
        let mut input = remote_handshake_input();
        append_mux_frame(&mut input, 6, &[]);
        input
    }

    fn remote_push_final_unsupported_mux_input() -> Vec<u8> {
        let mut input = remote_handshake_input();
        append_mux_payload(
            &mut input,
            &[
                1,
                (RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) as u8,
                ((RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) >> 8) as u8,
            ],
        );
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_frame(&mut input, 6, &[]);
        input
    }

    fn remote_pull_dry_run_input() -> Vec<u8> {
        remote_pull_dry_run_input_with_entries(
            &[
                RsyncFileListEntry {
                    path: PathBuf::from("."),
                    file_type: WireFileType::Directory,
                    len: 0,
                    mtime_unix: 0,
                    mode: RSYNC_DIRECTORY_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
                RsyncFileListEntry {
                    path: PathBuf::from("file.txt"),
                    file_type: WireFileType::File,
                    len: 5,
                    mtime_unix: 0,
                    mode: RSYNC_REGULAR_FILE_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
            ],
            1,
        )
    }

    fn daemon_pull_dry_run_input() -> Vec<u8> {
        remote_pull_dry_run_mux_input_with_entries(
            &[
                RsyncFileListEntry {
                    path: PathBuf::from("."),
                    file_type: WireFileType::Directory,
                    len: 0,
                    mtime_unix: 0,
                    mode: RSYNC_DIRECTORY_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
                RsyncFileListEntry {
                    path: PathBuf::from("file.txt"),
                    file_type: WireFileType::File,
                    len: 5,
                    mtime_unix: 0,
                    mode: RSYNC_REGULAR_FILE_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
            ],
            1,
        )
    }

    fn daemon_protocol31_setup_input() -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&[0x81, 0xff]);
        input.push(35);
        input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
        input.extend_from_slice(&0_i32.to_le_bytes());
        input
    }

    fn remote_pull_file_list_only_input(entries: &[RsyncFileListEntry]) -> Vec<u8> {
        let mut input = remote_handshake_input();
        let mut flist = Vec::new();
        write_rsync31_file_list_with_options(&mut flist, entries, false).unwrap();
        append_mux_payload(&mut input, &flist);
        input
    }

    fn remote_pull_transfer_input(
        path: &str,
        advertised_len: u64,
        literal_chunks: &[&[u8]],
    ) -> Vec<u8> {
        let mut checksum = RsyncMd4Checksum::plain();
        for chunk in literal_chunks {
            checksum.update(chunk);
        }
        remote_pull_transfer_input_with_checksum(
            path,
            advertised_len,
            literal_chunks,
            checksum.finalize(),
        )
    }

    fn remote_pull_transfer_input_with_checksum(
        path: &str,
        advertised_len: u64,
        literal_chunks: &[&[u8]],
        remote_checksum: [u8; 16],
    ) -> Vec<u8> {
        let mut input = remote_pull_file_list_only_input(&[
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 0,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from(path),
                file_type: WireFileType::File,
                len: advertised_len,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ]);

        let mut response = Vec::new();
        let mut index_state = RsyncIndexState::default();
        write_rsync_index(&mut response, &mut index_state, 1).unwrap();
        write_u16_le(&mut response, RSYNC_ITEM_TRANSFER | RSYNC_ITEM_IS_NEW).unwrap();
        write_sum_head(
            &mut response,
            RemoteSumHead {
                block_count: 0,
                block_len: 32 * 1024,
                checksum_len: 2,
                remainder: 0,
            },
        )
        .unwrap();

        for chunk in literal_chunks {
            write_i32_le(&mut response, chunk.len() as i32).unwrap();
            response.extend_from_slice(chunk);
        }
        write_i32_le(&mut response, 0).unwrap();
        response.extend_from_slice(&remote_checksum);
        write_rsync_index(&mut response, &mut index_state, RSYNC_INDEX_DONE).unwrap();
        append_mux_payload(&mut input, &response);

        let mut stats = Vec::new();
        for value in [0_u64, 0, advertised_len, 0, 0] {
            rsync_protocol::write_varlong(&mut stats, value, 3).unwrap();
        }
        append_mux_payload(&mut input, &stats);
        append_mux_payload(&mut input, &[0]);
        input
    }

    fn remote_pull_filter_dry_run_input() -> Vec<u8> {
        remote_pull_dry_run_input_with_entries(
            &[
                RsyncFileListEntry {
                    path: PathBuf::from("skip.tmp"),
                    file_type: WireFileType::File,
                    len: 4,
                    mtime_unix: 0,
                    mode: RSYNC_REGULAR_FILE_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
                RsyncFileListEntry {
                    path: PathBuf::from("file.txt"),
                    file_type: WireFileType::File,
                    len: 5,
                    mtime_unix: 0,
                    mode: RSYNC_REGULAR_FILE_MODE,
                    checksum: None,
                    hardlink_group: None,
                    metadata: RsyncFileListMetadata::default(),
                },
            ],
            1,
        )
    }

    fn remote_pull_dry_run_input_with_entries(
        entries: &[RsyncFileListEntry],
        response_wire_index: i32,
    ) -> Vec<u8> {
        let mut input = remote_handshake_input();
        input.extend(remote_pull_dry_run_mux_input_with_entries(
            entries,
            response_wire_index,
        ));
        input
    }

    fn remote_pull_dry_run_mux_input_with_entries(
        entries: &[RsyncFileListEntry],
        response_wire_index: i32,
    ) -> Vec<u8> {
        let mut input = Vec::new();
        let mut flist = Vec::new();
        write_rsync31_file_list_with_options(&mut flist, entries, false).unwrap();
        append_mux_payload(&mut input, &flist);
        append_mux_payload(
            &mut input,
            &[
                (response_wire_index + 1) as u8,
                (RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) as u8,
                ((RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) >> 8) as u8,
            ],
        );
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);
        append_mux_payload(&mut input, &[0]);

        let mut stats = Vec::new();
        for value in [0_u64, 0, 5, 0, 0] {
            rsync_protocol::write_varlong(&mut stats, value, 3).unwrap();
        }
        append_mux_payload(&mut input, &stats);
        append_mux_payload(&mut input, &[0]);
        input
    }

    fn remote_handshake_input() -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&31_u32.to_le_bytes());
        input.extend_from_slice(&[0x81, 0xff]);
        input.push(35);
        input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
        input.extend_from_slice(&0_i32.to_le_bytes());
        input
    }

    fn append_mux_payload(out: &mut Vec<u8>, payload: &[u8]) {
        append_mux_frame(out, 7, payload);
    }

    fn append_mux_frame(out: &mut Vec<u8>, tag: u32, payload: &[u8]) {
        let header = (tag << 24) | payload.len() as u32;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(payload);
    }

    fn written_protocol31_mux_payloads(written: &[u8]) -> Vec<Vec<u8>> {
        let mut pos = 8;
        let mut payloads = Vec::new();
        while pos + 4 <= written.len() {
            let header = u32::from_le_bytes([
                written[pos],
                written[pos + 1],
                written[pos + 2],
                written[pos + 3],
            ]);
            pos += 4;
            let tag = header >> 24;
            let len = (header & 0x00ff_ffff) as usize;
            assert_eq!(tag, 7);
            assert!(pos + len <= written.len());
            payloads.push(written[pos..pos + len].to_vec());
            pos += len;
        }
        assert_eq!(pos, written.len());
        payloads
    }

    #[derive(Debug)]
    struct TestTransport {
        input: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl TestTransport {
        fn with_input(input: Vec<u8>) -> Self {
            Self {
                input: std::io::Cursor::new(input),
                written: Vec::new(),
            }
        }
    }

    impl Read for TestTransport {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for TestTransport {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
