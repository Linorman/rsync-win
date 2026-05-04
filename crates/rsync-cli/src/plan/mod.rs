use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rsync_core::{
    archive_mode_components, archive_mode_degradations, metadata_policy_degradations, ChmodRules,
    Diagnostic, MetadataDegradation, MetadataFeature, MetadataPolicy, NtfsNativeMetadataRequest,
    PosixMetadataRequest, Report, Severity,
};
use rsync_filter::{Rule, RuleAction, RuleSet};
use rsync_fs::{DeleteMode, FileWriteMode, FileWriteOptions, SymlinkMode, UpdateMode};
use rsync_protocol::{
    build_remote_shell_invocation_for_paths, build_remote_shell_protocol31_invocation_for_paths,
    DaemonOperand, Protocol31SetupOptions, RemoteDeleteMode, RemoteShellInvocation,
    RemoteShellOperand, RemoteShellOptions, RsyncDeflatedTokenMode, SessionError,
    TransferDirection, REMOTE_SHELL_MODERN_PROTOCOL, REMOTE_SHELL_MVP_PROTOCOL,
};
use rsync_transport::remote_shell::SshRemoteCommand;
use rsync_transport::BandwidthLimit;

use crate::cli::{Cli, CliMetadataPolicy};
use crate::execute::remote_shell::build_remote_transport_command;
use crate::format::metadata_code;
use crate::RemoteCompressionConfig;

mod diagnostics;
mod filters;
mod limits;
mod metadata;
mod remote_args;

pub(crate) use diagnostics::*;
pub(crate) use filters::*;
pub(crate) use limits::*;
pub(crate) use metadata::*;
pub(crate) use remote_args::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteWireProtocol {
    Compat27,
    Modern31,
}

impl RemoteWireProtocol {
    pub(crate) fn protocol_number(self) -> u32 {
        match self {
            Self::Compat27 => REMOTE_SHELL_MVP_PROTOCOL,
            Self::Modern31 => REMOTE_SHELL_MODERN_PROTOCOL,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Compat27 => "protocol 27 compatibility mode",
            Self::Modern31 => "protocol 31 ordinary-file MVP",
        }
    }
}

pub(crate) fn remote_wire_protocol_from_cli(cli: &Cli, report: &mut Report) -> RemoteWireProtocol {
    match cli.protocol_version {
        Some(27) => RemoteWireProtocol::Compat27,
        Some(31) | None => RemoteWireProtocol::Modern31,
        Some(protocol) => {
            report.error(
                "E_UNSUPPORTED_PROTOCOL",
                format!(
                    "--protocol={protocol} is not supported by this build; supported execution protocols are 27 and 31"
                ),
            );
            RemoteWireProtocol::Modern31
        }
    }
}

pub(crate) fn build_remote_shell_invocation_for_wire_protocol(
    protocol: RemoteWireProtocol,
    options: &RemoteShellOptions,
    paths: &[&Path],
) -> Result<RemoteShellInvocation, SessionError> {
    match protocol {
        RemoteWireProtocol::Compat27 => build_remote_shell_invocation_for_paths(options, paths),
        RemoteWireProtocol::Modern31 => {
            build_remote_shell_protocol31_invocation_for_paths(options, paths)
        }
    }
}

pub(crate) fn add_remote_protocol_diagnostic(report: &mut Report, protocol: RemoteWireProtocol) {
    match protocol {
        RemoteWireProtocol::Modern31 => report.info(
            "I_REMOTE_PROTOCOL31_MVP",
            format!(
                "remote-shell execution tries protocol {REMOTE_SHELL_MODERN_PROTOCOL} first for the ordinary-file MVP"
            ),
        ),
        RemoteWireProtocol::Compat27 => report.info(
            "I_REMOTE_PROTOCOL",
            format!("remote-shell execution uses {}", protocol.label()),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferMode {
    Local,
    RemoteShell,
    DaemonClient,
    DaemonServer,
    InternalServer,
}

impl TransferMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::RemoteShell => "remote-shell",
            Self::DaemonClient => "daemon-client",
            Self::DaemonServer => "daemon-server",
            Self::InternalServer => "internal-server",
        }
    }
}

pub(crate) fn transfer_direction_label(direction: TransferDirection) -> &'static str {
    match direction {
        TransferDirection::Push => "upload",
        TransferDirection::Pull => "download",
    }
}

pub(crate) fn bandwidth_limit_from_plan(plan: &TransferPlan) -> Option<BandwidthLimit> {
    plan.bwlimit
        .filter(|bytes_per_second| *bytes_per_second > 0)
        .map(BandwidthLimit::new)
}

pub(crate) fn stop_deadline_from_cli(cli: &Cli, report: &mut Report) -> Option<Instant> {
    let now = Instant::now();
    let now_system = SystemTime::now();
    let mut deadline = None;

    for minutes in [cli.stop_after_minutes, cli.time_limit_minutes]
        .into_iter()
        .flatten()
    {
        match minutes_to_duration(minutes) {
            Some(duration) => remember_earliest_deadline(&mut deadline, now + duration),
            None => report.error(
                "E_STOP_LIMIT",
                format!("stop limit {minutes} minutes exceeds the supported duration range"),
            ),
        }
    }

    if let Some(stop_at) = &cli.stop_at {
        match stop_at_deadline(stop_at, now_system, now) {
            Ok(stop_at_deadline) => remember_earliest_deadline(&mut deadline, stop_at_deadline),
            Err(err) => report.error("E_STOP_AT", err.to_string()),
        }
    }

    deadline
}

pub(crate) fn remember_earliest_deadline(deadline: &mut Option<Instant>, candidate: Instant) {
    if match deadline {
        Some(existing) => candidate < *existing,
        None => true,
    } {
        *deadline = Some(candidate);
    }
}

pub(crate) fn minutes_to_duration(minutes: u64) -> Option<Duration> {
    minutes.checked_mul(60).map(Duration::from_secs)
}

pub(crate) fn check_transfer_deadline(deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        bail!("transfer stop deadline reached");
    }
    Ok(())
}

pub(crate) fn stop_at_deadline(
    value: &str,
    now_system: SystemTime,
    now: Instant,
) -> Result<Instant> {
    let target = if value.contains('T') {
        parse_full_stop_at_utc(value)?
    } else {
        parse_clock_stop_at_utc(value, now_system)?
    };
    let delay = target
        .duration_since(now_system)
        .map_err(|_| anyhow::anyhow!("--stop-at must resolve to a future time"))?;
    Ok(now + delay)
}

pub(crate) fn parse_clock_stop_at_utc(value: &str, now: SystemTime) -> Result<SystemTime> {
    let target_seconds = parse_stop_at_clock_seconds(value)?;
    let now_seconds = now
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let day_start = now_seconds - (now_seconds % 86_400);
    let mut candidate = day_start + target_seconds;
    if candidate <= now_seconds {
        candidate += 86_400;
    }
    Ok(UNIX_EPOCH + Duration::from_secs(candidate))
}

pub(crate) fn parse_full_stop_at_utc(value: &str) -> Result<SystemTime> {
    let (date, time) = value
        .split_once('T')
        .context("--stop-at full form must use y-m-dTh:m")?;
    let date_parts: Vec<_> = date.split(['-', '/']).collect();
    if date_parts.len() != 3 {
        bail!("--stop-at full date must use y-m-d");
    }
    let year = date_parts[0]
        .parse::<i32>()
        .context("--stop-at year is not valid")?;
    let month = date_parts[1]
        .parse::<u32>()
        .context("--stop-at month is not valid")?;
    let day = date_parts[2]
        .parse::<u32>()
        .context("--stop-at day is not valid")?;
    let seconds = parse_stop_at_clock_seconds(time)?;
    let days = days_from_civil(year, month, day)?;
    let epoch_seconds = days
        .checked_mul(86_400)
        .and_then(|base| base.checked_add(seconds as i64))
        .context("--stop-at timestamp exceeds the supported range")?;
    if epoch_seconds < 0 {
        bail!("--stop-at dates before 1970 are not supported");
    }
    Ok(UNIX_EPOCH + Duration::from_secs(epoch_seconds as u64))
}

pub(crate) fn parse_stop_at_clock_seconds(value: &str) -> Result<u64> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        bail!("--stop-at time must use HH:MM or HH:MM:SS");
    }
    let hour = parts[0]
        .parse::<u64>()
        .context("--stop-at hour is not valid")?;
    let minute = parts[1]
        .parse::<u64>()
        .context("--stop-at minute is not valid")?;
    let second = if parts.len() == 3 {
        parts[2]
            .parse::<u64>()
            .context("--stop-at second is not valid")?
    } else {
        0
    };
    if hour > 23 || minute > 59 || second > 59 {
        bail!("--stop-at time is outside the valid clock range");
    }
    Ok(hour * 3600 + minute * 60 + second)
}

pub(crate) fn days_from_civil(year: i32, month: u32, day: u32) -> Result<i64> {
    if !(1..=12).contains(&month) {
        bail!("--stop-at month is outside 1..12");
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        bail!("--stop-at day is outside the valid range for the month");
    }
    let mut y = year as i64;
    let m = month as i64;
    let d = day as i64;
    y -= (m <= 2) as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146_097 + doe - 719_468)
}

pub(crate) fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

pub(crate) fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[derive(Debug)]
pub(crate) struct TransferPlan {
    pub(crate) transfer_mode: TransferMode,
    pub(crate) recursive: bool,
    pub(crate) incremental_recursion: bool,
    pub(crate) relative: bool,
    pub(crate) implied_dirs: bool,
    pub(crate) transfer_dirs: bool,
    pub(crate) mkpath: bool,
    pub(crate) one_file_system: bool,
    pub(crate) preserve_times: bool,
    pub(crate) delete: bool,
    pub(crate) delete_mode: DeleteMode,
    pub(crate) delete_excluded: bool,
    pub(crate) ignore_errors: bool,
    pub(crate) force_delete: bool,
    pub(crate) max_delete: Option<usize>,
    pub(crate) dry_run: bool,
    pub(crate) whole_file: bool,
    pub(crate) compress: bool,
    pub(crate) compress_choice: Option<String>,
    pub(crate) compress_level: Option<u32>,
    pub(crate) compress_threads: Option<usize>,
    pub(crate) skip_compress: Vec<String>,
    pub(crate) verbosity: u8,
    pub(crate) progress: bool,
    pub(crate) human_readable: u8,
    pub(crate) update_mode: UpdateMode,
    pub(crate) skip_newer_receiver: bool,
    pub(crate) existing_only: bool,
    pub(crate) ignore_existing: bool,
    pub(crate) max_size: Option<u64>,
    pub(crate) min_size: Option<u64>,
    pub(crate) modify_window: i64,
    pub(crate) ignore_missing_args: bool,
    pub(crate) delete_missing_args: bool,
    pub(crate) file_write_mode: FileWriteMode,
    pub(crate) keep_partial: bool,
    pub(crate) partial_dir: Option<PathBuf>,
    pub(crate) temp_dir: Option<PathBuf>,
    pub(crate) delay_updates: bool,
    pub(crate) fsync: bool,
    pub(crate) append_verify: bool,
    pub(crate) append: bool,
    pub(crate) block_size: Option<u64>,
    pub(crate) checksum_choice: Option<String>,
    pub(crate) checksum_seed: Option<i32>,
    pub(crate) symlink_mode: SymlinkMode,
    pub(crate) keep_dirlinks: bool,
    pub(crate) hard_links: bool,
    pub(crate) preserve_devices: bool,
    pub(crate) preserve_specials: bool,
    pub(crate) preserve_permissions: bool,
    pub(crate) preserve_owner: bool,
    pub(crate) preserve_group: bool,
    pub(crate) preserve_executability: bool,
    pub(crate) preserve_acls: bool,
    pub(crate) preserve_xattrs: bool,
    pub(crate) fake_super: bool,
    pub(crate) atimes: bool,
    pub(crate) crtimes: bool,
    pub(crate) omit_dir_times: bool,
    pub(crate) omit_link_times: bool,
    pub(crate) vss: bool,
    pub(crate) numeric_ids: bool,
    pub(crate) user_maps: Vec<String>,
    pub(crate) group_maps: Vec<String>,
    pub(crate) chown: Option<String>,
    pub(crate) chmod: Option<String>,
    pub(crate) chmod_rules: Option<ChmodRules>,
    pub(crate) metadata_policy: MetadataPolicy,
    pub(crate) filter_rules: RuleSet,
    pub(crate) backup: bool,
    pub(crate) backup_dir: Option<PathBuf>,
    pub(crate) backup_suffix: String,
    pub(crate) remote_options: Vec<String>,
    pub(crate) rsync_path: Option<String>,
    pub(crate) blocking_io: bool,
    pub(crate) old_args: bool,
    pub(crate) secluded_args: bool,
    pub(crate) trust_sender: bool,
    pub(crate) ipv4: bool,
    pub(crate) ipv6: bool,
    pub(crate) remote_server_argv: Option<Vec<String>>,
    pub(crate) remote_protected_args: Option<Vec<String>>,
    pub(crate) remote_ssh_argv: Option<Vec<String>>,
    pub(crate) remote_ssh_command: Option<SshRemoteCommand>,
    pub(crate) remote_operand: Option<RemoteShellOperand>,
    pub(crate) remote_operands: Vec<RemoteShellOperand>,
    pub(crate) remote_direction: Option<TransferDirection>,
    pub(crate) remote_wire_protocol: Option<RemoteWireProtocol>,
    pub(crate) daemon_operand: Option<DaemonOperand>,
    pub(crate) daemon_direction: Option<TransferDirection>,
    // Chunk 12
    pub(crate) compare_dest: Vec<PathBuf>,
    pub(crate) copy_dest: Vec<PathBuf>,
    pub(crate) link_dest: Vec<PathBuf>,
    pub(crate) sparse: bool,
    pub(crate) preallocate: bool,
    pub(crate) fuzzy: bool,
    pub(crate) copy_as: Option<String>,
    pub(crate) super_flag: bool,
    pub(crate) write_batch: Option<PathBuf>,
    pub(crate) only_write_batch: Option<PathBuf>,
    pub(crate) read_batch: Option<PathBuf>,
    // Chunk 13: Resource limits and operational controls
    #[allow(dead_code)]
    pub(crate) bwlimit: Option<u64>,
    pub(crate) bwlimit_display: Option<String>,
    pub(crate) timeout_secs: Option<u64>,
    pub(crate) stop_after_minutes: Option<u64>,
    pub(crate) time_limit_minutes: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
    pub(crate) stop_at: Option<String>,
    #[allow(dead_code)]
    pub(crate) max_alloc: Option<u64>,
    pub(crate) max_alloc_display: Option<String>,
    pub(crate) early_input: Option<String>,
    pub(crate) outbuf: Option<String>,
    pub(crate) protocol_version: Option<u32>,
    pub(crate) iconv: Option<String>,
    pub(crate) open_noatime: bool,
    pub(crate) report: Report,
}

impl TransferPlan {
    pub(crate) fn from_cli(cli: &Cli) -> Self {
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
        let requested_incremental_recursion = incremental_recursion_from_cli(cli, recursive);
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
        let requested_remote_wire_protocol = remote_wire_protocol_from_cli(cli, &mut report);
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
                        match build_remote_shell_invocation_for_wire_protocol(
                            requested_remote_wire_protocol,
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
                                        add_remote_protocol_diagnostic(
                                            &mut report,
                                            requested_remote_wire_protocol,
                                        );
                                        (
                                            Some(invocation.argv),
                                            Some(invocation.protected_args),
                                            Some(render_ssh_command(&ssh_command)),
                                            Some(ssh_command),
                                            Some(remote.clone()),
                                            remotes,
                                            Some(direction),
                                            Some(requested_remote_wire_protocol),
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
                match build_remote_shell_invocation_for_wire_protocol(
                    requested_remote_wire_protocol,
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
                                add_remote_protocol_diagnostic(
                                    &mut report,
                                    requested_remote_wire_protocol,
                                );
                                (
                                    Some(invocation.argv),
                                    Some(invocation.protected_args),
                                    Some(render_ssh_command(&ssh_command)),
                                    Some(ssh_command),
                                    Some(remote.clone()),
                                    vec![remote.clone()],
                                    Some(direction),
                                    Some(requested_remote_wire_protocol),
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
        let incremental_recursion =
            requested_incremental_recursion && remote_direction == Some(TransferDirection::Pull);
        if requested_incremental_recursion && remote_direction == Some(TransferDirection::Push) {
            report.warn(
                "W_INC_RECURSIVE_PUSH_DISABLED",
                "--inc-recursive currently applies to protocol 31 remote pulls; remote-shell push is kept on --no-inc-recursive until sender-side upstream incremental recursion is implemented",
            );
        }

        Self {
            transfer_mode,
            recursive,
            incremental_recursion,
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
            compare_dest: cli.compare_dest.iter().map(PathBuf::from).collect(),
            copy_dest: cli.copy_dest.iter().map(PathBuf::from).collect(),
            link_dest: cli.link_dest.iter().map(PathBuf::from).collect(),
            sparse: cli.sparse,
            preallocate: cli.preallocate,
            fuzzy: cli.fuzzy,
            copy_as: cli.copy_as.clone(),
            super_flag: cli.super_flag,
            write_batch: cli.write_batch.clone(),
            only_write_batch: cli.only_write_batch.clone(),
            read_batch: cli.read_batch.clone(),
            // Chunk 13
            bwlimit: cli.bwlimit.as_ref().and_then(|v| parse_bwlimit_quiet(v)),
            bwlimit_display: cli.bwlimit.clone().map(|v| format_bwlimit(&v)),
            timeout_secs: cli.timeout_secs,
            stop_after_minutes: cli.stop_after_minutes,
            time_limit_minutes: cli.time_limit_minutes,
            stop_deadline: stop_deadline_from_cli(cli, &mut report),
            stop_at: cli.stop_at.clone(),
            max_alloc: cli
                .max_alloc
                .as_ref()
                .and_then(|v| parse_max_alloc_quiet(v)),
            max_alloc_display: cli.max_alloc.clone().map(|v| format_max_alloc(&v)),
            early_input: cli.early_input.clone(),
            outbuf: cli.outbuf.clone(),
            protocol_version: cli.protocol_version,
            iconv: cli.iconv.clone(),
            open_noatime: cli.open_noatime,
            report,
        }
    }
}
