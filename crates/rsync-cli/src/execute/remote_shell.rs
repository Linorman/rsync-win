use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rsync_fs::{FileWriteMode, SymlinkMode, UpdateMode};
use rsync_protocol::{
    build_remote_shell_invocation_for_paths, write_remote_shell_protected_args, RemoteShellOptions,
    TransferDirection, REMOTE_SHELL_MVP_PROTOCOL,
};
use rsync_transport::remote_shell::{
    build_custom_remote_shell_command_with_options, build_ssh_remote_command_with_options,
    default_ssh_program, spawn_ssh_remote_command, RemoteShellCommandOptions, SshAddressFamily,
    SshRemoteCommand,
};
use rsync_transport::BandwidthLimitedStream;

use crate::cli::Cli;
use crate::output::ProgressLog;
use crate::plan::*;
use crate::remote::flist::*;
use crate::remote::pull::{execute_remote_pull, execute_remote_pull_protocol27};
use crate::remote::push::{execute_remote_push, execute_remote_push_protocol27};
use crate::remote::session::should_fallback_to_protocol27;
use crate::transfer::*;

pub(crate) fn execute_remote_shell_sync(cli: &Cli, plan: TransferPlan) -> Result<String> {
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
    let session_result = if let Some(limit) = bandwidth_limit_from_plan(&plan) {
        let mut limited = BandwidthLimitedStream::new(&mut transport, limit);
        execute_remote_shell_session(cli, &plan, direction, &mut limited)
    } else {
        execute_remote_shell_session(cli, &plan, direction, &mut transport)
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
                && cli.protocol_version.is_none()
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

fn execute_remote_shell_session<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    direction: TransferDirection,
    transport: &mut T,
) -> Result<String> {
    if let Some(protected_args) = &plan.remote_protected_args {
        write_remote_shell_protected_args(transport, protected_args)
            .context("failed to send remote-shell protected args")?;
    }

    match direction {
        TransferDirection::Push => execute_remote_push(cli, plan, transport),
        TransferDirection::Pull => execute_remote_pull(cli, plan, transport),
    }
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
    let session_result = if let Some(limit) = bandwidth_limit_from_plan(plan) {
        let mut limited = BandwidthLimitedStream::new(&mut transport, limit);
        execute_remote_shell_protocol27_fallback_session(
            cli,
            plan,
            direction,
            &protected_args,
            &mut limited,
        )
    } else {
        execute_remote_shell_protocol27_fallback_session(
            cli,
            plan,
            direction,
            &protected_args,
            &mut transport,
        )
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

fn execute_remote_shell_protocol27_fallback_session<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    direction: TransferDirection,
    protected_args: &[String],
    transport: &mut T,
) -> Result<String> {
    write_remote_shell_protected_args(transport, protected_args)
        .context("failed to send remote-shell protected args for protocol 27 fallback")?;

    match direction {
        TransferDirection::Push => execute_remote_push_protocol27(cli, plan, transport),
        TransferDirection::Pull => execute_remote_pull_protocol27(cli, plan, transport),
    }
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
            incremental_recursion: false,
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
            outbuf: plan.outbuf.clone(),
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

pub(crate) fn build_remote_transport_command(
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
