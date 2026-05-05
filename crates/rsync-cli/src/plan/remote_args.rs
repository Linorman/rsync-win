use super::*;

pub(crate) fn transfer_mode_from_cli(
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

pub(crate) fn add_mode_gating_diagnostics(
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
            if cli.daemon_no_motd {
                report.warn(
                    "W_MODE_SCOPED_OPTION",
                    "--no-motd applies to rsync daemon module listing, not remote-shell mode",
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
            if cli.daemon_no_motd {
                report.warn(
                    "W_MODE_SCOPED_OPTION",
                    "--no-motd applies to rsync daemon module listing, not local mode",
                );
            }
        }
    }
}

pub(crate) fn plan_daemon_operands(
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

    let (index, mut operand) = operands.remove(0);
    if let Some(port) = cli.daemon_port {
        operand.port = port;
    }
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
        if operand.module.is_none() {
            report.error(
                "E_DAEMON_OPERANDS",
                "daemon push requires a module, e.g. host::module/path",
            );
            return (Some(operand), None, true);
        }
        return (Some(operand), Some(TransferDirection::Push), true);
    }

    report.error(
        "E_DAEMON_OPERANDS",
        "daemon operands cannot be mixed with additional local or remote sources in this MVP",
    );
    (Some(operand), None, true)
}

pub(crate) fn incremental_recursion_from_cli(cli: &Cli, recursive: bool) -> bool {
    recursive && cli.inc_recursive && !cli.no_inc_recursive
}

pub(crate) fn remote_shell_options_from_cli(
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
        incremental_recursion: direction == TransferDirection::Pull
            && incremental_recursion_from_cli(cli, recursive),
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
        outbuf: cli.outbuf.clone(),
        remote_options: cli.remote_options.clone(),
        includes,
        excludes,
        filters,
    }
}

pub(crate) fn daemon_remote_shell_options_from_cli(
    cli: &Cli,
    direction: TransferDirection,
    recursive: bool,
    preserve_times: bool,
    symlink_mode: SymlinkMode,
) -> RemoteShellOptions {
    let mut options =
        remote_shell_options_from_cli(cli, direction, recursive, preserve_times, symlink_mode);
    if direction == TransferDirection::Pull {
        options.executability = cli.executability;
        options.preserve_owner = cli_preserve_owner(cli);
        options.preserve_group = cli_preserve_group(cli);
        options.numeric_ids = cli.numeric_ids;
        options.user_maps = cli.user_maps.clone();
        options.group_maps = cli.group_maps.clone();
        options.chown = cli.chown.clone();
        options.chmod = cli.chmod.clone();
        options.acls = cli.acls;
        options.xattrs = cli.xattrs;
        options.fake_super = cli.fake_super;
        options.atimes = cli.atimes;
        options.crtimes = cli.crtimes;
    }
    if options.fake_super {
        options.xattrs = true;
    }
    options
}

pub(crate) fn remote_compress_choice_for_argv(
    compress: bool,
    choice: Option<&str>,
) -> Option<String> {
    if !compress {
        return None;
    }
    RsyncDeflatedTokenMode::from_choice(choice)
        .map(|mode| mode.remote_choice().to_string())
        .ok()
        .or_else(|| choice.map(str::to_string))
}

pub(crate) fn remote_delete_mode_from_cli(cli: &Cli) -> RemoteDeleteMode {
    remote_delete_mode(cli.delete, cli.delete_mode)
}

pub(crate) fn protocol31_setup_options_from_plan(plan: &TransferPlan) -> Protocol31SetupOptions {
    Protocol31SetupOptions {
        checksum_choices: plan
            .checksum_choice
            .as_deref()
            .map(split_option_list)
            .unwrap_or_else(|| vec!["md4".to_string()]),
        checksum_seed: plan.checksum_seed,
    }
}

pub(crate) fn split_option_list(value: &str) -> Vec<String> {
    value
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

pub(crate) fn remote_delete_mode(delete: bool, delete_mode: DeleteMode) -> RemoteDeleteMode {
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

pub(crate) fn cli_preserve_permissions(cli: &Cli) -> bool {
    (cli.preserve_permissions || cli.archive) && !cli.no_permissions
}

pub(crate) fn cli_preserve_owner(cli: &Cli) -> bool {
    cli.preserve_owner || (cli.archive && !cli.no_owner)
}

pub(crate) fn cli_preserve_group(cli: &Cli) -> bool {
    cli.preserve_group || (cli.archive && !cli.no_group)
}
