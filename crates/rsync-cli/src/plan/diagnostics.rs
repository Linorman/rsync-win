use super::*;

pub(crate) fn add_explicit_option_diagnostics(cli: &Cli, report: &mut Report) {
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

    // Chunk 12 diagnostics
    for compare_path in &cli.compare_dest {
        report.info(
            "I_OPTION_PARSED",
            format!("--compare-dest={compare_path} is represented in the execution plan"),
        );
    }
    for copy_path in &cli.copy_dest {
        report.info(
            "I_OPTION_PARSED",
            format!("--copy-dest={copy_path} is represented in the execution plan"),
        );
    }
    for link_path in &cli.link_dest {
        report.info(
            "I_OPTION_PARSED",
            format!("--link-dest={link_path} is represented in the execution plan"),
        );
    }
    if cli.sparse {
        report.info(
            "I_OPTION_PARSED",
            "--sparse is represented in the execution plan; sparse file creation requested on Windows where FSCTL_SET_SPARSE_FILE is supported",
        );
    }
    if cli.preallocate {
        report.info(
            "I_OPTION_PARSED",
            "--preallocate is represented in the execution plan; preallocation uses SetFileInformationByHandle on Windows",
        );
    }
    if cli.fuzzy {
        report.info(
            "I_OPTION_PARSED",
            "--fuzzy is represented in the execution plan; basis-file search uses best-effort name similarity",
        );
    }
    if let Some(ref copy_as) = cli.copy_as {
        report.info(
            "I_OPTION_PARSED",
            format!("--copy-as={copy_as} is parsed as a destination user identity; local Windows copies run as the current user unless run elevated"),
        );
    }
    if cli.super_flag {
        report.info(
            "I_OPTION_PARSED",
            "--super receiver attempts super-user activities where the platform permits",
        );
    }
    if let Some(ref batch) = cli.write_batch {
        report.info(
            "I_OPTION_PARSED",
            format!(
                "--write-batch={} will record transfer metadata for replay",
                batch.display()
            ),
        );
    }
    if let Some(ref batch) = cli.only_write_batch {
        report.info(
            "I_OPTION_PARSED",
            format!("--only-write-batch={} will record transfer metadata without updating the destination", batch.display()),
        );
    }
    if let Some(ref batch) = cli.read_batch {
        report.info(
            "I_OPTION_PARSED",
            format!(
                "--read-batch={} will replay a recorded transfer",
                batch.display()
            ),
        );
    }

    // Chunk 13 diagnostics
    if let Some(ref bwlimit) = cli.bwlimit {
        report.info(
            "I_OPTION_PARSED",
            format!("--bwlimit={bwlimit} bandwidth limiting will be applied to the transfer"),
        );
    }
    if let Some(timeout) = cli.timeout_secs {
        report.info(
            "I_OPTION_PARSED",
            format!("--timeout={timeout} sets I/O timeout in seconds during transfer"),
        );
    }
    if let Some(stop_after) = cli.stop_after_minutes {
        report.info(
            "I_OPTION_PARSED",
            format!("--stop-after={stop_after} will stop the transfer after the specified number of minutes"),
        );
    }
    if let Some(time_limit) = cli.time_limit_minutes {
        report.info(
            "I_OPTION_PARSED",
            format!("--time-limit={time_limit} sets a maximum runtime for the transfer"),
        );
    }
    if let Some(ref stop_at) = cli.stop_at {
        report.info(
            "I_OPTION_PARSED",
            format!("--stop-at={stop_at} will stop the transfer at the specified wall-clock time"),
        );
    }
    if let Some(ref max_alloc) = cli.max_alloc {
        report.info(
            "I_OPTION_PARSED",
            format!("--max-alloc={max_alloc} caps the largest single memory allocation during the transfer"),
        );
    }
    if let Some(ref early_input) = cli.early_input {
        report.info(
            "I_OPTION_PARSED",
            format!(
                "--early-input={early_input} provides pre-seed data to send before the file list"
            ),
        );
    }
    if let Some(ref outbuf) = cli.outbuf {
        report.info(
            "I_OPTION_PARSED",
            format!("--outbuf={outbuf} sets output buffering mode"),
        );
    }
    if let Some(protocol) = cli.protocol_version {
        report.info(
            "I_OPTION_PARSED",
            format!("--protocol={protocol} constrains protocol version negotiation"),
        );
    }
    if let Some(ref iconv) = cli.iconv {
        report.warn(
            "W_ICONV_UNAVAILABLE",
            format!("--iconv={iconv} charset conversion is not available on this platform; filenames are transferred as-is"),
        );
    }
    if cli.open_noatime {
        report.info(
            "I_OPTION_PARSED",
            "--open-noatime requested; O_NOATIME is not available on Windows, files are opened with normal access time semantics",
        );
    }
}

pub(crate) fn add_option_conflict_diagnostics(cli: &Cli, report: &mut Report) {
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
    // Chunk 12 conflict checks
    if cli.sparse && cli.preallocate {
        report.warn(
            "W_OPTION_OVERLAP",
            "--sparse and --preallocate together: preallocation will be skipped for sparse files",
        );
    }
    if cli.write_batch.is_some() && cli.only_write_batch.is_some() {
        report.error(
            "E_OPTION_CONFLICT",
            "--write-batch and --only-write-batch cannot both be specified",
        );
    }
    if cli.write_batch.is_some() && cli.read_batch.is_some() {
        report.error(
            "E_OPTION_CONFLICT",
            "--write-batch and --read-batch cannot both be specified",
        );
    }
    if cli.only_write_batch.is_some() && cli.read_batch.is_some() {
        report.error(
            "E_OPTION_CONFLICT",
            "--only-write-batch and --read-batch cannot both be specified",
        );
    }
    if cli.read_batch.is_some() && cli.dry_run {
        report.warn(
            "W_OPTION_OVERLAP",
            "--read-batch with --dry-run: replay will be a dry run",
        );
    }
}

pub(crate) fn ensure_local_execution_options_supported(cli: &Cli) -> Result<()> {
    if cli.inplace && cli.partial_dir.is_some() {
        bail!("--inplace and --partial-dir cannot both control the same local write path");
    }
    if cli.read_batch.is_some() && cli.paths.len() < 2 {
        bail!("--read-batch requires a destination operand");
    }

    Ok(())
}

pub(crate) fn ensure_remote_execution_options_supported(
    cli: &Cli,
    plan: &TransferPlan,
) -> Result<()> {
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

pub(crate) fn ensure_daemon_execution_options_supported(
    cli: &Cli,
    plan: &TransferPlan,
) -> Result<()> {
    let daemon = plan
        .daemon_operand
        .as_ref()
        .context("daemon execution could not be planned; run with --plan for diagnostics")?;
    if cli.remote_shell.is_some() {
        bail!("daemon client mode does not use --rsh/-e; omit the remote-shell option");
    }
    if daemon.module.is_none() && !cli.list_only {
        bail!("daemon module listing requires --list-only host::");
    }
    if daemon.module.is_none() && cli.paths.len() != 1 {
        bail!("daemon module listing takes exactly one daemon operand");
    }
    if daemon.module.is_some() && cli.paths.len() < 2 {
        bail!("daemon transfer requires at least one source and one destination");
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
    if cli.vss {
        bail!("daemon execution does not yet support VSS metadata options; run with --plan for diagnostics");
    }

    Ok(())
}

pub(crate) fn is_daemon_operand_syntax(operand: &str) -> bool {
    operand.starts_with("rsync://") || operand.contains("::")
}

pub(crate) fn is_remote_shell_operand(operand: &str) -> bool {
    if is_daemon_operand_syntax(operand) {
        return false;
    }
    matches!(RemoteShellOperand::parse(operand), Ok(Some(_)) | Err(_))
}
