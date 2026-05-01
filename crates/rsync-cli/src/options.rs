use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{bail, Result};
use rsync_fs::DeleteMode;

use crate::{Cli, CliMetadataPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    None,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatBehavior {
    Forbid,
    Count,
    Append,
    LastWins,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionScope {
    Client,
    Daemon,
    Internal,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplementationStatus {
    Implemented,
    Planned,
    CapabilityGated,
    ExplicitDiagnostic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionSpec {
    pub long: &'static str,
    pub short: Option<char>,
    pub aliases: &'static [&'static str],
    pub value_kind: ValueKind,
    pub repeat: RepeatBehavior,
    pub negatable: bool,
    pub scope: OptionScope,
    pub notes: &'static str,
    pub status: ImplementationStatus,
}

const fn spec(
    long: &'static str,
    short: Option<char>,
    value_kind: ValueKind,
    repeat: RepeatBehavior,
    negatable: bool,
    scope: OptionScope,
    status: ImplementationStatus,
) -> OptionSpec {
    OptionSpec {
        long,
        short,
        aliases: &[],
        value_kind,
        repeat,
        negatable,
        scope,
        notes: "",
        status,
    }
}

const fn flag(long: &'static str, short: Option<char>, status: ImplementationStatus) -> OptionSpec {
    spec(
        long,
        short,
        ValueKind::None,
        RepeatBehavior::LastWins,
        true,
        OptionScope::Client,
        status,
    )
}

const fn value(
    long: &'static str,
    short: Option<char>,
    status: ImplementationStatus,
) -> OptionSpec {
    spec(
        long,
        short,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Client,
        status,
    )
}

const fn append_value(
    long: &'static str,
    short: Option<char>,
    status: ImplementationStatus,
) -> OptionSpec {
    spec(
        long,
        short,
        ValueKind::Required,
        RepeatBehavior::Append,
        false,
        OptionScope::Client,
        status,
    )
}

const I: ImplementationStatus = ImplementationStatus::Implemented;
const P: ImplementationStatus = ImplementationStatus::Planned;

static UPSTREAM_CLIENT_OPTIONS: &[OptionSpec] = &[
    spec(
        "verbose",
        Some('v'),
        ValueKind::None,
        RepeatBehavior::Count,
        true,
        OptionScope::Client,
        I,
    ),
    append_value("info", None, I),
    append_value("debug", None, I),
    value("stderr", None, I),
    flag("msgs2stderr", None, I),
    flag("no-msgs2stderr", None, I),
    spec(
        "quiet",
        Some('q'),
        ValueKind::None,
        RepeatBehavior::Count,
        true,
        OptionScope::Client,
        I,
    ),
    flag("no-motd", None, I),
    flag("checksum", Some('c'), I),
    flag("archive", Some('a'), I),
    flag("recursive", Some('r'), I),
    flag("inc-recursive", None, P),
    flag("i-r", None, P),
    flag("no-inc-recursive", None, P),
    flag("no-i-r", None, P),
    flag("relative", Some('R'), I),
    flag("no-implied-dirs", None, I),
    flag("backup", Some('b'), I),
    value("backup-dir", None, I),
    value("suffix", None, I),
    flag("update", Some('u'), I),
    flag("inplace", None, I),
    flag("append", None, I),
    flag("append-verify", None, I),
    flag("dirs", Some('d'), I),
    flag("old-dirs", None, I),
    flag("old-d", None, I),
    flag("mkpath", None, I),
    flag("links", Some('l'), I),
    flag("copy-links", Some('L'), I),
    flag("copy-unsafe-links", None, I),
    flag("safe-links", None, I),
    flag("munge-links", None, I),
    flag("copy-dirlinks", Some('k'), I),
    flag("keep-dirlinks", Some('K'), I),
    flag("hard-links", Some('H'), I),
    flag("perms", Some('p'), I),
    flag("executability", Some('E'), I),
    value("chmod", None, I),
    flag("acls", Some('A'), I),
    flag("xattrs", Some('X'), I),
    flag("owner", Some('o'), I),
    flag("group", Some('g'), I),
    flag("devices", None, I),
    flag("copy-devices", None, I),
    flag("write-devices", None, I),
    flag("specials", None, I),
    flag("D", Some('D'), I),
    flag("times", Some('t'), I),
    flag("atimes", Some('U'), I),
    flag("open-noatime", None, P),
    flag("crtimes", Some('N'), I),
    flag("omit-dir-times", Some('O'), I),
    flag("omit-link-times", Some('J'), I),
    flag("super", None, P),
    flag("fake-super", None, I),
    flag("sparse", Some('S'), P),
    flag("preallocate", None, P),
    flag("dry-run", Some('n'), I),
    flag("whole-file", Some('W'), I),
    value("checksum-choice", None, I),
    value("cc", None, I),
    flag("one-file-system", Some('x'), I),
    value("block-size", Some('B'), I),
    value("rsh", Some('e'), I),
    value("rsync-path", None, I),
    flag("existing", None, I),
    flag("ignore-non-existing", None, I),
    flag("ignore-existing", None, I),
    flag("remove-source-files", None, P),
    flag("del", None, I),
    flag("delete", None, I),
    flag("delete-before", None, I),
    flag("delete-during", None, I),
    flag("delete-delay", None, I),
    flag("delete-after", None, I),
    flag("delete-excluded", None, I),
    flag("ignore-missing-args", None, I),
    flag("delete-missing-args", None, I),
    flag("ignore-errors", None, I),
    flag("force", None, I),
    value("max-delete", None, I),
    value("max-size", None, I),
    value("min-size", None, I),
    value("max-alloc", None, P),
    flag("partial", None, I),
    value("partial-dir", None, I),
    flag("delay-updates", None, I),
    flag("prune-empty-dirs", Some('m'), P),
    flag("numeric-ids", None, I),
    append_value("usermap", None, I),
    append_value("groupmap", None, I),
    value("chown", None, I),
    value("timeout", None, P),
    value("contimeout", None, I),
    flag("ignore-times", Some('I'), I),
    flag("size-only", None, I),
    value("modify-window", Some('@'), I),
    value("temp-dir", Some('T'), I),
    flag("fuzzy", Some('y'), P),
    value("compare-dest", None, P),
    value("copy-dest", None, P),
    value("link-dest", None, P),
    flag("compress", Some('z'), I),
    value("compression-choice", None, I),
    value("compress-choice", None, I),
    value("zc", None, I),
    value("compress-level", None, I),
    value("zl", None, I),
    value("compress-threads", None, I),
    value("zt", None, I),
    value("skip-compress", None, I),
    flag("cvs-exclude", Some('C'), I),
    append_value("filter", Some('f'), I),
    flag("F", Some('F'), I),
    append_value("exclude", None, I),
    append_value("exclude-from", None, I),
    append_value("include", None, I),
    append_value("include-from", None, I),
    value("files-from", None, I),
    flag("from0", Some('0'), I),
    flag("old-args", None, I),
    flag("secluded-args", Some('s'), I),
    flag("protect-args", None, I),
    flag("trust-sender", None, I),
    value("copy-as", None, P),
    value("address", None, I),
    value("port", None, I),
    value("sockopts", None, I),
    flag("blocking-io", None, I),
    value("outbuf", None, P),
    flag("stats", None, I),
    flag("8-bit-output", Some('8'), I),
    spec(
        "human-readable",
        Some('h'),
        ValueKind::None,
        RepeatBehavior::Count,
        true,
        OptionScope::Client,
        I,
    ),
    flag("progress", None, I),
    flag("P", Some('P'), I),
    flag("itemize-changes", Some('i'), I),
    append_value("remote-option", Some('M'), I),
    value("out-format", None, I),
    value("log-file", None, I),
    value("log-file-format", None, I),
    value("password-file", None, I),
    value("early-input", None, P),
    flag("list-only", None, I),
    value("bwlimit", None, P),
    value("stop-after", None, P),
    value("time-limit", None, P),
    value("stop-at", None, P),
    flag("fsync", None, I),
    value("write-batch", None, P),
    value("only-write-batch", None, P),
    value("read-batch", None, P),
    value("protocol", None, P),
    value("iconv", None, P),
    value("checksum-seed", None, I),
    flag("ipv4", Some('4'), I),
    flag("ipv6", Some('6'), I),
    flag("version", Some('V'), I),
    flag("help", None, I),
];

static DAEMON_OPTIONS: &[OptionSpec] = &[
    spec(
        "daemon",
        None,
        ValueKind::None,
        RepeatBehavior::Forbid,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "address",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "bwlimit",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "config",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "dparam",
        Some('M'),
        ValueKind::Required,
        RepeatBehavior::Append,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "no-detach",
        None,
        ValueKind::None,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "port",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "log-file",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "log-file-format",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "sockopts",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "verbose",
        Some('v'),
        ValueKind::None,
        RepeatBehavior::Count,
        true,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "ipv4",
        Some('4'),
        ValueKind::None,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "ipv6",
        Some('6'),
        ValueKind::None,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Daemon,
        I,
    ),
    spec(
        "help",
        Some('h'),
        ValueKind::None,
        RepeatBehavior::Forbid,
        false,
        OptionScope::Daemon,
        I,
    ),
];

static INTERNAL_SERVER_OPTIONS: &[OptionSpec] = &[
    spec(
        "server",
        None,
        ValueKind::None,
        RepeatBehavior::Forbid,
        false,
        OptionScope::Internal,
        P,
    ),
    spec(
        "sender",
        None,
        ValueKind::None,
        RepeatBehavior::Forbid,
        false,
        OptionScope::Internal,
        P,
    ),
];

static PROJECT_OPTIONS: &[OptionSpec] = &[
    spec(
        "plan",
        None,
        ValueKind::None,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Project,
        I,
    ),
    spec(
        "metadata-policy",
        None,
        ValueKind::Required,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Project,
        I,
    ),
    spec(
        "fail-on-metadata-loss",
        None,
        ValueKind::None,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Project,
        I,
    ),
    spec(
        "protocol-range",
        None,
        ValueKind::None,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Project,
        I,
    ),
    spec(
        "vss",
        None,
        ValueKind::None,
        RepeatBehavior::LastWins,
        false,
        OptionScope::Project,
        I,
    ),
];

pub fn upstream_client_option_specs() -> &'static [OptionSpec] {
    UPSTREAM_CLIENT_OPTIONS
}

pub fn daemon_option_specs() -> &'static [OptionSpec] {
    DAEMON_OPTIONS
}

pub fn internal_server_option_specs() -> &'static [OptionSpec] {
    INTERNAL_SERVER_OPTIONS
}

pub fn project_option_specs() -> &'static [OptionSpec] {
    PROJECT_OPTIONS
}

#[derive(Debug)]
pub struct ParsedOptions {
    cli: Cli,
}

impl ParsedOptions {
    pub fn as_cli(&self) -> &Cli {
        &self.cli
    }

    pub fn into_cli(self) -> Cli {
        self.cli
    }

    pub fn is_plan(&self) -> bool {
        self.cli.plan
    }

    pub fn is_help(&self) -> bool {
        self.cli.help
    }

    pub fn is_version(&self) -> bool {
        self.cli.version
    }

    pub fn verbosity(&self) -> u8 {
        self.cli.verbosity
    }

    pub fn quiet(&self) -> u8 {
        self.cli.quiet
    }

    pub fn human_readable(&self) -> u8 {
        self.cli.human_readable
    }

    pub fn operands(&self) -> &[String] {
        &self.cli.paths
    }

    pub fn remote_options(&self) -> &[String] {
        &self.cli.remote_options
    }
}

pub fn parse_options<I, T>(args: I) -> Result<ParsedOptions>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    parse_cli_impl(args).map(|cli| ParsedOptions { cli })
}

pub fn parse_cli<I, T>(args: I) -> Result<Cli>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    parse_options(args).map(ParsedOptions::into_cli)
}

fn parse_cli_impl<I, T>(args: I) -> Result<Cli>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let raw: Vec<String> = args
        .into_iter()
        .map(|arg| arg.into().to_string_lossy().into_owned())
        .collect();
    let mut cli = Cli::default();
    let mut index = argument_start_index(&raw);
    let help_only = raw.len() == index + 1
        && raw
            .get(index)
            .is_some_and(|arg| matches!(arg.as_str(), "-h" | "--help"));

    let option_scan_end = raw.iter().position(|arg| arg == "--").unwrap_or(raw.len());
    if help_only || raw.iter().take(option_scan_end).any(|arg| arg == "--help") {
        cli.help = true;
        return Ok(cli);
    }

    while index < raw.len() {
        let arg = &raw[index];
        if arg == "--" {
            cli.paths.extend(raw[index + 1..].iter().cloned());
            break;
        }
        if arg == "-h" && help_only {
            cli.help = true;
            index += 1;
            continue;
        }
        if let Some(option) = arg.strip_prefix("--") {
            let (name, inline_value) = split_long_option(option);
            let value = if long_requires_value(name) {
                Some(take_option_value(name, inline_value, &raw, &mut index)?)
            } else {
                if inline_value.is_some() {
                    bail!("option --{name} does not take a value");
                }
                None
            };
            apply_long_option(&mut cli, name, value.as_deref())?;
            index += 1;
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            parse_short_options(&mut cli, arg, &raw, &mut index, help_only)?;
            index += 1;
            continue;
        }
        cli.paths.push(arg.clone());
        index += 1;
    }

    Ok(cli)
}

fn argument_start_index(raw: &[String]) -> usize {
    if raw.first().is_some_and(|arg| is_program_name(arg)) {
        1
    } else {
        0
    }
}

fn is_program_name(arg: &str) -> bool {
    let normalized = arg.replace('\\', "/");
    let name = normalized
        .rsplit('/')
        .next()
        .unwrap_or(arg)
        .to_ascii_lowercase();
    matches!(name.as_str(), "rsync-win" | "rsync-win.exe")
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            version: false,
            protocol_range: false,
            plan: false,
            recursive: false,
            no_recursive: false,
            preserve_times: false,
            no_times: false,
            archive: false,
            dry_run: false,
            delete: false,
            delete_mode: DeleteMode::None,
            whole_file: false,
            compress: false,
            compress_choice: None,
            compress_level: None,
            compress_threads: None,
            skip_compress: Vec::new(),
            quiet: 0,
            info_flags: Vec::new(),
            debug_flags: Vec::new(),
            msgs2stderr: false,
            no_msgs2stderr: false,
            stderr_mode: None,
            out_format: None,
            eight_bit_output: false,
            client_log_file: None,
            client_log_file_format: None,
            human_readable: 0,
            help: false,
            progress: false,
            relative: false,
            implied_dirs: true,
            transfer_dirs: false,
            mkpath: false,
            one_file_system: false,
            verbosity: 0,
            itemize_changes: false,
            stats: false,
            list_only: false,
            metadata_policy: CliMetadataPolicy::Portable,
            fail_on_metadata_loss: false,
            preserve_permissions: false,
            no_permissions: false,
            preserve_owner: false,
            preserve_group: false,
            executability: false,
            acls: false,
            xattrs: false,
            fake_super: false,
            atimes: false,
            crtimes: false,
            omit_dir_times: false,
            omit_link_times: false,
            vss: false,
            daemon_server: false,
            daemon_config: None,
            daemon_params: Vec::new(),
            daemon_no_detach: false,
            daemon_address: None,
            daemon_port: None,
            daemon_sockopts: None,
            daemon_connect_timeout_secs: None,
            daemon_no_motd: false,
            daemon_log_file: None,
            daemon_log_file_format: None,
            daemon_bwlimit: None,
            internal_server: false,
            internal_sender: false,
            includes: Vec::new(),
            excludes: Vec::new(),
            filters: Vec::new(),
            exclude_from: Vec::new(),
            include_from: Vec::new(),
            cvs_exclude: false,
            files_from: None,
            from0: false,
            checksum: false,
            checksum_choice: None,
            checksum_seed: None,
            size_only: false,
            ignore_times: false,
            partial: false,
            partial_dir: None,
            inplace: false,
            append_verify: false,
            append: false,
            update: false,
            existing: false,
            ignore_existing: false,
            max_size: None,
            min_size: None,
            modify_window: 0,
            ignore_missing_args: false,
            delete_missing_args: false,
            delete_excluded: false,
            ignore_errors: false,
            force: false,
            max_delete: None,
            backup: false,
            backup_dir: None,
            suffix: None,
            temp_dir: None,
            delay_updates: false,
            fsync: false,
            numeric_ids: false,
            user_maps: Vec::new(),
            group_maps: Vec::new(),
            chown: None,
            no_owner: false,
            no_group: false,
            chmod: None,
            remote_shell: None,
            password_file: None,
            copy_links: false,
            safe_links: false,
            copy_unsafe_links: false,
            copy_dirlinks: false,
            keep_dirlinks: false,
            munge_links: false,
            links: false,
            no_links: false,
            hard_links: false,
            devices: false,
            specials: false,
            no_devices: false,
            no_specials: false,
            copy_devices: false,
            write_devices: false,
            block_size: None,
            remote_options: Vec::new(),
            rsync_path: None,
            blocking_io: false,
            old_args: false,
            secluded_args: false,
            trust_sender: false,
            ipv4: false,
            ipv6: false,
            accepted_unsupported_options: Vec::new(),
            paths: Vec::new(),
        }
    }
}

fn split_long_option(option: &str) -> (&str, Option<&str>) {
    option
        .split_once('=')
        .map(|(name, value)| (name, Some(value)))
        .unwrap_or((option, None))
}

fn long_requires_value(name: &str) -> bool {
    find_long_spec(name).is_some_and(|spec| spec.value_kind == ValueKind::Required)
}

fn take_option_value(
    name: &str,
    inline: Option<&str>,
    args: &[String],
    index: &mut usize,
) -> Result<String> {
    if let Some(value) = inline {
        return Ok(value.to_string());
    }
    let next_index = *index + 1;
    let Some(value) = args.get(next_index) else {
        bail!("option --{name} requires a value");
    };
    *index = next_index;
    Ok(value.clone())
}

fn parse_short_options(
    cli: &mut Cli,
    arg: &str,
    args: &[String],
    index: &mut usize,
    help_only: bool,
) -> Result<()> {
    for (offset, option) in arg[1..].char_indices() {
        if option == 'h' && help_only {
            cli.help = true;
            continue;
        }
        if short_requires_value(option) {
            let value_start = 1 + offset + option.len_utf8();
            let value = if value_start < arg.len() {
                arg[value_start..].trim_start_matches('=').to_string()
            } else {
                let next_index = *index + 1;
                let Some(value) = args.get(next_index) else {
                    bail!("option -{option} requires a value");
                };
                *index = next_index;
                value.clone()
            };
            apply_short_option(cli, option, Some(value.as_str()))?;
            return Ok(());
        }
        apply_short_option(cli, option, None)?;
    }
    Ok(())
}

fn short_requires_value(option: char) -> bool {
    matches!(option, 'e' | 'B' | '@' | 'T' | 'f' | 'M')
}

fn find_long_spec(name: &str) -> Option<&'static OptionSpec> {
    UPSTREAM_CLIENT_OPTIONS
        .iter()
        .chain(PROJECT_OPTIONS.iter())
        .chain(DAEMON_OPTIONS.iter())
        .chain(INTERNAL_SERVER_OPTIONS.iter())
        .find(|spec| spec.long == name || spec.aliases.contains(&name))
}

fn apply_short_option(cli: &mut Cli, option: char, value: Option<&str>) -> Result<()> {
    match option {
        'v' => cli.verbosity = cli.verbosity.saturating_add(1),
        'q' => cli.quiet = cli.quiet.saturating_add(1),
        'c' => cli.checksum = true,
        'a' => {
            cli.archive = true;
            cli.no_recursive = false;
            cli.no_times = false;
            cli.no_permissions = false;
            cli.no_owner = false;
            cli.no_group = false;
            cli.no_devices = false;
            cli.no_specials = false;
            cli.no_links = false;
        }
        'r' => {
            cli.recursive = true;
            cli.no_recursive = false;
        }
        'R' => cli.relative = true,
        'b' => cli.backup = true,
        'u' => cli.update = true,
        'd' => cli.transfer_dirs = true,
        'l' => {
            cli.links = true;
            cli.no_links = false;
        }
        'L' => {
            cli.copy_links = true;
            cli.no_links = false;
        }
        'k' => {
            cli.copy_dirlinks = true;
            cli.no_links = false;
        }
        'K' => cli.keep_dirlinks = true,
        'H' => cli.hard_links = true,
        'p' => {
            cli.preserve_permissions = true;
            cli.no_permissions = false;
        }
        'E' => cli.executability = true,
        'A' => {
            cli.acls = true;
            cli.preserve_permissions = true;
        }
        'X' => cli.xattrs = true,
        'o' => {
            cli.preserve_owner = true;
            cli.no_owner = false;
        }
        'g' => {
            cli.preserve_group = true;
            cli.no_group = false;
        }
        'D' => {
            cli.devices = true;
            cli.specials = true;
            cli.no_devices = false;
            cli.no_specials = false;
        }
        't' => {
            cli.preserve_times = true;
            cli.no_times = false;
        }
        'U' => cli.atimes = true,
        'N' => cli.crtimes = true,
        'O' => cli.omit_dir_times = true,
        'J' => cli.omit_link_times = true,
        'S' => remember_unsupported(cli, "--sparse"),
        'n' => cli.dry_run = true,
        'W' => cli.whole_file = true,
        'x' => cli.one_file_system = true,
        'B' => cli.block_size = Some(parse_size(value.expect("value checked"))?),
        'e' => cli.remote_shell = Some(value.expect("value checked").to_string()),
        'I' => cli.ignore_times = true,
        '@' => cli.modify_window = parse_i64(value.expect("value checked"), "--modify-window")?,
        'T' => cli.temp_dir = Some(value.expect("value checked").to_string()),
        'y' => remember_unsupported(cli, "--fuzzy"),
        'z' => cli.compress = true,
        'C' => cli.cvs_exclude = true,
        'f' => cli.filters.push(value.expect("value checked").to_string()),
        'F' => apply_filter_shorthand(cli),
        '0' => cli.from0 = true,
        's' => {
            cli.secluded_args = true;
            cli.old_args = false;
        }
        '8' => cli.eight_bit_output = true,
        'h' => cli.human_readable = cli.human_readable.saturating_add(1),
        'P' => {
            cli.partial = true;
            cli.progress = true;
        }
        'i' => cli.itemize_changes = true,
        'M' if cli.daemon_server => cli
            .daemon_params
            .push(value.expect("value checked").to_string()),
        'M' => cli
            .remote_options
            .push(value.expect("value checked").to_string()),
        '4' => {
            cli.ipv4 = true;
            cli.ipv6 = false;
        }
        '6' => {
            cli.ipv6 = true;
            cli.ipv4 = false;
        }
        'V' => cli.version = true,
        other => bail!("unknown option -{other}"),
    }
    Ok(())
}

fn apply_filter_shorthand(cli: &mut Cli) {
    let shorthand_count = cli
        .filters
        .iter()
        .filter(|filter| {
            filter.as_str() == ": .rsync-filter" || filter.as_str() == "- .rsync-filter"
        })
        .count();
    if shorthand_count == 0 {
        cli.filters.push(": .rsync-filter".to_string());
    } else {
        cli.filters.push("- .rsync-filter".to_string());
    }
}

fn apply_long_option(cli: &mut Cli, name: &str, value: Option<&str>) -> Result<()> {
    if name == "help" {
        cli.help = true;
        return Ok(());
    }
    if apply_standalone_no_prefixed_or_compat_alias(cli, name)? {
        return Ok(());
    }
    if let Some(negated) = name.strip_prefix("no-") {
        return apply_negated_option(cli, negated);
    }
    if find_long_spec(name).is_none() {
        bail!("unknown option --{name}");
    }

    match name {
        "verbose" => cli.verbosity = cli.verbosity.saturating_add(1),
        "quiet" => cli.quiet = cli.quiet.saturating_add(1),
        "checksum" => cli.checksum = true,
        "archive" => {
            cli.archive = true;
            cli.no_recursive = false;
            cli.no_times = false;
            cli.no_permissions = false;
            cli.no_owner = false;
            cli.no_group = false;
            cli.no_devices = false;
            cli.no_specials = false;
            cli.no_links = false;
        }
        "recursive" => {
            cli.recursive = true;
            cli.no_recursive = false;
        }
        "relative" => cli.relative = true,
        "backup" => cli.backup = true,
        "backup-dir" => {
            cli.backup = true;
            cli.backup_dir = Some(required_value(name, value)?.to_string());
        }
        "suffix" => cli.suffix = Some(required_value(name, value)?.to_string()),
        "update" => cli.update = true,
        "inplace" => cli.inplace = true,
        "append" => cli.append = true,
        "append-verify" => cli.append_verify = true,
        "dirs" | "old-dirs" | "old-d" => cli.transfer_dirs = true,
        "mkpath" => cli.mkpath = true,
        "links" => {
            cli.links = true;
            cli.no_links = false;
        }
        "copy-links" => {
            cli.copy_links = true;
            cli.no_links = false;
        }
        "copy-dirlinks" => {
            cli.copy_dirlinks = true;
            cli.no_links = false;
        }
        "keep-dirlinks" => cli.keep_dirlinks = true,
        "copy-unsafe-links" => {
            cli.copy_unsafe_links = true;
            cli.no_links = false;
        }
        "safe-links" => {
            cli.safe_links = true;
            cli.no_links = false;
        }
        "munge-links" => {
            cli.munge_links = true;
            cli.no_links = false;
        }
        "hard-links" => cli.hard_links = true,
        "perms" => {
            cli.preserve_permissions = true;
            cli.no_permissions = false;
        }
        "executability" => cli.executability = true,
        "chmod" => cli.chmod = Some(required_value(name, value)?.to_string()),
        "acls" => {
            cli.acls = true;
            cli.preserve_permissions = true;
        }
        "xattrs" => cli.xattrs = true,
        "owner" => {
            cli.preserve_owner = true;
            cli.no_owner = false;
        }
        "group" => {
            cli.preserve_group = true;
            cli.no_group = false;
        }
        "devices" => {
            cli.devices = true;
            cli.no_devices = false;
        }
        "copy-devices" => {
            cli.copy_devices = true;
            cli.no_devices = false;
        }
        "write-devices" => {
            cli.write_devices = true;
            cli.inplace = true;
            cli.no_devices = false;
        }
        "specials" => {
            cli.specials = true;
            cli.no_specials = false;
        }
        "D" => {
            cli.devices = true;
            cli.specials = true;
            cli.no_devices = false;
            cli.no_specials = false;
        }
        "times" => {
            cli.preserve_times = true;
            cli.no_times = false;
        }
        "atimes" => cli.atimes = true,
        "crtimes" => cli.crtimes = true,
        "omit-dir-times" => cli.omit_dir_times = true,
        "omit-link-times" => cli.omit_link_times = true,
        "fake-super" => cli.fake_super = true,
        "dry-run" => cli.dry_run = true,
        "whole-file" => cli.whole_file = true,
        "checksum-choice" | "cc" => {
            cli.checksum_choice = Some(required_value(name, value)?.to_string())
        }
        "checksum-seed" => cli.checksum_seed = Some(parse_i32(required_value(name, value)?, name)?),
        "one-file-system" => cli.one_file_system = true,
        "block-size" => cli.block_size = Some(parse_size(required_value(name, value)?)?),
        "rsh" => cli.remote_shell = Some(required_value(name, value)?.to_string()),
        "rsync-path" => cli.rsync_path = Some(required_value(name, value)?.to_string()),
        "existing" => cli.existing = true,
        "ignore-non-existing" => cli.existing = true,
        "ignore-existing" => cli.ignore_existing = true,
        "del" | "delete" | "delete-during" => {
            cli.delete = true;
            cli.delete_mode = DeleteMode::During;
        }
        "delete-before" => {
            cli.delete = true;
            cli.delete_mode = DeleteMode::Before;
        }
        "delete-delay" => {
            cli.delete = true;
            cli.delete_mode = DeleteMode::Delay;
        }
        "delete-after" => {
            cli.delete = true;
            cli.delete_mode = DeleteMode::After;
        }
        "delete-excluded" => cli.delete_excluded = true,
        "ignore-missing-args" => cli.ignore_missing_args = true,
        "delete-missing-args" => cli.delete_missing_args = true,
        "ignore-errors" => cli.ignore_errors = true,
        "force" => cli.force = true,
        "max-delete" => cli.max_delete = Some(parse_max_delete(required_value(name, value)?)?),
        "max-size" => cli.max_size = Some(parse_size(required_value(name, value)?)?),
        "min-size" => cli.min_size = Some(parse_size(required_value(name, value)?)?),
        "partial" => cli.partial = true,
        "partial-dir" => {
            cli.partial = true;
            cli.partial_dir = Some(required_value(name, value)?.to_string());
        }
        "delay-updates" => cli.delay_updates = true,
        "numeric-ids" => cli.numeric_ids = true,
        "usermap" => cli.user_maps.push(required_value(name, value)?.to_string()),
        "groupmap" => cli
            .group_maps
            .push(required_value(name, value)?.to_string()),
        "chown" => {
            let chown = required_value(name, value)?.to_string();
            apply_chown_implications(cli, &chown);
            cli.chown = Some(chown);
        }
        "ignore-times" => cli.ignore_times = true,
        "size-only" => cli.size_only = true,
        "modify-window" => cli.modify_window = parse_i64(required_value(name, value)?, name)?,
        "temp-dir" => cli.temp_dir = Some(required_value(name, value)?.to_string()),
        "compress" => cli.compress = true,
        "compression-choice" | "compress-choice" | "zc" => {
            cli.compress = true;
            cli.compress_choice = Some(required_value(name, value)?.to_string());
        }
        "compress-level" | "zl" => {
            cli.compress_level = Some(parse_u32(required_value(name, value)?, name)?)
        }
        "compress-threads" | "zt" => {
            cli.compress_threads = Some(parse_usize(required_value(name, value)?, name)?)
        }
        "skip-compress" => cli
            .skip_compress
            .push(required_value(name, value)?.to_string()),
        "cvs-exclude" => cli.cvs_exclude = true,
        "F" => apply_filter_shorthand(cli),
        "filter" => cli.filters.push(required_value(name, value)?.to_string()),
        "exclude" => cli.excludes.push(required_value(name, value)?.to_string()),
        "exclude-from" => cli
            .exclude_from
            .push(PathBuf::from(required_value(name, value)?)),
        "include" => cli.includes.push(required_value(name, value)?.to_string()),
        "include-from" => cli
            .include_from
            .push(PathBuf::from(required_value(name, value)?)),
        "files-from" => cli.files_from = Some(PathBuf::from(required_value(name, value)?)),
        "from0" => cli.from0 = true,
        "old-args" => {
            cli.old_args = true;
            cli.secluded_args = false;
        }
        "secluded-args" => {
            cli.secluded_args = true;
            cli.old_args = false;
        }
        "protect-args" => {
            cli.secluded_args = true;
            cli.old_args = false;
        }
        "trust-sender" => cli.trust_sender = true,
        "blocking-io" => cli.blocking_io = true,
        "human-readable" => cli.human_readable = cli.human_readable.saturating_add(1),
        "progress" => cli.progress = true,
        "P" => {
            cli.partial = true;
            cli.progress = true;
        }
        "itemize-changes" => cli.itemize_changes = true,
        "remote-option" => cli
            .remote_options
            .push(required_value(name, value)?.to_string()),
        "ipv4" => {
            cli.ipv4 = true;
            cli.ipv6 = false;
        }
        "ipv6" => {
            cli.ipv6 = true;
            cli.ipv4 = false;
        }
        "password-file" => cli.password_file = Some(PathBuf::from(required_value(name, value)?)),
        "address" => cli.daemon_address = Some(required_value(name, value)?.to_string()),
        "port" => cli.daemon_port = Some(parse_u16(required_value(name, value)?, name)?),
        "sockopts" => cli.daemon_sockopts = Some(required_value(name, value)?.to_string()),
        "contimeout" => {
            cli.daemon_connect_timeout_secs = Some(parse_u64(required_value(name, value)?, name)?)
        }
        "no-motd" => cli.daemon_no_motd = true,
        "config" => cli.daemon_config = Some(PathBuf::from(required_value(name, value)?)),
        "dparam" => cli
            .daemon_params
            .push(required_value(name, value)?.to_string()),
        "no-detach" => cli.daemon_no_detach = true,
        "log-file" => {
            let path = PathBuf::from(required_value(name, value)?);
            cli.daemon_log_file = Some(path.clone());
            cli.client_log_file = Some(path);
        }
        "log-file-format" => {
            let fmt = required_value(name, value)?.to_string();
            cli.daemon_log_file_format = Some(fmt.clone());
            cli.client_log_file_format = Some(fmt);
        }
        "bwlimit" => cli.daemon_bwlimit = Some(required_value(name, value)?.to_string()),
        "list-only" => cli.list_only = true,
        "stats" => cli.stats = true,
        "fsync" => cli.fsync = true,
        "daemon" => cli.daemon_server = true,
        "server" => {
            cli.internal_server = true;
            remember_unsupported(cli, "--server");
        }
        "sender" => {
            cli.internal_sender = true;
            remember_unsupported(cli, "--sender");
        }
        "version" => cli.version = true,
        "plan" => cli.plan = true,
        "protocol-range" => cli.protocol_range = true,
        "metadata-policy" => {
            cli.metadata_policy = parse_metadata_policy(required_value(name, value)?)?
        }
        "fail-on-metadata-loss" => cli.fail_on_metadata_loss = true,
        "vss" => cli.vss = true,
        "info" => cli
            .info_flags
            .push(required_value(name, value)?.to_string()),
        "debug" => cli
            .debug_flags
            .push(required_value(name, value)?.to_string()),
        "stderr" => {
            let mode = required_value(name, value)?;
            crate::output::parse_stderr_mode(mode)?;
            cli.stderr_mode = Some(mode.to_string());
        }
        "msgs2stderr" => {
            cli.msgs2stderr = true;
            cli.no_msgs2stderr = false;
            cli.stderr_mode = Some("all".to_string());
        }
        "no-msgs2stderr" => {
            cli.no_msgs2stderr = true;
            cli.msgs2stderr = false;
            cli.stderr_mode = Some("client".to_string());
        }
        "out-format" => cli.out_format = Some(required_value(name, value)?.to_string()),
        "8-bit-output" => cli.eight_bit_output = true,
        other => remember_unsupported(cli, &format!("--{other}")),
    }

    Ok(())
}

fn apply_standalone_no_prefixed_or_compat_alias(cli: &mut Cli, name: &str) -> Result<bool> {
    match name {
        "no-implied-dirs" => {
            cli.implied_dirs = false;
            Ok(true)
        }
        "protect-args" => {
            cli.secluded_args = true;
            cli.old_args = false;
            Ok(true)
        }
        "no-motd" => {
            cli.daemon_no_motd = true;
            Ok(true)
        }
        "no-detach" => {
            cli.daemon_no_detach = true;
            Ok(true)
        }
        "msgs2stderr" => {
            cli.msgs2stderr = true;
            cli.no_msgs2stderr = false;
            cli.stderr_mode = Some("all".to_string());
            Ok(true)
        }
        "no-msgs2stderr" => {
            cli.no_msgs2stderr = true;
            cli.msgs2stderr = false;
            cli.stderr_mode = Some("client".to_string());
            Ok(true)
        }
        "inc-recursive" | "i-r" | "no-inc-recursive" | "no-i-r" => {
            if find_long_spec(name).is_none() {
                bail!("unknown option --{name}");
            }
            remember_unsupported(cli, &format!("--{name}"));
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn apply_negated_option(cli: &mut Cli, name: &str) -> Result<()> {
    match name {
        "archive" | "a" => cli.archive = false,
        "acls" | "A" => cli.acls = false,
        "append" => cli.append = false,
        "append-verify" => cli.append_verify = false,
        "backup" | "b" => {
            cli.backup = false;
            cli.backup_dir = None;
        }
        "checksum" | "c" => cli.checksum = false,
        "compress" | "z" => {
            cli.compress = false;
            cli.compress_choice = None;
            cli.compress_level = None;
            cli.compress_threads = None;
            cli.skip_compress.clear();
        }
        "copy-links" | "L" => cli.copy_links = false,
        "copy-dirlinks" | "k" => cli.copy_dirlinks = false,
        "copy-unsafe-links" => cli.copy_unsafe_links = false,
        "keep-dirlinks" | "K" => cli.keep_dirlinks = false,
        "munge-links" => cli.munge_links = false,
        "delay-updates" => cli.delay_updates = false,
        "delete" | "del" => {
            cli.delete = false;
            cli.delete_mode = DeleteMode::None;
        }
        "delete-before" | "delete-during" | "delete-delay" | "delete-after" => {
            cli.delete = false;
            cli.delete_mode = DeleteMode::None;
        }
        "delete-excluded" => cli.delete_excluded = false,
        "delete-missing-args" => cli.delete_missing_args = false,
        "dry-run" | "n" => cli.dry_run = false,
        "existing" | "ignore-non-existing" => cli.existing = false,
        "executability" | "E" => cli.executability = false,
        "fake-super" => cli.fake_super = false,
        "force" => cli.force = false,
        "from0" | "0" => cli.from0 = false,
        "fsync" => cli.fsync = false,
        "hard-links" | "H" => cli.hard_links = false,
        "ignore-errors" => cli.ignore_errors = false,
        "ignore-existing" => cli.ignore_existing = false,
        "ignore-missing-args" => cli.ignore_missing_args = false,
        "ignore-times" | "I" => cli.ignore_times = false,
        "inplace" => cli.inplace = false,
        "itemize-changes" | "i" => cli.itemize_changes = false,
        "list-only" => cli.list_only = false,
        "mkpath" => cli.mkpath = false,
        "numeric-ids" => cli.numeric_ids = false,
        "atimes" | "U" => cli.atimes = false,
        "crtimes" | "N" => cli.crtimes = false,
        "omit-dir-times" | "O" => cli.omit_dir_times = false,
        "omit-link-times" | "J" => cli.omit_link_times = false,
        "partial" => {
            cli.partial = false;
            cli.partial_dir = None;
        }
        "progress" => cli.progress = false,
        "P" => {
            cli.progress = false;
            cli.partial = false;
            cli.partial_dir = None;
        }
        "recursive" | "r" => {
            cli.recursive = false;
            cli.no_recursive = true;
        }
        "relative" | "R" => cli.relative = false,
        "dirs" | "d" | "old-dirs" | "old-d" => cli.transfer_dirs = false,
        "times" | "t" => {
            cli.preserve_times = false;
            cli.no_times = true;
        }
        "whole-file" | "W" => cli.whole_file = false,
        "one-file-system" | "x" => cli.one_file_system = false,
        "D" => {
            cli.devices = false;
            cli.specials = false;
            cli.no_devices = true;
            cli.no_specials = true;
        }
        "links" | "l" => {
            cli.links = false;
            cli.no_links = true;
            cli.copy_links = false;
            cli.copy_dirlinks = false;
            cli.copy_unsafe_links = false;
            cli.munge_links = false;
            cli.safe_links = false;
        }
        "safe-links" => cli.safe_links = false,
        "implied-dirs" => cli.implied_dirs = false,
        "o" | "owner" => {
            cli.preserve_owner = false;
            cli.no_owner = true;
        }
        "g" | "group" => {
            cli.preserve_group = false;
            cli.no_group = true;
        }
        "human-readable" | "h" => cli.human_readable = 0,
        "old-args" => cli.old_args = false,
        "secluded-args" | "s" | "protect-args" => cli.secluded_args = false,
        "blocking-io" => cli.blocking_io = false,
        "trust-sender" => cli.trust_sender = false,
        "ipv4" | "4" => cli.ipv4 = false,
        "ipv6" | "6" => cli.ipv6 = false,
        "super" | "iconv" => remember_unsupported(cli, &format!("--no-{name}")),
        "perms" | "p" => {
            cli.preserve_permissions = false;
            cli.no_permissions = true;
        }
        "devices" => {
            cli.devices = false;
            cli.copy_devices = false;
            cli.write_devices = false;
            cli.no_devices = true;
        }
        "specials" => {
            cli.specials = false;
            cli.no_specials = true;
        }
        "size-only" => cli.size_only = false,
        "stats" => cli.stats = false,
        "update" | "u" => cli.update = false,
        "xattrs" | "X" => cli.xattrs = false,
        known if find_long_spec(known).is_some() => {
            remember_unsupported(cli, &format!("--no-{known}"));
        }
        _ => bail!("unknown option --no-{name}"),
    }
    Ok(())
}

fn required_value<'a>(name: &str, value: Option<&'a str>) -> Result<&'a str> {
    value.ok_or_else(|| anyhow::anyhow!("option --{name} requires a value"))
}

fn apply_chown_implications(cli: &mut Cli, chown: &str) {
    let (user, group) = chown.split_once(':').unwrap_or((chown, ""));
    if !user.is_empty() {
        cli.preserve_owner = true;
        cli.no_owner = false;
    }
    if !group.is_empty() {
        cli.preserve_group = true;
        cli.no_group = false;
    }
}

fn parse_metadata_policy(value: &str) -> Result<CliMetadataPolicy> {
    match value {
        "portable" => Ok(CliMetadataPolicy::Portable),
        "posix" => Ok(CliMetadataPolicy::Posix),
        "ntfs-native" => Ok(CliMetadataPolicy::NtfsNative),
        _ => bail!("invalid --metadata-policy value `{value}`"),
    }
}

fn parse_i64(value: &str, option: &str) -> Result<i64> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects an integer"))
}

fn parse_i32(value: &str, option: &str) -> Result<i32> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a 32-bit integer"))
}

fn parse_u32(value: &str, option: &str) -> Result<u32> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a non-negative integer"))
}

fn parse_u16(value: &str, option: &str) -> Result<u16> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a 16-bit integer"))
}

fn parse_u64(value: &str, option: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a non-negative integer"))
}

fn parse_usize(value: &str, option: &str) -> Result<usize> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a non-negative integer"))
}

fn parse_max_delete(value: &str) -> Result<usize> {
    if value == "-1" {
        return Ok(0);
    }
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --max-delete expects a non-negative integer or -1"))
}

fn parse_size(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("size value cannot be empty");
    }
    let split = trimmed
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split);
    let number: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid size value `{value}`"))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => bail!("invalid size suffix in `{value}`"),
    };
    Ok(number.saturating_mul(multiplier))
}

fn remember_unsupported(cli: &mut Cli, option: &str) {
    cli.accepted_unsupported_options.push(option.to_string());
    match option {
        "--write-devices" => cli.inplace = true,
        "--copy-devices" => {}
        _ => {}
    }
}
