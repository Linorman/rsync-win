use super::*;

pub(crate) fn remote_receiver_filter_args_from_cli(
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

pub(crate) fn add_remote_filter_file_args(
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

pub(crate) fn add_remote_filter_rule_arg(
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

pub(crate) fn filter_rule_can_use_short_arg(rule: &Rule) -> bool {
    rule.is_sender_side() && rule.is_receiver_side() && !rule.is_perishable()
}

pub(crate) fn format_remote_filter_rule(rule: &Rule) -> String {
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

pub(crate) fn update_mode_from_cli(cli: &Cli) -> UpdateMode {
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

pub(crate) fn symlink_mode_from_cli(cli: &Cli) -> SymlinkMode {
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

pub(crate) fn file_write_options_from_plan(plan: &TransferPlan) -> FileWriteOptions {
    FileWriteOptions {
        mode: plan.file_write_mode,
        keep_partial: plan.keep_partial,
        partial_dir: plan.partial_dir.clone(),
        temp_dir: plan.temp_dir.clone(),
        fsync: plan.fsync,
        sparse: plan.sparse,
        preallocate: plan.preallocate,
        bwlimit: plan.bwlimit,
        max_alloc: plan.max_alloc,
        stop_deadline: plan.stop_deadline,
    }
}

pub(crate) fn render_ssh_command(command: &SshRemoteCommand) -> Vec<String> {
    std::iter::once(&command.program)
        .chain(command.args.iter())
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

pub(crate) fn parse_remote_shell_operand(
    operand: &str,
    report: &mut Report,
) -> Option<RemoteShellOperand> {
    match RemoteShellOperand::parse(operand) {
        Ok(remote) => remote,
        Err(err) => {
            report.error("E_REMOTE_OPERAND", err.to_string());
            None
        }
    }
}

pub(crate) fn build_filter_rules(cli: &Cli, report: &mut Report) -> RuleSet {
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

pub(crate) fn add_filter_file_rules(
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
