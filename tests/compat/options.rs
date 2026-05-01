use std::collections::BTreeSet;
use std::fs;

use rsync_cli::options::{
    daemon_option_specs, parse_options, project_option_specs, upstream_client_option_specs,
    OptionSupport,
};
use rsync_cli::{parse_and_execute, parse_and_render, parse_and_render_result};

#[test]
fn upstream_client_registry_contains_upstream_rsync_long_options() {
    let actual: BTreeSet<_> = upstream_client_option_specs()
        .iter()
        .map(|spec| spec.long)
        .collect();
    let expected = [
        "verbose",
        "info",
        "debug",
        "stderr",
        "msgs2stderr",
        "no-msgs2stderr",
        "quiet",
        "no-motd",
        "checksum",
        "archive",
        "recursive",
        "inc-recursive",
        "i-r",
        "no-inc-recursive",
        "no-i-r",
        "relative",
        "no-implied-dirs",
        "backup",
        "backup-dir",
        "suffix",
        "update",
        "inplace",
        "append",
        "append-verify",
        "dirs",
        "old-dirs",
        "old-d",
        "mkpath",
        "links",
        "copy-links",
        "copy-unsafe-links",
        "safe-links",
        "munge-links",
        "copy-dirlinks",
        "keep-dirlinks",
        "hard-links",
        "perms",
        "executability",
        "chmod",
        "acls",
        "xattrs",
        "owner",
        "group",
        "devices",
        "copy-devices",
        "write-devices",
        "specials",
        "times",
        "atimes",
        "open-noatime",
        "crtimes",
        "omit-dir-times",
        "omit-link-times",
        "super",
        "fake-super",
        "sparse",
        "preallocate",
        "dry-run",
        "whole-file",
        "checksum-choice",
        "cc",
        "one-file-system",
        "block-size",
        "rsh",
        "rsync-path",
        "existing",
        "ignore-non-existing",
        "ignore-existing",
        "remove-source-files",
        "del",
        "delete",
        "delete-before",
        "delete-during",
        "delete-delay",
        "delete-after",
        "delete-excluded",
        "ignore-missing-args",
        "delete-missing-args",
        "ignore-errors",
        "force",
        "max-delete",
        "max-size",
        "min-size",
        "max-alloc",
        "partial",
        "partial-dir",
        "delay-updates",
        "prune-empty-dirs",
        "numeric-ids",
        "usermap",
        "groupmap",
        "chown",
        "timeout",
        "contimeout",
        "ignore-times",
        "size-only",
        "modify-window",
        "temp-dir",
        "fuzzy",
        "compare-dest",
        "copy-dest",
        "link-dest",
        "compress",
        "compression-choice",
        "compress-choice",
        "zc",
        "compress-level",
        "zl",
        "compress-threads",
        "zt",
        "skip-compress",
        "cvs-exclude",
        "filter",
        "exclude",
        "exclude-from",
        "include",
        "include-from",
        "files-from",
        "from0",
        "old-args",
        "secluded-args",
        "protect-args",
        "trust-sender",
        "copy-as",
        "address",
        "port",
        "sockopts",
        "blocking-io",
        "outbuf",
        "stats",
        "8-bit-output",
        "human-readable",
        "progress",
        "itemize-changes",
        "remote-option",
        "out-format",
        "log-file",
        "log-file-format",
        "password-file",
        "early-input",
        "list-only",
        "bwlimit",
        "stop-after",
        "time-limit",
        "stop-at",
        "fsync",
        "write-batch",
        "only-write-batch",
        "read-batch",
        "protocol",
        "iconv",
        "checksum-seed",
        "ipv4",
        "ipv6",
        "version",
        "help",
    ];

    for option in expected {
        assert!(actual.contains(option), "missing --{option}");
    }
}

#[test]
fn upstream_registry_contains_expected_short_options() {
    let actual: BTreeSet<_> = upstream_client_option_specs()
        .iter()
        .filter_map(|spec| spec.short)
        .collect();
    let expected = [
        'v', 'q', 'c', 'a', 'r', 'R', 'b', 'u', 'd', 'l', 'L', 'k', 'K', 'H', 'p', 'E', 'A', 'X',
        'o', 'g', 'D', 't', 'U', 'N', 'O', 'J', 'S', 'n', 'W', 'x', 'B', 'e', 'I', '@', 'T', 'y',
        'z', 'C', 'f', 'F', '0', 's', '8', 'h', 'P', 'i', 'M', '4', '6', 'V',
    ];

    for option in expected {
        assert!(actual.contains(&option), "missing -{option}");
    }
}

#[test]
fn daemon_and_project_options_are_classified_separately() {
    let daemon: BTreeSet<_> = daemon_option_specs().iter().map(|spec| spec.long).collect();
    let project: BTreeSet<_> = project_option_specs()
        .iter()
        .map(|spec| spec.long)
        .collect();

    for option in [
        "daemon",
        "config",
        "dparam",
        "no-detach",
        "log-file-format",
        "sockopts",
    ] {
        assert!(daemon.contains(option), "missing daemon --{option}");
    }

    for option in [
        "plan",
        "metadata-policy",
        "fail-on-metadata-loss",
        "protocol-range",
        "vss",
    ] {
        assert!(project.contains(option), "missing project --{option}");
        assert!(
            !daemon.contains(option),
            "project option --{option} leaked into daemon registry"
        );
    }
}

#[test]
fn chunk10_daemon_options_are_marked_implemented() {
    let daemon = daemon_option_specs()
        .iter()
        .map(|spec| (spec.long, spec.support))
        .collect::<std::collections::BTreeMap<_, _>>();

    for option in [
        "daemon",
        "config",
        "dparam",
        "no-detach",
        "log-file",
        "log-file-format",
        "address",
        "port",
        "sockopts",
        "ipv4",
        "ipv6",
        "bwlimit",
    ] {
        assert_eq!(
            daemon.get(option).copied(),
            Some(OptionSupport::Partial),
            "daemon --{option} should be implemented for chunk10"
        );
    }
}

#[test]
fn chunk11_output_options_are_marked_implemented() {
    let client = upstream_client_option_specs()
        .iter()
        .map(|spec| (spec.long, spec.support))
        .collect::<std::collections::BTreeMap<_, _>>();

    for option in [
        "verbose",
        "quiet",
        "info",
        "debug",
        "stderr",
        "msgs2stderr",
        "no-msgs2stderr",
        "human-readable",
        "8-bit-output",
        "progress",
        "out-format",
        "stats",
        "itemize-changes",
        "log-file",
        "log-file-format",
    ] {
        assert_eq!(
            client.get(option).copied(),
            Some(OptionSupport::Full),
            "client --{option} should be implemented for chunk11"
        );
    }
}

#[test]
fn option_status_model_does_not_overstate_execution_support() {
    let client = upstream_client_option_specs()
        .iter()
        .map(|spec| (spec.long, spec.support))
        .collect::<std::collections::BTreeMap<_, _>>();

    for (option, support) in [
        ("iconv", OptionSupport::DiagnosticOnly),
        ("compress-threads", OptionSupport::ParsedOnly),
        ("copy-as", OptionSupport::DiagnosticOnly),
        ("early-input", OptionSupport::Partial),
    ] {
        assert_eq!(client.get(option).copied(), Some(support));
        assert_ne!(support, OptionSupport::Full);
    }
}

#[test]
fn option_status_doc_separates_execution_support_levels() {
    let doc_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/OPTION-STATUS.md");
    let doc = fs::read_to_string(doc_path).unwrap();

    for heading in [
        "Fully implemented",
        "Partially implemented by mode",
        "Diagnostic/reporting only",
        "Parsed for compatibility only",
        "Planned",
    ] {
        assert!(doc.contains(heading), "missing status heading {heading}");
    }

    let full_line = doc
        .lines()
        .find(|line| line.starts_with("| Fully implemented |"))
        .unwrap_or("");
    for option in [
        "`--iconv`",
        "`--compress-threads`",
        "`--copy-as`",
        "`--early-input`",
    ] {
        assert!(
            !full_line.contains(option),
            "{option} must not be advertised as fully implemented"
        );
    }
}

#[test]
fn parser_accepts_rsync_short_clusters_and_plans_implications() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-avz",
        "-rtgoD",
        "-aAXH",
        "src",
        "dst",
    ]);

    assert!(output.contains("recursive: true"));
    assert!(output.contains("preserve times: true"));
    assert!(output.contains("compress: true"));
    assert!(output.contains("posix metadata: perms,owner,group,acls,xattrs,hard-links"));
    assert!(output.contains("special files: true"));
    assert!(output.contains("devices: true"));
}

#[test]
fn parser_accepts_attached_values_for_short_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-essh -p 2222",
        "-M--fake-super",
        "-B8192",
        "src",
        "host:/dest",
    ]);

    assert!(output.contains("-e/--rsh remote shell command: ssh -p 2222"));
    assert!(output.contains("remote options: --fake-super"));
    assert!(output.contains("block size: 8192"));
}

#[test]
fn parser_routes_chunk8_checksum_and_compression_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--checksum-choice=md5,md4",
        "--cc=md4",
        "--checksum-seed=12345",
        "--compress",
        "--compress-choice=zlib",
        "--compress-level=6",
        "--compress-threads=2",
        "--skip-compress=jpg,zip",
        "src",
        "host:/dst",
    ]);

    assert!(output.contains("checksum choice: md4"), "{output}");
    assert!(output.contains("checksum seed: 12345"), "{output}");
    assert!(output.contains("compress: true"), "{output}");
    assert!(output.contains("compress choice: zlib"), "{output}");
    assert!(output.contains("compress level: 6"), "{output}");
    assert!(output.contains("compress threads: 2"), "{output}");
    assert!(output.contains("skip compress: jpg,zip"), "{output}");
    assert!(output.contains("--checksum-choice=md4"), "{output}");
    assert!(output.contains("--checksum-seed=12345"), "{output}");
    assert!(output.contains("--compress"), "{output}");
    assert!(output.contains("--compress-choice=zlib"), "{output}");
    assert!(!output.contains("W_COMPRESS_UNSUPPORTED"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn parser_accepts_long_equals_space_and_negated_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--archive",
        "--no-D",
        "--no-links",
        "--relative",
        "--no-implied-dirs",
        "--max-size=4K",
        "--min-size",
        "2",
        "--modify-window=2",
        "--no-o",
        "--no-g",
        "src",
        "dst",
    ]);

    assert!(output.contains("relative: true"));
    assert!(output.contains("implied dirs: false"));
    assert!(output.contains("symlink mode: skip"));
    assert!(output.contains("devices: false"));
    assert!(output.contains("special files: false"));
    assert!(output.contains("max size: 4096"));
    assert!(output.contains("min size: 2"));
    assert!(output.contains("modify window: 2"));
    assert!(output.contains("posix metadata: perms"));
}

#[test]
fn parser_accepts_no_prefixed_standalone_options_and_compat_aliases() {
    let output = parse_and_render_result([
        "rsync-win",
        "--plan",
        "--no-motd",
        "--msgs2stderr",
        "--no-msgs2stderr",
        "--inc-recursive",
        "--i-r",
        "--no-inc-recursive",
        "--no-i-r",
        "--compression-choice=zlib",
        "--time-limit=1",
        "--ignore-non-existing",
        "src",
        "dst",
    ])
    .unwrap();

    assert!(output.contains("existing only: true"));
    assert!(output.contains("compress choice: zlib"));

    // --msgs2stderr / --no-msgs2stderr are now fully implemented with last option wins.
    assert!(
        output.lines().any(|line| line == "msgs2stderr: false"),
        "msgs2stderr flag not set: {output}"
    );
    assert!(
        output.lines().any(|line| line == "no msgs2stderr: true"),
        "no-msgs2stderr flag not set: {output}"
    );
    assert!(
        output.lines().any(|line| line == "stderr: client"),
        "{output}"
    );

    for option in [
        "--no-motd",
        "--inc-recursive",
        "--i-r",
        "--no-inc-recursive",
        "--no-i-r",
    ] {
        assert!(
            output.contains(option),
            "missing compatibility diagnostic for {option}: {output}"
        );
    }
    // --time-limit is now implemented
    assert!(output.contains("time limit: 1 minutes"));

    let daemon_output =
        parse_and_render_result(["rsync-win", "--plan", "--daemon", "--no-detach"]).unwrap();
    assert!(daemon_output.contains("daemon no detach: true"));
}

#[test]
fn parser_rejects_invalid_stderr_mode() {
    let err = parse_and_render_result([
        "rsync-win",
        "--plan",
        "--stderr=definitely-not-a-mode",
        "src",
        "dst",
    ])
    .unwrap_err();

    assert!(err.to_string().contains("invalid --stderr mode"), "{err:#}");
}

#[test]
fn negated_short_aliases_disable_prior_flags() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--dirs",
        "--no-d",
        "--one-file-system",
        "--no-x",
        "src",
        "dst",
    ]);

    assert!(output.contains("dirs: false"));
    assert!(output.contains("one file system: false"));
}

#[test]
fn repeated_human_readable_and_help_match_rsync_h_behavior() {
    let help = parse_and_render(["rsync-win", "-h"]);
    assert!(help.contains("rsync-win"));
    assert!(help.contains("--archive"));

    let output = parse_and_render(["rsync-win", "--plan", "-hh", "src", "dst"]);
    assert!(output.contains("human readable: 2"));

    let mixed_help = parse_and_render(["rsync-win", "--help", "-h"]);
    assert!(mixed_help.contains("Usage: rsync-win"));
    assert!(mixed_help.contains("--archive"));
}

#[test]
fn parser_accepts_repeated_verbosity_and_version_flags() {
    let output = parse_and_render(["rsync-win", "--plan", "-vv", "--verbose", "src", "dst"]);
    assert!(output.contains("verbosity: 3"));

    let long_version = parse_and_render(["rsync-win", "--version", "--version"]);
    assert!(long_version.contains("rsync-win "));
    assert!(long_version.contains("protocol primitives range:"));

    let short_version = parse_and_render(["rsync-win", "-VV"]);
    assert!(short_version.contains("rsync-win "));
    assert!(short_version.contains("protocol primitives range:"));
}

#[test]
fn parser_exposes_structured_parsed_options() {
    let parsed = parse_options([
        "rsync-win",
        "--plan",
        "-vv",
        "--remote-option=--fake-super",
        "src",
        "host:/dst",
    ])
    .unwrap();

    assert!(parsed.is_plan());
    assert_eq!(parsed.verbosity(), 2);
    assert_eq!(parsed.operands(), ["src", "host:/dst"]);
    assert_eq!(parsed.remote_options(), ["--fake-super"]);
}

#[test]
fn parser_routes_chunk9_remote_shell_transport_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--rsync-path",
        "sudo rsync",
        "--remote-option=--fake-super",
        "--blocking-io",
        "--secluded-args",
        "--trust-sender",
        "--ipv4",
        "src dir",
        "host:/dst path;name",
    ]);

    assert!(output.contains("remote rsync path: sudo rsync"), "{output}");
    assert!(
        output.contains("remote shell blocking io: true"),
        "{output}"
    );
    assert!(output.contains("secluded args: true"), "{output}");
    assert!(output.contains("trust sender: true"), "{output}");
    assert!(output.contains("address family: ipv4"), "{output}");
    assert!(output.contains("remote options: --fake-super"), "{output}");
    assert!(
        output.contains("remote --server argv: sudo rsync --server -s"),
        "{output}"
    );
    assert!(
        output.contains("remote protected args: rsync")
            && output.contains("--fake-super")
            && output.contains("/dst path;name"),
        "{output}"
    );
    assert!(
        output.contains("remote ssh argv: ssh -o BatchMode=yes -o ConnectTimeout=10 -4 host"),
        "{output}"
    );
    assert!(
        output.contains("sudo rsync --server -s") && !output.contains("'/dst path;name'"),
        "{output}"
    );
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn parser_accepts_help_without_explicit_program_name() {
    for args in [["--help"], ["-h"]] {
        let help = parse_and_render(args);

        assert!(help.contains("Usage: rsync-win"), "{help}");
        assert!(help.contains("--archive"), "{help}");
    }
}

#[test]
fn executor_renders_help_without_falling_back_to_empty_plan() {
    let help = parse_and_execute(["rsync-win", "--help"]).unwrap();

    assert!(help.contains("Usage: rsync-win"), "{help}");
    assert!(!help.contains("operands: 0"), "{help}");
}

#[test]
fn shortcut_implications_and_conflicts_are_reported_in_plan() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-P",
        "-E",
        "-F",
        "-F",
        "--delete",
        "--del",
        "--delete-after",
        "--inplace",
        "--delay-updates",
        "src",
        "dst",
    ]);

    assert!(output.contains("partial: true"));
    assert!(output.contains("progress: true"));
    assert!(output.contains("posix metadata: executability"));
    assert!(output.contains("filter rules: 2"));
    assert!(output.contains("delete mode: after"));
    assert!(output.contains("[error] E_OPTION_CONFLICT"));
}

#[test]
fn parser_accepts_backward_compatible_max_delete_minus_one() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--delete",
        "--ignore-errors",
        "--force",
        "--max-delete=-1",
        "src",
        "dst",
    ]);

    assert!(output.contains("delete mode: during"));
    assert!(output.contains("ignore errors: true"));
    assert!(output.contains("force delete: true"));
    assert!(output.contains("max delete: 0"));
}

#[test]
fn unknown_options_fail_unless_sent_as_remote_option() {
    let err =
        parse_and_render_result(["rsync-win", "--not-an-rsync-option", "src", "dst"]).unwrap_err();
    assert!(err
        .to_string()
        .contains("unknown option --not-an-rsync-option"));

    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--remote-option=--not-local",
        "src",
        "host:/dst",
    ]);
    assert!(output.contains("remote options: --not-local"));
}

#[test]
fn fsync_is_disabled_by_default_and_enabled_explicitly() {
    let default_output = parse_and_render(["rsync-win", "--plan", "src", "dst"]);
    assert!(default_output.contains("fsync: false"));

    let explicit_output = parse_and_render(["rsync-win", "--plan", "--fsync", "src", "dst"]);
    assert!(explicit_output.contains("fsync: true"));
}

#[test]
fn negated_options_disable_prior_flags_and_archive_implications() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-azrtD",
        "--perms",
        "--owner",
        "--group",
        "--relative",
        "--no-compress",
        "--no-times",
        "--no-recursive",
        "--no-relative",
        "--no-perms",
        "--no-owner",
        "--no-group",
        "--no-devices",
        "--no-specials",
        "src",
        "dst",
    ]);

    assert!(output.contains("recursive: false"));
    assert!(output.contains("relative: false"));
    assert!(output.contains("preserve times: false"));
    assert!(output.contains("compress: false"));
    assert!(output.contains("devices: false"));
    assert!(output.contains("special files: false"));
    assert!(output.contains("posix metadata: none"));
}

#[test]
fn dirs_mode_does_not_override_recursive_flags() {
    let recursive_then_dirs = parse_and_render(["rsync-win", "--plan", "-rd", "src", "dst"]);
    assert!(recursive_then_dirs.contains("recursive: true"));
    assert!(recursive_then_dirs.contains("dirs: true"));

    let archive_with_dirs =
        parse_and_render(["rsync-win", "--plan", "--archive", "--dirs", "src", "dst"]);
    assert!(archive_with_dirs.contains("recursive: true"));
    assert!(archive_with_dirs.contains("dirs: true"));

    let dirs_only = parse_and_render(["rsync-win", "--plan", "--dirs", "src", "dst"]);
    assert!(dirs_only.contains("recursive: false"));
    assert!(dirs_only.contains("dirs: true"));
}

#[test]
fn negated_implemented_options_really_clear_prior_state() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--backup-dir=old",
        "--suffix=.bak",
        "--update",
        "--existing",
        "--ignore-existing",
        "--max-size=1K",
        "--min-size=1",
        "--ignore-missing-args",
        "--delete-missing-args",
        "--delete-after",
        "--delete-excluded",
        "--ignore-errors",
        "--force",
        "--partial-dir=.rsync-partial",
        "--delay-updates",
        "--fsync",
        "--copy-links",
        "--hard-links",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--omit-link-times",
        "--numeric-ids",
        "--progress",
        "--itemize-changes",
        "--stats",
        "--from0",
        "--no-backup",
        "--no-update",
        "--no-existing",
        "--no-ignore-existing",
        "--no-ignore-missing-args",
        "--no-delete-missing-args",
        "--no-delete-after",
        "--no-delete-excluded",
        "--no-ignore-errors",
        "--no-force",
        "--no-partial",
        "--no-delay-updates",
        "--no-fsync",
        "--no-copy-links",
        "--no-hard-links",
        "--no-acls",
        "--no-xattrs",
        "--no-fake-super",
        "--no-omit-link-times",
        "--no-numeric-ids",
        "--no-progress",
        "--no-itemize-changes",
        "--no-stats",
        "--no-from0",
        "src",
        "dst",
    ]);

    for expected in [
        "delete: false",
        "delete mode: none",
        "delete excluded: false",
        "ignore errors: false",
        "force delete: false",
        "delay updates: false",
        "fsync: false",
        "symlink mode: skip",
        "hard links: false",
        "backup: false",
        "progress: false",
        "itemize changes: false",
        "stats: false",
        "update newer only: false",
        "existing only: false",
        "ignore existing: false",
    ] {
        assert!(
            output.contains(expected),
            "missing `{expected}` in output:\n{output}"
        );
    }
    assert!(!output.contains("partial: true"));
    assert!(!output.contains("partial-dir: .rsync-partial"));
    assert!(!output.contains("backup-dir: old"));
    assert!(!output.contains("posix metadata: acls"));
    assert!(!output.contains("posix metadata: xattrs"));
}

#[test]
fn link_mode_defaults_and_last_option_wins_are_rsync_like() {
    let default_output = parse_and_render(["rsync-win", "--plan", "src", "dst"]);
    assert!(default_output.contains("symlink mode: skip"));

    let links_output = parse_and_render(["rsync-win", "--plan", "--links", "src", "dst"]);
    assert!(links_output.contains("symlink mode: preserve"));

    let archive_output = parse_and_render(["rsync-win", "--plan", "--archive", "src", "dst"]);
    assert!(archive_output.contains("symlink mode: preserve"));

    let disabled_output = parse_and_render([
        "rsync-win",
        "--plan",
        "--archive",
        "--no-links",
        "src",
        "dst",
    ]);
    assert!(disabled_output.contains("symlink mode: skip"));

    let reenabled_output = parse_and_render([
        "rsync-win",
        "--plan",
        "--no-links",
        "--copy-links",
        "src",
        "dst",
    ]);
    assert!(reenabled_output.contains("symlink mode: copy-links"));
}

#[test]
fn parser_loads_include_and_exclude_from_files_with_from0() {
    let root =
        std::env::temp_dir().join(format!("rsync-win-filter-options-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let include = root.join("include.rules");
    let exclude = root.join("exclude.rules");
    fs::write(&include, b"keep/**\0").unwrap();
    fs::write(&exclude, b"*.tmp\0").unwrap();

    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--from0",
        "--include-from",
        include.to_str().unwrap(),
        "--exclude-from",
        exclude.to_str().unwrap(),
        "src",
        "dst",
    ]);

    assert!(output.contains("filter rules: 2"), "{output}");
    assert!(!output.contains("[error] E_FILTER"), "{output}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_plan_expands_filter_files_into_server_argv() {
    let root = std::env::temp_dir().join(format!(
        "rsync-win-remote-filter-options-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let exclude = root.join("exclude.rules");
    fs::write(&exclude, b"*.tmp\n").unwrap();

    let push = parse_and_render([
        "rsync-win",
        "--plan",
        "--exclude-from",
        exclude.to_str().unwrap(),
        "src",
        "host:/dst",
    ]);
    let push_server_line = push
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();
    assert!(push_server_line.contains("--exclude=*.tmp"), "{push}");

    let pull = parse_and_render([
        "rsync-win",
        "--plan",
        "--exclude-from",
        exclude.to_str().unwrap(),
        "host:/src",
        "dst",
    ]);
    let pull_server_line = pull
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();
    assert!(pull_server_line.contains("--exclude=*.tmp"), "{pull}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parser_routes_full_link_and_device_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-kK",
        "--munge-links",
        "--copy-devices",
        "--write-devices",
        "--specials",
        "src",
        "dst",
    ]);

    assert!(output.contains("symlink mode: copy-dirlinks"), "{output}");
    assert!(output.contains("keep dirlinks: true"), "{output}");
    assert!(output.contains("file write mode: inplace"), "{output}");
    assert!(output.contains("devices: true"), "{output}");
    assert!(output.contains("special files: true"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn parser_routes_chunk7_posix_metadata_options_to_remote_receiver() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-rtO",
        "--owner",
        "--group",
        "--numeric-ids",
        "--usermap=0:root,*:nobody",
        "--groupmap=0:root,*:nogroup",
        "--chown=deploy:staff",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--atimes",
        "--crtimes",
        "--chmod=u=rwX,go=rX",
        "src",
        "host:/dst",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(output.contains("posix metadata: perms,owner,group,acls,xattrs,fake-super,omit-dir-times,atimes,crtimes,numeric-ids,chmod,usermap,groupmap,chown"), "{output}");
    for expected in [
        "--owner",
        "--group",
        "--numeric-ids",
        "--usermap=0:root,*:nobody",
        "--groupmap=0:root,*:nogroup",
        "--chown=deploy:staff",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--omit-dir-times",
        "--atimes",
        "--crtimes",
        "--chmod=u=rwX,go=rX",
    ] {
        assert!(
            server_line.contains(expected),
            "missing {expected} in {server_line}"
        );
    }
    assert!(
        !output.contains("--omit-dir-times is accepted for future compatibility"),
        "{output}"
    );
}

#[test]
fn transfer_plan_reports_mode_gating_for_all_modes() {
    let local = parse_and_render(["rsync-win", "--plan", "src", "dst"]);
    assert!(local.contains("transfer mode: local"), "{local}");
    assert!(!local.contains("E_MODE"), "{local}");

    let remote_shell = parse_and_render(["rsync-win", "--plan", "src", "host:/dst"]);
    assert!(
        remote_shell.contains("transfer mode: remote-shell"),
        "{remote_shell}"
    );
    assert!(
        remote_shell.contains("remote direction: upload (local -> remote)"),
        "{remote_shell}"
    );

    let daemon_client = parse_and_render(["rsync-win", "--plan", "host::module", "dst"]);
    assert!(
        daemon_client.contains("transfer mode: daemon-client"),
        "{daemon_client}"
    );
    assert!(
        daemon_client.contains("daemon mode: client"),
        "{daemon_client}"
    );

    let daemon_server =
        parse_and_render(["rsync-win", "--plan", "--daemon", "--config=rsyncd.conf"]);
    assert!(
        daemon_server.contains("transfer mode: daemon-server"),
        "{daemon_server}"
    );
    assert!(
        daemon_server.contains("daemon mode: server"),
        "{daemon_server}"
    );
    assert!(
        !daemon_server.contains("E_UNSUPPORTED_MODE"),
        "{daemon_server}"
    );

    let internal_server =
        parse_and_render(["rsync-win", "--plan", "--server", "--sender", ".", "src"]);
    assert!(
        internal_server.contains("transfer mode: internal-server"),
        "{internal_server}"
    );
    assert!(
        internal_server.contains("internal server mode: remote peer"),
        "{internal_server}"
    );
    assert!(
        internal_server.contains("E_UNSUPPORTED_MODE"),
        "{internal_server}"
    );
}

#[test]
fn conflict_engine_reports_update_delete_temp_metadata_and_link_conflicts() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--min-size=10",
        "--max-size=1",
        "--ignore-missing-args",
        "--delete-missing-args",
        "--inplace",
        "--delay-updates",
        "--partial-dir=.rsync-partial",
        "--temp-dir=.rsync-tmp",
        "--fake-super",
        "--metadata-policy=ntfs-native",
        "--copy-links",
        "--safe-links",
        "src",
        "dst",
    ]);

    for expected in [
        "--min-size cannot be greater than --max-size",
        "--ignore-missing-args cannot be combined with --delete-missing-args",
        "--inplace cannot be combined with --delay-updates",
        "--inplace and --partial-dir cannot both control the same write path",
        "--inplace and --temp-dir cannot both control the same write path",
        "--fake-super cannot be combined with --metadata-policy=ntfs-native",
        "multiple symlink transfer modes were requested",
    ] {
        assert!(
            output.contains(expected),
            "missing `{expected}` in output:\n{output}"
        );
    }
}

// Chunk 13: Resource Limits and Operational Controls

#[test]
fn chunk13_bwlimit_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--bwlimit=128", "src", "dst"]);
    assert!(output.contains("bwlimit: 128.0 KB/s"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_bwlimit_parses_megabytes() {
    let output = parse_and_render(["rsync-win", "--plan", "--bwlimit=2M", "src", "dst"]);
    assert!(output.contains("bwlimit: 2.0 MB/s"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_timeout_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--timeout=30", "src", "dst"]);
    assert!(output.contains("timeout: 30s"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_stop_after_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--stop-after=5", "src", "dst"]);
    assert!(output.contains("stop after: 5 minutes"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_stop_at_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--stop-at=23:59", "src", "dst"]);
    assert!(output.contains("stop at: 23:59"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_max_alloc_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--max-alloc=256M", "src", "dst"]);
    assert!(output.contains("max alloc: 256 MB"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_time_limit_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--time-limit=60", "src", "dst"]);
    assert!(output.contains("time limit: 60 minutes"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_protocol_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--protocol=31", "src", "dst"]);
    assert!(output.contains("protocol: 31"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_protocol_27_gates_remote_shell_plan() {
    let output = parse_and_render(["rsync-win", "--plan", "--protocol=27", "src", "host:/dest"]);

    assert!(output.contains("protocol: 27"), "{output}");
    assert!(
        output.contains("wire protocol: experimental protocol 27 compatibility mode (27)"),
        "{output}"
    );
    assert!(!output.contains("--no-inc-recursive"), "{output}");
}

#[test]
fn chunk13_protocol_rejects_unsupported_execution_version() {
    let err =
        parse_and_render_result(["rsync-win", "--plan", "--protocol=30", "src", "host:/dest"])
            .unwrap_err();

    assert!(err.to_string().contains("--protocol"), "{err}");
    assert!(err.to_string().contains("27 and 31"), "{err}");
}

#[test]
fn chunk13_iconv_emits_diagnostic() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--iconv=UTF-8,ISO-8859-1",
        "src",
        "dst",
    ]);
    assert!(output.contains("iconv: UTF-8,ISO-8859-1"), "{output}");
    assert!(output.contains("charset conversion"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_open_noatime_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--open-noatime", "src", "dst"]);
    assert!(output.contains("open noatime: true"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_outbuf_is_parsed_and_rendered() {
    let output = parse_and_render(["rsync-win", "--plan", "--outbuf=L", "src", "dst"]);
    assert!(output.contains("outbuf: L"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_outbuf_routes_to_remote_server_argv() {
    let output = parse_and_render(["rsync-win", "--plan", "--outbuf=L", "src", "host:/dest"]);

    assert!(output.contains("remote --server argv:"), "{output}");
    assert!(output.contains("--outbuf=L"), "{output}");
}

#[test]
fn chunk13_early_input_is_parsed_and_rendered() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--early-input=preseed.dat",
        "src",
        "dst",
    ]);
    assert!(output.contains("early input: preseed.dat"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_all_limits_combined_no_warnings() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--bwlimit=1M",
        "--timeout=60",
        "--stop-after=10",
        "--time-limit=30",
        "--max-alloc=512M",
        "--protocol=31",
        "--outbuf=L",
        "--early-input=seed.bin",
        "src",
        "dst",
    ]);
    assert!(output.contains("bwlimit: 1.0 MB/s"), "{output}");
    assert!(output.contains("timeout: 60s"), "{output}");
    assert!(output.contains("stop after: 10 minutes"), "{output}");
    assert!(output.contains("time limit: 30 minutes"), "{output}");
    assert!(output.contains("max alloc: 512 MB"), "{output}");
    assert!(output.contains("protocol: 31"), "{output}");
    assert!(output.contains("outbuf: L"), "{output}");
    assert!(output.contains("early input: seed.bin"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_clustered_short_limits() {
    let output = parse_and_render(["rsync-win", "--plan", "-4", "--ipv6", "src", "dst"]);
    assert!(output.contains("address family: ipv6"), "{output}");
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
}

#[test]
fn chunk13_resource_limit_values_are_validated() {
    for args in [
        vec!["rsync-win", "--plan", "--bwlimit=-1", "src", "dst"],
        vec!["rsync-win", "--plan", "--bwlimit=not-a-rate", "src", "dst"],
        vec!["rsync-win", "--plan", "--max-alloc=-1", "src", "dst"],
        vec!["rsync-win", "--plan", "--max-alloc=bad-size", "src", "dst"],
        vec!["rsync-win", "--plan", "--outbuf=X", "src", "dst"],
        vec!["rsync-win", "--plan", "--stop-at=25:61", "src", "dst"],
    ] {
        assert!(
            parse_and_render_result(args.clone()).is_err(),
            "{args:?} should be rejected"
        );
    }
}

#[test]
fn chunk13_registry_status_is_implemented() {
    let specs = rsync_cli::options::upstream_client_option_specs();
    let chunk13_options = [
        ("bwlimit", OptionSupport::Partial),
        ("timeout", OptionSupport::Partial),
        ("stop-after", OptionSupport::Partial),
        ("time-limit", OptionSupport::Partial),
        ("stop-at", OptionSupport::Partial),
        ("max-alloc", OptionSupport::Partial),
        ("protocol", OptionSupport::Partial),
        ("iconv", OptionSupport::DiagnosticOnly),
        ("open-noatime", OptionSupport::DiagnosticOnly),
        ("outbuf", OptionSupport::Partial),
        ("early-input", OptionSupport::Partial),
    ];
    for (option, support) in chunk13_options {
        let spec = specs
            .iter()
            .find(|s| s.long == option)
            .expect(&format!("missing --{option}"));
        assert_eq!(
            spec.support, support,
            "--{option} should have conservative execution support"
        );
    }
}
