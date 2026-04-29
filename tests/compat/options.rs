use std::collections::BTreeSet;
use std::fs;

use rsync_cli::options::{daemon_option_specs, project_option_specs, upstream_client_option_specs};
use rsync_cli::{parse_and_render, parse_and_render_result};

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
        "--protect-args",
        "--compression-choice=zlib",
        "--time-limit=1",
        "--secluded-args",
        "--no-s",
        "--old-args",
        "--no-old-args",
        "--blocking-io",
        "--no-blocking-io",
        "--ignore-non-existing",
        "src",
        "dst",
    ])
    .unwrap();

    assert!(output.contains("existing only: true"));
    for option in [
        "--no-motd",
        "--msgs2stderr",
        "--no-msgs2stderr",
        "--inc-recursive",
        "--i-r",
        "--no-inc-recursive",
        "--no-i-r",
        "--protect-args",
        "--compression-choice",
        "--time-limit",
        "--secluded-args",
        "--no-s",
        "--old-args",
        "--no-old-args",
        "--blocking-io",
        "--no-blocking-io",
    ] {
        assert!(
            output.contains(option),
            "missing compatibility diagnostic for {option}: {output}"
        );
    }

    let daemon_output =
        parse_and_render_result(["rsync-win", "--plan", "--daemon", "--no-detach"]).unwrap();
    assert!(daemon_output.contains("--no-detach"));
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
