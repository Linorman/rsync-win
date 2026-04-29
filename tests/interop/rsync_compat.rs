#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use common::{discover_tools, skip_external_test, FixtureTempDir};
use rsync_cli::parse_and_render_result;

const SSH_TARGET_ENV: &str = "RSYNC_WIN_SSH_TARGET";
const SSH_TMP_ROOT_ENV: &str = "RSYNC_WIN_SSH_TMP_ROOT";
const MACOS_TARGET_ENV: &str = "RSYNC_WIN_MACOS_RSYNC_TARGET";
const OPENRSYNC_TARGET_ENV: &str = "RSYNC_WIN_OPENRSYNC_TARGET";
const CYGWIN_TARGET_ENV: &str = "RSYNC_WIN_CYGWIN_TARGET";
const MSYS2_TARGET_ENV: &str = "RSYNC_WIN_MSYS2_TARGET";
const DAEMON_URL_ENV: &str = "RSYNC_WIN_DAEMON_URL";

#[test]
fn option_family_smoke_matrix_plans_without_external_fixtures() {
    let cases: &[(&str, &[&str])] = &[
        ("path-selection", &["-rR", "--no-implied-dirs", "--mkpath"]),
        (
            "update-delete-backup",
            &[
                "--update",
                "--existing",
                "--ignore-existing",
                "--max-size=4K",
                "--min-size=1",
                "--delete-delay",
                "--backup",
                "--suffix=.bak",
                "--partial",
                "--temp-dir=.tmp",
            ],
        ),
        (
            "filters",
            &[
                "--include=keep/**",
                "--exclude=*.tmp",
                "--filter=protect *.bak",
            ],
        ),
        (
            "links-devices",
            &[
                "--links",
                "--safe-links",
                "--hard-links",
                "--devices",
                "--specials",
            ],
        ),
        (
            "metadata",
            &[
                "--perms",
                "--executability",
                "--chmod=F600,D700",
                "--numeric-ids",
                "--acls",
                "--xattrs",
                "--fake-super",
                "--omit-link-times",
            ],
        ),
        (
            "checksums-output",
            &[
                "--checksum",
                "--whole-file",
                "--block-size=8192",
                "--compress",
                "--progress",
                "--stats",
                "--itemize-changes",
            ],
        ),
        (
            "transport",
            &[
                "-essh -p 22",
                "--remote-option=--fake-super",
                "--password-file=fixture.pass",
            ],
        ),
        (
            "limits-compat",
            &[
                "--bwlimit=100",
                "--timeout=5",
                "--stop-after=1",
                "--protocol=31",
                "--iconv=utf-8",
                "--outbuf=L",
            ],
        ),
    ];

    for (name, options) in cases {
        let mut args = vec!["rsync-win", "--plan"];
        args.extend_from_slice(options);
        args.extend_from_slice(&["src", "dst"]);

        let output = parse_and_render_result(args).unwrap_or_else(|err| {
            panic!("option family {name} should parse cleanly, got {err}");
        });

        assert!(
            output.contains("rsync-win development transfer planner"),
            "{name}: {output}"
        );
    }
}

#[test]
fn upstream_rsync_over_ssh_small_push_pull_and_cleanup() {
    let Some((target, ssh)) = ssh_fixture("upstream rsync SSH push/pull") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-compat-ssh").unwrap();
    let source = temp.path().join("source");
    let pull_dest = temp.path().join("pull-dest");
    fs::create_dir_all(source.join("dir")).unwrap();
    fs::create_dir_all(&pull_dest).unwrap();
    fs::write(source.join("dir/file.txt"), b"compat-smoke").unwrap();

    let remote_root = remote_temp_root("compat");
    let remote_dest = format!("{remote_root}/dest");
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "rm -rf {}; mkdir -p {}",
            shell_quote(&remote_root),
            shell_quote(&remote_dest)
        ),
    );

    let push = Command::new(&rsync_win)
        .args([
            "-rt",
            "--whole-file",
            &format!("{}/", source.to_string_lossy()),
            &format!("{target}:{remote_dest}/"),
        ])
        .output()
        .unwrap();

    let verify_push = remote_command_output(
        &ssh,
        &target,
        &format!(
            "test -s {} && cat {}",
            shell_quote(&format!("{remote_dest}/dir/file.txt")),
            shell_quote(&format!("{remote_dest}/dir/file.txt"))
        ),
    );

    let pull = Command::new(&rsync_win)
        .args([
            "-rt",
            "--whole-file",
            &format!("{target}:{remote_dest}/"),
            pull_dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert_command_success("ssh push", &push);
    assert_command_success("ssh push verification", &verify_push);
    assert_eq!(String::from_utf8_lossy(&verify_push.stdout), "compat-smoke");
    assert_command_success("ssh pull", &pull);
    assert_eq!(
        fs::read_to_string(pull_dest.join("dir/file.txt")).unwrap(),
        "compat-smoke"
    );
}

#[test]
fn upstream_rsync_over_ssh_copy_links_pulls_posix_symlink_referent() {
    let Some((target, ssh)) = ssh_fixture("upstream rsync SSH POSIX symlink copy-links") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-compat-symlink").unwrap();
    let pull_dest = temp.path().join("pull-dest");
    fs::create_dir_all(&pull_dest).unwrap();

    let remote_root = remote_temp_root("symlink");
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "rm -rf {}; mkdir -p {}; printf %s posix-link > {}; ln -s target.txt {}",
            shell_quote(&remote_root),
            shell_quote(&remote_root),
            shell_quote(&format!("{remote_root}/target.txt")),
            shell_quote(&format!("{remote_root}/link.txt"))
        ),
    );

    let pull = Command::new(&rsync_win)
        .args([
            "-rt",
            "--copy-links",
            &format!("{target}:{remote_root}/link.txt"),
            pull_dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert_command_success("ssh copy-links POSIX symlink pull", &pull);
    assert_eq!(
        fs::read_to_string(pull_dest.join("link.txt")).unwrap(),
        "posix-link"
    );
}

#[test]
fn update_predicates_match_upstream_rsync_fixture_where_available() {
    let Some((target, ssh)) = ssh_fixture("upstream rsync SSH update predicate comparison") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-compat-update").unwrap();
    let source = temp.path().join("source");
    let dest = temp.path().join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("create.txt"), b"create").unwrap();
    fs::write(source.join("skip-existing.txt"), b"new").unwrap();
    fs::write(source.join("update.txt"), b"new").unwrap();
    fs::write(dest.join("skip-existing.txt"), b"old").unwrap();
    fs::write(dest.join("update.txt"), b"old").unwrap();

    let local = Command::new(&rsync_win)
        .args([
            "-rt",
            "--ignore-existing",
            &format!("{}/", source.to_string_lossy()),
            dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    let remote_root = remote_temp_root("update-predicate");
    let remote_source = format!("{remote_root}/source");
    let remote_dest = format!("{remote_root}/dest");
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "rm -rf {}; mkdir -p {} {}; printf %s create > {}; printf %s new > {}; printf %s new > {}; printf %s old > {}; printf %s old > {}",
            shell_quote(&remote_root),
            shell_quote(&remote_source),
            shell_quote(&remote_dest),
            shell_quote(&format!("{remote_source}/create.txt")),
            shell_quote(&format!("{remote_source}/skip-existing.txt")),
            shell_quote(&format!("{remote_source}/update.txt")),
            shell_quote(&format!("{remote_dest}/skip-existing.txt")),
            shell_quote(&format!("{remote_dest}/update.txt"))
        ),
    );
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "rsync -rt --ignore-existing {} {}",
            shell_quote(&format!("{remote_source}/")),
            shell_quote(&format!("{remote_dest}/"))
        ),
    );
    let remote_manifest = remote_command_output(
        &ssh,
        &target,
        &manifest_command(
            &remote_dest,
            &["create.txt", "skip-existing.txt", "update.txt"],
        ),
    );
    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert_command_success("local --ignore-existing comparison", &local);
    assert_command_success(
        "remote upstream --ignore-existing manifest",
        &remote_manifest,
    );
    assert_eq!(
        local_manifest(&dest, &["create.txt", "skip-existing.txt", "update.txt"]),
        String::from_utf8_lossy(&remote_manifest.stdout)
    );
}

#[test]
fn optional_ssh_peer_version_fixtures_skip_cleanly() {
    for (name, env_var) in [
        ("macOS rsync peer", MACOS_TARGET_ENV),
        ("openrsync peer", OPENRSYNC_TARGET_ENV),
        ("Cygwin rsync peer", CYGWIN_TARGET_ENV),
        ("MSYS2 rsync peer", MSYS2_TARGET_ENV),
    ] {
        let Some((target, ssh)) = ssh_fixture_from_env(
            name,
            env_var,
            "set the peer-specific target env var to user@host to enable this optional fixture",
        ) else {
            continue;
        };

        let output = remote_command_output(&ssh, &target, "rsync --version");
        assert_command_success(name, &output);
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .to_ascii_lowercase()
                .contains("rsync")
                || String::from_utf8_lossy(&output.stderr)
                    .to_ascii_lowercase()
                    .contains("rsync"),
            "{name}: stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn daemon_fixture_module_listing_skips_cleanly() {
    let url = match env::var(DAEMON_URL_ENV) {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            skip_external_test(
                "daemon module listing compatibility",
                Some("set RSYNC_WIN_DAEMON_URL=rsync://host:873 to enable daemon fixture"),
            );
            return;
        }
    };

    let output = Command::new(rsync_win_binary())
        .args(["--list-only", &format!("{}/", url.trim_end_matches('/'))])
        .output()
        .unwrap();

    assert_command_success("daemon module listing compatibility", &output);
}

fn ssh_fixture(name: &str) -> Option<(String, PathBuf)> {
    ssh_fixture_from_env(
        name,
        SSH_TARGET_ENV,
        "set RSYNC_WIN_SSH_TARGET=user@host to enable upstream rsync SSH interop",
    )
}

fn ssh_fixture_from_env(
    name: &str,
    env_var: &str,
    missing_message: &'static str,
) -> Option<(String, PathBuf)> {
    let target = match env::var(env_var) {
        Ok(target) if !target.trim().is_empty() => target,
        _ => {
            skip_external_test(name, Some(missing_message));
            return None;
        }
    };

    let tools = discover_tools();
    let Some(ssh) = tools.ssh.path() else {
        skip_external_test(name, tools.ssh.reason());
        return None;
    };

    Some((target, ssh.to_path_buf()))
}

fn rsync_win_binary() -> PathBuf {
    env::var_os("CARGO_BIN_EXE_rsync-win")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut path = env::current_exe().unwrap();
            path.pop();
            path.pop();
            path.push(if cfg!(windows) {
                "rsync-win.exe"
            } else {
                "rsync-win"
            });
            path
        })
}

fn remote_temp_root(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let parent = env::var(SSH_TMP_ROOT_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/tmp".to_string());
    let parent = parent.trim_end_matches('/');
    format!("{parent}/rsync-win-{label}-{}-{nanos}", std::process::id())
}

fn run_remote_command(ssh: &Path, target: &str, command: &str) {
    let output = remote_command_output(ssh, target, command);
    assert_command_success(command, &output);
}

fn remote_command_output(ssh: &Path, target: &str, command: &str) -> std::process::Output {
    Command::new(ssh)
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            target,
            command,
        ])
        .output()
        .unwrap()
}

fn assert_command_success(name: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{name} failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn local_manifest(root: &Path, names: &[&str]) -> String {
    let mut output = String::new();
    for name in names {
        let path = root.join(name);
        output.push_str(name);
        output.push('=');
        if path.exists() {
            output.push_str(&fs::read_to_string(path).unwrap());
        } else {
            output.push_str("<missing>");
        }
        output.push('\n');
    }
    output
}

fn manifest_command(root: &str, names: &[&str]) -> String {
    let mut command = format!("ROOT={};", shell_quote(root));
    for name in names {
        command.push_str(&format!(
            " if test -e \"$ROOT/{}\"; then printf '%s=' {}; cat \"$ROOT/{}\"; printf '\\n'; else printf '%s=<missing>\\n' {}; fi;",
            name,
            shell_quote(name),
            name,
            shell_quote(name)
        ));
    }
    command
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
