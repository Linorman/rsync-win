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
use rsync_fs::{LocalFileSystem, PortableFileSystem};

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
fn upstream_rsync_over_ssh_command_family_matrix_matches_upstream_manifests() {
    let Some((target, ssh)) = ssh_fixture("upstream rsync SSH command-family matrix") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-compat-ssh-matrix").unwrap();
    let remote = RemoteTempDir::new("ssh-matrix", &ssh, &target);
    let remote_source = remote.join("source");
    let remote_files_from = remote.join("files-from.txt");
    let local_files_from = temp.path().join("files-from.txt");

    run_remote_command(
        &ssh,
        &target,
        &remote_fixture_source_command(&remote_source),
    );
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "printf '%s\n%s\n' {} {} > {}",
            shell_quote("keep.txt"),
            shell_quote("dir/nested.txt"),
            shell_quote(&remote_files_from)
        ),
    );
    fs::write(&local_files_from, b"keep.txt\ndir/nested.txt\n").unwrap();

    let files_from_arg = local_files_from.to_string_lossy().into_owned();
    let cases = vec![
        PullManifestCase {
            name: "archive-no-owner-group",
            win_options: strings(&["-a", "--no-o", "--no-g", "--whole-file"]),
            upstream_options: strings(&["-a", "--no-o", "--no-g"]),
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: Vec::new(),
        },
        PullManifestCase {
            name: "delete-exclude",
            win_options: strings(&["-rt", "--delete", "--exclude=*.tmp", "--whole-file"]),
            upstream_options: strings(&["-rt", "--delete", "--exclude=*.tmp"]),
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: vec![
                ("stale.txt", "delete-me"),
                ("drop.tmp", "receiver-protected"),
            ],
        },
        PullManifestCase {
            name: "files-from",
            win_options: vec![
                "-rt".to_string(),
                "--files-from".to_string(),
                files_from_arg,
            ],
            upstream_options: vec![
                "-rt".to_string(),
                format!("--files-from={remote_files_from}"),
            ],
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: Vec::new(),
        },
        PullManifestCase {
            name: "checksum",
            win_options: strings(&["-rt", "--checksum", "--whole-file"]),
            upstream_options: strings(&["-rt", "--checksum"]),
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: vec![("checksum.txt", "same-size-old")],
        },
        PullManifestCase {
            name: "partial-dir",
            win_options: strings(&["-rt", "--partial", "--partial-dir=.rsync-partial"]),
            upstream_options: strings(&["-rt", "--partial", "--partial-dir=.rsync-partial"]),
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: Vec::new(),
        },
        PullManifestCase {
            name: "inplace",
            win_options: strings(&["-rt", "--inplace"]),
            upstream_options: strings(&["-rt", "--inplace"]),
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: vec![("keep.txt", "old")],
        },
        PullManifestCase {
            name: "append-verify",
            win_options: strings(&["-rt", "--append-verify"]),
            upstream_options: strings(&["-rt", "--append-verify"]),
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: vec![("append.txt", "prefix")],
        },
        PullManifestCase {
            name: "compress-zlibx",
            win_options: strings(&["-rt", "--compress", "--compress-choice=zlibx"]),
            upstream_options: strings(&["-rt", "--compress", "--compress-choice=zlibx"]),
            remote_sources: vec![format!("{remote_source}/")],
            prepopulate: Vec::new(),
        },
        PullManifestCase {
            name: "multiple-sources-spaces-unicode",
            win_options: strings(&["-rt"]),
            upstream_options: strings(&["-rt"]),
            remote_sources: vec![
                format!("{remote_source}/name with spaces.txt"),
                format!("{remote_source}/unicode-\u{4e2d}.txt"),
            ],
            prepopulate: Vec::new(),
        },
    ];

    for case in cases {
        run_pull_manifest_case(&rsync_win, &target, &ssh, &remote, temp.path(), case);
    }

    let local_push_source = temp.path().join("push-source");
    let remote_push_source = remote.join("push-source");
    create_local_fixture_source(&local_push_source);
    run_remote_command(
        &ssh,
        &target,
        &remote_fixture_source_command(&remote_push_source),
    );
    let local_push_files_from = temp.path().join("push-files-from.txt");
    let remote_push_files_from = remote.join("push-files-from.txt");
    fs::write(&local_push_files_from, b"keep.txt\ndir/nested.txt\n").unwrap();
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "printf '%s\n%s\n' {} {} > {}",
            shell_quote("keep.txt"),
            shell_quote("dir/nested.txt"),
            shell_quote(&remote_push_files_from)
        ),
    );

    let local_source_arg = format!("{}/", local_push_source.to_string_lossy());
    let remote_source_arg = format!("{remote_push_source}/");
    let push_files_from_arg = local_push_files_from.to_string_lossy().into_owned();
    let push_cases = vec![
        PushManifestCase {
            name: "push-archive-no-owner-group",
            win_options: strings(&["-a", "--no-o", "--no-g", "--whole-file"]),
            upstream_options: strings(&["-a", "--no-o", "--no-g"]),
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: Vec::new(),
        },
        PushManifestCase {
            name: "push-delete-exclude",
            win_options: strings(&["-rt", "--delete", "--exclude=*.tmp", "--whole-file"]),
            upstream_options: strings(&["-rt", "--delete", "--exclude=*.tmp"]),
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: vec![
                ("stale.txt", "delete-me"),
                ("drop.tmp", "receiver-protected"),
            ],
        },
        PushManifestCase {
            name: "push-files-from",
            win_options: vec![
                "-rt".to_string(),
                "--files-from".to_string(),
                push_files_from_arg,
            ],
            upstream_options: vec![
                "-rt".to_string(),
                format!("--files-from={remote_push_files_from}"),
            ],
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: Vec::new(),
        },
        PushManifestCase {
            name: "push-checksum",
            win_options: strings(&["-rt", "--checksum", "--whole-file"]),
            upstream_options: strings(&["-rt", "--checksum"]),
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: vec![("checksum.txt", "same-size-old")],
        },
        PushManifestCase {
            name: "push-partial-dir",
            win_options: strings(&["-rt", "--partial", "--partial-dir=.rsync-partial"]),
            upstream_options: strings(&["-rt", "--partial", "--partial-dir=.rsync-partial"]),
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: Vec::new(),
        },
        PushManifestCase {
            name: "push-inplace",
            win_options: strings(&["-rt", "--inplace"]),
            upstream_options: strings(&["-rt", "--inplace"]),
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: vec![("keep.txt", "old")],
        },
        PushManifestCase {
            name: "push-append-verify",
            win_options: strings(&["-rt", "--append-verify"]),
            upstream_options: strings(&["-rt", "--append-verify"]),
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: vec![("append.txt", "prefix")],
        },
        PushManifestCase {
            name: "push-compress-zlibx",
            win_options: strings(&["-rt", "--compress", "--compress-choice=zlibx"]),
            upstream_options: strings(&["-rt", "--compress", "--compress-choice=zlibx"]),
            win_sources: vec![local_source_arg.clone()],
            upstream_sources: vec![remote_source_arg.clone()],
            prepopulate: Vec::new(),
        },
        PushManifestCase {
            name: "push-multiple-sources-spaces-unicode",
            win_options: strings(&["-rt"]),
            upstream_options: strings(&["-rt"]),
            win_sources: vec![
                local_push_source
                    .join("name with spaces.txt")
                    .to_string_lossy()
                    .into_owned(),
                local_push_source
                    .join("unicode-\u{4e2d}.txt")
                    .to_string_lossy()
                    .into_owned(),
            ],
            upstream_sources: vec![
                format!("{remote_push_source}/name with spaces.txt"),
                format!("{remote_push_source}/unicode-\u{4e2d}.txt"),
            ],
            prepopulate: Vec::new(),
        },
    ];

    for case in push_cases {
        run_push_manifest_case(&rsync_win, &target, &ssh, &remote, case);
    }
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

struct PullManifestCase {
    name: &'static str,
    win_options: Vec<String>,
    upstream_options: Vec<String>,
    remote_sources: Vec<String>,
    prepopulate: Vec<(&'static str, &'static str)>,
}

struct PushManifestCase {
    name: &'static str,
    win_options: Vec<String>,
    upstream_options: Vec<String>,
    win_sources: Vec<String>,
    upstream_sources: Vec<String>,
    prepopulate: Vec<(&'static str, &'static str)>,
}

struct RemoteTempDir {
    ssh: PathBuf,
    target: String,
    root: String,
}

impl RemoteTempDir {
    fn new(label: &str, ssh: &Path, target: &str) -> Self {
        let root = remote_temp_root(label);
        let temp = Self {
            ssh: ssh.to_path_buf(),
            target: target.to_string(),
            root,
        };
        run_remote_command(
            &temp.ssh,
            &temp.target,
            &format!(
                "rm -rf {}; mkdir -p {}",
                shell_quote(&temp.root),
                shell_quote(&temp.root)
            ),
        );
        temp
    }

    fn join(&self, path: &str) -> String {
        format!("{}/{}", self.root, path.trim_start_matches('/'))
    }
}

impl Drop for RemoteTempDir {
    fn drop(&mut self) {
        let _ = remote_command_output(
            &self.ssh,
            &self.target,
            &format!("rm -rf {}", shell_quote(&self.root)),
        );
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn run_pull_manifest_case(
    rsync_win: &Path,
    target: &str,
    ssh: &Path,
    remote: &RemoteTempDir,
    temp_root: &Path,
    case: PullManifestCase,
) {
    let local_dest = temp_root.join(format!("pull-{}", case.name));
    let upstream_dest = remote.join(&format!("upstream-{}", case.name));
    fs::create_dir_all(&local_dest).unwrap();
    run_remote_command(
        ssh,
        target,
        &format!(
            "rm -rf {}; mkdir -p {}",
            shell_quote(&upstream_dest),
            shell_quote(&upstream_dest)
        ),
    );
    prepopulate_local_dest(&local_dest, &case.prepopulate);
    if !case.prepopulate.is_empty() {
        run_remote_command(
            ssh,
            target,
            &remote_prepopulate_command(&upstream_dest, &case.prepopulate),
        );
    }

    let mut upstream_args = case.upstream_options.clone();
    upstream_args.extend(case.remote_sources.clone());
    upstream_args.push(format!("{upstream_dest}/"));
    run_remote_command(ssh, target, &shell_command_words("rsync", &upstream_args));

    let mut command = Command::new(rsync_win);
    command.args(&case.win_options);
    for source in &case.remote_sources {
        command.arg(format!("{target}:{source}"));
    }
    command.arg(&local_dest);
    let output = command.output().unwrap();
    assert_command_success(case.name, &output);

    let local = local_tree_manifest(&local_dest);
    let upstream = remote_tree_manifest(ssh, target, &upstream_dest);
    assert_eq!(local, upstream, "{} manifest mismatch", case.name);
}

fn run_push_manifest_case(
    rsync_win: &Path,
    target: &str,
    ssh: &Path,
    remote: &RemoteTempDir,
    case: PushManifestCase,
) {
    let win_dest = remote.join(&format!("win-{}", case.name));
    let upstream_dest = remote.join(&format!("upstream-{}", case.name));
    run_remote_command(
        ssh,
        target,
        &format!(
            "rm -rf {} {}; mkdir -p {} {}",
            shell_quote(&win_dest),
            shell_quote(&upstream_dest),
            shell_quote(&win_dest),
            shell_quote(&upstream_dest)
        ),
    );
    if !case.prepopulate.is_empty() {
        run_remote_command(
            ssh,
            target,
            &remote_prepopulate_command(&win_dest, &case.prepopulate),
        );
        run_remote_command(
            ssh,
            target,
            &remote_prepopulate_command(&upstream_dest, &case.prepopulate),
        );
    }

    let mut upstream_args = case.upstream_options.clone();
    upstream_args.extend(case.upstream_sources.clone());
    upstream_args.push(format!("{upstream_dest}/"));
    run_remote_command(ssh, target, &shell_command_words("rsync", &upstream_args));

    let mut command = Command::new(rsync_win);
    command.args(&case.win_options);
    command.args(&case.win_sources);
    command.arg(format!("{target}:{win_dest}/"));
    let output = command.output().unwrap();
    assert_command_success(case.name, &output);

    let win_manifest = remote_tree_manifest(ssh, target, &win_dest);
    let upstream_manifest = remote_tree_manifest(ssh, target, &upstream_dest);
    assert_eq!(
        win_manifest, upstream_manifest,
        "{} manifest mismatch",
        case.name
    );
}

fn create_local_fixture_source(root: &Path) {
    let mut fs_adapter = LocalFileSystem;
    for (relative, content, mtime) in fixture_source_files() {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content.as_bytes()).unwrap();
        fs_adapter
            .set_mtime(&path, UNIX_EPOCH + std::time::Duration::from_secs(mtime))
            .unwrap();
    }
}

fn prepopulate_local_dest(root: &Path, files: &[(&str, &str)]) {
    let mut fs_adapter = LocalFileSystem;
    for (relative, content) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content.as_bytes()).unwrap();
        fs_adapter
            .set_mtime(
                &path,
                UNIX_EPOCH + std::time::Duration::from_secs(PREPOPULATE_MTIME),
            )
            .unwrap();
    }
}

const PREPOPULATE_MTIME: u64 = 1_699_999_000;

fn remote_prepopulate_command(root: &str, files: &[(&str, &str)]) -> String {
    let mut command = String::new();
    for (relative, content) in files {
        push_remote_file_command(&mut command, root, relative, content, PREPOPULATE_MTIME);
    }
    command
}

fn remote_fixture_source_command(root: &str) -> String {
    let mut command = format!(
        "rm -rf {}; mkdir -p {}",
        shell_quote(root),
        shell_quote(root)
    );
    for (relative, content, mtime) in fixture_source_files() {
        push_remote_file_command(&mut command, root, relative, content, mtime);
    }
    command
}

fn fixture_source_files() -> [(&'static str, &'static str, u64); 8] {
    [
        ("keep.txt", "keep-v1", 1_700_000_001),
        ("drop.tmp", "drop-source", 1_700_000_002),
        ("dir/nested.txt", "nested-v1", 1_700_000_003),
        ("checksum.txt", "checksum-new", 1_700_000_004),
        ("partial.txt", "partial-v1", 1_700_000_005),
        ("append.txt", "prefix-suffix", 1_700_000_006),
        ("name with spaces.txt", "space-name", 1_700_000_007),
        ("unicode-\u{4e2d}.txt", "unicode-name", 1_700_000_008),
    ]
}

fn push_remote_file_command(
    command: &mut String,
    root: &str,
    relative: &str,
    content: &str,
    mtime: u64,
) {
    let path = format!("{root}/{relative}");
    let parent = Path::new(relative)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| format!("{root}/{}", parent.to_string_lossy().replace('\\', "/")))
        .unwrap_or_else(|| root.to_string());
    if !command.is_empty() {
        command.push_str("; ");
    }
    command.push_str(&format!(
        "mkdir -p {}; printf %s {} > {}; touch -m -d @{} {}",
        shell_quote(&parent),
        shell_quote(content),
        shell_quote(&path),
        mtime,
        shell_quote(&path)
    ));
}

fn shell_command_words(program: &str, args: &[String]) -> String {
    let mut command = shell_quote(program);
    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }
    command
}

fn local_tree_manifest(root: &Path) -> String {
    let mut lines = Vec::new();
    collect_local_manifest(root, root, &mut lines);
    sorted_lines(lines)
}

fn collect_local_manifest(root: &Path, current: &Path, lines: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(current)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::metadata(&path).unwrap();
        if metadata.is_dir() {
            lines.push(format!("dir\t{relative}"));
            collect_local_manifest(root, &path, lines);
        } else if metadata.is_file() {
            let mtime = metadata
                .modified()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let content = fs::read_to_string(&path).unwrap();
            lines.push(format!("file\t{relative}\t{mtime}\t{content}"));
        }
    }
}

fn remote_tree_manifest(ssh: &Path, target: &str, root: &str) -> String {
    let output = remote_command_output(ssh, target, &remote_manifest_command(root));
    assert_command_success("remote manifest", &output);
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    sorted_lines(lines)
}

fn sorted_lines(mut lines: Vec<String>) -> String {
    lines.sort();
    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    output
}

fn remote_manifest_command(root: &str) -> String {
    format!(
        "ROOT={}; cd \"$ROOT\" && find . -mindepth 1 -print | LC_ALL=C sort | while IFS= read -r p; do rel=${{p#./}}; if test -d \"$p\"; then printf 'dir\\t%s\\n' \"$rel\"; elif test -f \"$p\"; then printf 'file\\t%s\\t%s\\t' \"$rel\" \"$(stat -c %Y \"$p\")\"; cat \"$p\"; printf '\\n'; fi; done",
        shell_quote(root)
    )
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
