#[path = "../common/mod.rs"]
mod common;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use common::{
    discover_platform_capabilities, discover_tools, skip_external_test, CapabilityStatus,
    FixtureTempDir,
};

const SSH_TARGET_ENV: &str = "RSYNC_WIN_SSH_TARGET";
const SSH_PROTOCOL27_TARGET_ENV: &str = "RSYNC_WIN_SSH_PROTOCOL27_TARGET";
const SSH_TMP_ROOT_ENV: &str = "RSYNC_WIN_SSH_TMP_ROOT";

#[test]
fn fixture_temp_directory_is_created_and_removed() {
    let path = {
        let temp = FixtureTempDir::new("rsync-win-fixture").unwrap();
        let marker = temp.path().join("marker.txt");
        fs::write(&marker, b"fixture").unwrap();
        assert_eq!(fs::read(&marker).unwrap(), b"fixture");
        temp.path().to_path_buf()
    };

    assert!(!path.exists());
}

#[test]
fn discovers_tools_without_requiring_external_binaries() {
    let tools = discover_tools();

    eprintln!("rsync discovery: {:?}", tools.rsync);
    eprintln!("ssh discovery: {:?}", tools.ssh);
    eprintln!("powershell discovery: {:?}", tools.powershell);

    assert_eq!(tools.rsync.path().is_some(), tools.rsync.is_available());
    assert_eq!(tools.ssh.path().is_some(), tools.ssh.is_available());
    assert_eq!(
        tools.powershell.path().is_some(),
        tools.powershell.is_available()
    );
}

#[test]
fn rsync_version_probe_skips_when_rsync_is_missing() {
    let tools = discover_tools();
    let Some(rsync) = tools.rsync.path() else {
        skip_external_test("rsync --version", tools.rsync.reason());
        return;
    };

    let output = Command::new(rsync).arg("--version").output().unwrap();
    assert!(
        output.status.success(),
        "rsync --version should exit successfully"
    );
}

#[test]
fn ssh_version_probe_skips_when_ssh_is_missing() {
    let tools = discover_tools();
    let Some(ssh) = tools.ssh.path() else {
        skip_external_test("ssh -V", tools.ssh.reason());
        return;
    };

    let output = Command::new(ssh).arg("-V").output().unwrap();
    assert!(output.status.success(), "ssh -V should exit successfully");
}

#[test]
fn remote_shell_rsync_probe_skips_without_ssh_target() {
    let target = match env::var("RSYNC_WIN_SSH_TARGET") {
        Ok(target) if !target.trim().is_empty() => target,
        _ => {
            skip_external_test(
                "ssh target rsync --version",
                Some("set RSYNC_WIN_SSH_TARGET=user@host to enable remote-shell probe"),
            );
            return;
        }
    };

    let tools = discover_tools();
    let Some(ssh) = tools.ssh.path() else {
        skip_external_test("ssh target rsync --version", tools.ssh.reason());
        return;
    };

    let output = Command::new(ssh)
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            &target,
            "rsync --version",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "remote rsync probe failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn remote_shell_push_small_tree_skips_without_ssh_target() {
    let Some((target, ssh)) = remote_shell_fixture("remote-shell push small tree") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-remote-push").unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("dir")).unwrap();
    fs::write(source.join("dir/file.txt"), b"hello").unwrap();

    let remote_root = remote_temp_root("push");
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

    let output = Command::new(&rsync_win)
        .args([
            "-r",
            "--whole-file",
            source.to_string_lossy().as_ref(),
            &format!("{target}:{remote_dest}"),
        ])
        .output()
        .unwrap();

    let verify = remote_command_output(
        &ssh,
        &target,
        &format!(
            "cat {}",
            shell_quote(&format!("{remote_dest}/dir/file.txt"))
        ),
    );
    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert!(
        output.status.success(),
        "remote push failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&verify.stdout), "hello");
}

#[test]
fn remote_shell_push_delete_tree_skips_without_ssh_target() {
    let Some((target, ssh)) = remote_shell_fixture("remote-shell push -rt --delete") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-remote-push-delete").unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.txt"), b"fresh").unwrap();

    let remote_root = remote_temp_root("push-delete");
    let remote_dest = format!("{remote_root}/dest");
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "rm -rf {}; mkdir -p {}; printf %s stale > {}",
            shell_quote(&remote_root),
            shell_quote(&remote_dest),
            shell_quote(&format!("{remote_dest}/stale.txt"))
        ),
    );

    let source_arg = format!("{}/", source.to_string_lossy());
    let dest_arg = format!("{target}:{remote_dest}/");
    let output = Command::new(&rsync_win)
        .args(["-r", "-t", "--delete", "--whole-file", &source_arg, &dest_arg])
        .output()
        .unwrap();

    let verify = remote_command_output(
        &ssh,
        &target,
        &format!(
            "test -f {} && test ! -e {} && cat {}",
            shell_quote(&format!("{remote_dest}/keep.txt")),
            shell_quote(&format!("{remote_dest}/stale.txt")),
            shell_quote(&format!("{remote_dest}/keep.txt"))
        ),
    );
    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert!(
        output.status.success(),
        "remote push --delete failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        verify.status.success(),
        "remote delete verification failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&verify.stdout), "fresh");
}

#[test]
fn remote_shell_push_delete_with_exclude_protects_receiver_files() {
    let Some((target, ssh)) =
        remote_shell_fixture("remote-shell push --delete --exclude receiver protection")
    else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-remote-push-filter-delete").unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.txt"), b"fresh").unwrap();
    fs::write(source.join("skip.tmp"), b"local-skip").unwrap();

    let remote_root = remote_temp_root("push-filter-delete");
    let remote_dest = format!("{remote_root}/dest");
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "rm -rf {}; mkdir -p {}; printf %s protected > {}",
            shell_quote(&remote_root),
            shell_quote(&remote_dest),
            shell_quote(&format!("{remote_dest}/skip.tmp"))
        ),
    );

    let source_arg = format!("{}/", source.to_string_lossy());
    let dest_arg = format!("{target}:{remote_dest}/");
    let output = Command::new(&rsync_win)
        .args([
            "-r",
            "--delete",
            "--whole-file",
            "--exclude",
            "*.tmp",
            &source_arg,
            &dest_arg,
        ])
        .output()
        .unwrap();

    let verify = remote_command_output(
        &ssh,
        &target,
        &format!(
            "test -f {} && test -f {} && cat {} && printf : && cat {}",
            shell_quote(&format!("{remote_dest}/keep.txt")),
            shell_quote(&format!("{remote_dest}/skip.tmp")),
            shell_quote(&format!("{remote_dest}/keep.txt")),
            shell_quote(&format!("{remote_dest}/skip.tmp"))
        ),
    );
    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert!(
        output.status.success(),
        "remote push --delete --exclude failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        verify.status.success(),
        "remote exclude delete protection verification failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&verify.stdout), "fresh:protected");
}

#[test]
fn remote_shell_pull_small_tree_skips_without_ssh_target() {
    let Some((target, ssh)) = remote_shell_fixture("remote-shell pull small tree") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-remote-pull").unwrap();
    let dest = temp.path().join("dest");
    fs::create_dir_all(&dest).unwrap();

    let remote_root = remote_temp_root("pull");
    let remote_source = format!("{remote_root}/source");
    run_remote_command(
        &ssh,
        &target,
        &format!(
            "rm -rf {}; mkdir -p {}; printf %s pulled > {}",
            shell_quote(&remote_root),
            shell_quote(&format!("{remote_source}/dir")),
            shell_quote(&format!("{remote_source}/dir/file.txt"))
        ),
    );

    let output = Command::new(&rsync_win)
        .args([
            "-r",
            "--whole-file",
            &format!("{target}:{remote_source}/"),
            dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();
    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert!(
        output.status.success(),
        "remote pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(dest.join("dir/file.txt")).unwrap(),
        "pulled"
    );
}

#[test]
fn remote_shell_protocol27_fallback_skips_without_old_peer_fixture() {
    let Some((target, ssh)) = remote_shell_fixture_from_env(
        "remote-shell protocol 27 fallback",
        SSH_PROTOCOL27_TARGET_ENV,
        "set RSYNC_WIN_SSH_PROTOCOL27_TARGET=user@old-host to enable protocol 27 fallback smoke",
    ) else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-remote-protocol27").unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"compat").unwrap();

    let remote_root = remote_temp_root("protocol27");
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

    let output = Command::new(&rsync_win)
        .args([
            "-r",
            "--whole-file",
            source.to_string_lossy().as_ref(),
            &format!("{target}:{remote_dest}"),
        ])
        .output()
        .unwrap();
    run_remote_command(
        &ssh,
        &target,
        &format!("rm -rf {}", shell_quote(&remote_root)),
    );

    assert!(
        output.status.success(),
        "protocol 27 fallback smoke failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("protocol: 27"),
        "fallback fixture did not exercise protocol 27; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn discovers_platform_capabilities() {
    let capabilities = discover_platform_capabilities();

    eprintln!("platform capabilities: {capabilities:#?}");

    assert!(!capabilities.os.is_empty());
    assert!(matches!(
        capabilities.symlink_files,
        CapabilityStatus::Available | CapabilityStatus::Unavailable { .. }
    ));
    assert!(matches!(
        capabilities.hardlinks,
        CapabilityStatus::Available | CapabilityStatus::Unavailable { .. }
    ));
    assert!(matches!(
        capabilities.long_paths,
        CapabilityStatus::Available | CapabilityStatus::Unavailable { .. }
    ));
    assert!(matches!(
        capabilities.case_sensitive_names,
        CapabilityStatus::Available | CapabilityStatus::Unavailable { .. }
    ));
}

fn remote_shell_fixture(name: &str) -> Option<(String, PathBuf)> {
    remote_shell_fixture_from_env(
        name,
        SSH_TARGET_ENV,
        "set RSYNC_WIN_SSH_TARGET=user@host to enable remote-shell interop",
    )
}

fn remote_shell_fixture_from_env(
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
    if parent.is_empty() {
        format!("/rsync-win-{label}-{}-{nanos}", std::process::id())
    } else {
        format!("{parent}/rsync-win-{label}-{}-{nanos}", std::process::id())
    }
}

fn run_remote_command(ssh: &std::path::Path, target: &str, command: &str) {
    let output = remote_command_output(ssh, target, command);
    assert!(
        output.status.success(),
        "remote command failed: {command}; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn remote_command_output(
    ssh: &std::path::Path,
    target: &str,
    command: &str,
) -> std::process::Output {
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

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
