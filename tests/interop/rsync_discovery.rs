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
fn daemon_module_list_skips_without_ssh_target() {
    let Some(fixture) = RemoteDaemonFixture::start("daemon module list") else {
        return;
    };
    let rsync_win = rsync_win_binary();

    let output = Command::new(&rsync_win)
        .args(["--contimeout", "3", &fixture.url("")])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "daemon module list failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("- files"));
}

#[test]
fn daemon_pull_small_tree_skips_without_ssh_target() {
    let Some(fixture) = RemoteDaemonFixture::start("daemon pull small tree") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-daemon-pull").unwrap();
    let dest = temp.path().join("dest");
    fs::create_dir_all(&dest).unwrap();

    let output = Command::new(&rsync_win)
        .args([
            "-r",
            "--whole-file",
            "--contimeout",
            "3",
            &fixture.url("files/source/"),
            dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "daemon pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(dest.join("dir/file.txt")).unwrap(),
        "pulled"
    );
}

#[test]
fn daemon_push_small_tree_skips_without_ssh_target() {
    let Some(fixture) = RemoteDaemonFixture::start("daemon push small tree") else {
        return;
    };
    let rsync_win = rsync_win_binary();
    let temp = FixtureTempDir::new("rsync-win-daemon-push").unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("dir")).unwrap();
    fs::write(source.join("dir/file.txt"), b"pushed").unwrap();

    let output = Command::new(&rsync_win)
        .args([
            "-r",
            "--whole-file",
            "--contimeout",
            "3",
            source.to_string_lossy().as_ref(),
            &fixture.url("files/dest/"),
        ])
        .output()
        .unwrap();

    let verify = remote_command_output(
        &fixture.ssh,
        &fixture.target,
        &format!(
            "cat {}",
            shell_quote(&format!("{}/module/dest/dir/file.txt", fixture.root))
        ),
    );

    assert!(
        output.status.success(),
        "daemon push failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&verify.stdout), "pushed");
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

struct RemoteDaemonFixture {
    ssh: PathBuf,
    target: String,
    host: String,
    root: String,
    port: u16,
}

impl RemoteDaemonFixture {
    fn start(name: &str) -> Option<Self> {
        let Some((target, ssh)) = remote_shell_fixture(name) else {
            return None;
        };
        let root = remote_temp_root("daemon");
        let port = daemon_test_port();
        let host = env::var("RSYNC_WIN_DAEMON_HOST")
            .ok()
            .filter(|host| !host.trim().is_empty())
            .unwrap_or_else(|| daemon_host_from_ssh_target(&target));

        let module_root = format!("{root}/module");
        let config = format!("{root}/rsyncd.conf");
        let pid = format!("{root}/rsyncd.pid");
        let process_pid = format!("{root}/daemon.pid");
        let log = format!("{root}/rsyncd.log");
        let out = format!("{root}/daemon.out");
        let command = format!(
            "rm -rf {root_q}; mkdir -p {source_q} {dest_q}; printf %s pulled > {file_q}; cat > {config_q} <<'EOF'\nuse chroot = no\npid file = {pid}\nlog file = {log}\n[files]\n    path = {module_root}\n    read only = false\n    list = yes\nEOF\nrsync --daemon --no-detach --config={config_q} --port={port} > {out_q} 2>&1 & echo $! > {process_pid_q}; sleep 1",
            root_q = shell_quote(&root),
            source_q = shell_quote(&format!("{module_root}/source/dir")),
            dest_q = shell_quote(&format!("{module_root}/dest")),
            file_q = shell_quote(&format!("{module_root}/source/dir/file.txt")),
            config_q = shell_quote(&config),
            process_pid_q = shell_quote(&process_pid),
            out_q = shell_quote(&out),
        );
        run_remote_command(&ssh, &target, &command);

        Some(Self {
            ssh,
            target,
            host,
            root,
            port,
        })
    }

    fn url(&self, module_path: &str) -> String {
        format!("rsync://{}:{}/{}", self.host, self.port, module_path)
    }
}

impl Drop for RemoteDaemonFixture {
    fn drop(&mut self) {
        let process_pid = format!("{}/daemon.pid", self.root);
        let command = format!(
            "if test -f {pid}; then kill $(cat {pid}) >/dev/null 2>&1 || true; fi; rm -rf {root}",
            pid = shell_quote(&process_pid),
            root = shell_quote(&self.root),
        );
        let _ = remote_command_output(&self.ssh, &self.target, &command);
    }
}

fn remote_shell_fixture(name: &str) -> Option<(String, PathBuf)> {
    let target = match env::var("RSYNC_WIN_SSH_TARGET") {
        Ok(target) if !target.trim().is_empty() => target,
        _ => {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_SSH_TARGET=user@host to enable remote-shell interop"),
            );
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
    format!("/tmp/rsync-win-{label}-{}-{nanos}", std::process::id())
}

fn daemon_test_port() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or_default();
    20_000 + (nanos % 20_000) as u16
}

fn daemon_host_from_ssh_target(target: &str) -> String {
    let host = target
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(target);
    host.split(':').next().unwrap_or(host).to_string()
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
