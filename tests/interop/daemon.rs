#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

use std::env;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::{skip_external_test, FixtureTempDir};

const DAEMON_URL_ENV: &str = "RSYNC_WIN_DAEMON_URL";
const DAEMON_MODULE_ENV: &str = "RSYNC_WIN_DAEMON_MODULE";
const DAEMON_PATH_ENV: &str = "RSYNC_WIN_DAEMON_PATH";
const DAEMON_WRITABLE_MODULE_ENV: &str = "RSYNC_WIN_DAEMON_WRITABLE_MODULE";
const DAEMON_USER_ENV: &str = "RSYNC_WIN_DAEMON_USER";
const DAEMON_PASSWORD_FILE_ENV: &str = "RSYNC_WIN_DAEMON_PASSWORD_FILE";
const DAEMON_AUTH_MODULE_ENV: &str = "RSYNC_WIN_DAEMON_AUTH_MODULE";
const DAEMON_AUTH_PATH_ENV: &str = "RSYNC_WIN_DAEMON_AUTH_PATH";

#[test]
fn daemon_module_listing_skips_without_fixture() {
    let Some(url) = daemon_url_fixture("daemon module listing") else {
        return;
    };

    let output = Command::new(rsync_win_binary())
        .args(["--list-only", &format!("{}/", url.trim_end_matches('/'))])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "daemon module listing failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("rsync-win daemon module list"),
        "daemon listing did not use daemon client output; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn daemon_connection_controls_skip_without_fixture() {
    let Some(url) = daemon_url_fixture("daemon connection controls") else {
        return;
    };

    let output = Command::new(rsync_win_binary())
        .args([
            "--list-only",
            "--no-motd",
            "--contimeout=5",
            "--sockopts=TCP_NODELAY",
            &format!("{}/", url.trim_end_matches('/')),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "daemon connection controls failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("rsync-win daemon module list"),
        "daemon connection controls did not use daemon client output; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn daemon_no_auth_pull_skips_without_fixture() {
    let Some((url, module, path)) = daemon_pull_fixture("daemon no-auth pull") else {
        return;
    };
    let temp = FixtureTempDir::new("rsync-win-daemon-pull").unwrap();
    let dest = temp.path().join("dest");
    let source = format!(
        "{}/{}/{}",
        url.trim_end_matches('/'),
        module.trim_matches('/'),
        path.trim_start_matches('/')
    );

    let output = Command::new(rsync_win_binary())
        .args([
            "-r",
            "--whole-file",
            &source,
            dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "daemon no-auth pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("rsync-win daemon pull"),
        "daemon pull did not use daemon client output; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn daemon_bwlimit_pull_skips_without_fixture() {
    let Some((url, module, path)) = daemon_pull_fixture("daemon bwlimit pull") else {
        return;
    };
    let temp = FixtureTempDir::new("rsync-win-daemon-bwlimit-pull").unwrap();
    let dest = temp.path().join("dest");
    let source = format!(
        "{}/{}/{}",
        url.trim_end_matches('/'),
        module.trim_matches('/'),
        path.trim_start_matches('/')
    );

    let output = Command::new(rsync_win_binary())
        .args([
            "-r",
            "--whole-file",
            "--bwlimit=128K",
            &source,
            dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "daemon bwlimit pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn daemon_auth_pull_skips_without_fixture() {
    let Some((url, module, path, user, password_file)) =
        daemon_auth_pull_fixture("daemon auth pull")
    else {
        return;
    };
    let temp = FixtureTempDir::new("rsync-win-daemon-auth-pull").unwrap();
    let dest = temp.path().join("dest");
    let source = daemon_url_with_user(&url, &user, &module, &path);

    let output = Command::new(rsync_win_binary())
        .args([
            "-r",
            "--whole-file",
            "--password-file",
            password_file.to_string_lossy().as_ref(),
            &source,
            dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "daemon auth pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("rsync-win daemon pull"),
        "daemon auth pull did not use daemon client output; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn daemon_auth_failure_skips_without_fixture() {
    let Some((url, module, path, user, _password_file)) =
        daemon_auth_pull_fixture("daemon auth failure")
    else {
        return;
    };
    let temp = FixtureTempDir::new("rsync-win-daemon-auth-failure").unwrap();
    let wrong_password = temp.path().join("wrong-password.txt");
    write_password_file(&wrong_password, "definitely-wrong\n");
    let dest = temp.path().join("dest");
    let source = daemon_url_with_user(&url, &user, &module, &path);

    let output = Command::new(rsync_win_binary())
        .args([
            "-r",
            "--whole-file",
            "--password-file",
            wrong_password.to_string_lossy().as_ref(),
            &source,
            dest.to_string_lossy().as_ref(),
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "daemon unexpectedly accepted invalid auth; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn daemon_writable_auth_push_skips_without_fixture() {
    let Some((url, module, user, password_file)) =
        daemon_writable_auth_fixture("daemon writable auth push")
    else {
        return;
    };
    let temp = FixtureTempDir::new("rsync-win-daemon-auth-push").unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("upload.txt"), b"daemon external auth upload").unwrap();
    let test_dir = format!("rsync-win-auth-push-{}", unique_suffix());
    let destination = daemon_url_with_user(&url, &user, &module, &test_dir);

    let output = Command::new(rsync_win_binary())
        .args([
            "-r",
            "--whole-file",
            "--password-file",
            password_file.to_string_lossy().as_ref(),
            source.to_string_lossy().as_ref(),
            &destination,
        ])
        .output()
        .unwrap();

    cleanup_daemon_test_dir(&url, &module, &user, &password_file, &test_dir, temp.path());
    assert!(
        output.status.success(),
        "daemon auth push failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn local_daemon_server_lists_disposable_module() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server").unwrap();
    let server = LocalDaemonServer::start(&temp, true);

    let output = run_rsync_with_timeout(["--list-only", server.url.as_str()]);
    assert!(
        output.status.success(),
        "daemon server listing failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("- public\tDisposable module"),
        "daemon server did not list module; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn local_daemon_server_serves_file_pull_from_disposable_module() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-pull").unwrap();
    let server = LocalDaemonServer::start(&temp, true);
    let dest = temp.path().join("dest");
    let source = format!("{}/public/file.txt", server.url);

    let output = run_rsync_with_timeout([
        "-r",
        "--whole-file",
        &source,
        dest.to_string_lossy().as_ref(),
    ]);

    assert!(
        output.status.success(),
        "daemon server pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(dest.join("file.txt")).unwrap(),
        b"small fixture".to_vec()
    );
}

#[test]
fn local_daemon_server_serves_pull_with_posix_metadata_options() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-pull-metadata").unwrap();
    let server = LocalDaemonServer::start(&temp, true);
    let dest = temp.path().join("dest");
    let source = format!("{}/public/file.txt", server.url);

    let output = run_rsync_with_timeout([
        "-r",
        "--whole-file",
        "--owner",
        "--group",
        "--numeric-ids",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--atimes",
        "--crtimes",
        &source,
        dest.to_string_lossy().as_ref(),
    ]);

    assert!(
        output.status.success(),
        "daemon metadata pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(dest.join("file.txt")).unwrap(),
        b"small fixture".to_vec()
    );
}

#[test]
fn local_daemon_server_accepts_push_to_writable_module() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-push").unwrap();
    let server = LocalDaemonServer::start(&temp, false);
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("upload.txt"), b"small upload fixture").unwrap();
    let destination = format!("{}/public/upload", server.url);

    let output = run_rsync_with_timeout([
        "-r",
        "--whole-file",
        source.to_string_lossy().as_ref(),
        &destination,
    ]);

    assert!(
        output.status.success(),
        "daemon server push failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(server.module_root.join("upload").join("upload.txt")).unwrap(),
        b"small upload fixture".to_vec()
    );
}

#[test]
fn local_daemon_server_accepts_push_with_posix_metadata_options() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-push-metadata").unwrap();
    let server = LocalDaemonServer::start(&temp, false);
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("upload.txt"), b"metadata upload fixture").unwrap();
    let destination = format!("{}/public/upload", server.url);

    let output = run_rsync_with_timeout([
        "-r",
        "--whole-file",
        "--owner",
        "--group",
        "--numeric-ids",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--atimes",
        "--crtimes",
        "--chmod=u=rw,go=r",
        source.to_string_lossy().as_ref(),
        &destination,
    ]);

    assert!(
        output.status.success(),
        "daemon metadata push failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(server.module_root.join("upload").join("upload.txt")).unwrap(),
        b"metadata upload fixture".to_vec()
    );
}

#[test]
fn local_daemon_server_rejects_push_to_read_only_module() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-read-only").unwrap();
    let server = LocalDaemonServer::start(&temp, true);
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("blocked.txt"), b"blocked").unwrap();
    let destination = format!("{}/public/upload", server.url);

    let output = run_rsync_with_timeout([
        "-r",
        "--whole-file",
        source.to_string_lossy().as_ref(),
        &destination,
    ]);

    assert!(
        !output.status.success(),
        "daemon server unexpectedly accepted read-only push; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!server.module_root.join("upload").exists());
}

#[test]
fn local_daemon_server_authenticates_valid_user_for_pull() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-auth-pull").unwrap();
    let server = LocalDaemonServer::start_authenticated(&temp, true, false);
    let dest = temp.path().join("dest");
    let source = format!("{}/public/file.txt", server.user_url("alice"));

    let output = run_rsync_with_timeout_env(
        [
            "-r",
            "--whole-file",
            &source,
            dest.to_string_lossy().as_ref(),
        ],
        &[("RSYNC_PASSWORD", "secret")],
    );

    assert!(
        output.status.success(),
        "daemon auth pull failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(dest.join("file.txt")).unwrap(),
        b"small fixture".to_vec()
    );
}

#[test]
fn local_daemon_server_rejects_invalid_password() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-auth-bad-password").unwrap();
    let server = LocalDaemonServer::start_authenticated(&temp, true, false);
    let dest = temp.path().join("dest");
    let source = format!("{}/public/file.txt", server.user_url("alice"));

    let output = run_rsync_with_timeout_env(
        [
            "-r",
            "--whole-file",
            &source,
            dest.to_string_lossy().as_ref(),
        ],
        &[("RSYNC_PASSWORD", "wrong")],
    );

    assert!(
        !output.status.success(),
        "daemon accepted invalid password; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!dest.join("file.txt").exists());
}

#[test]
fn local_daemon_server_rejects_missing_auth_user() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-auth-missing-user").unwrap();
    let server = LocalDaemonServer::start_authenticated(&temp, true, false);
    let dest = temp.path().join("dest");
    let source = format!("{}/public/file.txt", server.url);

    let output = run_rsync_with_timeout_env(
        [
            "-r",
            "--whole-file",
            &source,
            dest.to_string_lossy().as_ref(),
        ],
        &[
            ("RSYNC_PASSWORD", "secret"),
            ("USER", ""),
            ("LOGNAME", ""),
            ("USERNAME", ""),
        ],
    );

    assert!(
        !output.status.success(),
        "daemon accepted missing user; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!dest.join("file.txt").exists());
}

#[test]
fn local_daemon_server_rejects_auth_push_to_read_only_module() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-auth-read-only").unwrap();
    let server = LocalDaemonServer::start_authenticated(&temp, true, false);
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("blocked.txt"), b"blocked").unwrap();
    let destination = format!("{}/public/upload", server.user_url("alice"));

    let output = run_rsync_with_timeout_env(
        [
            "-r",
            "--whole-file",
            source.to_string_lossy().as_ref(),
            &destination,
        ],
        &[("RSYNC_PASSWORD", "secret")],
    );

    assert!(
        !output.status.success(),
        "daemon accepted auth push to read-only module; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!server.module_root.join("upload").exists());
}

#[test]
fn local_daemon_server_accepts_auth_push_to_writable_module() {
    let temp = FixtureTempDir::new("rsync-win-daemon-server-auth-push").unwrap();
    let server = LocalDaemonServer::start_authenticated(&temp, false, false);
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("upload.txt"), b"authenticated upload").unwrap();
    let destination = format!("{}/public/upload", server.user_url("alice"));

    let output = run_rsync_with_timeout_env(
        [
            "-r",
            "--whole-file",
            source.to_string_lossy().as_ref(),
            &destination,
        ],
        &[("RSYNC_PASSWORD", "secret")],
    );

    assert!(
        output.status.success(),
        "daemon auth push failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(server.module_root.join("upload").join("upload.txt")).unwrap(),
        b"authenticated upload".to_vec()
    );
}

fn daemon_url_fixture(name: &str) -> Option<String> {
    match env::var(DAEMON_URL_ENV) {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_URL=rsync://host:port to enable daemon interop"),
            );
            None
        }
    }
}

fn daemon_pull_fixture(name: &str) -> Option<(String, String, String)> {
    let url = daemon_url_fixture(name)?;
    let module = match env::var(DAEMON_MODULE_ENV) {
        Ok(module) if !module.trim().is_empty() => module,
        _ => {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_MODULE to enable daemon pull interop"),
            );
            return None;
        }
    };
    let path = match env::var(DAEMON_PATH_ENV) {
        Ok(path) if !path.trim().is_empty() => path,
        _ => {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_PATH to a readable fixture path"),
            );
            return None;
        }
    };
    Some((url, module, path))
}

fn daemon_auth_pull_fixture(name: &str) -> Option<(String, String, String, String, PathBuf)> {
    let url = daemon_url_fixture(name)?;
    let module = env::var(DAEMON_AUTH_MODULE_ENV)
        .ok()
        .filter(|module| !module.trim().is_empty())
        .or_else(|| env::var(DAEMON_MODULE_ENV).ok())
        .filter(|module| !module.trim().is_empty())
        .unwrap_or_else(|| {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_AUTH_MODULE or RSYNC_WIN_DAEMON_MODULE for authenticated daemon interop"),
            );
            String::new()
        });
    if module.is_empty() {
        return None;
    }
    let path = env::var(DAEMON_AUTH_PATH_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
        .or_else(|| env::var(DAEMON_PATH_ENV).ok())
        .filter(|path| !path.trim().is_empty())
        .unwrap_or_else(|| {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_AUTH_PATH or RSYNC_WIN_DAEMON_PATH for authenticated daemon interop"),
            );
            String::new()
        });
    if path.is_empty() {
        return None;
    }
    let (user, password_file) = daemon_auth_fixture(name)?;
    Some((url, module, path, user, password_file))
}

fn daemon_writable_auth_fixture(name: &str) -> Option<(String, String, String, PathBuf)> {
    let url = daemon_url_fixture(name)?;
    let module = match env::var(DAEMON_WRITABLE_MODULE_ENV) {
        Ok(module) if !module.trim().is_empty() => module,
        _ => {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_WRITABLE_MODULE to enable daemon push interop"),
            );
            return None;
        }
    };
    let (user, password_file) = daemon_auth_fixture(name)?;
    Some((url, module, user, password_file))
}

fn daemon_auth_fixture(name: &str) -> Option<(String, PathBuf)> {
    let user = match env::var(DAEMON_USER_ENV) {
        Ok(user) if !user.trim().is_empty() => user,
        _ => {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_USER for authenticated daemon interop"),
            );
            return None;
        }
    };
    let password_file = match env::var_os(DAEMON_PASSWORD_FILE_ENV) {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            skip_external_test(
                name,
                Some("set RSYNC_WIN_DAEMON_PASSWORD_FILE for authenticated daemon interop"),
            );
            return None;
        }
    };
    Some((user, password_file))
}

fn daemon_url_with_user(url: &str, user: &str, module: &str, path: &str) -> String {
    let base = url.trim_end_matches('/');
    let user_base = base
        .strip_prefix("rsync://")
        .map(|rest| format!("rsync://{user}@{rest}"))
        .unwrap_or_else(|| format!("{user}@{base}"));
    format!(
        "{}/{}/{}",
        user_base,
        module.trim_matches('/'),
        path.trim_start_matches('/')
    )
}

fn cleanup_daemon_test_dir(
    url: &str,
    module: &str,
    user: &str,
    password_file: &PathBuf,
    path: &str,
    temp_root: &std::path::Path,
) {
    let empty = temp_root.join("empty-cleanup");
    let _ = fs::create_dir_all(&empty);
    let destination = daemon_url_with_user(url, user, module, path);
    let _ = Command::new(rsync_win_binary())
        .args([
            "-r",
            "--delete",
            "--password-file",
            password_file.to_string_lossy().as_ref(),
            empty.to_string_lossy().as_ref(),
            &destination,
        ])
        .output();
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn unused_local_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

struct LocalDaemonServer {
    child: Child,
    url: String,
    module_root: PathBuf,
}

impl LocalDaemonServer {
    fn start(temp: &FixtureTempDir, read_only: bool) -> Self {
        Self::start_with_options(temp, read_only, false, false)
    }

    fn start_authenticated(temp: &FixtureTempDir, read_only: bool, write_only: bool) -> Self {
        Self::start_with_options(temp, read_only, write_only, true)
    }

    fn start_with_options(
        temp: &FixtureTempDir,
        read_only: bool,
        write_only: bool,
        auth: bool,
    ) -> Self {
        let module_root = temp.path().join("module root");
        fs::create_dir_all(&module_root).unwrap();
        fs::write(module_root.join("file.txt"), b"small fixture").unwrap();
        let config = temp.path().join("rsyncd.conf");
        let auth_config = if auth {
            let secrets = temp.path().join("rsyncd.secrets");
            write_password_file(&secrets, "alice:secret\n");
            format!(
                "    auth users = alice\n    secrets file = {}\n",
                secrets.display()
            )
        } else {
            String::new()
        };
        fs::write(
            &config,
            format!(
                "[public]\n    path = {}\n    comment = Disposable module\n    read only = {}\n    write only = {}\n{}",
                module_root.display(),
                if read_only { "true" } else { "false" },
                if write_only { "true" } else { "false" },
                auth_config
            ),
        )
        .unwrap();
        let port = unused_local_port();
        let child = Command::new(rsync_win_binary())
            .args([
                "--daemon",
                "--no-detach",
                "--config",
                config.to_string_lossy().as_ref(),
                "--address",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            url: format!("rsync://127.0.0.1:{port}"),
            module_root,
        };
        server.wait_until_ready();
        server
    }

    fn user_url(&self, user: &str) -> String {
        self.url
            .strip_prefix("rsync://")
            .map(|rest| format!("rsync://{user}@{rest}"))
            .unwrap_or_else(|| format!("{user}@{}", self.url))
    }

    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("daemon server exited early with {status}");
            }

            let output = run_rsync_with_timeout(["--list-only", self.url.as_str()]);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if output.status.success() && stdout.contains("- public\tDisposable module") {
                return;
            }
            if Instant::now() >= deadline {
                let stderr = String::from_utf8_lossy(&output.stderr);
                panic!(
                    "daemon server did not become ready; last stdout: {stdout}; last stderr: {stderr}"
                );
            }
            sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for LocalDaemonServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_rsync_with_timeout<const N: usize>(args: [&str; N]) -> Output {
    run_rsync_with_timeout_env(args, &[])
}

fn run_rsync_with_timeout_env<const N: usize>(args: [&str; N], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(rsync_win_binary());
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "rsync-win command timed out; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        sleep(Duration::from_millis(50));
    }
}

fn write_password_file(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
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
