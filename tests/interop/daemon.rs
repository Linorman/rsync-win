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
        let module_root = temp.path().join("module root");
        fs::create_dir_all(&module_root).unwrap();
        fs::write(module_root.join("file.txt"), b"small fixture").unwrap();
        let config = temp.path().join("rsyncd.conf");
        fs::write(
            &config,
            format!(
                "[public]\n    path = {}\n    comment = Disposable module\n    read only = {}\n",
                module_root.display(),
                if read_only { "true" } else { "false" }
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
    let mut child = Command::new(rsync_win_binary())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
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
