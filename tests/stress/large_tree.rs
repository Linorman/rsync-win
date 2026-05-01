#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::FixtureTempDir;

#[test]
fn local_copy_larger_than_max_alloc_uses_bounded_buffers() {
    let temp = FixtureTempDir::new("rsync-win-large-tree-local").unwrap();
    let source = temp.path().join("source");
    let dest = temp.path().join("dest");
    fs::create_dir_all(&source).unwrap();
    write_pattern_file(&source.join("large.bin"), 2 * 1024 * 1024, 0x11).unwrap();

    let source_arg = format!("{}/", source.display());
    let output = run_rsync_with_timeout([
        "-r",
        "--max-alloc=1K",
        &source_arg,
        dest.to_string_lossy().as_ref(),
    ]);

    assert_command_success(&output, "local copy with low max-alloc");
    assert_files_equal(&source.join("large.bin"), &dest.join("large.bin"));
}

#[test]
fn daemon_push_rejects_file_list_over_max_alloc_before_mutating_receiver() {
    let temp = FixtureTempDir::new("rsync-win-large-tree-push-budget").unwrap();
    let server = LocalDaemonServer::start(&temp, false);
    let source = temp.path().join("source");
    create_many_small_files(&source, 200).unwrap();

    let source_arg = format!("{}/", source.display());
    let dest_arg = format!("{}/public/", server.url);
    let output = run_rsync_with_timeout(["-r", "--max-alloc=1K", &source_arg, &dest_arg]);

    assert_command_failure_contains(&output, "max-alloc");
    assert_eq!(count_regular_files(&server.module_root), 0);
}

#[test]
fn daemon_pull_rejects_file_list_over_max_alloc_before_mutating_receiver() {
    let temp = FixtureTempDir::new("rsync-win-large-tree-pull-budget").unwrap();
    let server = LocalDaemonServer::start(&temp, true);
    create_many_small_files(&server.module_root, 200).unwrap();
    let dest = temp.path().join("dest");

    let source_arg = format!("{}/public/", server.url);
    let output = run_rsync_with_timeout([
        "-r",
        "--max-alloc=1K",
        &source_arg,
        dest.to_string_lossy().as_ref(),
    ]);

    assert_command_failure_contains(&output, "max-alloc");
    assert!(
        !dest.exists(),
        "destination was created before file-list budget rejection"
    );
}

#[test]
fn daemon_pull_rejects_basis_block_over_max_alloc_before_replacing_file() {
    let temp = FixtureTempDir::new("rsync-win-large-tree-basis-budget").unwrap();
    let server = LocalDaemonServer::start(&temp, true);
    let source_file = server.module_root.join("large.bin");
    write_pattern_file(&source_file, 512 * 1024, 0x22).unwrap();

    let dest = temp.path().join("dest");
    fs::create_dir_all(&dest).unwrap();
    let basis_file = dest.join("large.bin");
    write_pattern_file(&basis_file, 512 * 1024, 0x23).unwrap();
    let before = fs::read(&basis_file).unwrap();

    let source_arg = format!("{}/public/large.bin", server.url);
    let output = run_rsync_with_timeout([
        "-r",
        "--block-size=128K",
        "--max-alloc=64K",
        &source_arg,
        dest.to_string_lossy().as_ref(),
    ]);

    assert_command_failure_contains(&output, "max-alloc");
    assert_eq!(fs::read(&basis_file).unwrap(), before);
}

fn create_many_small_files(root: &Path, count: usize) -> io::Result<()> {
    fs::create_dir_all(root)?;
    for index in 0..count {
        let dir = root.join(format!("dir-{index:04}"));
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(format!("file-{index:04}.txt")), b"payload")?;
    }
    Ok(())
}

fn count_regular_files(root: &Path) -> usize {
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let ty = entry.file_type().unwrap();
            if ty.is_dir() {
                stack.push(entry.path());
            } else if ty.is_file() {
                count += 1;
            }
        }
    }
    count
}

fn write_pattern_file(path: &Path, len: usize, seed: u8) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    let mut remaining = len;
    let mut offset = 0_usize;
    let mut buf = [0_u8; 32 * 1024];
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        for (index, byte) in buf[..chunk].iter_mut().enumerate() {
            *byte = seed.wrapping_add(((offset + index) % 251) as u8);
        }
        file.write_all(&buf[..chunk])?;
        remaining -= chunk;
        offset += chunk;
    }
    Ok(())
}

fn assert_files_equal(expected: &Path, actual: &Path) {
    let expected_bytes = fs::read(expected).unwrap();
    let actual_bytes = fs::read(actual).unwrap();
    assert_eq!(actual_bytes, expected_bytes);
}

fn assert_command_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_command_failure_contains(output: &Output, needle: &str) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(needle),
        "output did not contain `{needle}`; combined output: {combined}"
    );
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
    let deadline = Instant::now() + Duration::from_secs(30);
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
