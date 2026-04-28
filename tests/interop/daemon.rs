#[allow(dead_code)]
#[path = "../common/mod.rs"]
mod common;

use std::env;
use std::path::PathBuf;
use std::process::Command;

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
