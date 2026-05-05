use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).unwrap_or_else(|err| {
        panic!("failed to read {relative}: {err}");
    })
}

#[test]
fn release_script_runs_required_smoke_gates() {
    let script = read_repo_file("scripts/package-release.ps1");

    for required in [
        "rsync-win.exe --version",
        "rsync-win.exe --help",
        "--delete",
        "--exclude=*.tmp",
        "RSYNC_WIN_SSH_TARGET",
        "RSYNC_WIN_SSH_TMP_ROOT",
        "SHA256",
        "Release zip is missing",
    ] {
        assert!(
            script.contains(required),
            "package-release.ps1 should contain release gate `{required}`"
        );
    }
}

#[test]
fn ci_runs_stable_and_msrv_windows_jobs() {
    let ci = read_repo_file(".github/workflows/ci.yml");

    for required in [
        "matrix:",
        "stable",
        "1.76.0",
        "cargo fmt --all -- --check",
        "cargo clippy --workspace --all-features -- -D warnings",
        "cargo test --workspace --all-features",
        ".\\scripts\\package-release.ps1",
    ] {
        assert!(ci.contains(required), "ci.yml should contain `{required}`");
    }
}

#[test]
fn release_candidate_metadata_is_frozen_in_docs() {
    let cargo = read_repo_file("Cargo.toml");
    let readme = read_repo_file("README.md");
    let compatibility = read_repo_file("docs/COMPATIBILITY.md");
    let release_notes = read_repo_file("docs/RELEASE-NOTES-TEMPLATE.md");
    let lock = read_repo_file("Cargo.lock");

    assert!(cargo.contains("version = \"0.2.0-rc1\""));
    assert!(cargo.contains("clap = { version = \">=4.5,<4.6\""));
    assert!(
        lock.contains("name = \"clap_lex\"\nversion = \"1.0.0\""),
        "Cargo.lock should keep clap_lex on a Cargo 1.76-compatible release"
    );
    assert!(readme.contains("v0.2.0-rc1"));
    assert!(compatibility.contains("Windows 10"));
    assert!(compatibility.contains("Windows 11"));
    assert!(compatibility.contains("Windows Server"));
    assert!(compatibility.contains("upstream rsync 3.2"));
    assert!(compatibility.contains("Max tested file size"));
    assert!(compatibility.contains("Max tested file count"));
    assert!(compatibility.contains("local delete/filter smoke"));
    assert!(compatibility.contains("optional SSH smoke"));
    assert!(release_notes.contains("Daemon push"));
    assert!(release_notes.contains("VSS snapshot reads"));
    assert!(!release_notes.contains("- Daemon push."));
    assert!(!release_notes.contains("- VSS snapshot reads."));
}
