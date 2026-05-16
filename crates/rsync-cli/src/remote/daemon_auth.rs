use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use rsync_protocol::DaemonOperand;

pub(crate) fn daemon_auth_user(daemon: &DaemonOperand) -> Result<String> {
    if let Some(user) = daemon.user.as_deref() {
        return normalize_daemon_auth_user(user)
            .context("daemon auth username is empty or contains a NUL byte");
    }

    local_daemon_auth_user().context(
        "daemon module requires auth but no username was supplied; use user@host::module or set USER, LOGNAME, or USERNAME",
    )
}

fn local_daemon_auth_user() -> Option<String> {
    daemon_auth_user_from_vars([
        ("USER", std::env::var("USER").ok()),
        ("LOGNAME", std::env::var("LOGNAME").ok()),
        ("USERNAME", std::env::var("USERNAME").ok()),
    ])
}

pub(crate) fn daemon_auth_user_from_vars<I, K>(vars: I) -> Option<String>
where
    I: IntoIterator<Item = (K, Option<String>)>,
{
    vars.into_iter()
        .filter_map(|(_, value)| value)
        .find_map(|value| normalize_daemon_auth_user(&value))
}

pub(crate) fn daemon_password(password_file: Option<&Path>) -> Result<String> {
    if let Some(password_file) = password_file {
        return read_password_file(password_file);
    }
    daemon_password_from_vars([("RSYNC_PASSWORD", std::env::var("RSYNC_PASSWORD").ok())])
        .context("daemon module requires auth; pass --password-file or set RSYNC_PASSWORD")
}

pub(crate) fn daemon_password_from_vars<I, K>(vars: I) -> Option<String>
where
    I: IntoIterator<Item = (K, Option<String>)>,
    K: AsRef<str>,
{
    vars.into_iter()
        .filter(|(key, _)| key.as_ref() == "RSYNC_PASSWORD")
        .filter_map(|(_, value)| value)
        .find_map(|value| normalize_daemon_password(&value))
}

fn normalize_daemon_auth_user(value: &str) -> Option<String> {
    let user = value.trim();
    if user.is_empty() || user.as_bytes().contains(&0) {
        None
    } else {
        Some(user.to_string())
    }
}

fn normalize_daemon_password(value: &str) -> Option<String> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        None
    } else {
        Some(value.to_string())
    }
}

pub(crate) fn read_password_file(path: &Path) -> Result<String> {
    validate_password_file(path)?;
    let mut password = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon password file {}", path.display()))?;
    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }
    Ok(password)
}

fn validate_password_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect daemon password file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "daemon password file must be a regular file: {}",
            path.display()
        );
    }
    validate_password_file_permissions(path, &metadata)
}

#[cfg(unix)]
fn validate_password_file_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "daemon password file must not be accessible by group or other users: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_password_file_permissions(path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    if rsync_winfs::password_file_has_broad_access(path).with_context(|| {
        format!(
            "failed to inspect daemon password file ACL {}",
            path.display()
        )
    })? {
        bail!(
            "daemon password file must not grant read access to broad Windows principals: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_password_file_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}
