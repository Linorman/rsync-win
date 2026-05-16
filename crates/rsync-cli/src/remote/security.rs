use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use rsync_fs::FsError;
use rsync_protocol::{RsyncFileListEntry, TransferDirection};

use super::receive::{
    remote_entry_is_top_dir, remote_receiver_path_is_filtered, remote_source_path_is_filtered,
};
use crate::plan::TransferPlan;

pub(crate) fn windows_destination_path_preflight(paths: &[PathBuf]) -> Result<(), FsError> {
    rsync_winfs::path::preflight_destination_paths(paths)
        .map_err(|err| FsError::DestinationPathPreflight(err.to_string()))
}

pub(crate) fn validate_remote_file_list_paths(entries: &[RsyncFileListEntry]) -> Result<()> {
    let destination_relatives: Vec<_> = entries
        .iter()
        .filter(|entry| !remote_entry_is_top_dir(entry))
        .map(|entry| entry.path.clone())
        .collect();
    windows_destination_path_preflight(&destination_relatives)?;
    Ok(())
}

pub(crate) fn validate_remote_sender_claims(
    plan: &TransferPlan,
    entries: &[RsyncFileListEntry],
    _files_from: Option<&[PathBuf]>,
) -> Result<()> {
    if plan.trust_sender {
        return Ok(());
    }
    let allowed_single_file_sources = if plan.old_args {
        Vec::new()
    } else {
        remote_single_file_source_basenames(plan)
    };
    for entry in entries {
        if remote_entry_is_top_dir(entry) {
            continue;
        }
        if !remote_entry_matches_single_file_sources(&entry.path, &allowed_single_file_sources) {
            bail!(
                "remote sender sent unrequested path `{}`; use --trust-sender to accept remote file-list names",
                entry.path.display()
            );
        }
        if remote_source_path_is_filtered(&plan.filter_rules, &entry.path, entry.file_type)
            || remote_receiver_path_is_filtered(&plan.filter_rules, &entry.path, entry.file_type)
        {
            bail!(
                "remote sender sent filtered path `{}`; use --trust-sender to accept remote file-list names",
                entry.path.display()
            );
        }
    }
    Ok(())
}

fn remote_single_file_source_basenames(plan: &TransferPlan) -> Vec<String> {
    if plan.remote_direction != Some(TransferDirection::Pull) {
        return Vec::new();
    }
    plan.remote_operands
        .iter()
        .filter_map(|operand| remote_single_file_source_basename(&operand.path))
        .collect()
}

fn remote_single_file_source_basename(path: &str) -> Option<String> {
    if path.ends_with('/') || path.ends_with('\\') {
        return None;
    }
    let normalized = path.replace('\\', "/");
    let basename = normalized.rsplit('/').next()?.trim();
    if basename.is_empty() || !basename.contains('.') {
        return None;
    }
    Some(basename.to_string())
}

fn remote_entry_matches_single_file_sources(relative: &Path, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let relative = relative.to_string_lossy().replace('\\', "/");
    allowed
        .iter()
        .any(|basename| relative == *basename || relative.starts_with(&format!("{basename}/")))
}
