mod actions;
mod names;
mod report;

mod prelude {
    pub(super) use std::path::Path;
    pub(super) use std::time::Duration;

    pub(super) use anyhow::Result;
    pub(super) use rsync_core::{MetadataFeature, Report, Severity};
    pub(super) use rsync_fs::{DeleteMode, FileWriteMode, SymlinkMode, SyncAction, UpdateMode};
    pub(super) use rsync_protocol::WireFileType;

    pub(super) use crate::cli::Cli;
    pub(super) use crate::output;
    pub(super) use crate::output::ProgressLog;
    pub(super) use crate::remote::flist::RemoteSourceEntry;
}

pub(crate) use actions::{
    append_action_report, append_out_format_and_client_log,
    append_remote_source_out_format_and_client_log, log_sync_actions, metadata_code,
};
pub(crate) use names::{format_bytes, transfer_rate_label};
pub(crate) use report::{
    append_diagnostics, delete_mode_label, file_write_mode_label, severity_label,
    symlink_mode_label, update_mode_label,
};
