use super::*;
use crate::batch;
use crate::execute::daemon_client::execute_daemon_sync_with_transport;
use crate::execute::local::ntfs_sidecar_root;
use crate::remote::daemon_auth::{
    daemon_auth_user, daemon_auth_user_from_vars, daemon_password_from_vars, read_password_file,
};
use crate::remote::flist::*;
use crate::remote::pull::execute_remote_pull;
use crate::remote::push::execute_remote_push;
use crate::remote::receive::{
    delete_local_extras, selected_remote_entry_indexes, sort_remote_entries_for_sender_indexes,
};
use crate::remote::security::windows_destination_path_preflight;
use crate::remote::session::{protocol31_setup_error, should_fallback_to_protocol27};
use crate::transfer::*;
use clap::Parser;
use rsync_core::ChmodRules;

use rsync_filter::{Rule, RuleSet};
use rsync_fs::{FsError, LocalFileSystem, SymlinkMode, SyncAction};
use rsync_protocol::{
    write_i32_le, write_rsync31_file_list_with_options, write_rsync_index, write_u16_le,
    DaemonOperand, MultiplexReadState, RemoteSessionError, RsyncDeflatedTokenMode,
    RsyncFileListEntry, RsyncFileListMetadata, RsyncIndexState, RsyncMd4Checksum, SessionError,
    WireFileType, RSYNC_DIRECTORY_MODE, RSYNC_INDEX_DONE, RSYNC_INDEX_FLIST_EOF,
    RSYNC_INDEX_FLIST_OFFSET, RSYNC_REGULAR_FILE_MODE,
};
use rsync_winfs::to_long_path_safe;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod chunk12;
mod core;
mod daemon;
mod local;
mod remote;
mod support;

use support::*;
