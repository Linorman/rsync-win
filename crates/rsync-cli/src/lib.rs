mod app;
pub mod batch;
mod cli;
mod daemon_server;
mod execute;
mod format;
pub mod options;
pub mod output;
mod plan;
mod remote;
mod transfer;

pub use app::{
    build_command, parse_and_execute, parse_and_render, parse_and_render_result, run_from_env,
    run_from_env_main, supported_protocol_range, version_output,
};
pub(crate) use app::{
    checked_file_index, delete_local_extras, read_multiplexed_rsync31_index,
    receive_remote_sender_files_protocol31, remote_entry_is_top_dir, remote_file_index_offset,
    request_remote_sender_files_protocol31, selected_remote_entries, selected_remote_entry_indexes,
    selected_remote_transfer_indexes, sort_remote_entries_for_sender_indexes,
    validate_remote_file_list_paths, windows_destination_path_preflight, write_rsync31_done,
    write_rsync31_index, RemoteReceiveContext,
};
pub use cli::{Cli, CliMetadataPolicy};
pub(crate) use output::ProgressLog;
pub(crate) use remote::flist::{
    collect_local_source_entries, LocalSourceCollectOptions, RemoteSourceEntry,
};
pub(crate) use rsync_protocol::{read_multiplexed_i32, RemoteSessionError};
pub(crate) use transfer::{
    read_remote_block_signatures_from_reader, read_rsync31_optional_item_attrs, read_sum_head,
    write_delta_tokens_from_path, write_rsync31_optional_item_attrs, write_sum_head,
    DeltaWriteRuntime, RemoteCompressionConfig, RemoteExecutionStats, RemoteFileChecksum,
    RemoteFinalChecksum, RSYNC31_MUX_FRAME_SIZE, RSYNC_ITEM_TRANSFER,
};
