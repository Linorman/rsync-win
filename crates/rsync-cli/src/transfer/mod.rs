mod checksum;
mod delta;
mod fs_ops;
mod limits;
mod progress;
mod sum_head;
mod tokens;

mod prelude {
    pub(super) use std::fs::{self, File};
    pub(super) use std::io::{Read, Seek, SeekFrom, Write};
    pub(super) use std::path::{Path, PathBuf};
    pub(super) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    pub(super) use anyhow::{bail, Context, Result};
    pub(super) use digest::Digest;
    #[cfg(test)]
    pub(super) use rsync_delta::DeltaToken;
    pub(super) use rsync_delta::{rolling_checksum, BlockSignature, StrongChecksum};
    pub(super) use rsync_protocol::{
        read_i32_le, read_multiplexed_i32, read_u8, read_vstring, write_i32_le, write_rsync_i32,
        write_vstring, MultiplexReadState, MultiplexedReader, RemoteSessionError,
        RsyncDeflatedToken, RsyncDeflatedTokenMode, RsyncDeflatedTokenReader,
        RsyncDeflatedTokenWriter, RsyncMd4Checksum,
    };
    pub(super) use rsync_winfs::to_long_path_safe;

    pub(super) use crate::format::{format_bytes, transfer_rate_label};
    pub(super) use crate::output::ProgressLog;
    pub(super) use crate::plan::{check_transfer_deadline, TransferPlan};
}

#[cfg(test)]
pub(crate) use checksum::{
    remote_checksum_for_bytes, remote_file_checksum_builder, remote_final_checksum_for_bytes,
};
pub(crate) use checksum::{RemoteFileChecksum, RemoteFinalChecksum};
#[cfg(test)]
pub(crate) use delta::write_delta_tokens_from_bytes_with_checksum;
pub(crate) use delta::{
    local_basis_signature_request, read_remote_block_signatures_from_reader,
    read_remote_block_signatures_multiplexed, remote_delta_block_size,
    write_delta_tokens_from_path, write_remote_block_signatures, DeltaWriteRuntime,
};
pub(crate) use fs_ops::{
    open_local_file, read_local_file, receive_temp_path, remove_local_file_best_effort,
};
pub(crate) use limits::sync_action_len;
pub(crate) use progress::{
    FileProgress, RemoteCompressionConfig, RemoteExecutionStats, RemoteTransferRuntime,
    REMOTE_FILE_LIST_BATCH_ENTRIES, RSYNC31_MUX_FRAME_SIZE,
};
#[cfg(test)]
pub(crate) use sum_head::RSYNC_ITEM_BASIS_TYPE_FOLLOWS;
pub(crate) use sum_head::{
    read_rsync31_optional_item_attrs, read_sum_head, remote_sum_head_file_len,
    write_rsync31_optional_item_attrs, write_sum_head, RemoteSumHead, RSYNC_ITEM_IS_NEW,
    RSYNC_ITEM_LOCAL_CHANGE, RSYNC_ITEM_TRANSFER,
};
pub(crate) use tokens::{
    read_file_tokens_to_path_with_basis, write_append_verify_file_tokens_from_path,
};
#[cfg(test)]
pub(crate) use tokens::{
    write_append_verify_literal_tokens_from_reader_with_checksum,
    write_literal_tokens_from_reader_with_checksum,
};
