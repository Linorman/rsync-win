use super::*;

pub(super) fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
    path
}

pub(super) fn write_test_password_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

pub(super) fn test_remote_entry(path: &str, file_type: WireFileType) -> RsyncFileListEntry {
    RsyncFileListEntry {
        path: PathBuf::from(path),
        file_type,
        len: 0,
        mtime_unix: 0,
        mode: match file_type {
            WireFileType::Directory => RSYNC_DIRECTORY_MODE,
            _ => RSYNC_REGULAR_FILE_MODE,
        },
        checksum: None,
        hardlink_group: None,
        metadata: RsyncFileListMetadata::default(),
    }
}

#[cfg(windows)]
pub(super) fn test_stream_data_path(path: &Path, stream_name: &str) -> PathBuf {
    let mut stream_path = to_long_path_safe(path).into_os_string();
    stream_path.push(format!(":{stream_name}"));
    PathBuf::from(stream_path)
}

pub(super) fn ntfs_sidecar_source_paths(dest: &Path) -> BTreeSet<PathBuf> {
    fs::read_dir(ntfs_sidecar_root(dest))
        .unwrap()
        .map(|entry| {
            let manifest = fs::read_to_string(entry.unwrap().path()).unwrap();
            rsync_winfs::parse_ntfs_native_sidecar_manifest(&manifest)
                .unwrap()
                .sidecar
                .path
        })
        .collect()
}

#[cfg(windows)]
pub(super) fn security_dacl_fragment(sddl: &str) -> &str {
    let Some(start) = sddl.find("D:") else {
        return "";
    };
    let rest = &sddl[start..];
    let end = rest.find("S:").unwrap_or(rest.len());
    &rest[..end]
}

pub(super) fn test_remote_block_signatures(
    basis: &[u8],
    block_size: usize,
    checksum_len: usize,
    checksum: RemoteFileChecksum,
) -> Vec<rsync_delta::BlockSignature> {
    basis
        .chunks(block_size)
        .enumerate()
        .map(|(index, block)| {
            let mut strong = remote_file_checksum_builder(checksum);
            strong.update(block);
            rsync_delta::BlockSignature {
                index,
                offset: index * block_size,
                len: block.len(),
                weak: rsync_delta::rolling_checksum(block),
                strong: strong.finalize()[..checksum_len].to_vec(),
            }
        })
        .collect()
}

pub(super) fn remote_push_dry_run_input() -> Vec<u8> {
    let mut input = remote_handshake_input();
    append_remote_push_dry_run_response(&mut input);
    input
}

pub(super) fn daemon_push_dry_run_input() -> Vec<u8> {
    let mut input = daemon_protocol31_setup_input();
    append_remote_push_dry_run_response(&mut input);
    input
}

pub(super) fn append_remote_push_dry_run_response(input: &mut Vec<u8>) {
    append_mux_payload(
        input,
        &[
            1,
            (RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) as u8,
            ((RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) >> 8) as u8,
        ],
    );
    append_mux_payload(input, &[0]);
    append_mux_payload(input, &[0]);
    append_mux_payload(input, &[0]);
    append_mux_payload(input, &[0]);
    append_mux_payload(input, &[0]);
    append_mux_payload(input, &[0]);
    append_mux_payload(input, &[0]);
}

pub(super) fn remote_push_transfer_request_input(index: i32) -> Vec<u8> {
    let mut input = remote_handshake_input();
    let mut request = Vec::new();
    let mut state = RsyncIndexState::default();
    write_rsync_index(&mut request, &mut state, index).unwrap();
    write_u16_le(
        &mut request,
        RSYNC_ITEM_TRANSFER | RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE,
    )
    .unwrap();
    write_sum_head(
        &mut request,
        RemoteSumHead {
            block_count: 0,
            block_len: 0,
            checksum_len: 0,
            remainder: 0,
        },
    )
    .unwrap();
    append_mux_payload(&mut input, &request);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    input
}

pub(super) fn remote_push_append_verify_input() -> Vec<u8> {
    remote_push_append_verify_input_with_sum_head(RemoteSumHead {
        block_count: 1,
        block_len: 3,
        checksum_len: 2,
        remainder: 0,
    })
}

pub(super) fn remote_push_append_verify_oversized_basis_input() -> Vec<u8> {
    remote_push_append_verify_input_with_sum_head(RemoteSumHead {
        block_count: 3,
        block_len: 3,
        checksum_len: 2,
        remainder: 0,
    })
}

pub(super) fn remote_push_append_verify_input_with_sum_head(sum_head: RemoteSumHead) -> Vec<u8> {
    let mut input = remote_handshake_input();
    let mut request = Vec::new();
    let mut state = RsyncIndexState::default();
    write_rsync_index(&mut request, &mut state, 1).unwrap();
    write_u16_le(
        &mut request,
        RSYNC_ITEM_TRANSFER | RSYNC_ITEM_BASIS_TYPE_FOLLOWS,
    )
    .unwrap();
    request.push(0);
    write_sum_head(&mut request, sum_head).unwrap();
    append_mux_payload(&mut input, &request);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    input
}

pub(super) fn remote_push_unsupported_mux_input() -> Vec<u8> {
    let mut input = remote_handshake_input();
    append_mux_frame(&mut input, 6, &[]);
    input
}

pub(super) fn remote_push_final_unsupported_mux_input() -> Vec<u8> {
    let mut input = remote_handshake_input();
    append_mux_payload(
        &mut input,
        &[
            1,
            (RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) as u8,
            ((RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) >> 8) as u8,
        ],
    );
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_frame(&mut input, 6, &[]);
    input
}

pub(super) fn remote_pull_dry_run_input() -> Vec<u8> {
    remote_pull_dry_run_input_with_entries(
        &[
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 0,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ],
        1,
    )
}

pub(super) fn daemon_pull_dry_run_input() -> Vec<u8> {
    remote_pull_dry_run_mux_input_with_entries(
        &[
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 0,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ],
        1,
    )
}

pub(super) fn daemon_protocol31_setup_input() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&[0x81, 0xff]);
    input.push(35);
    input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
    input.extend_from_slice(&0_i32.to_le_bytes());
    input
}

pub(super) fn remote_pull_file_list_only_input(entries: &[RsyncFileListEntry]) -> Vec<u8> {
    let mut input = remote_handshake_input();
    let mut flist = Vec::new();
    write_rsync31_file_list_with_options(&mut flist, entries, false).unwrap();
    append_mux_payload(&mut input, &flist);
    input
}

pub(super) fn remote_pull_transfer_input(
    path: &str,
    advertised_len: u64,
    literal_chunks: &[&[u8]],
) -> Vec<u8> {
    let mut checksum = RsyncMd4Checksum::plain();
    for chunk in literal_chunks {
        checksum.update(chunk);
    }
    remote_pull_transfer_input_with_checksum(
        path,
        advertised_len,
        literal_chunks,
        checksum.finalize(),
    )
}

pub(super) fn remote_pull_transfer_input_with_checksum(
    path: &str,
    advertised_len: u64,
    literal_chunks: &[&[u8]],
    remote_checksum: [u8; 16],
) -> Vec<u8> {
    let mut input = remote_pull_file_list_only_input(&[
        RsyncFileListEntry {
            path: PathBuf::from("."),
            file_type: WireFileType::Directory,
            len: 0,
            mtime_unix: 0,
            mode: RSYNC_DIRECTORY_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        },
        RsyncFileListEntry {
            path: PathBuf::from(path),
            file_type: WireFileType::File,
            len: advertised_len,
            mtime_unix: 0,
            mode: RSYNC_REGULAR_FILE_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        },
    ]);

    let mut response = Vec::new();
    let mut index_state = RsyncIndexState::default();
    write_rsync_index(&mut response, &mut index_state, 1).unwrap();
    write_u16_le(&mut response, RSYNC_ITEM_TRANSFER | RSYNC_ITEM_IS_NEW).unwrap();
    write_sum_head(
        &mut response,
        RemoteSumHead {
            block_count: 0,
            block_len: 32 * 1024,
            checksum_len: 2,
            remainder: 0,
        },
    )
    .unwrap();

    for chunk in literal_chunks {
        write_i32_le(&mut response, chunk.len() as i32).unwrap();
        response.extend_from_slice(chunk);
    }
    write_i32_le(&mut response, 0).unwrap();
    response.extend_from_slice(&remote_checksum);
    write_rsync_index(&mut response, &mut index_state, RSYNC_INDEX_DONE).unwrap();
    append_mux_payload(&mut input, &response);

    let mut stats = Vec::new();
    for value in [0_u64, 0, advertised_len, 0, 0] {
        rsync_protocol::write_varlong(&mut stats, value, 3).unwrap();
    }
    append_mux_payload(&mut input, &stats);
    append_mux_payload(&mut input, &[0]);
    input
}

pub(super) fn remote_pull_filter_dry_run_input() -> Vec<u8> {
    remote_pull_dry_run_input_with_entries(
        &[
            RsyncFileListEntry {
                path: PathBuf::from("skip.tmp"),
                file_type: WireFileType::File,
                len: 4,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("file.txt"),
                file_type: WireFileType::File,
                len: 5,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ],
        1,
    )
}

pub(super) fn remote_pull_incremental_dry_run_input() -> Vec<u8> {
    let mut input = remote_handshake_input();
    let mut initial_flist = Vec::new();
    write_rsync31_file_list_with_options(
        &mut initial_flist,
        &[
            RsyncFileListEntry {
                path: PathBuf::from("."),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 0,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("dir"),
                file_type: WireFileType::Directory,
                len: 0,
                mtime_unix: 0,
                mode: RSYNC_DIRECTORY_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
            RsyncFileListEntry {
                path: PathBuf::from("root.txt"),
                file_type: WireFileType::File,
                len: 4,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ],
        false,
    )
    .unwrap();
    append_mux_payload(&mut input, &initial_flist);

    let mut response = Vec::new();
    let mut index_state = RsyncIndexState::default();
    write_rsync_index(
        &mut response,
        &mut index_state,
        RSYNC_INDEX_FLIST_OFFSET - 2,
    )
    .unwrap();
    write_rsync31_file_list_with_options(
        &mut response,
        &[RsyncFileListEntry {
            path: PathBuf::from("dir/file.txt"),
            file_type: WireFileType::File,
            len: 5,
            mtime_unix: 0,
            mode: RSYNC_REGULAR_FILE_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        }],
        false,
    )
    .unwrap();
    write_rsync_index(&mut response, &mut index_state, RSYNC_INDEX_FLIST_EOF).unwrap();
    write_rsync_index(&mut response, &mut index_state, 1).unwrap();
    write_u16_le(&mut response, RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE).unwrap();
    write_rsync_index(&mut response, &mut index_state, 3).unwrap();
    write_u16_le(&mut response, RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE).unwrap();
    write_rsync_index(&mut response, &mut index_state, RSYNC_INDEX_DONE).unwrap();
    append_mux_payload(&mut input, &response);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);

    let mut stats = Vec::new();
    for value in [0_u64, 0, 9, 0, 0] {
        rsync_protocol::write_varlong(&mut stats, value, 3).unwrap();
    }
    append_mux_payload(&mut input, &stats);
    append_mux_payload(&mut input, &[0]);
    input
}

pub(super) fn remote_pull_dry_run_input_with_entries(
    entries: &[RsyncFileListEntry],
    response_wire_index: i32,
) -> Vec<u8> {
    let mut input = remote_handshake_input();
    input.extend(remote_pull_dry_run_mux_input_with_entries(
        entries,
        response_wire_index,
    ));
    input
}

pub(super) fn remote_pull_dry_run_mux_input_with_entries(
    entries: &[RsyncFileListEntry],
    response_wire_index: i32,
) -> Vec<u8> {
    let mut input = Vec::new();
    let mut flist = Vec::new();
    write_rsync31_file_list_with_options(&mut flist, entries, false).unwrap();
    append_mux_payload(&mut input, &flist);
    append_mux_payload(
        &mut input,
        &[
            (response_wire_index + 1) as u8,
            (RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) as u8,
            ((RSYNC_ITEM_IS_NEW | RSYNC_ITEM_LOCAL_CHANGE) >> 8) as u8,
        ],
    );
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);
    append_mux_payload(&mut input, &[0]);

    let mut stats = Vec::new();
    for value in [0_u64, 0, 5, 0, 0] {
        rsync_protocol::write_varlong(&mut stats, value, 3).unwrap();
    }
    append_mux_payload(&mut input, &stats);
    append_mux_payload(&mut input, &[0]);
    input
}

pub(super) fn remote_handshake_input() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&31_u32.to_le_bytes());
    input.extend_from_slice(&[0x81, 0xff]);
    input.push(35);
    input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
    input.extend_from_slice(&0_i32.to_le_bytes());
    input
}

pub(super) fn append_mux_payload(out: &mut Vec<u8>, payload: &[u8]) {
    append_mux_frame(out, 7, payload);
}

pub(super) fn append_mux_frame(out: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    let header = (tag << 24) | payload.len() as u32;
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(payload);
}

pub(super) fn written_protocol31_mux_payloads(written: &[u8]) -> Vec<Vec<u8>> {
    let mut pos = 8;
    let mut payloads = Vec::new();
    while pos + 4 <= written.len() {
        let header = u32::from_le_bytes([
            written[pos],
            written[pos + 1],
            written[pos + 2],
            written[pos + 3],
        ]);
        pos += 4;
        let tag = header >> 24;
        let len = (header & 0x00ff_ffff) as usize;
        assert_eq!(tag, 7);
        assert!(pos + len <= written.len());
        payloads.push(written[pos..pos + len].to_vec());
        pos += len;
    }
    assert_eq!(pos, written.len());
    payloads
}

#[derive(Debug)]
pub(super) struct TestTransport {
    pub(super) input: std::io::Cursor<Vec<u8>>,
    pub(super) written: Vec<u8>,
}

impl TestTransport {
    pub(super) fn with_input(input: Vec<u8>) -> Self {
        Self {
            input: std::io::Cursor::new(input),
            written: Vec::new(),
        }
    }
}

impl Read for TestTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for TestTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
