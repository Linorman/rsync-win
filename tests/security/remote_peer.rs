use std::io::Read;
use std::path::PathBuf;

use rsync_protocol::{
    read_rsync31_file_list, read_rsync_long, write_rsync31_file_list_with_options, FileListError,
    MultiplexReadState, MultiplexedReader, RsyncFileListEntry, WireFileType,
    RSYNC_REGULAR_FILE_MODE,
};

#[test]
fn protocol31_reader_rejects_parent_absolute_and_windows_prefixed_paths() {
    for path in [
        "../escape.txt",
        "/escape.txt",
        "C:/escape.txt",
        "//server/share/escape.txt",
        "CON.txt",
        "dir/bad.",
        "dir/bad ",
    ] {
        let err = read_single_protocol31_path(path).unwrap_err();

        assert!(
            err.to_string()
                .contains("not a portable relative rsync path"),
            "{path} should be rejected as an unsafe remote file-list path, got {err:?}"
        );
    }
}

#[test]
fn destination_preflight_detects_case_and_unicode_collisions() {
    for paths in [
        [PathBuf::from("dir/Foo.txt"), PathBuf::from("dir/foo.txt")],
        [
            PathBuf::from("caf\u{00e9}.txt"),
            PathBuf::from("cafe\u{0301}.txt"),
        ],
    ] {
        let err = rsync_winfs::path::preflight_destination_paths(paths).unwrap_err();

        assert!(
            err.to_string().contains("case/normalization collision"),
            "{err}"
        );
    }
}

#[test]
fn protocol31_reader_rejects_excessive_path_lengths() {
    let err = read_rsync31_file_list(
        &mut encoded_protocol31_path("dir/file.txt").as_slice(),
        16,
        4,
    )
    .unwrap_err();

    assert!(err.to_string().contains("exceeds limit 4"), "{err}");
}

#[test]
fn multiplexed_reader_rejects_unsupported_frames_before_payload_reads() {
    let mut bytes = Vec::new();
    write_multiplex_frame(&mut bytes, 6, b"bad");
    let mut state = MultiplexReadState::default();
    let mut input = bytes.as_slice();
    let mut reader = MultiplexedReader::new(&mut input, &mut state);
    let mut one = [0_u8; 1];

    let err = reader.read_exact(&mut one).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string()
            .contains("unsupported multiplex message tag 6"),
        "{err}"
    );
}

#[test]
fn protocol_long_reader_rejects_negative_non_marker_values() {
    let bytes = (-2_i32).to_le_bytes().to_vec();

    let err = read_rsync_long(&mut bytes.as_slice()).unwrap_err();

    assert!(
        err.to_string().contains("negative protocol long marker"),
        "{err}"
    );
}

fn read_single_protocol31_path(path: &str) -> Result<Vec<RsyncFileListEntry>, FileListError> {
    read_rsync31_file_list(&mut encoded_protocol31_path(path).as_slice(), 16, 256)
}

fn encoded_protocol31_path(path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let entry = RsyncFileListEntry {
        path: PathBuf::from(path),
        file_type: WireFileType::File,
        len: 1,
        mtime_unix: 1_700_000_000,
        mode: RSYNC_REGULAR_FILE_MODE,
        checksum: None,
        hardlink_group: None,
    };

    write_rsync31_file_list_with_options(&mut bytes, &[entry], false).unwrap();
    bytes
}

fn write_multiplex_frame(out: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    let header = (tag << 24) | payload.len() as u32;
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(payload);
}
