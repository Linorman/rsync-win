use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use rsync_cli::output::{
    exit_code_from_error, EXIT_PROTOCOL, EXIT_PROTOCOL_STREAM, EXIT_START_PROTOCOL, EXIT_TIMEOUT,
};
use rsync_protocol::{
    read_rsync31_file_list, read_rsync_long, write_rsync31_file_list_with_options, FileListError,
    MultiplexReadState, MultiplexedReader, RsyncDeflatedTokenMode, RsyncDeflatedTokenReader,
    RsyncFileListEntry, RsyncFileListMetadata, WireFileType, RSYNC_REGULAR_FILE_MODE,
};
use rsync_transport::process::ChildTransport;

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
fn protocol31_reader_rejects_oversized_entry_counts_before_entries() {
    let err = read_rsync31_file_list(
        &mut encoded_protocol31_path("dir/file.txt").as_slice(),
        0,
        256,
    )
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("file list entry count exceeds limit"),
        "{err}"
    );
}

#[test]
fn protocol_varint_reader_rejects_malformed_overwide_values() {
    let mut bytes = [0xff, 0xff, 0xff, 0xff, 0xff].as_slice();

    let err = rsync_protocol::io::read_varint(&mut bytes).unwrap_err();

    assert!(err.to_string().contains("exceeds u32 width"), "{err}");
}

#[test]
fn compressed_token_reader_rejects_corrupt_literal_payloads() {
    let stream = vec![0x40, 0x01, 0x06, 0x00];
    let mut reader = RsyncDeflatedTokenReader::new(RsyncDeflatedTokenMode::Zlibx);

    let err = reader.next_token(&mut stream.as_slice()).unwrap_err();

    assert!(
        err.to_string().contains("inflate")
            || err.to_string().contains("deflate")
            || err.to_string().contains("zlib"),
        "{err}"
    );
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

#[test]
fn remote_shell_failures_map_to_rsync_like_exit_codes() {
    for (message, expected) in [
        (
            "remote-shell session failed: protocol 31 setup failed: early EOF; remote stderr: rsync: command not found",
            EXIT_START_PROTOCOL,
        ),
        (
            "remote-shell session failed: protocol 31 setup failed: early EOF; remote stderr: Permission denied (publickey)",
            EXIT_START_PROTOCOL,
        ),
        (
            "remote-shell session failed: unsupported protocol 99 from peer",
            EXIT_PROTOCOL,
        ),
        (
            "remote-shell session failed: early EOF while reading protocol stream",
            EXIT_PROTOCOL_STREAM,
        ),
        (
            "remote-shell session failed: checksum mismatch while receiving file",
            EXIT_PROTOCOL_STREAM,
        ),
        (
            "remote-shell child process timed out after 1s",
            EXIT_TIMEOUT,
        ),
    ] {
        let err = anyhow::anyhow!(message);

        assert_eq!(
            exit_code_from_error(&err),
            expected,
            "{message} should map to {expected}"
        );
    }
}

#[test]
fn child_transport_timeout_kills_hung_process_and_keeps_stderr() {
    let (program, args) = stderr_then_sleep_process();
    let transport = ChildTransport::spawn(program, args).unwrap();

    let report = transport
        .wait_with_diagnostics_timeout(Duration::from_millis(1500))
        .unwrap();

    assert!(report.timed_out, "process should be reported as timed out");
    assert!(
        !report.status.success(),
        "killed timed-out process should not report success"
    );
    assert!(
        String::from_utf8_lossy(&report.stderr).contains("stderr-before-sleep"),
        "stderr should be retained for diagnostics"
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
        metadata: RsyncFileListMetadata::default(),
    };

    write_rsync31_file_list_with_options(&mut bytes, &[entry], false).unwrap();
    bytes
}

fn write_multiplex_frame(out: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    let header = (tag << 24) | payload.len() as u32;
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(payload);
}

#[cfg(windows)]
fn stderr_then_sleep_process() -> (&'static std::ffi::OsStr, Vec<&'static std::ffi::OsStr>) {
    (
        std::ffi::OsStr::new("powershell"),
        vec![
            std::ffi::OsStr::new("-NoProfile"),
            std::ffi::OsStr::new("-Command"),
            std::ffi::OsStr::new(
                "[Console]::Error.WriteLine('stderr-before-sleep'); Start-Sleep -Seconds 5",
            ),
        ],
    )
}

#[cfg(not(windows))]
fn stderr_then_sleep_process() -> (&'static std::ffi::OsStr, Vec<&'static std::ffi::OsStr>) {
    (
        std::ffi::OsStr::new("sh"),
        vec![
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new("echo stderr-before-sleep >&2; sleep 5"),
        ],
    )
}
