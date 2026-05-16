use super::*;

#[test]
fn renders_default_banner() {
    let output = parse_and_render(["rsync-win"]);

    assert!(output.contains("rsync-win development transfer planner"));
    assert!(output.contains("execution: plan output only"));
    assert!(output.contains("protocol primitives range: 20-32"));
}

#[test]
fn renders_protocol_range() {
    let output = parse_and_render(["rsync-win", "--protocol-range"]);

    assert_eq!(output, "20-32\n");
}

#[test]
fn renders_version_with_protocol_range() {
    let output = parse_and_render(["rsync-win", "--version"]);

    assert!(output.contains(&format!("rsync-win {}", env!("CARGO_PKG_VERSION"))));
    assert!(output.contains("protocol primitives range: 20-32"));
    assert!(output.contains(
        "remote-shell MVP tries protocol 31 first with protocol 27 compatibility fallback"
    ));
}

#[test]
fn command_has_version_and_help_output() {
    let mut command = build_command();
    let help = command.render_long_help().to_string();
    assert!(help.contains("Native Windows rsync development build"));
    assert!(help.contains("--version"));
    assert!(help.contains("--protocol-range"));
    assert!(help.contains("--plan"));
    assert!(help.contains("--metadata-policy"));
    assert!(help.contains("--fail-on-metadata-loss"));
}

#[test]
fn archive_mode_reports_unsupported_metadata_without_claiming_success() {
    let output = parse_and_render([
        "rsync-win",
        "-a",
        "--delete",
        "--dry-run",
        "src",
        "host:dest",
    ]);

    assert!(output.contains("archive mode expands to -rlptgoD"));
    assert!(output.contains("[warning] W_METADATA_OWNER"));
    assert!(output.contains("[warning] W_METADATA_GROUP"));
    assert!(output.contains("[warning] W_METADATA_DEVICE"));
    assert!(output.contains(
            "remote --server argv: rsync --server --delete-during --no-inc-recursive --perms --owner --group --links --devices --specials -ntre.LsfxCIvu"
        ));
    assert!(output.contains("[info] I_REMOTE_PROTOCOL31_MVP"));
    assert!(output.contains("wire protocol: experimental protocol 31"));
}

#[test]
fn remote_shell_plan_shows_ssh_command_without_claiming_transfer_execution() {
    let output = parse_and_render([
        "rsync-win",
        "-rt",
        "--whole-file",
        "--plan",
        "src",
        "user@example.test:/tmp/path with spaces",
    ]);

    assert!(
        output.contains("remote --server argv: rsync --server --no-inc-recursive -Wtre.LsfxCIvu")
    );
    assert!(output
        .contains("remote ssh argv: ssh -o BatchMode=yes -o ConnectTimeout=10 user@example.test"));
    assert!(output.contains("'/tmp/path with spaces'"));
    assert!(output.contains("wire protocol: experimental protocol 31"));
    assert!(output.contains("[info] I_REMOTE_PROTOCOL31_MVP"));
    assert!(!output.contains("local portable sync"));
}

#[test]
fn inc_recursive_remote_plan_omits_no_inc_recursive() {
    let output = parse_and_render([
        "rsync-win",
        "-rt",
        "--inc-recursive",
        "--plan",
        "host:/tmp/source",
        "dest",
    ]);

    assert!(output.contains("incremental recursion: true"), "{output}");
    assert!(output.contains("remote --server argv: rsync --server --sender -tre.iLsfxCIvu"));
    assert!(!output.contains("W_UNIMPLEMENTED_OPTION"), "{output}");
    assert!(!output.contains("--no-inc-recursive"), "{output}");
}

#[test]
fn inc_recursive_remote_push_keeps_no_inc_recursive_until_sender_side_is_supported() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--inc-recursive",
        "--plan",
        "src",
        "host:/tmp/dest",
    ]);

    assert!(output.contains("incremental recursion: false"), "{output}");
    assert!(
        output.contains("remote --server argv: rsync --server --no-inc-recursive"),
        "{output}"
    );
    assert!(output.contains("W_INC_RECURSIVE_PUSH_DISABLED"), "{output}");
}

#[test]
fn remote_shell_plan_accepts_rsync_e_compress_and_no_owner_group() {
    let output = parse_and_render([
        "rsync-win",
        "-avz",
        "--no-o",
        "--no-g",
        "./hunyuan_only_run/",
        "-e",
        "ssh -p 10080",
        "root@118.145.32.132:/mnt/afs/250010150/huozhiyu/VBench-exp/hunyuan_only_run/",
    ]);

    assert!(output.contains("compress: true"));
    assert!(output.contains("remote direction: upload (local -> remote)"));
    assert!(output.contains("remote ssh argv: ssh -p 10080 root@118.145.32.132"));
    assert!(output.contains("[info] I_REMOTE_SHELL"));
    assert!(!output.contains("[warning] W_COMPRESS_UNSUPPORTED"));
    assert!(!output.contains("BatchMode=yes"));
    assert!(!output.contains("W_METADATA_OWNER"));
    assert!(!output.contains("W_METADATA_GROUP"));
}

#[test]
fn literal_token_writer_checksums_while_streaming() {
    let mut output = Vec::new();
    let mut input = &b"abcdef"[..];

    let sent = write_literal_tokens_from_reader_with_checksum(
        &mut output,
        &mut input,
        RemoteFinalChecksum::PlainMd4,
        None,
        None,
        None,
    )
    .unwrap();

    assert_eq!(sent, 6);
    assert_eq!(i32::from_le_bytes(output[0..4].try_into().unwrap()), 6);
    assert_eq!(&output[4..10], b"abcdef");
    assert_eq!(i32::from_le_bytes(output[10..14].try_into().unwrap()), 0);
    assert_eq!(
        &output[14..30],
        &rsync_protocol::rsync_plain_md4_checksum(b"abcdef")
    );
}

#[test]
fn delta_token_writer_emits_copy_tokens_for_matching_basis_blocks() {
    let basis = b"AAAABBBBCCCC";
    let target = b"AAAAXXXXCCCC";
    let signatures = test_remote_block_signatures(basis, 4, 16, RemoteFileChecksum::PlainMd4);
    let mut output = Vec::new();

    let stats = write_delta_tokens_from_bytes_with_checksum(
        &mut output,
        target,
        RemoteFileChecksum::PlainMd4,
        RemoteFinalChecksum::PlainMd4,
        &signatures,
        None,
        None,
    )
    .unwrap();

    assert_eq!(stats.literal_bytes, 4);
    assert_eq!(stats.copied_bytes, 8);
    assert_eq!(i32::from_le_bytes(output[0..4].try_into().unwrap()), -1);
    assert_eq!(i32::from_le_bytes(output[4..8].try_into().unwrap()), 4);
    assert_eq!(&output[8..12], b"XXXX");
    assert_eq!(i32::from_le_bytes(output[12..16].try_into().unwrap()), -3);
    assert_eq!(i32::from_le_bytes(output[16..20].try_into().unwrap()), 0);
    assert_eq!(
        &output[20..36],
        &rsync_protocol::rsync_plain_md4_checksum(target)
    );
}

#[test]
fn delta_token_writer_sends_less_literal_data_for_large_small_edit() {
    let block_size = 4096;
    let block_count = 512;
    let mut basis = Vec::with_capacity(block_size * block_count);
    for block in 0..block_count {
        for offset in 0..block_size {
            basis.push(((block * 31 + offset) % 251) as u8);
        }
    }
    let mut target = basis.clone();
    let edit_start = 257 * block_size + 128;
    target[edit_start..edit_start + 256].fill(0x7f);
    let signatures =
        test_remote_block_signatures(&basis, block_size, 16, RemoteFileChecksum::PlainMd4);
    let mut output = Vec::new();

    let stats = write_delta_tokens_from_bytes_with_checksum(
        &mut output,
        &target,
        RemoteFileChecksum::PlainMd4,
        RemoteFinalChecksum::PlainMd4,
        &signatures,
        None,
        None,
    )
    .unwrap();

    assert!(stats.literal_bytes <= block_size as u64);
    assert!(stats.copied_bytes >= (target.len() - block_size) as u64);
    assert!(stats.literal_bytes < target.len() as u64 / 100, "{stats:?}");
}

#[test]
fn delta_token_reader_applies_copy_tokens_from_basis_file() {
    let root = unique_temp_dir("rsync-cli-delta-token-reader");
    let basis = root.join("basis.txt");
    let dest = root.join("dest.txt");
    fs::create_dir_all(&root).unwrap();
    fs::write(&basis, b"AAAABBBBCCCC").unwrap();

    let mut payload = Vec::new();
    write_i32_le(&mut payload, -1).unwrap();
    write_i32_le(&mut payload, 4).unwrap();
    payload.extend_from_slice(b"XXXX");
    write_i32_le(&mut payload, -3).unwrap();
    write_i32_le(&mut payload, 0).unwrap();
    payload.extend_from_slice(&rsync_protocol::rsync_plain_md4_checksum(b"AAAAXXXXCCCC"));
    let mut input = Vec::new();
    append_mux_payload(&mut input, &payload);
    let mut input = &input[..];
    let mut mux = MultiplexReadState::default();

    let bytes = read_file_tokens_to_path_with_basis(
        &mut input,
        &mut mux,
        RemoteFinalChecksum::PlainMd4,
        Path::new("dest.txt"),
        &dest,
        12,
        Some((
            &basis,
            RemoteSumHead {
                block_count: 3,
                block_len: 4,
                checksum_len: 16,
                remainder: 0,
            },
        )),
        None,
        None,
        None,
        None,
    )
    .unwrap();

    assert_eq!(bytes, 12);
    assert_eq!(fs::read(&dest).unwrap(), b"AAAAXXXXCCCC");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn compressed_delta_tokens_roundtrip_with_copy_tokens() {
    let root = unique_temp_dir("rsync-cli-compressed-delta-token-reader");
    let basis_path = root.join("basis.txt");
    let dest = root.join("dest.txt");
    fs::create_dir_all(&root).unwrap();
    let basis = b"AAAABBBBCCCC";
    let target = b"AAAAXXXXCCCC";
    fs::write(&basis_path, basis).unwrap();
    let signatures = test_remote_block_signatures(basis, 4, 16, RemoteFileChecksum::PlainMd4);
    let mut payload = Vec::new();

    let stats = write_delta_tokens_from_bytes_with_checksum(
        &mut payload,
        target,
        RemoteFileChecksum::PlainMd4,
        RemoteFinalChecksum::PlainMd4,
        &signatures,
        Some(6),
        None,
    )
    .unwrap();
    assert_eq!(stats.literal_bytes, 4);
    assert_eq!(stats.copied_bytes, 8);

    let mut input = Vec::new();
    append_mux_payload(&mut input, &payload);
    let mut input = &input[..];
    let mut mux = MultiplexReadState::default();
    let compression = RemoteCompressionConfig {
        mode: RsyncDeflatedTokenMode::Zlibx,
        level: 6,
        skip_suffixes: Vec::new(),
    };

    let bytes = read_file_tokens_to_path_with_basis(
        &mut input,
        &mut mux,
        RemoteFinalChecksum::PlainMd4,
        Path::new("dest.txt"),
        &dest,
        12,
        Some((
            &basis_path,
            RemoteSumHead {
                block_count: 3,
                block_len: 4,
                checksum_len: 16,
                remainder: 0,
            },
        )),
        Some(&compression),
        None,
        None,
        None,
    )
    .unwrap();

    assert_eq!(bytes, 12);
    assert_eq!(fs::read(&dest).unwrap(), target);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn append_verify_token_writer_sends_suffix_but_checksums_whole_file() {
    let mut output = Vec::new();
    let mut input = &b"abcdef"[..];

    let sent = write_append_verify_literal_tokens_from_reader_with_checksum(
        &mut output,
        &mut input,
        RemoteFinalChecksum::PlainMd4,
        3,
        None,
        None,
        None,
    )
    .unwrap();

    assert_eq!(sent, 3);
    assert_eq!(i32::from_le_bytes(output[0..4].try_into().unwrap()), 3);
    assert_eq!(&output[4..7], b"def");
    assert_eq!(i32::from_le_bytes(output[7..11].try_into().unwrap()), 0);
    assert_eq!(
        &output[11..27],
        &rsync_protocol::rsync_plain_md4_checksum(b"abcdef")
    );
}

#[test]
fn protocol31_checksum_choice_controls_block_and_final_digest_algorithm() {
    let md5_abc = [
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f,
        0x72,
    ];
    let block_checksum = RemoteFileChecksum::protocol31(Some("md5"), 0).unwrap();
    let final_checksum = RemoteFinalChecksum::protocol31(Some("md5")).unwrap();

    assert_eq!(remote_checksum_for_bytes(block_checksum, b"abc"), md5_abc);
    assert_eq!(
        remote_final_checksum_for_bytes(final_checksum, b"abc"),
        md5_abc
    );
    assert_ne!(
        remote_checksum_for_bytes(block_checksum, b"abc"),
        rsync_protocol::rsync_plain_md4_checksum(b"abc")
    );
}

#[cfg(windows)]
#[test]
fn remote_token_file_io_handles_windows_long_paths() {
    let root = unique_temp_dir("rsync-cli-long-path");
    let mut long_dir = root.clone();
    while long_dir.as_os_str().to_string_lossy().len() < 280 {
        long_dir.push("segment0123456789");
    }
    let source = long_dir.join("source.txt");
    let dest = long_dir.join("dest.txt");
    assert!(source.as_os_str().to_string_lossy().len() > 260);

    std::fs::create_dir_all(to_long_path_safe(&long_dir)).unwrap();
    std::fs::write(to_long_path_safe(&source), b"abc").unwrap();

    let mut upload_tokens = Vec::new();
    assert_eq!(
        write_delta_tokens_from_path(
            &mut upload_tokens,
            RemoteFileChecksum::PlainMd4,
            RemoteFinalChecksum::PlainMd4,
            &source,
            &[],
            DeltaWriteRuntime {
                compression: None,
                progress: None,
                max_alloc: None,
                stop_deadline: None,
            },
        )
        .unwrap()
        .literal_bytes,
        3
    );
    assert_eq!(
        checksum_local_path(&source).unwrap(),
        rsync_protocol::rsync_plain_md4_checksum(b"abc")
    );

    let mut payload = Vec::new();
    write_i32_le(&mut payload, 3).unwrap();
    payload.extend_from_slice(b"abc");
    write_i32_le(&mut payload, 0).unwrap();
    payload.extend_from_slice(&rsync_protocol::rsync_plain_md4_checksum(b"abc"));
    let mut input = Vec::new();
    append_mux_payload(&mut input, &payload);
    let mut input = &input[..];
    let mut mux = MultiplexReadState::default();

    assert_eq!(
        read_file_tokens_to_path_with_basis(
            &mut input,
            &mut mux,
            RemoteFinalChecksum::PlainMd4,
            Path::new("dest.txt"),
            &dest,
            3,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap(),
        3
    );
    assert_eq!(std::fs::read(to_long_path_safe(&dest)).unwrap(), b"abc");

    std::fs::remove_dir_all(to_long_path_safe(&root)).unwrap();
}

#[test]
fn should_fallback_to_protocol27_accepts_protocol31_setup_errors() {
    let fallback_errors = vec![
        anyhow::Error::new(RemoteSessionError::UnsupportedProtocol {
            negotiated: 30,
            supported: REMOTE_SHELL_MODERN_PROTOCOL,
        }),
        anyhow::Error::new(RemoteSessionError::UnsupportedChecksumNegotiation),
        anyhow::Error::new(RemoteSessionError::InvalidChecksumList),
        anyhow::Error::new(RemoteSessionError::Session(
            SessionError::NonProtocolOutput("banner".to_string()),
        )),
        anyhow::Error::new(RemoteSessionError::Session(
            SessionError::IncompleteProtocolPrefix,
        )),
        anyhow::Error::new(RemoteSessionError::Session(
            SessionError::InvalidProtocolPrefix(0x7273_796e),
        )),
        protocol31_setup_error(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated setup frame",
        )),
        protocol31_setup_error(RemoteSessionError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated handshake",
        ))),
    ];

    for err in fallback_errors {
        assert!(should_fallback_to_protocol27(&err), "{err}");
    }
}

#[test]
fn should_fallback_to_protocol27_rejects_transfer_errors() {
    let non_fallback_errors = vec![
        anyhow::Error::new(RemoteSessionError::InvalidFileIndex {
            index: 99,
            file_count: 1,
        }),
        anyhow::Error::new(RemoteSessionError::NonFileBlockRequest { index: 0 }),
        anyhow::Error::new(RemoteSessionError::FileChecksumMismatch {
            path: "file.txt".to_string(),
        }),
        anyhow::Error::new(RemoteSessionError::InvalidPhaseAck(0)),
        anyhow::Error::new(RemoteSessionError::InvalidFinalAck(0)),
        anyhow::Error::new(RemoteSessionError::UnexpectedToken {
            token: -1,
            path: "file.txt".to_string(),
        }),
        anyhow::Error::new(RemoteSessionError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated transfer",
        ))),
        anyhow::Error::new(RemoteSessionError::Session(
            SessionError::RemoteErrorMessage("remote refused transfer".to_string()),
        )),
    ];

    for err in non_fallback_errors {
        assert!(!should_fallback_to_protocol27(&err), "{err}");
    }
}
