use super::*;
use crate::batch;
use crate::remote::flist::*;
use crate::transfer::*;
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

#[test]
fn remote_shell_execute_rejects_nonportable_metadata_policy_before_spawning() {
    let err = parse_and_execute([
        "rsync-win",
        "-rt",
        "--metadata-policy",
        "posix",
        "src",
        "user@example.test:/tmp/dest",
    ])
    .unwrap_err();

    assert!(err
        .to_string()
        .contains("remote-shell MVP currently supports only --metadata-policy=portable"));
}

#[test]
fn remote_push_delete_with_filters_routes_receiver_protection() {
    let cli = Cli::parse_from([
        "rsync-win",
        "-rt",
        "--delete",
        "--exclude",
        "*.tmp",
        "src",
        "user@example.test:/tmp/dest",
    ]);
    let plan = TransferPlan::from_cli(&cli);

    ensure_remote_execution_options_supported(&cli, &plan).unwrap();
    let argv = plan.remote_server_argv.as_ref().unwrap();
    assert!(argv.contains(&"--delete-during".to_string()));
    assert!(argv.contains(&"--exclude=*.tmp".to_string()));
}

#[test]
fn remote_shell_execute_allows_chunk7_posix_metadata_options_before_spawning() {
    let cli = options::parse_cli([
        "rsync-win",
        "-r",
        "--owner",
        "--group",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--atimes",
        "--crtimes",
        "--usermap=*:root",
        "--groupmap=*:root",
        "--chown=root:root",
        "src",
        "user@example.test:/tmp/dest",
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);

    ensure_remote_execution_options_supported(&cli, &plan).unwrap();

    let argv = plan.remote_server_argv.as_ref().unwrap();
    for expected in [
        "--owner",
        "--group",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--atimes",
        "--crtimes",
        "--usermap=*:root",
        "--groupmap=*:root",
        "--chown=root:root",
    ] {
        assert!(argv.contains(&expected.to_string()), "{expected}: {argv:?}");
    }
}

#[test]
fn remote_push_still_rejects_delete_with_files_from() {
    let cli = Cli::parse_from([
        "rsync-win",
        "-rt",
        "--delete",
        "--files-from",
        "list.txt",
        "src",
        "user@example.test:/tmp/dest",
    ]);
    let plan = TransferPlan::from_cli(&cli);

    let err = ensure_remote_execution_options_supported(&cli, &plan).unwrap_err();

    assert!(err
        .to_string()
        .contains("remote-shell push does not yet support --delete together with --files-from"));
}

#[test]
fn remote_shell_plan_includes_supported_phase5_execution_options() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--size-only",
        "--partial",
        "--partial-dir",
        ".rsync-partial",
        "--plan",
        "src",
        "user@example.test:/tmp/dest",
    ]);

    assert!(output.contains("--size-only"));
    assert!(output.contains("--partial"));
    assert!(output.contains("--partial-dir=.rsync-partial"));
    assert!(output.contains("update mode: size-only"));
    assert!(output.contains("partial: true"));
}

#[test]
fn remote_shell_plan_routes_delete_timing_options() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--delete-after",
        "--plan",
        "src",
        "user@example.test:/tmp/dest",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(server_line.contains("--delete-after"));
    assert!(!server_line.contains("--delete-before"));
}

#[test]
fn remote_shell_plan_routes_checksum_and_receiver_metadata_options() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "-c",
        "--numeric-ids",
        "--chmod",
        "F600,D700",
        "--plan",
        "src",
        "user@example.test:/tmp/dest",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(server_line.contains("--checksum"));
    assert!(server_line.contains("--numeric-ids"));
    assert!(server_line.contains("--chmod=F600,D700"));
    assert!(output.contains("update mode: checksum"));
}

#[test]
fn remote_push_chmod_with_fail_on_metadata_loss_keeps_supported_mapping() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--chmod",
        "F600",
        "--fail-on-metadata-loss",
        "--plan",
        "src",
        "user@example.test:/tmp/dest",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(output.contains("remote direction: upload (local -> remote)"));
    assert!(server_line.contains("--chmod=F600"));
    assert!(!output.contains("[error] E_METADATA_PERMISSIONS"));
}

#[test]
fn remote_push_executability_with_fail_on_metadata_loss_keeps_supported_mapping() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--executability",
        "--fail-on-metadata-loss",
        "--plan",
        "src",
        "user@example.test:/tmp/dest",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(output.contains("remote direction: upload (local -> remote)"));
    assert!(server_line.contains("--executability"));
    assert!(!output.contains("[error] E_METADATA_LOSS"));
}

#[test]
fn remote_pull_routes_sender_link_options_to_remote_server() {
    let copy_links_output = parse_and_render([
        "rsync-win",
        "-r",
        "--copy-links",
        "--plan",
        "user@example.test:/tmp/source",
        "dest",
    ]);
    let copy_links_server_line = copy_links_output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();
    let copy_unsafe_output = parse_and_render([
        "rsync-win",
        "-r",
        "--copy-unsafe-links",
        "--plan",
        "user@example.test:/tmp/source",
        "dest",
    ]);
    let copy_unsafe_server_line = copy_unsafe_output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(copy_links_server_line.contains("--copy-links"));
    assert!(!copy_links_server_line.contains("--copy-unsafe-links"));
    assert!(copy_unsafe_server_line.contains("--copy-unsafe-links"));
    assert!(!copy_unsafe_server_line.contains("--copy-links"));
}

#[test]
fn remote_pull_plan_accepts_multiple_sources_from_same_host() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--plan",
        "user@example.test:/tmp/one",
        "user@example.test:/tmp/two",
        "dest",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(output.contains("remote direction: download (remote -> local)"));
    assert!(server_line.contains("--sender"));
    assert!(server_line.contains("--no-inc-recursive"));
    assert!(server_line.ends_with(" . /tmp/one /tmp/two"));
    assert!(!output.contains("[error] E_REMOTE"));
}

#[test]
fn remote_pull_plan_rejects_multiple_hosts() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--plan",
        "one@example.test:/tmp/one",
        "two@example.test:/tmp/two",
        "dest",
    ]);

    assert!(output.contains("[error] E_REMOTE_HOST_MISMATCH"));
    assert!(!output.contains("remote --server argv:"));
}

#[test]
fn remote_pull_sender_index_sort_places_files_before_directory_walks() {
    let mut entries = vec![
        test_remote_entry(".", WireFileType::Directory),
        test_remote_entry("analysis", WireFileType::Directory),
        test_remote_entry("subdir", WireFileType::Directory),
        test_remote_entry("root.txt", WireFileType::File),
        test_remote_entry("analysis/config_overview.json", WireFileType::File),
        test_remote_entry("subdir/a.txt", WireFileType::File),
    ];

    sort_remote_entries_for_sender_indexes(&mut entries);

    let paths: Vec<_> = entries.iter().map(|entry| entry.path.as_path()).collect();
    assert_eq!(
        paths,
        vec![
            Path::new("."),
            Path::new("root.txt"),
            Path::new("analysis"),
            Path::new("analysis/config_overview.json"),
            Path::new("subdir"),
            Path::new("subdir/a.txt"),
        ]
    );
}

#[test]
fn remote_push_routes_append_verify_without_whole_file() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--whole-file",
        "--append-verify",
        "--plan",
        "src",
        "user@example.test:/tmp/dest",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(server_line.contains("--append-verify"));
    assert!(!server_line.contains("-W"));
    assert!(output.contains("append verify: true"));
}

#[test]
fn remote_pull_keeps_append_verify_on_local_receiver_only() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--append-verify",
        "--plan",
        "user@example.test:/tmp/source",
        "dest",
    ]);
    let server_line = output
        .lines()
        .find(|line| line.starts_with("remote --server argv:"))
        .unwrap();

    assert!(!server_line.contains("--append-verify"));
    assert!(output.contains("append verify: true"));
}

#[test]
fn remote_push_protocol31_dry_run_exchanges_session_bytes() {
    let root = unique_temp_dir("rsync-cli-remote-push-mvp");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--dry-run".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_dry_run_input());

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win remote-shell push"));
    assert!(output.contains("protocol: 31 (peer advertised 31)"));
    assert!(output.contains("checksum negotiation: md4"));
    assert!(output.contains("files offered: 1"));
    assert!(output.contains("files sent: 0"));
    assert!(transport.written.starts_with(&31_u32.to_le_bytes()));
    assert!(transport
        .written
        .windows("file.txt".len())
        .any(|window| window == b"file.txt"));
    assert!(!output.contains("transfer note: no file data was sent"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_uses_sorted_sender_indexes_for_upstream_requests() {
    let root = unique_temp_dir("rsync-cli-remote-push-sorted-indexes");
    let source = root.join("source");
    fs::create_dir_all(source.join("dir")).unwrap();
    fs::write(source.join("root.txt"), b"alpha").unwrap();
    fs::write(source.join("dir/file.txt"), b"beta").unwrap();
    let source_arg = format!("{}/", source.display());

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-rn".to_string(),
        source_arg,
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_transfer_request_input(1));

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("files offered: 2"), "{output}");
    assert!(output.contains("files sent: 0"), "{output}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_accepts_local_source_with_trailing_forward_separator() {
    let root = unique_temp_dir("rsync-cli-remote-push-trailing-separator");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();
    let source_arg = format!("{}/", source.to_string_lossy());

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--dry-run".to_string(),
        source_arg,
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_dry_run_input());

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("files offered: 1"));
    assert!(transport
        .written
        .windows("file.txt".len())
        .any(|window| window == b"file.txt"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_delete_sends_filter_list_terminator_before_file_list() {
    let root = unique_temp_dir("rsync-cli-remote-push-delete-filter-list");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--delete".to_string(),
        "--dry-run".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_dry_run_input());

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();
    let payloads = written_protocol31_mux_payloads(&transport.written);

    assert!(output.contains("files offered: 1"));
    assert_eq!(
        payloads.first().map(Vec::as_slice),
        Some(&[0_u8, 0, 0, 0][..])
    );
    assert!(payloads.iter().skip(1).any(|payload| {
        payload
            .windows("file.txt".len())
            .any(|window| window == b"file.txt")
    }));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_notes_when_quick_check_skips_all_file_data() {
    let root = unique_temp_dir("rsync-cli-remote-push-quick-check-skip");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_dry_run_input());

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("files sent: 0"));
    assert!(output.contains("bytes sent: 0"));
    assert!(output.contains(
            "transfer note: no file data was sent; remote quick-check treated the destination as up-to-date by size and mtime"
        ));
    assert!(output.contains(
        "hint: if the remote file may be corrupt, rerun with -c/--checksum or --ignore-times"
    ));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_append_verify_sends_only_suffix_tokens() {
    let root = unique_temp_dir("rsync-cli-remote-push-append");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"abcdef").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--append-verify".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_append_verify_input());

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("files sent: 1"));
    assert!(output.contains("bytes sent: 3"));
    assert!(transport
        .written
        .windows("def".len())
        .any(|window| window == b"def"));
    assert!(!transport
        .written
        .windows("abcdef".len())
        .any(|window| window == b"abcdef"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_applies_out_format_and_log_file_format() {
    let root = unique_temp_dir("rsync-cli-remote-push-output-format");
    let source = root.join("source");
    let log_file = root.join("transfer.log");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"abcdef").unwrap();

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--append-verify".to_string(),
        "--out-format".to_string(),
        "%i %n %l".to_string(),
        "--log-file".to_string(),
        log_file.to_string_lossy().into_owned(),
        "--log-file-format".to_string(),
        "%i|%n|%l|%M".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_append_verify_input());

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

    assert!(
        output.lines().any(|line| line == ">f+++++++++ file.txt 6"),
        "{output}"
    );
    let log = fs::read_to_string(&log_file).unwrap();
    assert!(
        log.lines()
            .any(|line| line == ">f+++++++++|file.txt|6|send file.txt"),
        "{log}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_rejects_append_basis_larger_than_sender() {
    let root = unique_temp_dir("rsync-cli-remote-push-append-oversize");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"abcdef").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--append-verify".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport =
        TestTransport::with_input(remote_push_append_verify_oversized_basis_input());

    let err = execute_remote_push(&cli, &plan, &mut transport).unwrap_err();

    assert!(
        err.to_string()
            .contains("remote append basis is larger than sender file"),
        "{err:#}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_rejects_unsupported_mux_during_transfer() {
    let root = unique_temp_dir("rsync-cli-remote-push-bad-mux-transfer");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_unsupported_mux_input());

    let err = execute_remote_push(&cli, &plan, &mut transport).unwrap_err();

    assert!(
        err.to_string().contains("unsupported multiplex message"),
        "{err:#}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_rejects_unsupported_mux_during_final_goodbye() {
    let root = unique_temp_dir("rsync-cli-remote-push-bad-mux-final");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--dry-run".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_final_unsupported_mux_input());

    let err = execute_remote_push(&cli, &plan, &mut transport).unwrap_err();

    assert!(
        err.to_string().contains("unsupported multiplex message"),
        "{err:#}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_push_protocol31_filters_local_sender_entries() {
    let root = unique_temp_dir("rsync-cli-remote-push-filter");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();
    fs::write(source.join("skip.tmp"), b"skip").unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--dry-run".to_string(),
        "--exclude".to_string(),
        "*.tmp".to_string(),
        source.to_string_lossy().into_owned(),
        "host:/tmp/dest".to_string(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_push_dry_run_input());

    let output = execute_remote_push(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("files offered: 1"));
    assert!(transport
        .written
        .windows("file.txt".len())
        .any(|window| window == b"file.txt"));
    assert!(!transport
        .written
        .windows("skip.tmp".len())
        .any(|window| window == b"skip.tmp"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_protocol31_dry_run_reads_file_list_and_reports_actions() {
    let root = unique_temp_dir("rsync-cli-remote-pull-mvp");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_dry_run_input());

    let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win remote-shell pull"));
    assert!(output.contains("protocol: 31 (peer advertised 31)"));
    assert!(output.contains("checksum negotiation: md4"));
    assert!(output.contains("write-file"));
    assert!(output.contains("files received: 1"));
    assert!(!dest.join("file.txt").exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_protocol31_applies_out_format_and_log_file_format() {
    let root = unique_temp_dir("rsync-cli-remote-pull-output-format");
    let dest = root.join("dest");
    let log_file = root.join("transfer.log");
    fs::create_dir_all(&dest).unwrap();

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "--out-format".to_string(),
        "%i %n %l".to_string(),
        "--log-file".to_string(),
        log_file.to_string_lossy().into_owned(),
        "--log-file-format".to_string(),
        "%i|%n|%l|%M".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_dry_run_input());

    let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

    assert!(
        output.lines().any(|line| line == ">f+++++++++ file.txt 5"),
        "{output}"
    );
    let log = fs::read_to_string(&log_file).unwrap();
    assert!(
        log.lines()
            .any(|line| line == ">f+++++++++|file.txt|5|write file.txt"),
        "{log}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_rejects_security_file_list_parent_escape_before_writes() {
    let root = unique_temp_dir("rsync-cli-remote-pull-escape");
    let dest = root.join("dest");
    fs::create_dir_all(&root).unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
        test_remote_entry(".", WireFileType::Directory),
        RsyncFileListEntry {
            path: PathBuf::from("../escape.txt"),
            file_type: WireFileType::File,
            len: 3,
            mtime_unix: 0,
            mode: RSYNC_REGULAR_FILE_MODE,
            checksum: None,
            hardlink_group: None,
            metadata: RsyncFileListMetadata::default(),
        },
    ]));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(err.to_string().contains("portable"), "{err:#}");
    assert!(!dest.exists());
    assert!(!root.join("escape.txt").exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_rejects_security_absolute_or_prefixed_file_list_paths_before_writes() {
    for (label, wire_path) in [
        ("drive", "C:/escape.txt"),
        ("root", "/escape.txt"),
        ("unc", "//server/share/escape.txt"),
    ] {
        let root = unique_temp_dir(&format!("rsync-cli-remote-pull-{label}-path"));
        let dest = root.join("dest");
        fs::create_dir_all(&root).unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
            test_remote_entry(".", WireFileType::Directory),
            RsyncFileListEntry {
                path: PathBuf::from(wire_path),
                file_type: WireFileType::File,
                len: 3,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ]));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(
            err.to_string()
                .contains("not a portable relative rsync path"),
            "{wire_path}: {err:#}"
        );
        assert!(
            !dest.exists(),
            "{wire_path}: destination directory was created"
        );
        assert!(
            fs::read_dir(&root).unwrap().next().is_none(),
            "{wire_path}: rejected path left files under test root"
        );

        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn remote_pull_rejects_security_reserved_trailing_and_unicode_paths_before_writes() {
    for (label, wire_path, expected) in [
        ("reserved", "CON.txt", "not a portable relative rsync path"),
        (
            "trailing-dot",
            "dir/bad.",
            "not a portable relative rsync path",
        ),
        (
            "trailing-space",
            "dir/bad ",
            "not a portable relative rsync path",
        ),
    ] {
        let root = unique_temp_dir(&format!("rsync-cli-remote-pull-{label}"));
        let dest = root.join("dest");
        fs::create_dir_all(&root).unwrap();

        let cli = Cli::parse_from(vec![
            "rsync-win".to_string(),
            "host:/tmp/source".to_string(),
            dest.to_string_lossy().into_owned(),
        ]);
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
            test_remote_entry(".", WireFileType::Directory),
            RsyncFileListEntry {
                path: PathBuf::from(wire_path),
                file_type: WireFileType::File,
                len: 3,
                mtime_unix: 0,
                mode: RSYNC_REGULAR_FILE_MODE,
                checksum: None,
                hardlink_group: None,
                metadata: RsyncFileListMetadata::default(),
            },
        ]));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(err.to_string().contains(expected), "{wire_path}: {err:#}");
        assert!(
            !dest.exists(),
            "{wire_path}: destination directory was created"
        );
        assert!(
            fs::read_dir(&root).unwrap().next().is_none(),
            "{wire_path}: rejected path left files under test root"
        );

        fs::remove_dir_all(root).unwrap();
    }

    let root = unique_temp_dir("rsync-cli-remote-pull-unicode-collision");
    let dest = root.join("dest");
    fs::create_dir_all(&root).unwrap();
    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&[
        test_remote_entry(".", WireFileType::Directory),
        test_remote_entry("caf\u{00e9}.txt", WireFileType::File),
        test_remote_entry("cafe\u{301}.txt", WireFileType::File),
    ]));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(
        err.to_string().contains("case/normalization collision"),
        "{err:#}"
    );
    assert!(!dest.exists());
    assert!(fs::read_dir(&root).unwrap().next().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn trust_sender_default_rejects_remote_filter_violations() {
    let root = unique_temp_dir("rsync-cli-trust-sender-filter-default");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "--exclude".to_string(),
        "*.tmp".to_string(),
        "host:/tmp/source/".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
        &[
            test_remote_entry(".", WireFileType::Directory),
            test_remote_entry("skip.tmp", WireFileType::File),
            test_remote_entry("file.txt", WireFileType::File),
        ],
        2,
    ));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(
        err.to_string().contains("remote sender sent filtered path"),
        "{err:#}"
    );
    assert!(fs::read_dir(&dest).unwrap().next().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn trust_sender_default_rejects_unrequested_single_file_entries() {
    let root = unique_temp_dir("rsync-cli-trust-sender-extra-source-default");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "host:/tmp/allowed.txt".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
        &[
            test_remote_entry(".", WireFileType::Directory),
            test_remote_entry("other.txt", WireFileType::File),
        ],
        1,
    ));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(
        err.to_string()
            .contains("remote sender sent unrequested path"),
        "{err:#}"
    );
    assert!(fs::read_dir(&dest).unwrap().next().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn old_args_trusts_remote_source_arg_names_but_not_filters() {
    let root = unique_temp_dir("rsync-cli-old-args-source-trust");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "--old-args".to_string(),
        "host:/tmp/allowed.txt".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
        &[
            test_remote_entry(".", WireFileType::Directory),
            test_remote_entry("other.txt", WireFileType::File),
        ],
        1,
    ));

    let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("files received: 1"), "{output}");
    assert!(fs::read_dir(&dest).unwrap().next().is_none());

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "--old-args".to_string(),
        "--exclude".to_string(),
        "*.tmp".to_string(),
        "host:/tmp/allowed.txt".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_dry_run_input_with_entries(
        &[
            test_remote_entry(".", WireFileType::Directory),
            test_remote_entry("skip.tmp", WireFileType::File),
        ],
        1,
    ));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(
        err.to_string().contains("remote sender sent filtered path"),
        "{err:#}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn trust_sender_keeps_destination_path_validation_strict() {
    for (label, entries, expected) in [
        (
            "parent",
            vec![
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("../escape.txt", WireFileType::File),
            ],
            "not a portable relative rsync path",
        ),
        (
            "absolute",
            vec![
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("/escape.txt", WireFileType::File),
            ],
            "not a portable relative rsync path",
        ),
        (
            "reserved",
            vec![
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("CON.txt", WireFileType::File),
            ],
            "not a portable relative rsync path",
        ),
        (
            "case-collision",
            vec![
                test_remote_entry(".", WireFileType::Directory),
                test_remote_entry("Report.txt", WireFileType::File),
                test_remote_entry("report.txt", WireFileType::File),
            ],
            "case/normalization collision",
        ),
    ] {
        let root = unique_temp_dir(&format!("rsync-cli-trust-sender-{label}"));
        let dest = root.join("dest");
        fs::create_dir_all(&root).unwrap();

        let cli = options::parse_cli(vec![
            "rsync-win".to_string(),
            "--trust-sender".to_string(),
            "host:/tmp/source/".to_string(),
            dest.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let plan = TransferPlan::from_cli(&cli);
        let mut transport = TestTransport::with_input(remote_pull_file_list_only_input(&entries));

        let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

        assert!(err.to_string().contains(expected), "{label}: {err:#}");
        assert!(!dest.exists(), "{label}: destination directory was created");

        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn remote_pull_rejects_security_oversized_literal_stream_without_final_file() {
    let root = unique_temp_dir("rsync-cli-remote-pull-oversize");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_transfer_input(
        "file.txt",
        3,
        &[b"abcdef".as_slice()],
    ));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(err.to_string().contains("exceeding advertised length 3"));
    assert!(!dest.join("file.txt").exists());
    assert!(fs::read_dir(&dest).unwrap().next().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_rejects_security_short_literal_stream_without_final_file() {
    let root = unique_temp_dir("rsync-cli-remote-pull-short");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_transfer_input(
        "file.txt",
        6,
        &[b"abc".as_slice()],
    ));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(err.to_string().contains("below advertised length 6"));
    assert!(!dest.join("file.txt").exists());
    assert!(fs::read_dir(&dest).unwrap().next().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_rejects_security_checksum_mismatch_without_final_file() {
    let root = unique_temp_dir("rsync-cli-remote-pull-checksum");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();

    let cli = Cli::parse_from(vec![
        "rsync-win".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_transfer_input_with_checksum(
        "file.txt",
        3,
        &[b"abc".as_slice()],
        [0_u8; 16],
    ));

    let err = execute_remote_pull(&cli, &plan, &mut transport).unwrap_err();

    assert!(err.to_string().contains("checksum mismatch"), "{err:#}");
    assert!(!dest.join("file.txt").exists());
    assert!(fs::read_dir(&dest).unwrap().next().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_protocol31_filters_requests_and_protects_delete() {
    let root = unique_temp_dir("rsync-cli-remote-pull-filter");
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();
    fs::write(dest.join("skip.tmp"), b"local").unwrap();

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "--trust-sender".to_string(),
        "--delete".to_string(),
        "--exclude".to_string(),
        "*.tmp".to_string(),
        "host:/tmp/source".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_filter_dry_run_input());

    let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("write-file"));
    assert!(output.contains("protect-delete"));
    assert!(output.contains("files received: 1"));
    assert!(dest.join("skip.tmp").exists());
    let payloads = written_protocol31_mux_payloads(&transport.written);
    assert!(payloads.iter().any(|payload| payload == &[1]));
    assert!(!payloads.iter().any(|payload| payload == &[2]));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_protocol31_inc_recursive_reads_extra_file_list_and_requests_new_files() {
    let root = unique_temp_dir("rsync-cli-remote-pull-inc-recursive");
    let dest = root.join("dest");
    fs::create_dir_all(&root).unwrap();
    let cli = Cli::parse_from([
        "rsync-win",
        "-rn",
        "--inc-recursive",
        "host:/src/",
        &dest.to_string_lossy(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(remote_pull_incremental_dry_run_input());

    let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("files received: 2"), "{output}");
    let payloads = written_protocol31_mux_payloads(&transport.written);
    assert!(
        payloads
            .iter()
            .filter(|payload| payload.starts_with(&[2]))
            .count()
            >= 2,
        "expected dry-run requests for sorted file indexes 1 and 3; payloads={payloads:?}"
    );
    assert!(
            !payloads.iter().any(|payload| payload.starts_with(&[3])),
            "incremental pull must request sorted sender indexes, not raw wire-order file index 2; payloads={payloads:?}"
        );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_delete_protects_descendants_of_filtered_directories() {
    let root = unique_temp_dir("rsync-cli-remote-delete-protect-dir");
    let dest = root.join("dest");
    fs::create_dir_all(dest.join("cache")).unwrap();
    fs::write(dest.join("cache/old.txt"), b"old").unwrap();
    let mut local = LocalFileSystem;
    let mut actions = Vec::new();

    delete_local_extras(
        &mut local,
        &dest,
        &[],
        &RuleSet::new(vec![Rule::exclude("cache/").unwrap()]),
        None,
        false,
        &mut actions,
    )
    .unwrap();

    assert!(dest.join("cache/old.txt").exists());
    assert!(actions.iter().any(|action| {
        matches!(action, SyncAction::ProtectDelete(path) if path.ends_with("cache/old.txt"))
    }));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_pull_files_from_retains_needed_parent_dirs_only() {
    let entries = vec![
        test_remote_entry(".", WireFileType::Directory),
        test_remote_entry("dir", WireFileType::Directory),
        test_remote_entry("dir/keep.txt", WireFileType::File),
        test_remote_entry("dir/drop.txt", WireFileType::File),
        test_remote_entry("other", WireFileType::Directory),
        test_remote_entry("other/file.txt", WireFileType::File),
    ];
    let files_from = vec![PathBuf::from("dir/keep.txt")];

    let selected = selected_remote_entry_indexes(&entries, &RuleSet::empty(), Some(&files_from));
    let selected_paths: Vec<_> = entries
        .iter()
        .enumerate()
        .filter(|(index, _)| selected.contains(index))
        .map(|(_, entry)| entry.path.as_path())
        .collect();

    assert_eq!(
        selected_paths,
        vec![Path::new("."), Path::new("dir"), Path::new("dir/keep.txt")]
    );
}

#[test]
fn remote_pull_files_from_accepts_full_sender_list_before_local_selection() {
    let root = unique_temp_dir("rsync-cli-remote-pull-files-from-full-list");
    let dest = root.join("dest");
    let files_from = root.join("files-from.txt");
    fs::create_dir_all(&dest).unwrap();
    fs::write(&files_from, b"dir/keep.txt\n").unwrap();

    let cli = options::parse_cli(vec![
        "rsync-win".to_string(),
        "--dry-run".to_string(),
        "--files-from".to_string(),
        files_from.to_string_lossy().into_owned(),
        "host:/tmp/source/".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let entries = vec![
        test_remote_entry(".", WireFileType::Directory),
        test_remote_entry("dir", WireFileType::Directory),
        test_remote_entry("dir/keep.txt", WireFileType::File),
        test_remote_entry("dir/drop.txt", WireFileType::File),
        test_remote_entry("other", WireFileType::Directory),
        test_remote_entry("other/file.txt", WireFileType::File),
    ];
    let mut transport =
        TestTransport::with_input(remote_pull_dry_run_input_with_entries(&entries, 1));

    let output = execute_remote_pull(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win remote-shell pull"), "{output}");
    assert!(!output.contains("dir/drop.txt"), "{output}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn daemon_operands_route_to_daemon_plan_without_remote_shell_argv() {
    let output = parse_and_render(["rsync-win", "--plan", "host::module/path", "dest"]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon endpoint: host:873"));
    assert!(output.contains("daemon direction: download (daemon -> local)"));
    assert!(output.contains("daemon module: module"));
    assert!(output.contains("daemon path: path"));
    assert!(!output.contains("E_REMOTE_OPERAND"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_url_operands_route_to_daemon_plan() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "rsync://user@example.test:8873/pub/dir",
        "dest",
    ]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon endpoint: example.test:8873"));
    assert!(output.contains("daemon module: pub"));
    assert!(output.contains("daemon path: dir"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_module_listing_plan_uses_daemon_mode() {
    let output = parse_and_render(["rsync-win", "--plan", "--list-only", "host::"]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon module: <list>"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn windows_drive_operands_are_not_daemon_operands() {
    let output = parse_and_render(["rsync-win", "--plan", r"C:\src", "dest"]);

    assert!(!output.contains("daemon mode: client"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_password_file_does_not_render_secret_or_path() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--password-file",
        "secret-password.txt",
        "user@host::module/path",
        "dest",
    ]);

    assert!(output.contains("daemon auth: password-file configured"));
    assert!(!output.contains("secret-password"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_auth_user_prefers_operand_and_uses_local_env_fallback_order() {
    let daemon = DaemonOperand::parse("alice@host::module").unwrap().unwrap();

    assert_eq!(daemon_auth_user(&daemon).unwrap(), "alice");
    assert_eq!(
        daemon_auth_user_from_vars([
            ("USER", Some(String::new())),
            ("LOGNAME", Some(" logname ".to_string())),
            ("USERNAME", Some("winuser".to_string())),
        ]),
        Some("logname".to_string())
    );
    assert_eq!(
        daemon_auth_user_from_vars([
            ("USER", Some("bad\0user".to_string())),
            ("LOGNAME", None),
            ("USERNAME", Some("winuser".to_string())),
        ]),
        Some("winuser".to_string())
    );
}

#[test]
fn daemon_password_falls_back_to_rsync_password_env() {
    assert_eq!(
        daemon_password_from_vars([("RSYNC_PASSWORD", Some("env-secret".to_string()))]).unwrap(),
        "env-secret"
    );
    assert_eq!(
        daemon_password_from_vars([
            ("RSYNC_PASSWORD", Some(String::new())),
            ("OTHER", Some("ignored".to_string())),
        ]),
        None
    );
}

#[test]
fn daemon_password_file_rejects_non_regular_paths() {
    let root = unique_temp_dir("rsync-cli-password-file-dir");
    fs::create_dir_all(&root).unwrap();

    let err = read_password_file(&root).unwrap_err();

    assert!(err.to_string().contains("must be a regular file"));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn daemon_password_file_rejects_group_or_other_access() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_temp_dir("rsync-cli-password-file-perms");
    fs::create_dir_all(&root).unwrap();
    let password_file = root.join("pw.txt");
    fs::write(&password_file, "secret\n").unwrap();
    fs::set_permissions(&password_file, fs::Permissions::from_mode(0o644)).unwrap();

    let err = read_password_file(&password_file).unwrap_err();

    assert!(err
        .to_string()
        .contains("must not be accessible by group or other users"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn daemon_module_listing_executes_over_in_memory_transport() {
    let cli = Cli::parse_from(["rsync-win", "--list-only", "host::"]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(
        b"@RSYNCD: 31.0\nhello\npublic\tPublic files\n@RSYNCD: EXIT\n".to_vec(),
    );

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win daemon module list"));
    assert!(output.contains("endpoint: host:873"));
    assert!(output.contains("- hello"));
    assert!(output.contains("- public\tPublic files"));
    assert_eq!(transport.written, b"@RSYNCD: 31.0 md5 md4\n#list\n");
}

#[test]
fn daemon_no_auth_pull_uses_remote_pull_receive_path() {
    let root = unique_temp_dir("rsync-cli-daemon-pull");
    let dest = root.join("dest");
    let cli = Cli::parse_from([
        "rsync-win",
        "--dry-run",
        "host::module/file.txt",
        &dest.to_string_lossy(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut input = b"@RSYNCD: 31.0\n@RSYNCD: OK\n".to_vec();
    input.extend_from_slice(&daemon_protocol31_setup_input());
    input.extend_from_slice(&daemon_pull_dry_run_input());
    let mut transport = TestTransport::with_input(input);

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win daemon pull"));
    assert!(output.contains("source: host::module/file.txt"));
    assert!(output.contains("dry run: true"));
    assert!(transport
        .written
        .starts_with(b"@RSYNCD: 31.0 md5 md4\nmodule\n--server\0--sender\0"));
    assert!(transport
        .written
        .windows(b"file.txt\0".len())
        .any(|window| window == b"file.txt\0"));
    if root.exists() {
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn daemon_destination_operands_route_to_push_plan() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-r",
        "local-src",
        "host::module/upload",
    ]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon direction: upload (local -> daemon)"));
    assert!(output.contains("daemon module: module"));
    assert!(output.contains("daemon path: upload"));
    assert!(!output.contains("E_DAEMON_PUSH_UNSUPPORTED"));
}

#[test]
fn daemon_client_plan_applies_connection_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--port",
        "8873",
        "--address",
        "127.0.0.1",
        "--sockopts",
        "TCP_NODELAY,SO_KEEPALIVE",
        "--contimeout",
        "7",
        "--no-motd",
        "host::module/path",
        "dest",
    ]);

    assert!(output.contains("daemon endpoint: host:8873"));
    assert!(output.contains("daemon bind address: 127.0.0.1"));
    assert!(output.contains("daemon socket options: TCP_NODELAY,SO_KEEPALIVE"));
    assert!(output.contains("daemon connect timeout: 7s"));
    assert!(output.contains("daemon motd: disabled"));
    assert!(!output.contains("W_UNSUPPORTED_OPTION"));
}

#[test]
fn daemon_push_uses_remote_receiver_path() {
    let root = unique_temp_dir("rsync-cli-daemon-push");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();
    let cli = options::parse_cli([
        "rsync-win",
        "-n",
        "-r",
        &source.to_string_lossy(),
        "host::module/upload",
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut input = b"@RSYNCD: 31.0\n@RSYNCD: OK\n".to_vec();
    input.extend_from_slice(&daemon_push_dry_run_input());
    let mut transport = TestTransport::with_input(input);

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win daemon push"));
    assert!(output.contains("direction: upload (local -> daemon)"));
    assert!(output.contains("destination: host::module/upload"));
    assert!(transport
        .written
        .starts_with(b"@RSYNCD: 31.0 md5 md4\nmodule\n--server\0"));
    assert!(
        transport
            .written
            .windows(b"md4".len())
            .filter(|window| *window == b"md4")
            .count()
            >= 2
    );
    assert!(!transport
        .written
        .windows(b"--sender".len())
        .any(|window| window == b"--sender"));
    assert!(transport
        .written
        .windows(b"--no-inc-recursive".len())
        .any(|window| window == b"--no-inc-recursive"));
    assert!(transport
        .written
        .windows(b"e.LsfxCIvu".len())
        .any(|window| window == b"e.LsfxCIvu"));
    assert!(!transport
        .written
        .windows(b"e.iLsfxCIvu".len())
        .any(|window| window == b"e.iLsfxCIvu"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn daemon_server_plan_accepts_core_daemon_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--daemon",
        "--no-detach",
        "--config",
        "rsyncd.conf",
        "--dparam",
        "public.comment=Overridden",
        "--address",
        "127.0.0.1",
        "--port",
        "0",
        "--sockopts",
        "TCP_NODELAY",
        "--log-file",
        "daemon.log",
        "--log-file-format",
        "%m %f",
        "--bwlimit",
        "128",
    ]);

    assert!(output.contains("daemon mode: server"));
    assert!(output.contains("daemon config: rsyncd.conf"));
    assert!(output.contains("daemon dparam: public.comment=Overridden"));
    assert!(output.contains("daemon listen: 127.0.0.1:0"));
    assert!(output.contains("daemon no detach: true"));
    assert!(output.contains("daemon log file: daemon.log"));
    assert!(output.contains("daemon bwlimit: 128"));
    assert!(!output.contains("E_UNSUPPORTED_MODE"));
    assert!(!output.contains("W_UNSUPPORTED_OPTION"));
}

#[test]
fn daemon_password_file_auth_hashes_without_logging_secret() {
    let root = unique_temp_dir("rsync-cli-daemon-auth");
    fs::create_dir_all(&root).unwrap();
    let password_file = root.join("pw.txt");
    let dest = root.join("dest");
    write_test_password_file(&password_file, "secret\n");
    let cli = Cli::parse_from([
        "rsync-win",
        "--dry-run",
        "--password-file",
        &password_file.to_string_lossy(),
        "alice@host::module/file.txt",
        &dest.to_string_lossy(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut input = b"@RSYNCD: 31.0\n@RSYNCD: AUTHREQD challenge\n@RSYNCD: OK\n".to_vec();
    input.extend_from_slice(&daemon_protocol31_setup_input());
    input.extend_from_slice(&daemon_pull_dry_run_input());
    let mut transport = TestTransport::with_input(input);

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();
    let written = String::from_utf8_lossy(&transport.written);

    assert!(output.contains("rsync-win daemon pull"));
    assert!(written.contains("alice "));
    assert!(!written.contains("secret"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn fail_on_metadata_loss_upgrades_archive_degradations_to_errors() {
    let output = parse_and_render(["rsync-win", "-a", "--fail-on-metadata-loss", "src", "dest"]);

    assert!(output.contains("[error] E_METADATA_OWNER"));
    assert!(output.contains("[error] E_METADATA_GROUP"));
    assert!(output.contains("[error] E_METADATA_DEVICE"));
}

#[test]
fn nonportable_metadata_policy_reports_loss_without_archive_mode() {
    let output = parse_and_render([
        "rsync-win",
        "--metadata-policy",
        "ntfs-native",
        "--fail-on-metadata-loss",
        "src",
        "dest",
    ]);

    assert!(output.contains("metadata policy: ntfs-native"));
    assert!(output.contains("[error] E_METADATA_LOSS"));
    assert!(output.contains("metadata-policy=ntfs-native requests NTFS security descriptor"));
    assert!(!output.contains("metadata-policy=ntfs-native requests creation time"));
}

#[test]
fn posix_metadata_options_render_plan_and_fail_on_loss() {
    let output = parse_and_render([
        "rsync-win",
        "--metadata-policy",
        "posix",
        "--perms",
        "--owner",
        "--group",
        "--executability",
        "--acls",
        "--xattrs",
        "--fake-super",
        "--fail-on-metadata-loss",
        "src",
        "dest",
    ]);

    assert!(output.contains("metadata policy: posix"));
    assert!(
        output.contains("posix metadata: perms,owner,group,executability,acls,xattrs,fake-super")
    );
    assert!(output.contains("[error] E_METADATA_OWNER"));
    assert!(output.contains("[error] E_METADATA_GROUP"));
    assert!(output.contains("[error] E_METADATA_PERMISSIONS"));
    assert!(output.contains("fake-super metadata stored"));
    assert!(output.contains("[error] E_METADATA_LOSS"));
    assert!(output.contains("acl metadata stored"));
}

#[test]
fn fake_super_fail_on_metadata_loss_keeps_stored_sidecar_metadata_non_error() {
    let output = parse_and_render([
        "rsync-win",
        "--fake-super",
        "--acls",
        "--xattrs",
        "--fail-on-metadata-loss",
        "src",
        "dest",
    ]);

    assert!(!output.contains("[error] E_METADATA_LOSS"));
    assert!(!output.contains("[error] E_METADATA_PERMISSIONS"));
    assert!(output.contains("fake-super metadata stored"));
    assert!(output.contains("acl metadata stored"));
    assert!(output.contains("xattr metadata stored"));
}

#[test]
fn local_fake_super_writes_posix_sidecar_manifest() {
    let root = unique_temp_dir("rsync-cli-posix-sidecar");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"data").unwrap();

    let output = parse_and_execute([
        "rsync-win",
        "-r",
        "--fake-super",
        "--acls",
        "--xattrs",
        "--atimes",
        "--crtimes",
        "--chmod=u=rw,go=r",
        &source.to_string_lossy(),
        &dest.to_string_lossy(),
    ])
    .unwrap();

    assert!(
        output.contains("posix sidecars: planned 2, written 2"),
        "{output}"
    );
    let sidecar_root = dest.join(".rsync-win.fake-super");
    let manifests: Vec<_> = fs::read_dir(&sidecar_root)
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect();
    assert!(manifests
        .iter()
        .any(|manifest| manifest.contains("path=") && manifest.contains("file.txt")));
    assert!(manifests
        .iter()
        .any(|manifest| manifest.contains("fake_super=true")));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_fake_super_restores_existing_source_sidecar_manifest() {
    let root = unique_temp_dir("rsync-cli-posix-sidecar-restore");
    let source = root.join("source");
    let dest = root.join("dest");
    let source_sidecar_root = source.join(".rsync-win.fake-super");
    fs::create_dir_all(&source_sidecar_root).unwrap();
    fs::write(source.join("file.txt"), b"data").unwrap();
    fs::write(
        source_sidecar_root.join("restored.posix.meta"),
        [
            "rsync-win posix fake-super sidecar v1",
            "path=file.txt",
            "mode=100644",
            "uid=1000",
            "gid=1001",
            "user_name=alice",
            "group_name=staff",
            "access_time=none",
            "creation_time=none",
            "acls=0",
            "xattrs=0",
            "fake_super=true",
            "",
        ]
        .join("\n"),
    )
    .unwrap();

    let output = parse_and_execute([
        "rsync-win",
        "-r",
        "--fake-super",
        &source.to_string_lossy(),
        &dest.to_string_lossy(),
    ])
    .unwrap();

    assert!(output.contains("restored 1"), "{output}");
    let restored = fs::read_to_string(
        dest.join(".rsync-win.fake-super")
            .join("restored.posix.meta"),
    )
    .unwrap();
    assert!(restored.contains("user_name=alice"));
    assert!(restored.contains("fake_super=true"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn numeric_ids_alone_is_reported_without_metadata_loss_error() {
    let output = parse_and_render([
        "rsync-win",
        "--numeric-ids",
        "--fail-on-metadata-loss",
        "src",
        "dest",
    ]);

    assert!(output.contains("posix metadata: numeric-ids"));
    assert!(output.contains("[warning] W_UNSUPPORTED_OPTION"));
    assert!(!output.contains("[error] E_METADATA_OWNER"));
    assert!(!output.contains("[error] E_METADATA_GROUP"));
}

#[test]
fn ntfs_native_plan_reports_sidecar_and_vss_runtime_path() {
    let output = parse_and_render([
        "rsync-win",
        "--metadata-policy",
        "ntfs-native",
        "--vss",
        "--fail-on-metadata-loss",
        "src",
        "dest",
    ]);

    assert!(output.contains("metadata policy: ntfs-native"));
    assert!(output.contains("ntfs-native metadata: sidecar-capture restore path, vss=true"));
    assert!(output.contains("security-descriptor metadata degraded"));
    assert!(output.contains("alternate-data-stream metadata degraded"));
    assert!(!output.contains("vss-snapshot metadata rejected"));
}

#[test]
fn local_execute_rejects_vss_without_ntfs_native_before_mutating() {
    let root = unique_temp_dir("rsync-cli-vss-policy");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("file.txt"), b"payload").unwrap();

    let err = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--vss".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap_err();

    assert!(
        format!("{err:#}").contains("--vss requires --metadata-policy=ntfs-native"),
        "{err:#}"
    );
    assert!(!dest.join("file.txt").exists());

    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn local_ntfs_native_vss_sync_reads_snapshot_or_skips_cleanly() {
    let root = unique_temp_dir("rsync-cli-vss-sync");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("file.txt"), b"snapshot payload").unwrap();

    let result = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        "--vss".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ]);

    match result {
        Ok(output) => {
            assert!(output.contains("vss snapshots: active 1"), "{output}");
            assert_eq!(
                fs::read(dest.join("file.txt")).unwrap(),
                b"snapshot payload"
            );
        }
        Err(err) if format!("{err:#}").contains("create VSS snapshot") => {
            eprintln!("SKIP: VSS snapshot creation unavailable in this environment: {err:#}");
        }
        Err(err) => panic!("unexpected VSS execution error: {err:#}"),
    }

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parses_filters_without_executing_transfer() {
    let output = parse_and_render([
        "rsync-win",
        "-r",
        "--include",
        "*.rs",
        "--exclude",
        "target/",
        "--filter",
        "protect *.bak",
        "--files-from",
        "list.txt",
        "--from0",
        "src",
        "dest",
    ]);

    assert!(output.contains("filter rules: 3"));
    assert!(output.contains("files-from: list.txt"));
    assert!(output.contains("from0: true"));
    assert!(output.contains("execution: plan output only"));
}

#[test]
fn local_executor_copies_files_and_deletes_extras() {
    let root = unique_temp_dir("rsync-cli-local-exec");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("nested/file.txt"), b"new").unwrap();
    fs::write(dest.join("old.txt"), b"old").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-rt".to_string(),
        "--delete".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("nested/file.txt")).unwrap(), b"new");
    assert!(!dest.join("old.txt").exists());
    assert!(output.contains("rsync-win local portable sync"));
    assert!(output.contains("changes:"));
    assert!(output.contains("file writes"));
    assert!(output.contains("deletes"));
    assert!(!output.contains("actions:\n"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_batches_multiple_sources() {
    let root = unique_temp_dir("rsync-cli-local-batch");
    let file_source = root.join("one.txt");
    let dir_source = root.join("dir");
    let dest = root.join("dest");
    fs::create_dir_all(dir_source.join("nested")).unwrap();
    fs::write(&file_source, b"one").unwrap();
    fs::write(dir_source.join("nested/two.txt"), b"two").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        file_source.to_string_lossy().into_owned(),
        dir_source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("one.txt")).unwrap(), b"one");
    assert_eq!(fs::read(dest.join("dir/nested/two.txt")).unwrap(), b"two");
    assert!(output.contains("sources: 2"));
    assert!(output.contains("changes:"));
    assert!(output.contains("file writes"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_write_batch_updates_destination_and_replays_changed_destination() {
    let root = unique_temp_dir("rsync-cli-write-batch");
    let source = root.join("source.txt");
    let dest = root.join("dest");
    let batch = root.join("transfer.batch");
    fs::create_dir_all(&dest).unwrap();
    fs::write(&source, b"from-source").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "--write-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("source.txt")).unwrap(), b"from-source");
    assert!(batch.exists());
    assert!(output.contains("rsync-win batch --write-batch"));
    assert!(output.contains("rsync-win local portable sync"));

    fs::write(dest.join("source.txt"), b"changed receiver").unwrap();

    let replay = parse_and_execute(vec![
        "rsync-win".to_string(),
        "--read-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        "ignored-source".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert!(replay.contains("batch replay complete"));
    assert_eq!(fs::read(dest.join("source.txt")).unwrap(), b"from-source");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_only_write_batch_records_replay_data_without_updating_destination() {
    let root = unique_temp_dir("rsync-cli-only-write-batch");
    let source = root.join("source.txt");
    let dest = root.join("dest");
    let batch = root.join("transfer.batch");
    fs::create_dir_all(&dest).unwrap();
    fs::write(&source, b"batch-only").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "--only-write-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert!(output.contains("rsync-win batch --only-write-batch"));
    assert!(batch.exists());
    assert!(!dest.join("source.txt").exists());

    parse_and_execute(vec![
        "rsync-win".to_string(),
        "--read-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        "ignored-source".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("source.txt")).unwrap(), b"batch-only");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_only_write_batch_replays_empty_directories() {
    let root = unique_temp_dir("rsync-cli-only-write-batch-empty-dir");
    let source = root.join("source");
    let dest = root.join("dest");
    let batch = root.join("transfer.batch");
    fs::create_dir_all(source.join("empty")).unwrap();

    parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--only-write-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert!(!dest.exists());

    parse_and_execute(vec![
        "rsync-win".to_string(),
        "--read-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        "ignored-source".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert!(dest.join("empty").is_dir());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_only_write_batch_honors_filters_for_replay_records() {
    let root = unique_temp_dir("rsync-cli-filtered-batch");
    let source = root.join("source");
    let dest = root.join("dest");
    let batch = root.join("transfer.batch");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("keep.txt"), b"keep").unwrap();
    fs::write(source.join("skip.tmp"), b"skip").unwrap();

    parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--exclude".to_string(),
        "*.tmp".to_string(),
        "--only-write-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let reader = batch::BatchReader::open(&batch).unwrap();
    let manifest = reader.manifest();
    assert_eq!(manifest.token_stream, "literal-file-contents");
    assert!(
        manifest
            .options
            .iter()
            .any(|option| option == "recursive=true"),
        "{manifest:?}"
    );
    assert!(
        manifest
            .filters
            .iter()
            .any(|filter| filter.contains("Exclude") && filter.contains("*.tmp")),
        "{manifest:?}"
    );
    let records = reader.records();
    let file_records: Vec<_> = records
        .iter()
        .copied()
        .filter(|record| record.kind == batch::BatchRecordKind::File)
        .collect();
    assert_eq!(file_records.len(), 1);
    assert_ne!(file_records[0].checksum, [0u8; 16]);

    parse_and_execute(vec![
        "rsync-win".to_string(),
        "--read-batch".to_string(),
        batch.to_string_lossy().into_owned(),
        "ignored-source".to_string(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep");
    assert!(!dest.join("skip.tmp").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_ntfs_native_sync_writes_sidecar_manifests_when_explicit() {
    let root = unique_temp_dir("rsync-cli-ntfs-sidecar");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let sidecar_root = dest.join(".rsync-win.ntfs-native");
    let sidecar_file = fs::read_dir(&sidecar_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("source__file.txt--") && name.ends_with(".ntfs.meta")
                })
        })
        .expect("expected source file sidecar");

    assert!(output.contains("ntfs sidecars: planned"));
    assert!(sidecar_file.exists());
    assert!(fs::read_to_string(sidecar_file)
        .unwrap()
        .contains("rsync-win ntfs-native sidecar v1"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_ntfs_native_sidecar_names_do_not_flatten_to_collisions() {
    let root = unique_temp_dir("rsync-cli-ntfs-sidecar-collision");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(source.join("a")).unwrap();
    fs::write(source.join("a/b.txt"), b"nested").unwrap();
    fs::write(source.join("a__b.txt"), b"flat").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let sidecar_root = dest.join(".rsync-win.ntfs-native");
    let sidecar_names: BTreeSet<_> = fs::read_dir(sidecar_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();

    assert!(output.contains("ntfs sidecars: planned 4, written 4"));
    assert_eq!(sidecar_names.len(), 4);
    assert!(sidecar_names
        .iter()
        .any(|name| { name.starts_with("source__a__b.txt--") && name.ends_with(".ntfs.meta") }));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_ntfs_native_sidecars_respect_filters() {
    let root = unique_temp_dir("rsync-cli-ntfs-filter");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.txt"), b"keep").unwrap();
    fs::write(source.join("secret.txt"), b"secret").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        "--exclude".to_string(),
        "secret.txt".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let sidecar_paths = ntfs_sidecar_source_paths(&dest);
    assert!(output.contains("ntfs sidecars: planned 2, written 2"));
    assert!(sidecar_paths.contains(&source));
    assert!(sidecar_paths.contains(&source.join("keep.txt")));
    assert!(!sidecar_paths.contains(&source.join("secret.txt")));
    assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep");
    assert!(!dest.join("secret.txt").exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_ntfs_native_sidecars_respect_files_from() {
    let root = unique_temp_dir("rsync-cli-ntfs-files-from");
    let source = root.join("source");
    let dest = root.join("dest");
    let list = root.join("files.txt");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.txt"), b"keep").unwrap();
    fs::write(source.join("drop.txt"), b"drop").unwrap();
    fs::write(&list, b"keep.txt\n").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        "--files-from".to_string(),
        list.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let sidecar_paths = ntfs_sidecar_source_paths(&dest);
    assert!(output.contains("ntfs sidecars: planned 2, written 2"));
    assert!(sidecar_paths.contains(&source));
    assert!(sidecar_paths.contains(&source.join("keep.txt")));
    assert!(!sidecar_paths.contains(&source.join("drop.txt")));
    assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep");
    assert!(!dest.join("drop.txt").exists());

    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn local_ntfs_native_sync_restores_safe_windows_attributes() {
    let root = unique_temp_dir("rsync-cli-ntfs-attributes");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    let source_file = source.join("file.txt");
    fs::write(&source_file, b"hello").unwrap();
    rsync_winfs::restore_safe_windows_attributes(
        &source_file,
        Some(rsync_winfs::FILE_ATTRIBUTE_READONLY | rsync_winfs::FILE_ATTRIBUTE_ARCHIVE),
    )
    .unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let dest_file = dest.join("file.txt");
    let dest_metadata = rsync_winfs::read_windows_metadata(&dest_file).unwrap();
    assert!(dest_metadata
        .attributes
        .is_some_and(|attrs| { attrs & rsync_winfs::FILE_ATTRIBUTE_READONLY != 0 }));
    assert!(output.contains("ntfs attributes: applied"));

    rsync_winfs::restore_safe_windows_attributes(
        &source_file,
        Some(rsync_winfs::FILE_ATTRIBUTE_ARCHIVE),
    )
    .unwrap();
    rsync_winfs::restore_safe_windows_attributes(
        &dest_file,
        Some(rsync_winfs::FILE_ATTRIBUTE_ARCHIVE),
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn local_ntfs_native_sync_copies_alternate_stream_payloads() {
    let root = unique_temp_dir("rsync-cli-ntfs-streams");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    let source_file = source.join("file.txt");
    fs::write(&source_file, b"default").unwrap();
    fs::write(
        test_stream_data_path(&source_file, "Zone.Identifier"),
        b"zone",
    )
    .unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let dest_file = dest.join("file.txt");
    assert_eq!(fs::read(&dest_file).unwrap(), b"default");
    assert_eq!(
        fs::read(test_stream_data_path(&dest_file, "Zone.Identifier")).unwrap(),
        b"zone"
    );
    assert!(output.contains("ntfs streams: copied 1, degraded 0"));

    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn local_ntfs_native_super_restores_security_descriptor_dacl() {
    let root = unique_temp_dir("rsync-cli-ntfs-security");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    let source_file = source.join("file.txt");
    fs::write(&source_file, b"secure").unwrap();
    let source_descriptor = rsync_winfs::SecurityDescriptorSummary {
        captured: true,
        byte_len: None,
        stable_hash: None,
        sddl: Some("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)".to_string()),
        message: None,
    };
    rsync_winfs::restore_security_descriptor(&source_file, &source_descriptor, false).unwrap();
    let captured_source = rsync_winfs::capture_security_descriptor_summary(&source_file).unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        "--super".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let dest_file = dest.join("file.txt");
    let captured_dest = rsync_winfs::capture_security_descriptor_summary(&dest_file).unwrap();
    assert_eq!(
        security_dacl_fragment(captured_dest.sddl.as_deref().unwrap()),
        security_dacl_fragment(captured_source.sddl.as_deref().unwrap())
    );
    assert!(
        output.contains("ntfs security descriptors: restored 2, degraded 0"),
        "{output}"
    );
    assert!(
        !output.contains("security-descriptor metadata degraded"),
        "{output}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn local_ntfs_native_sparse_sync_preserves_sparse_ranges() {
    let root = unique_temp_dir("rsync-cli-ntfs-sparse-ranges");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    let source_file = source.join("sparse.bin");
    let len = 1024 * 1024;
    let range_len = 64 * 1024;
    fs::write(&source_file, vec![0_u8; len]).unwrap();
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .open(&source_file)
            .unwrap();
        handle.write_all(&vec![1_u8; range_len]).unwrap();
        handle
            .seek(SeekFrom::Start((len - range_len) as u64))
            .unwrap();
        handle.write_all(&vec![2_u8; range_len]).unwrap();
    }
    let ranges = vec![
        rsync_winfs::SparseRange {
            offset: 0,
            len: range_len as u64,
        },
        rsync_winfs::SparseRange {
            offset: (len - range_len) as u64,
            len: range_len as u64,
        },
    ];
    rsync_winfs::restore_sparse_ranges(&source_file, len as u64, &ranges).unwrap();
    assert_eq!(
        rsync_winfs::query_sparse_allocated_ranges(&source_file, len as u64).unwrap(),
        ranges
    );

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--sparse".to_string(),
        "--metadata-policy".to_string(),
        "ntfs-native".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let dest_file = dest.join("sparse.bin");
    assert_eq!(
        fs::read(&dest_file).unwrap(),
        fs::read(&source_file).unwrap()
    );
    assert_eq!(
        rsync_winfs::query_sparse_allocated_ranges(&dest_file, len as u64).unwrap(),
        ranges
    );
    assert!(
        output.contains("ntfs sparse ranges: restored 1, degraded 0"),
        "{output}"
    );
    assert!(
        !output.contains("sparse-file metadata degraded"),
        "{output}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_honors_files_from_records() {
    let root = unique_temp_dir("rsync-cli-files-from");
    let source = root.join("source");
    let dest = root.join("dest");
    let list = root.join("files.txt");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("keep.txt"), b"keep").unwrap();
    fs::write(source.join("skip.txt"), b"skip").unwrap();
    fs::write(&list, b"keep.txt\n").unwrap();

    parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--files-from".to_string(),
        list.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep");
    assert!(!dest.join("skip.txt").exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_runs_append_verify_itemize_and_stats() {
    let root = unique_temp_dir("rsync-cli-append-verify");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("file.txt"), b"abcdef").unwrap();
    fs::write(dest.join("file.txt"), b"abc").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--append-verify".to_string(),
        "--itemize-changes".to_string(),
        "--stats".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("file.txt")).unwrap(), b"abcdef");
    assert!(output.contains("itemized changes:"));
    assert!(output.contains(">f+++++a+++"));
    assert!(output.contains("structured stats:"));
    assert!(output.contains("- appended files: 1"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_applies_out_format_and_log_file_format() {
    let root = unique_temp_dir("rsync-cli-output-format");
    let source = root.join("source");
    let dest = root.join("dest");
    let log_file = root.join("transfer.log");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("file.txt"), b"payload").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--out-format".to_string(),
        "%i %n %l".to_string(),
        "--log-file".to_string(),
        log_file.to_string_lossy().into_owned(),
        "--log-file-format".to_string(),
        "%i|%n|%l|%M".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert!(
        output.lines().any(|line| line == ">f+++++++++ file.txt 7"),
        "{output}"
    );
    let log = fs::read_to_string(&log_file).unwrap();
    assert!(
        log.lines()
            .any(|line| line == ">f+++++++++|file.txt|7|write file.txt"),
        "{log}"
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_escapes_out_format_names_unless_8_bit_output_is_set() {
    let root = unique_temp_dir("rsync-cli-8bit-output");
    let source = root.join("source");
    let dest = root.join("dest");
    let filename = "caf\u{00e9}.txt";
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join(filename), b"payload").unwrap();

    let escaped = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--out-format".to_string(),
        "%n".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert!(
        escaped.lines().any(|line| line == "caf\\#303\\#251.txt"),
        "{escaped}"
    );

    fs::remove_dir_all(&dest).unwrap();
    fs::create_dir_all(&dest).unwrap();

    let literal = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--8-bit-output".to_string(),
        "--out-format".to_string(),
        "%n".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert!(literal.lines().any(|line| line == filename), "{literal}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_fails_before_transfer_when_log_file_cannot_be_opened() {
    let root = unique_temp_dir("rsync-cli-log-file-open");
    let source = root.join("source");
    let dest = root.join("dest");
    let log_file = root.join("missing").join("transfer.log");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("file.txt"), b"payload").unwrap();

    let err = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "--log-file".to_string(),
        log_file.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap_err();

    assert!(
        format!("{err:#}").contains("failed to open client log file"),
        "{err:#}"
    );
    assert!(!dest.join("file.txt").exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_runs_inplace_mode() {
    let root = unique_temp_dir("rsync-cli-inplace");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();
    fs::write(source.join("file.txt"), b"new").unwrap();
    fs::write(dest.join("file.txt"), b"old").unwrap();

    let output = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        "-vv".to_string(),
        "--ignore-times".to_string(),
        "--inplace".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap();

    assert_eq!(fs::read(dest.join("file.txt")).unwrap(), b"new");
    assert!(output.contains("write-file-inplace"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_rejects_unicode_normalization_collision_before_write() {
    let root = unique_temp_dir("rsync-cli-unicode-preflight");
    let source = root.join("source");
    let dest = root.join("dest");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&dest).unwrap();

    let composed = source.join("caf\u{00e9}.txt");
    let decomposed = source.join("cafe\u{0301}.txt");
    if fs::write(&composed, b"composed").is_err() || fs::write(&decomposed, b"decomposed").is_err()
    {
        fs::remove_dir_all(root).unwrap();
        return;
    }
    if fs::read_dir(&source).unwrap().count() < 2 {
        fs::remove_dir_all(root).unwrap();
        return;
    }

    let err = parse_and_execute(vec![
        "rsync-win".to_string(),
        "-r".to_string(),
        source.to_string_lossy().into_owned(),
        dest.to_string_lossy().into_owned(),
    ])
    .unwrap_err();

    assert!(err
        .to_string()
        .contains("destination path preflight failed"));
    assert!(err.to_string().contains("case/normalization collision"));
    assert!(fs::read_dir(&dest).unwrap().next().is_none());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn local_executor_preflight_rejects_case_collision_paths() {
    let err = windows_destination_path_preflight(&[
        PathBuf::from("dir/Foo.txt"),
        PathBuf::from("dir/foo.txt"),
    ])
    .unwrap_err();

    assert!(matches!(err, FsError::DestinationPathPreflight(_)));
}

#[test]
fn remote_sender_executability_sets_execute_bits_for_windows_scripts() {
    let root = unique_temp_dir("rsync-cli-executability-mode");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("app.exe"), b"exe").unwrap();
    fs::write(source.join("run.bat"), b"echo hi").unwrap();
    fs::write(source.join("run.cmd"), b"echo hi").unwrap();
    fs::write(source.join("script.ps1"), b"Write-Host hi").unwrap();
    fs::write(source.join("notes.txt"), b"notes").unwrap();
    let filter_rules = RuleSet::empty();
    let options = LocalSourceCollectOptions {
        recursive: true,
        filter_rules: &filter_rules,
        files_from: None,
        symlink_mode: SymlinkMode::Preserve,
        include_checksums: false,
        preserve_executability: true,
        preserve_hard_links: false,
        chmod_rules: None,
    };

    let entries = collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();

    for path in ["app.exe", "run.bat", "run.cmd", "script.ps1"] {
        let entry = entries
            .iter()
            .find(|entry| entry.wire.path.as_path() == Path::new(path))
            .unwrap();
        assert_eq!(entry.wire.mode & 0o111, 0o111, "{path}");
    }
    let notes = entries
        .iter()
        .find(|entry| entry.wire.path.as_path() == Path::new("notes.txt"))
        .unwrap();

    assert_eq!(notes.wire.mode & 0o111, 0);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_sender_chmod_applies_numeric_modes_to_remote_file_list() {
    let root = unique_temp_dir("rsync-cli-chmod-mode");
    let source = root.join("source");
    fs::create_dir_all(source.join("dir")).unwrap();
    fs::write(source.join("dir/file.txt"), b"data").unwrap();
    let chmod_rules = "F600,D700".parse::<ChmodRules>().unwrap();
    let filter_rules = RuleSet::empty();
    let options = LocalSourceCollectOptions {
        recursive: true,
        filter_rules: &filter_rules,
        files_from: None,
        symlink_mode: SymlinkMode::Preserve,
        include_checksums: false,
        preserve_executability: false,
        preserve_hard_links: false,
        chmod_rules: Some(&chmod_rules),
    };

    let entries = collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();

    let dir = entries
        .iter()
        .find(|entry| entry.wire.path.as_path() == Path::new("dir"))
        .unwrap();
    let file = entries
        .iter()
        .find(|entry| entry.wire.path.as_path() == Path::new("dir/file.txt"))
        .unwrap();

    assert_eq!(dir.wire.mode & 0o7777, 0o700);
    assert_eq!(file.wire.mode & 0o7777, 0o600);

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_sender_protect_filter_keeps_source_entries() {
    let root = unique_temp_dir("rsync-cli-protect-sender");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.bak"), b"backup").unwrap();
    let filter_rules = RuleSet::new(vec![Rule::protect("*.bak").unwrap()]);
    let options = LocalSourceCollectOptions {
        recursive: true,
        filter_rules: &filter_rules,
        files_from: None,
        symlink_mode: SymlinkMode::Preserve,
        include_checksums: false,
        preserve_executability: false,
        preserve_hard_links: false,
        chmod_rules: None,
    };

    let entries = collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();

    assert!(entries
        .iter()
        .any(|entry| entry.wire.path.as_path() == Path::new("keep.bak")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_sender_collects_file_list_batches_during_local_walk() {
    let root = unique_temp_dir("rsync-cli-source-batches");
    let source = root.join("source");
    fs::create_dir_all(source.join("dir")).unwrap();
    for path in ["a.txt", "b.txt", "dir/c.txt", "dir/d.txt"] {
        fs::write(source.join(path), b"x").unwrap();
    }
    let filter_rules = RuleSet::empty();
    let options = LocalSourceCollectOptions {
        recursive: true,
        filter_rules: &filter_rules,
        files_from: None,
        symlink_mode: SymlinkMode::Preserve,
        include_checksums: false,
        preserve_executability: false,
        preserve_hard_links: false,
        chmod_rules: None,
    };

    let mut batch_lengths = Vec::new();
    let mut paths = Vec::new();
    collect_local_source_entry_batches(std::slice::from_ref(&source), &options, 2, None, |batch| {
        assert!(batch.entries.len() <= 2);
        batch_lengths.push(batch.entries.len());
        paths.extend(batch.entries.iter().map(|entry| entry.wire.path.clone()));
        Ok(())
    })
    .unwrap();

    assert!(batch_lengths.len() >= 3);
    assert_eq!(paths.first().map(PathBuf::as_path), Some(Path::new(".")));
    assert!(paths.contains(&PathBuf::from("dir/c.txt")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn remote_sender_marks_hardlink_groups_in_file_list() {
    let root = unique_temp_dir("rsync-cli-remote-hardlink-groups");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    let original = source.join("original.txt");
    let alias = source.join("alias.txt");
    fs::write(&original, b"same").unwrap();
    if fs::hard_link(&original, &alias).is_err() {
        fs::remove_dir_all(root).unwrap();
        return;
    }
    let filter_rules = RuleSet::empty();
    let options = LocalSourceCollectOptions {
        recursive: true,
        filter_rules: &filter_rules,
        files_from: None,
        symlink_mode: SymlinkMode::Preserve,
        include_checksums: false,
        preserve_executability: false,
        preserve_hard_links: true,
        chmod_rules: None,
    };

    let entries = collect_local_source_entries(std::slice::from_ref(&source), &options).unwrap();
    let original_entry = entries
        .iter()
        .find(|entry| entry.wire.path.as_path() == Path::new("original.txt"))
        .unwrap();
    let alias_entry = entries
        .iter()
        .find(|entry| entry.wire.path.as_path() == Path::new("alias.txt"))
        .unwrap();

    assert!(original_entry.wire.hardlink_group.is_some());
    assert_eq!(
        original_entry.wire.hardlink_group,
        alias_entry.wire.hardlink_group
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn chmod_accepts_symbolic_forms_in_cli_plan() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--chmod",
        "u+rw,go-w",
        "src",
        "host:/dest",
    ]);

    assert!(output.contains("posix metadata: chmod"));
    assert!(!output.contains("[error] E_CHMOD"));
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
    path
}

fn write_test_password_file(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn test_remote_entry(path: &str, file_type: WireFileType) -> RsyncFileListEntry {
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
fn test_stream_data_path(path: &Path, stream_name: &str) -> PathBuf {
    let mut stream_path = to_long_path_safe(path).into_os_string();
    stream_path.push(format!(":{stream_name}"));
    PathBuf::from(stream_path)
}

fn ntfs_sidecar_source_paths(dest: &Path) -> BTreeSet<PathBuf> {
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
fn security_dacl_fragment(sddl: &str) -> &str {
    let Some(start) = sddl.find("D:") else {
        return "";
    };
    let rest = &sddl[start..];
    let end = rest.find("S:").unwrap_or(rest.len());
    &rest[..end]
}

fn test_remote_block_signatures(
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

fn remote_push_dry_run_input() -> Vec<u8> {
    let mut input = remote_handshake_input();
    append_remote_push_dry_run_response(&mut input);
    input
}

fn daemon_push_dry_run_input() -> Vec<u8> {
    let mut input = daemon_protocol31_setup_input();
    append_remote_push_dry_run_response(&mut input);
    input
}

fn append_remote_push_dry_run_response(input: &mut Vec<u8>) {
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

fn remote_push_transfer_request_input(index: i32) -> Vec<u8> {
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

fn remote_push_append_verify_input() -> Vec<u8> {
    remote_push_append_verify_input_with_sum_head(RemoteSumHead {
        block_count: 1,
        block_len: 3,
        checksum_len: 2,
        remainder: 0,
    })
}

fn remote_push_append_verify_oversized_basis_input() -> Vec<u8> {
    remote_push_append_verify_input_with_sum_head(RemoteSumHead {
        block_count: 3,
        block_len: 3,
        checksum_len: 2,
        remainder: 0,
    })
}

fn remote_push_append_verify_input_with_sum_head(sum_head: RemoteSumHead) -> Vec<u8> {
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

fn remote_push_unsupported_mux_input() -> Vec<u8> {
    let mut input = remote_handshake_input();
    append_mux_frame(&mut input, 6, &[]);
    input
}

fn remote_push_final_unsupported_mux_input() -> Vec<u8> {
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

fn remote_pull_dry_run_input() -> Vec<u8> {
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

fn daemon_pull_dry_run_input() -> Vec<u8> {
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

fn daemon_protocol31_setup_input() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&[0x81, 0xff]);
    input.push(35);
    input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
    input.extend_from_slice(&0_i32.to_le_bytes());
    input
}

fn remote_pull_file_list_only_input(entries: &[RsyncFileListEntry]) -> Vec<u8> {
    let mut input = remote_handshake_input();
    let mut flist = Vec::new();
    write_rsync31_file_list_with_options(&mut flist, entries, false).unwrap();
    append_mux_payload(&mut input, &flist);
    input
}

fn remote_pull_transfer_input(
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

fn remote_pull_transfer_input_with_checksum(
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

fn remote_pull_filter_dry_run_input() -> Vec<u8> {
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

fn remote_pull_incremental_dry_run_input() -> Vec<u8> {
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

fn remote_pull_dry_run_input_with_entries(
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

fn remote_pull_dry_run_mux_input_with_entries(
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

fn remote_handshake_input() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&31_u32.to_le_bytes());
    input.extend_from_slice(&[0x81, 0xff]);
    input.push(35);
    input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
    input.extend_from_slice(&0_i32.to_le_bytes());
    input
}

fn append_mux_payload(out: &mut Vec<u8>, payload: &[u8]) {
    append_mux_frame(out, 7, payload);
}

fn append_mux_frame(out: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    let header = (tag << 24) | payload.len() as u32;
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(payload);
}

fn written_protocol31_mux_payloads(written: &[u8]) -> Vec<Vec<u8>> {
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
struct TestTransport {
    input: std::io::Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl TestTransport {
    fn with_input(input: Vec<u8>) -> Self {
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

// Chunk 12: Advanced Transfer Features tests

#[test]
fn plan_renders_compare_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--compare-dest=/tmp/basis",
        "src",
        "dst",
    ]);
    assert!(plan.contains("compare dest: /tmp/basis"));
    assert!(plan.contains("--compare-dest=/tmp/basis is represented in the execution plan"));
}

#[test]
fn plan_renders_multiple_compare_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--compare-dest=/tmp/basis1",
        "--compare-dest=/tmp/basis2",
        "src",
        "dst",
    ]);
    assert!(plan.contains("compare dest: /tmp/basis1 /tmp/basis2"));
}

#[test]
fn plan_renders_copy_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--copy-dest=/tmp/basis",
        "src",
        "dst",
    ]);
    assert!(plan.contains("copy dest: /tmp/basis"));
}

#[test]
fn plan_renders_link_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--link-dest=/tmp/basis",
        "src",
        "dst",
    ]);
    assert!(plan.contains("link dest: /tmp/basis"));
}

#[test]
fn plan_renders_sparse() {
    let plan = parse_and_render(["rsync-win", "--plan", "-S", "src", "dst"]);
    assert!(plan.contains("sparse: true"));
    assert!(plan.contains("FSCTL_SET_SPARSE_FILE"));
}

#[test]
fn plan_renders_preallocate() {
    let plan = parse_and_render(["rsync-win", "--plan", "--preallocate", "src", "dst"]);
    assert!(plan.contains("preallocate: true"));
}

#[test]
fn plan_warns_sparse_preallocate_overlap() {
    let plan = parse_and_render(["rsync-win", "--plan", "-S", "--preallocate", "src", "dst"]);
    assert!(plan.contains("--sparse and --preallocate together"));
}

#[test]
fn plan_renders_fuzzy() {
    let plan = parse_and_render(["rsync-win", "--plan", "-y", "src", "dst"]);
    assert!(plan.contains("fuzzy: true"));
}

#[test]
fn plan_renders_copy_as() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--copy-as=Administrator",
        "src",
        "dst",
    ]);
    assert!(plan.contains("copy-as: Administrator"));
}

#[test]
fn plan_renders_super() {
    let plan = parse_and_render(["rsync-win", "--plan", "--super", "src", "dst"]);
    assert!(plan.contains("super: true"));
}

#[test]
fn plan_renders_no_super() {
    let plan = parse_and_render(["rsync-win", "--plan", "--no-super", "src", "dst"]);
    assert!(!plan.contains("super: true"));
}

#[test]
fn plan_renders_negated_chunk12_flags() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "-S",
        "--no-sparse",
        "--preallocate",
        "--no-preallocate",
        "-y",
        "--no-fuzzy",
        "src",
        "dst",
    ]);

    assert!(!plan.contains("sparse: true"), "{plan}");
    assert!(!plan.contains("preallocate: true"), "{plan}");
    assert!(!plan.contains("fuzzy: true"), "{plan}");
    assert!(!plan.contains("W_UNIMPLEMENTED_OPTION"), "{plan}");
}

#[test]
fn plan_renders_write_batch() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--write-batch=/tmp/batch.bin",
        "src",
        "dst",
    ]);
    assert!(plan.contains("write-batch: /tmp/batch.bin"));
}

#[test]
fn plan_renders_read_batch() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--read-batch=/tmp/batch.bin",
        "src",
        "dst",
    ]);
    assert!(plan.contains("read-batch: /tmp/batch.bin"));
}

#[test]
fn plan_errors_on_write_and_only_write_batch_together() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--write-batch=a",
        "--only-write-batch=b",
        "src",
        "dst",
    ]);
    assert!(plan.contains("--write-batch and --only-write-batch cannot both be specified"));
}

#[test]
fn plan_errors_on_write_and_read_batch_together() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--write-batch=a",
        "--read-batch=b",
        "src",
        "dst",
    ]);
    assert!(plan.contains("--write-batch and --read-batch cannot both be specified"));
}

#[test]
fn plan_shows_all_chunk12_options_together() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--compare-dest=/tmp/a",
        "--copy-dest=/tmp/b",
        "--link-dest=/tmp/c",
        "-S",
        "--preallocate",
        "-y",
        "src",
        "dst",
    ]);
    assert!(plan.contains("compare dest: /tmp/a"));
    assert!(plan.contains("copy dest: /tmp/b"));
    assert!(plan.contains("link dest: /tmp/c"));
    assert!(plan.contains("sparse: true"));
    assert!(plan.contains("preallocate: true"));
    assert!(plan.contains("fuzzy: true"));
}
