use super::*;

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
