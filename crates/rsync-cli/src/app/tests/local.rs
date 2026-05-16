use super::*;

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
