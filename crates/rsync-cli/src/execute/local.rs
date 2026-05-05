use std::fs::{self};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use rsync_core::{ChmodFileKind, MetadataPolicy};
use rsync_fs::{
    selected_source_paths, sync_sources, FileType, LocalFileSystem, PortableFileSystem,
    SourceSelectionOptions, SyncOptions, UpdateMode,
};
use rsync_protocol::WireFileType;
use rsync_winfs::{
    capture_ntfs_native_sidecar, copy_alternate_data_streams,
    parse_posix_fake_super_sidecar_manifest, read_windows_metadata, restore_creation_time,
    restore_safe_windows_attributes, restore_security_descriptor, restore_sparse_ranges,
    PosixAclRecord, PosixFakeSuperSidecar, PosixXattrRecord, VssSnapshot,
};

use crate::cli::Cli;
use crate::format::*;
use crate::plan::*;
use crate::remote::flist::*;
use crate::remote::receive::{system_time_to_unix_nanos, windows_destination_path_preflight};
use crate::{batch, output, ProgressLog};

pub(crate) fn execute_local_sync(cli: &Cli, plan: TransferPlan) -> Result<String> {
    let sources = local_source_paths(cli);
    let (effective_sources, vss_snapshots) = prepare_vss_sources(&sources, &plan)?;
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
    let files_from = load_files_from(cli)?;
    let ntfs_files_from = files_from.clone();
    let mut fs = LocalFileSystem;
    let mut client_log = output::TransferLog::from_cli(cli)?;
    let progress = ProgressLog::from_cli(cli);
    progress.info(format!(
        "local sync starting: {} source(s) -> {}",
        sources.len(),
        dest.display()
    ));
    let sync_report = sync_sources(
        &mut fs,
        &effective_sources,
        dest,
        SyncOptions {
            recursive: plan.recursive,
            delete: plan.delete,
            delete_mode: plan.delete_mode,
            preserve_mtime: plan.preserve_times,
            omit_dir_times: plan.omit_dir_times,
            dry_run: plan.dry_run,
            filter_rules: plan.filter_rules.clone(),
            destination_path_preflight: Some(windows_destination_path_preflight),
            update_mode: plan.update_mode,
            files_from,
            file_write_mode: plan.file_write_mode,
            keep_partial: plan.keep_partial,
            partial_dir: plan.partial_dir.clone(),
            temp_dir: plan.temp_dir.clone(),
            delay_updates: plan.delay_updates,
            fsync: plan.fsync,
            append_verify: plan.append_verify,
            symlink_mode: plan.symlink_mode,
            transfer_dirs: plan.transfer_dirs,
            mkpath: plan.mkpath,
            relative_paths: plan.relative,
            implied_dirs: plan.implied_dirs,
            one_file_system: plan.one_file_system,
            skip_newer_receiver: plan.skip_newer_receiver,
            existing_only: plan.existing_only,
            ignore_existing: plan.ignore_existing,
            max_size: plan.max_size,
            min_size: plan.min_size,
            modify_window: plan.modify_window,
            ignore_missing_args: plan.ignore_missing_args,
            delete_missing_args: plan.delete_missing_args,
            delete_excluded: plan.delete_excluded,
            ignore_errors: plan.ignore_errors,
            force_delete: plan.force_delete,
            max_delete: plan.max_delete,
            backup: plan.backup,
            backup_dir: plan.backup_dir.clone(),
            backup_suffix: plan.backup_suffix.clone(),
            preserve_hard_links: plan.hard_links,
            keep_dirlinks: plan.keep_dirlinks,
            preserve_devices: plan.preserve_devices,
            preserve_specials: plan.preserve_specials,
            fail_on_metadata_loss: cli.fail_on_metadata_loss,
            compare_dest: plan.compare_dest.clone(),
            copy_dest: plan.copy_dest.clone(),
            link_dest: plan.link_dest.clone(),
            sparse: plan.sparse,
            preallocate: plan.preallocate,
            fuzzy: plan.fuzzy,
            bwlimit: plan.bwlimit,
            max_alloc: plan.max_alloc,
            stop_deadline: plan.stop_deadline,
        },
    )?;
    log_sync_actions(progress, sync_report.actions());
    progress.info(format!(
        "local sync finished: {} action(s)",
        sync_report.actions().len()
    ));
    let ntfs_sidecars =
        handle_ntfs_native_sidecars(&sources, dest, &plan, ntfs_files_from.as_deref())?;
    let posix_sidecars =
        handle_posix_fake_super_sidecars(&sources, dest, &plan, ntfs_files_from.as_deref())?;

    let mut output = String::new();
    output.push_str("rsync-win local portable sync\n");
    append_sources_summary(&mut output, &sources);
    output.push_str(&format!("destination: {}\n", dest.display()));
    output.push_str(&format!("dry run: {}\n", plan.dry_run));
    output.push_str(&format!("metadata policy: {}\n", plan.metadata_policy));
    output.push_str(&format!(
        "posix metadata: {}\n",
        posix_metadata_summary(&plan)
    ));
    if plan.metadata_policy == MetadataPolicy::NtfsNative || plan.vss {
        output.push_str(&format!(
            "ntfs-native metadata: sidecar-capture restore path, vss={}\n",
            plan.vss
        ));
    }
    if !vss_snapshots.is_empty() {
        output.push_str(&format!("vss snapshots: active {}\n", vss_snapshots.len()));
    }
    if let Some(sidecars) = ntfs_sidecars {
        output.push_str(&format!(
            "ntfs sidecars: planned {}, written {}\n",
            sidecars.planned, sidecars.written
        ));
        output.push_str(&format!(
            "ntfs attributes: applied {}, degraded {}\n",
            sidecars.attributes_applied, sidecars.attributes_degraded
        ));
        output.push_str(&format!(
            "ntfs creation times: applied {}\n",
            sidecars.creation_times_applied
        ));
        output.push_str(&format!(
            "ntfs streams: copied {}, degraded {}\n",
            sidecars.streams_copied, sidecars.streams_degraded
        ));
        output.push_str(&format!(
            "ntfs security descriptors: restored {}, degraded {}\n",
            sidecars.security_restored, sidecars.security_degraded
        ));
        output.push_str(&format!(
            "ntfs sparse ranges: restored {}, degraded {}\n",
            sidecars.sparse_restored, sidecars.sparse_degraded
        ));
        output.push_str(&format!("ntfs sidecar root: {}\n", sidecars.root.display()));
    }
    if let Some(sidecars) = posix_sidecars {
        output.push_str(&format!(
            "posix sidecars: planned {}, written {}, restored {}\n",
            sidecars.planned, sidecars.written, sidecars.restored
        ));
        output.push_str(&format!(
            "posix sidecar root: {}\n",
            sidecars.root.display()
        ));
    }

    if !plan.report.is_empty() {
        output.push_str("diagnostics:\n");
        append_diagnostics(&mut output, &plan.report);
    }

    append_action_report(&mut output, cli, sync_report.actions());
    append_out_format_and_client_log(&mut output, cli, sync_report.actions(), &mut client_log)?;

    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NtfsSidecarExecution {
    root: PathBuf,
    planned: usize,
    written: usize,
    attributes_applied: usize,
    attributes_degraded: usize,
    creation_times_applied: usize,
    streams_copied: usize,
    streams_degraded: usize,
    security_restored: usize,
    security_degraded: usize,
    sparse_restored: usize,
    sparse_degraded: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PosixSidecarExecution {
    root: PathBuf,
    planned: usize,
    written: usize,
    restored: usize,
}

// Chunk 12: Batch mode execution helpers

pub(crate) fn execute_local_sync_with_batch(
    cli: &Cli,
    plan: TransferPlan,
    batch_path: &Path,
    only_write_batch: bool,
) -> Result<String> {
    let sources = local_source_paths(cli);
    let dest = Path::new(cli.paths.last().expect("checked operand count"));
    let mut fs = LocalFileSystem;
    let files_from = load_files_from(cli)?;
    let collect_options = local_source_collect_options(&plan, files_from.as_deref());
    let entries = collect_local_source_entries(&sources, &collect_options)?;
    let manifest = batch_manifest_from_plan(cli, &plan);
    let mut batch_writer =
        batch::BatchWriter::create_with_manifest(batch_path, plan.dry_run, manifest)?;

    for entry in &entries {
        let source_meta = fs.metadata(&entry.local_path)?;
        match entry.wire.file_type {
            WireFileType::File => {
                batch_writer.append_file(
                    &mut fs,
                    &entry.wire.path,
                    &entry.local_path,
                    dest,
                    entry.wire.len,
                    source_meta.modified,
                )?;
            }
            WireFileType::Directory => {
                batch_writer.append_directory(&entry.wire.path, source_meta.modified)?;
            }
            _ => {}
        }
    }

    let records = batch_writer.finish()?;
    let mut output = String::new();
    output.push_str(&format!(
        "rsync-win batch {}: {} record(s) written to {}\n",
        if only_write_batch {
            "--only-write-batch"
        } else {
            "--write-batch"
        },
        records.len(),
        batch_path.display()
    ));
    if !only_write_batch {
        output.push_str(&execute_local_sync(cli, plan)?);
    }
    Ok(output)
}

fn batch_manifest_from_plan(cli: &Cli, plan: &TransferPlan) -> batch::BatchManifest {
    let mut options = vec![
        format!("recursive={}", plan.recursive),
        format!("delete={}", plan.delete),
        format!("delete-mode={:?}", plan.delete_mode),
        format!("preserve-times={}", plan.preserve_times),
        format!("dry-run={}", plan.dry_run),
        format!("relative={}", plan.relative),
        format!("checksum={}", plan.update_mode == UpdateMode::Checksum),
        format!("whole-file={}", plan.whole_file),
        format!("sparse={}", plan.sparse),
        format!("preallocate={}", plan.preallocate),
        format!("fuzzy={}", plan.fuzzy),
    ];
    if let Some(files_from) = &cli.files_from {
        options.push(format!("files-from={}", files_from.display()));
    }
    if cli.from0 {
        options.push("from0=true".to_string());
    }
    for dir in &plan.compare_dest {
        options.push(format!("compare-dest={}", dir.display()));
    }
    for dir in &plan.copy_dest {
        options.push(format!("copy-dest={}", dir.display()));
    }
    for dir in &plan.link_dest {
        options.push(format!("link-dest={}", dir.display()));
    }

    batch::BatchManifest {
        options,
        filters: plan
            .filter_rules
            .rules()
            .iter()
            .map(|rule| format!("{rule:?}"))
            .collect(),
        token_stream: "literal-file-contents".to_string(),
    }
}

pub(crate) fn execute_read_batch(
    batch_file: &Path,
    paths: &[String],
    dry_run_override: bool,
) -> Result<String> {
    let dest = Path::new(
        paths
            .last()
            .context("read-batch requires a destination operand")?,
    );
    let mut output = String::new();
    output.push_str(&format!(
        "rsync-win batch replay: {}\n",
        batch_file.display()
    ));
    output.push_str(&format!("destination: {}\n", dest.display()));
    if dry_run_override {
        output.push_str("dry run: true\n");
    }
    batch::replay_batch(
        batch_file,
        dest,
        if dry_run_override { Some(true) } else { None },
    )?;
    output.push_str("batch replay complete\n");
    Ok(output)
}

fn handle_ntfs_native_sidecars(
    sources: &[PathBuf],
    dest: &Path,
    plan: &TransferPlan,
    files_from: Option<&[PathBuf]>,
) -> Result<Option<NtfsSidecarExecution>> {
    if plan.metadata_policy != MetadataPolicy::NtfsNative {
        return Ok(None);
    }

    let fs = LocalFileSystem;
    let sidecar_root = ntfs_sidecar_root(dest);
    let capture_paths = collect_ntfs_sidecar_paths(&fs, sources, plan, files_from)?;
    if plan.dry_run {
        return Ok(Some(NtfsSidecarExecution {
            root: sidecar_root,
            planned: capture_paths.len(),
            written: 0,
            attributes_applied: 0,
            attributes_degraded: 0,
            creation_times_applied: 0,
            streams_copied: 0,
            streams_degraded: 0,
            security_restored: 0,
            security_degraded: 0,
            sparse_restored: 0,
            sparse_degraded: 0,
        }));
    }

    fs::create_dir_all(&sidecar_root)?;
    let mut written = 0;
    let mut attributes_applied = 0;
    let mut attributes_degraded = 0;
    let mut creation_times_applied = 0;
    let mut streams_copied = 0;
    let mut streams_degraded = 0;
    let mut security_restored = 0;
    let mut security_degraded = 0;
    let mut sparse_restored = 0;
    let mut sparse_degraded = 0;
    for source_path in &capture_paths {
        let sidecar = capture_ntfs_native_sidecar(source_path, plan.vss)
            .with_context(|| format!("capture NTFS metadata for {}", source_path.display()))?;
        if let Some(target_path) = ntfs_destination_for_source(sources, dest, source_path) {
            if target_path.exists() {
                if restore_creation_time(
                    &target_path,
                    sidecar
                        .creation_time_unix_nanos
                        .and_then(unix_nanos_to_system_time),
                )
                .with_context(|| format!("restore creation time for {}", target_path.display()))?
                {
                    creation_times_applied += 1;
                }
                if sidecar.file_type == FileType::File {
                    let report = copy_alternate_data_streams(source_path, &target_path)
                        .with_context(|| {
                            format!("copy alternate data streams to {}", target_path.display())
                        })?;
                    streams_copied += report.copied;
                    if report.unavailable && !sidecar.streams.is_empty() {
                        streams_degraded += sidecar.streams.len();
                    }
                }
                if sidecar.file_type == FileType::File && sidecar.sparse_file {
                    if plan.sparse {
                        let restore = restore_sparse_ranges(
                            &target_path,
                            sidecar.len,
                            &sidecar.sparse_ranges,
                        )
                        .with_context(|| {
                            format!("restore sparse ranges for {}", target_path.display())
                        })?;
                        if restore.applied {
                            sparse_restored += 1;
                        }
                        if !restore.available || restore.message.is_some() {
                            sparse_degraded += 1;
                        }
                    } else {
                        sparse_degraded += 1;
                    }
                }
                if sidecar.security.captured {
                    if plan.super_flag {
                        let restore =
                            restore_security_descriptor(&target_path, &sidecar.security, true)
                                .with_context(|| {
                                    format!(
                                        "restore security descriptor for {}",
                                        target_path.display()
                                    )
                                })?;
                        if restore.applied {
                            security_restored += 1;
                        }
                        if !restore.available || restore.message.is_some() {
                            security_degraded += 1;
                        }
                    } else {
                        security_degraded += 1;
                    }
                }
                let restore = restore_safe_windows_attributes(&target_path, sidecar.attributes)
                    .with_context(|| {
                        format!(
                            "restore safe Windows attributes for {}",
                            target_path.display()
                        )
                    })?;
                if restore.applied_mask != 0 {
                    attributes_applied += 1;
                }
                if restore.degraded_mask != 0 || !restore.available {
                    attributes_degraded += 1;
                }
            } else if sidecar.attributes.is_some() {
                attributes_degraded += 1;
                streams_degraded += sidecar.streams.len();
                if sidecar.security.captured {
                    security_degraded += 1;
                }
                if sidecar.sparse_file {
                    sparse_degraded += 1;
                }
            }
        }
        let relative = ntfs_sidecar_relative_name(sources, source_path);
        let manifest_path = sidecar_root.join(format!("{relative}.ntfs.meta"));
        fs::write(&manifest_path, sidecar.manifest())?;
        written += 1;
    }

    Ok(Some(NtfsSidecarExecution {
        root: sidecar_root,
        planned: capture_paths.len(),
        written,
        attributes_applied,
        attributes_degraded,
        creation_times_applied,
        streams_copied,
        streams_degraded,
        security_restored,
        security_degraded,
        sparse_restored,
        sparse_degraded,
    }))
}

fn prepare_vss_sources(
    sources: &[PathBuf],
    plan: &TransferPlan,
) -> Result<(Vec<PathBuf>, Vec<VssSnapshot>)> {
    if !plan.vss {
        return Ok((sources.to_vec(), Vec::new()));
    }
    if plan.metadata_policy != MetadataPolicy::NtfsNative {
        anyhow::bail!("--vss requires --metadata-policy=ntfs-native");
    }
    if plan.dry_run {
        return Ok((sources.to_vec(), Vec::new()));
    }

    let mut snapshots = Vec::with_capacity(sources.len());
    let mut mapped_sources = Vec::with_capacity(sources.len());
    for source in sources {
        let snapshot = VssSnapshot::create_for_source(source)
            .with_context(|| format!("create VSS snapshot for {}", source.display()))?;
        let mapped = snapshot
            .map_source_path(source)
            .with_context(|| format!("map VSS snapshot source {}", source.display()))?;
        mapped_sources.push(mapped);
        snapshots.push(snapshot);
    }

    Ok((mapped_sources, snapshots))
}

fn unix_nanos_to_system_time(nanos: i128) -> Option<std::time::SystemTime> {
    if nanos < 0 {
        return None;
    }
    let nanos = u128::try_from(nanos).ok()?;
    let secs = u64::try_from(nanos / 1_000_000_000).ok()?;
    let sub = u32::try_from(nanos % 1_000_000_000).ok()?;
    Some(std::time::UNIX_EPOCH + std::time::Duration::new(secs, sub))
}

fn handle_posix_fake_super_sidecars(
    sources: &[PathBuf],
    dest: &Path,
    plan: &TransferPlan,
    files_from: Option<&[PathBuf]>,
) -> Result<Option<PosixSidecarExecution>> {
    if !plan.fake_super
        && !plan.preserve_acls
        && !plan.preserve_xattrs
        && !plan.atimes
        && !plan.crtimes
        && plan.chown.is_none()
        && plan.user_maps.is_empty()
        && plan.group_maps.is_empty()
    {
        return Ok(None);
    }

    let fs = LocalFileSystem;
    let sidecar_root = posix_sidecar_root(dest);
    let capture_paths = collect_ntfs_sidecar_paths(&fs, sources, plan, files_from)?;
    if plan.dry_run {
        return Ok(Some(PosixSidecarExecution {
            root: sidecar_root,
            planned: capture_paths.len(),
            written: 0,
            restored: 0,
        }));
    }

    fs::create_dir_all(&sidecar_root)?;
    let mut written = 0;
    for source_path in &capture_paths {
        let sidecar = capture_posix_fake_super_sidecar(source_path, plan)
            .with_context(|| format!("capture POSIX sidecar for {}", source_path.display()))?;
        let relative = ntfs_sidecar_relative_name(sources, source_path);
        let manifest_path = sidecar_root.join(format!("{relative}.posix.meta"));
        fs::write(&manifest_path, sidecar.manifest())?;
        written += 1;
    }
    let restored = restore_posix_fake_super_sidecar_manifests(sources, &sidecar_root)?;

    Ok(Some(PosixSidecarExecution {
        root: sidecar_root,
        planned: capture_paths.len(),
        written,
        restored,
    }))
}

fn restore_posix_fake_super_sidecar_manifests(
    sources: &[PathBuf],
    dest_sidecar_root: &Path,
) -> Result<usize> {
    let mut restored = 0;
    for source in sources {
        let source_sidecar_root = source.join(".rsync-win.fake-super");
        if !source_sidecar_root.is_dir() {
            continue;
        }
        if sidecar_roots_overlap(&source_sidecar_root, dest_sidecar_root) {
            continue;
        }
        restored += copy_posix_fake_super_sidecar_manifests(
            &source_sidecar_root,
            &source_sidecar_root,
            dest_sidecar_root,
        )?;
    }
    Ok(restored)
}

fn copy_posix_fake_super_sidecar_manifests(
    source_root: &Path,
    current: &Path,
    dest_sidecar_root: &Path,
) -> Result<usize> {
    let mut restored = 0;
    for entry in fs::read_dir(current)
        .with_context(|| format!("read POSIX sidecar directory {}", current.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            restored +=
                copy_posix_fake_super_sidecar_manifests(source_root, &path, dest_sidecar_root)?;
            continue;
        }
        if !metadata.is_file() || !is_posix_fake_super_manifest_path(&path) {
            continue;
        }

        let manifest = fs::read_to_string(&path)
            .with_context(|| format!("read POSIX sidecar manifest {}", path.display()))?;
        parse_posix_fake_super_sidecar_manifest(&manifest)
            .with_context(|| format!("parse POSIX sidecar manifest {}", path.display()))?;
        let relative = path.strip_prefix(source_root).with_context(|| {
            format!("compute POSIX sidecar relative path for {}", path.display())
        })?;
        let target = dest_sidecar_root.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, manifest)
            .with_context(|| format!("write POSIX sidecar manifest {}", target.display()))?;
        restored += 1;
    }
    Ok(restored)
}

fn sidecar_roots_overlap(source_sidecar_root: &Path, dest_sidecar_root: &Path) -> bool {
    match (
        fs::canonicalize(source_sidecar_root),
        fs::canonicalize(dest_sidecar_root),
    ) {
        (Ok(source), Ok(dest)) => source == dest || dest.starts_with(&source),
        _ => false,
    }
}

fn is_posix_fake_super_manifest_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".posix.meta"))
}

fn capture_posix_fake_super_sidecar(
    path: &Path,
    plan: &TransferPlan,
) -> Result<PosixFakeSuperSidecar> {
    let metadata = read_windows_metadata(path)?;
    let mode = posix_sidecar_mode(&metadata.portable, path, plan);
    let std_metadata = fs::symlink_metadata(path)?;

    Ok(PosixFakeSuperSidecar {
        path: path.to_path_buf(),
        mode: Some(mode),
        uid: None,
        gid: None,
        user_name: plan.chown.as_ref().and_then(|chown| {
            let (user, _) = chown.split_once(':').unwrap_or((chown.as_str(), ""));
            (!user.is_empty()).then(|| user.to_string())
        }),
        group_name: plan.chown.as_ref().and_then(|chown| {
            let (_, group) = chown.split_once(':').unwrap_or(("", ""));
            (!group.is_empty()).then(|| group.to_string())
        }),
        access_time_unix_nanos: plan
            .atimes
            .then(|| {
                std_metadata
                    .accessed()
                    .ok()
                    .and_then(system_time_to_unix_nanos)
            })
            .flatten(),
        creation_time_unix_nanos: plan
            .crtimes
            .then(|| {
                read_windows_metadata(path)
                    .ok()?
                    .creation_time
                    .and_then(system_time_to_unix_nanos)
            })
            .flatten(),
        acls: if plan.preserve_acls {
            vec![PosixAclRecord {
                tag: "windows-security-descriptor".to_string(),
                qualifier: None,
                perms: "stored".to_string(),
            }]
        } else {
            Vec::new()
        },
        xattrs: if plan.preserve_xattrs {
            vec![PosixXattrRecord {
                name: "rsync.%stat".to_string(),
                value_hex: format!("{mode:08x}"),
            }]
        } else {
            Vec::new()
        },
        fake_super: plan.fake_super,
    })
}

fn posix_sidecar_mode(
    metadata: &rsync_fs::PortableMetadata,
    path: &Path,
    plan: &TransferPlan,
) -> u32 {
    let mut mode = metadata.posix_mode_for_path(Some(path), plan.preserve_executability);
    if let Some(chmod_rules) = &plan.chmod_rules {
        let kind = if metadata.file_type == FileType::Directory {
            ChmodFileKind::Directory
        } else {
            ChmodFileKind::File
        };
        mode = chmod_rules.apply(mode, kind);
    }
    mode
}

fn posix_sidecar_root(dest: &Path) -> PathBuf {
    let dest_is_file = fs::metadata(dest)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    if dest_is_file {
        dest.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".rsync-win.fake-super")
    } else {
        dest.join(".rsync-win.fake-super")
    }
}

fn ntfs_destination_for_source(
    sources: &[PathBuf],
    dest: &Path,
    source_path: &Path,
) -> Option<PathBuf> {
    if sources.len() == 1 {
        let source = &sources[0];
        let source_metadata = fs::metadata(source).ok()?;
        if source_path == source {
            if source_metadata.is_file()
                && fs::metadata(dest)
                    .map(|metadata| metadata.is_dir())
                    .unwrap_or(false)
            {
                return source.file_name().map(|name| dest.join(name));
            }
            return Some(dest.to_path_buf());
        }
        return source_path
            .strip_prefix(source)
            .ok()
            .map(|relative| dest.join(relative));
    }

    for source in sources {
        if source_path == source {
            return source.file_name().map(|name| dest.join(name));
        }
        if let Ok(relative) = source_path.strip_prefix(source) {
            return source
                .file_name()
                .map(|name| dest.join(name).join(relative));
        }
    }
    None
}

fn collect_ntfs_sidecar_paths(
    fs: &LocalFileSystem,
    sources: &[PathBuf],
    plan: &TransferPlan,
    files_from: Option<&[PathBuf]>,
) -> Result<Vec<PathBuf>> {
    Ok(selected_source_paths(
        fs,
        sources,
        SourceSelectionOptions {
            recursive: plan.recursive,
            filter_rules: &plan.filter_rules,
            files_from,
            symlink_mode: plan.symlink_mode,
            one_file_system: plan.one_file_system,
        },
    )?)
}

pub(crate) fn ntfs_sidecar_root(dest: &Path) -> PathBuf {
    let dest_is_file = fs::metadata(dest)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    if dest_is_file {
        dest.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".rsync-win.ntfs-native")
    } else {
        dest.join(".rsync-win.ntfs-native")
    }
}

fn ntfs_sidecar_relative_name(sources: &[PathBuf], path: &Path) -> String {
    let relative = sources
        .iter()
        .find_map(|source| {
            if path == source {
                source.file_name().map(PathBuf::from)
            } else {
                path.strip_prefix(source).ok().map(|relative| {
                    source
                        .file_name()
                        .map(|name| PathBuf::from(name).join(relative))
                        .unwrap_or_else(|| relative.to_path_buf())
                })
            }
        })
        .unwrap_or_else(|| path.file_name().map(PathBuf::from).unwrap_or_default());
    let display_name = sanitize_sidecar_name(&relative);
    let hash = stable_sidecar_path_hash(&relative);
    format!("{display_name}--{hash:016x}")
}

fn sanitize_sidecar_name(path: &Path) -> String {
    let mut name = String::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        if !name.is_empty() {
            name.push_str("__");
        }
        for ch in part.to_string_lossy().chars() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                name.push(ch);
            } else {
                name.push('_');
            }
        }
    }
    if name.is_empty() {
        "_root".to_string()
    } else {
        name
    }
}

fn stable_sidecar_path_hash(path: &Path) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        for byte in part.to_string_lossy().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
