use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rsync_filter::{Rule, RuleSet};
use rsync_fs::{sync_tree, LocalFileSystem, SyncOptions, UpdateMode};

const SMALL_FILE_COUNT: usize = 10_000;
const EMPTY_FILE_COUNT: usize = 100_000;
const FILTER_RULE_COUNT: usize = 1_024;
const DELETE_HEAVY_COUNT: usize = 10_000;
const SMALL_FILE_SIZE: usize = 512;
const ONE_GIB: u64 = 1_073_741_824;
const EDITED_LARGE_FILE_SIZE: u64 = 64 * 1024 * 1024;

struct BenchScenario {
    name: &'static str,
    setup: fn(&Path, &Path) -> std::io::Result<SyncOptions>,
}

fn main() {
    let iterations = std::env::var("RSYNC_WIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);

    let scenarios = [
        BenchScenario {
            name: "small_files_10000",
            setup: setup_small_files,
        },
        BenchScenario {
            name: "empty_files_100000",
            setup: setup_empty_files,
        },
        BenchScenario {
            name: "ordinary_file_1gib",
            setup: setup_one_gib_file,
        },
        BenchScenario {
            name: "small_edits_large_file",
            setup: setup_small_edit_large_file,
        },
        BenchScenario {
            name: "filters_many_rules",
            setup: setup_many_filter_rules,
        },
        BenchScenario {
            name: "delete_heavy_receiver_tree",
            setup: setup_delete_heavy_receiver,
        },
    ];

    for scenario in scenarios {
        run_scenario(&scenario, iterations);
    }
}

fn run_scenario(scenario: &BenchScenario, iterations: usize) {
    let started = Instant::now();
    let mut total_bytes = 0_u64;
    let mut total_actions = 0_usize;

    for iteration in 0..iterations {
        let root = unique_temp_dir(&format!(
            "rsync-fs-local-sync-bench-{}-{iteration}",
            scenario.name
        ));
        let source = root.join("source");
        let dest = root.join("dest");
        let options = (scenario.setup)(&source, &dest).expect("create benchmark fixture");

        let mut fs_adapter = LocalFileSystem;
        let report =
            sync_tree(&mut fs_adapter, &source, &dest, options).expect("run local sync benchmark");
        total_bytes += report
            .actions()
            .iter()
            .filter_map(|action| match action {
                rsync_fs::SyncAction::WriteFile { len, .. }
                | rsync_fs::SyncAction::WriteFileInPlace { len, .. }
                | rsync_fs::SyncAction::AppendFile { len, .. } => Some(*len as u64),
                _ => None,
            })
            .sum::<u64>();
        total_actions += report.actions().len();
        fs::remove_dir_all(&root).expect("cleanup benchmark fixture");
    }

    let elapsed = started.elapsed();
    println!("local_sync scenario: {}", scenario.name);
    println!("local_sync {} iterations: {iterations}", scenario.name);
    println!("local_sync {} actions: {total_actions}", scenario.name);
    println!("local_sync {} bytes copied: {total_bytes}", scenario.name);
    println!(
        "local_sync {} elapsed_ms: {:.3}",
        scenario.name,
        elapsed.as_secs_f64() * 1000.0
    );
    if elapsed.as_secs_f64() > 0.0 {
        let mib = total_bytes as f64 / (1024.0 * 1024.0);
        println!(
            "local_sync {} throughput_mib_s: {:.3}",
            scenario.name,
            mib / elapsed.as_secs_f64()
        );
    }
}

fn setup_small_files(source: &Path, _dest: &Path) -> std::io::Result<SyncOptions> {
    create_many_files(source, SMALL_FILE_COUNT, SMALL_FILE_SIZE)?;
    Ok(active_sync_options())
}

fn setup_empty_files(source: &Path, _dest: &Path) -> std::io::Result<SyncOptions> {
    create_many_files(source, EMPTY_FILE_COUNT, 0)?;
    Ok(active_sync_options())
}

fn setup_one_gib_file(source: &Path, _dest: &Path) -> std::io::Result<SyncOptions> {
    fs::create_dir_all(source)?;
    fs::File::create(source.join("large-1gib.bin"))?.set_len(ONE_GIB)?;
    Ok(active_sync_options())
}

fn setup_small_edit_large_file(source: &Path, dest: &Path) -> std::io::Result<SyncOptions> {
    fs::create_dir_all(source)?;
    fs::create_dir_all(dest)?;
    let source_file = source.join("large-edited.bin");
    let dest_file = dest.join("large-edited.bin");
    fs::File::create(&source_file)?.set_len(EDITED_LARGE_FILE_SIZE)?;
    fs::File::create(&dest_file)?.set_len(EDITED_LARGE_FILE_SIZE)?;
    patch_file_bytes(
        &source_file,
        &[64, EDITED_LARGE_FILE_SIZE / 2, EDITED_LARGE_FILE_SIZE - 65],
    )?;
    Ok(SyncOptions {
        dry_run: false,
        preserve_mtime: false,
        update_mode: UpdateMode::Checksum,
        ..SyncOptions::default()
    })
}

fn setup_many_filter_rules(source: &Path, _dest: &Path) -> std::io::Result<SyncOptions> {
    create_many_files(source, SMALL_FILE_COUNT, SMALL_FILE_SIZE)?;
    let mut rules = Vec::with_capacity(FILTER_RULE_COUNT + 1);
    for index in 0..FILTER_RULE_COUNT {
        rules.push(Rule::exclude(format!("never-match-{index:04}.tmp")).unwrap());
    }
    rules.push(Rule::include("***").unwrap());
    Ok(SyncOptions {
        dry_run: false,
        preserve_mtime: false,
        filter_rules: RuleSet::new(rules),
        ..SyncOptions::default()
    })
}

fn setup_delete_heavy_receiver(source: &Path, dest: &Path) -> std::io::Result<SyncOptions> {
    fs::create_dir_all(source)?;
    create_many_files(dest, DELETE_HEAVY_COUNT, SMALL_FILE_SIZE)?;
    Ok(SyncOptions {
        dry_run: false,
        preserve_mtime: false,
        delete: true,
        ..SyncOptions::default()
    })
}

fn active_sync_options() -> SyncOptions {
    SyncOptions {
        dry_run: false,
        preserve_mtime: false,
        ..SyncOptions::default()
    }
}

fn create_many_files(root: &Path, count: usize, size: usize) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    for index in 0..count {
        let dir = root.join(format!("bucket{:03}", index % 257));
        fs::create_dir_all(&dir)?;
        write_pattern_file(&dir.join(format!("item{index:06}.dat")), size, index)?;
    }
    Ok(())
}

fn write_pattern_file(path: &Path, size: usize, seed: usize) -> std::io::Result<()> {
    let mut file = fs::File::create(path)?;
    let mut remaining = size;
    let mut offset = 0_usize;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let len = remaining.min(buffer.len());
        for (index, byte) in buffer[..len].iter_mut().enumerate() {
            *byte = ((seed + offset + index) % 251) as u8;
        }
        file.write_all(&buffer[..len])?;
        remaining -= len;
        offset += len;
    }
    Ok(())
}

fn patch_file_bytes(path: &Path, offsets: &[u64]) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom};

    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    for (index, offset) in offsets.iter().enumerate() {
        file.seek(SeekFrom::Start(*offset))?;
        file.write_all(&[0xa0_u8.wrapping_add(index as u8)])?;
    }
    Ok(())
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
    path
}
