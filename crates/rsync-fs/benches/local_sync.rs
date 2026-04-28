use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rsync_fs::{sync_tree, LocalFileSystem, SyncOptions};

const TREE_FILE_COUNT: usize = 128;
const TREE_FILE_SIZE: usize = 8 * 1024;
const MANY_SMALL_FILE_COUNT: usize = 1_024;
const MANY_SMALL_FILE_SIZE: usize = 512;
const LARGE_FILE_SIZE: usize = 8 * 1024 * 1024;

struct BenchScenario {
    name: &'static str,
    create_fixture: fn(&Path) -> std::io::Result<()>,
}

fn main() {
    let iterations = std::env::var("RSYNC_WIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);

    let scenarios = [
        BenchScenario {
            name: "tree_128x8k",
            create_fixture: create_tree_fixture,
        },
        BenchScenario {
            name: "many_small_1024x512b",
            create_fixture: create_many_small_fixture,
        },
        BenchScenario {
            name: "large_file_8mib",
            create_fixture: create_large_file_fixture,
        },
    ];

    for scenario in scenarios {
        run_scenario(&scenario, iterations);
    }
}

fn run_scenario(scenario: &BenchScenario, iterations: usize) {
    let root = unique_temp_dir(&format!("rsync-fs-local-sync-bench-{}", scenario.name));
    let source = root.join("source");
    let dest = root.join("dest");

    (scenario.create_fixture)(&source).expect("create benchmark fixture");
    let mut total_bytes = 0_u64;
    let started = Instant::now();
    for _ in 0..iterations {
        if dest.exists() {
            fs::remove_dir_all(&dest).expect("remove destination");
        }
        let mut fs_adapter = LocalFileSystem;
        let report = sync_tree(
            &mut fs_adapter,
            &source,
            &dest,
            SyncOptions {
                dry_run: false,
                preserve_mtime: false,
                ..SyncOptions::default()
            },
        )
        .expect("run local sync benchmark");
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
    }
    let elapsed = started.elapsed();

    println!("local_sync scenario: {}", scenario.name);
    println!("local_sync {} iterations: {iterations}", scenario.name);
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

    fs::remove_dir_all(&root).expect("cleanup benchmark fixture");
}

fn create_tree_fixture(source: &Path) -> std::io::Result<()> {
    fs::create_dir_all(source)?;
    for index in 0..TREE_FILE_COUNT {
        let dir = source.join(format!("dir{:02}", index % 16));
        fs::create_dir_all(&dir)?;
        write_pattern_file(
            &dir.join(format!("file{:03}.bin", index)),
            TREE_FILE_SIZE,
            index,
        )?;
    }
    Ok(())
}

fn create_many_small_fixture(source: &Path) -> std::io::Result<()> {
    fs::create_dir_all(source)?;
    for index in 0..MANY_SMALL_FILE_COUNT {
        let dir = source.join(format!("bucket{:02}", index % 64));
        fs::create_dir_all(&dir)?;
        write_pattern_file(
            &dir.join(format!("item{:04}.dat", index)),
            MANY_SMALL_FILE_SIZE,
            index,
        )?;
    }
    Ok(())
}

fn create_large_file_fixture(source: &Path) -> std::io::Result<()> {
    fs::create_dir_all(source)?;
    write_pattern_file(&source.join("large.bin"), LARGE_FILE_SIZE, 0)
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

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
    path
}
