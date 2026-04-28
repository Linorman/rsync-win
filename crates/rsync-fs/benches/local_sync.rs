use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rsync_fs::{sync_tree, LocalFileSystem, SyncOptions};

const FILE_COUNT: usize = 128;
const FILE_SIZE: usize = 8 * 1024;

fn main() {
    let iterations = std::env::var("RSYNC_WIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);

    let root = unique_temp_dir("rsync-fs-local-sync-bench");
    let source = root.join("source");
    let dest = root.join("dest");

    create_fixture(&source).expect("create benchmark fixture");

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

    println!("local_sync iterations: {iterations}");
    println!("local_sync files/iteration: {FILE_COUNT}");
    println!("local_sync bytes copied: {total_bytes}");
    println!(
        "local_sync elapsed_ms: {:.3}",
        elapsed.as_secs_f64() * 1000.0
    );
    if elapsed.as_secs_f64() > 0.0 {
        let mib = total_bytes as f64 / (1024.0 * 1024.0);
        println!(
            "local_sync throughput_mib_s: {:.3}",
            mib / elapsed.as_secs_f64()
        );
    }

    fs::remove_dir_all(&root).expect("cleanup benchmark fixture");
}

fn create_fixture(source: &Path) -> std::io::Result<()> {
    fs::create_dir_all(source)?;
    let content: Vec<u8> = (0..FILE_SIZE).map(|index| (index % 251) as u8).collect();
    for index in 0..FILE_COUNT {
        let dir = source.join(format!("dir{:02}", index % 16));
        fs::create_dir_all(&dir)?;
        let mut file_content = content.clone();
        file_content[0] = (index % 251) as u8;
        fs::write(dir.join(format!("file{:03}.bin", index)), &file_content)?;
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
