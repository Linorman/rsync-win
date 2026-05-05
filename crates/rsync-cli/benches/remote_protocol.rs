use std::io;
use std::path::PathBuf;
use std::time::Instant;

use rsync_delta::{generate_delta_with, generate_signatures_with, DeterministicStrongChecksum};
use rsync_protocol::{
    read_rsync31_file_list, write_rsync31_file_list_with_options, RsyncDeflatedTokenWriter,
    RsyncFileListEntry, RsyncFileListMetadata, WireFileType, RSYNC_DIRECTORY_MODE,
    RSYNC_REGULAR_FILE_MODE,
};

const SMALL_FILE_COUNT: usize = 10_000;
const EMPTY_FILE_COUNT: usize = 100_000;
const ONE_GIB: u64 = 1_073_741_824;
const LARGE_EDIT_BYTES: usize = 16 * 1024 * 1024;
const TOKEN_CHUNK: usize = 64 * 1024;

struct BenchScenario {
    name: &'static str,
    run: fn(usize) -> io::Result<()>,
}

fn main() {
    let iterations = std::env::var("RSYNC_WIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);

    let scenarios = [
        BenchScenario {
            name: "file_list_10000_small_files",
            run: bench_file_list_10k,
        },
        BenchScenario {
            name: "file_list_100000_empty_files",
            run: bench_file_list_100k,
        },
        BenchScenario {
            name: "literal_tokens_1gib",
            run: bench_literal_tokens_1gib,
        },
        BenchScenario {
            name: "small_edits_large_file_delta",
            run: bench_small_edit_delta,
        },
    ];

    for scenario in scenarios {
        let started = Instant::now();
        for _ in 0..iterations {
            (scenario.run)(iterations).expect("run remote protocol benchmark scenario");
        }
        let elapsed = started.elapsed();
        println!("remote_protocol scenario: {}", scenario.name);
        println!("remote_protocol {} iterations: {iterations}", scenario.name);
        println!(
            "remote_protocol {} elapsed_ms: {:.3}",
            scenario.name,
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

fn bench_file_list_10k(_iterations: usize) -> io::Result<()> {
    round_trip_file_list(SMALL_FILE_COUNT, false)
}

fn bench_file_list_100k(_iterations: usize) -> io::Result<()> {
    round_trip_file_list(EMPTY_FILE_COUNT, true)
}

fn round_trip_file_list(count: usize, empty_files: bool) -> io::Result<()> {
    let entries: Vec<_> = (0..count)
        .map(|index| synthetic_entry(index, empty_files))
        .collect();
    let mut bytes = Vec::new();
    write_rsync31_file_list_with_options(&mut bytes, &entries, false).map_err(io_other)?;
    let decoded =
        read_rsync31_file_list(&mut bytes.as_slice(), count + 1, 32 * 1024).map_err(io_other)?;
    if decoded.len() != count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file-list benchmark decoded the wrong entry count",
        ));
    }
    Ok(())
}

fn bench_literal_tokens_1gib(_iterations: usize) -> io::Result<()> {
    let chunk = vec![0_u8; TOKEN_CHUNK];
    let mut writer = RsyncDeflatedTokenWriter::new(1);
    let mut sink = io::sink();
    let mut remaining = ONE_GIB;
    while remaining > 0 {
        let len = remaining.min(TOKEN_CHUNK as u64) as usize;
        writer.send_literal(&mut sink, &chunk[..len])?;
        remaining -= len as u64;
    }
    writer.finish(&mut sink)
}

fn bench_small_edit_delta(_iterations: usize) -> io::Result<()> {
    let mut basis = vec![0_u8; LARGE_EDIT_BYTES];
    fill_pattern(&mut basis, 0x31);
    let mut edited = basis.clone();
    for offset in [64, LARGE_EDIT_BYTES / 2, LARGE_EDIT_BYTES - 65] {
        edited[offset] ^= 0x5a;
    }

    let strong = DeterministicStrongChecksum;
    let signatures = generate_signatures_with(&basis, 32 * 1024, &strong)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let tokens = generate_delta_with(&signatures, &edited, &strong);
    if tokens.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "delta benchmark produced no tokens",
        ));
    }
    Ok(())
}

fn synthetic_entry(index: usize, empty_file: bool) -> RsyncFileListEntry {
    let directory = index % 257 == 0;
    RsyncFileListEntry {
        path: if directory {
            PathBuf::from(format!("dir-{index:06}"))
        } else {
            PathBuf::from(format!("dir-{index:06}/file-{index:06}.dat"))
        },
        file_type: if directory {
            WireFileType::Directory
        } else {
            WireFileType::File
        },
        len: if directory || empty_file { 0 } else { 512 },
        mtime_unix: 1_700_000_000,
        mode: if directory {
            RSYNC_DIRECTORY_MODE
        } else {
            RSYNC_REGULAR_FILE_MODE
        },
        checksum: None,
        hardlink_group: None,
        metadata: RsyncFileListMetadata::default(),
    }
}

fn fill_pattern(bytes: &mut [u8], seed: u8) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add((index % 251) as u8);
    }
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}
