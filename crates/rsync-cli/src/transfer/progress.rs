use super::prelude::*;
#[derive(Debug, Default, Clone)]
pub(crate) struct RemoteExecutionStats {
    pub(crate) files: usize,
    pub(crate) bytes: u64,
    pub(crate) transferred_entry_indexes: Vec<usize>,
}

#[derive(Debug)]
pub(crate) struct FileProgress {
    progress: ProgressLog,
    operation: &'static str,
    path: String,
    total: Option<u64>,
    started: Instant,
    last_report: Instant,
    transferred: u64,
}

impl FileProgress {
    pub(crate) fn start(
        progress: ProgressLog,
        operation: &'static str,
        path: &Path,
        total: Option<u64>,
    ) -> Self {
        let now = Instant::now();
        let meter = Self {
            progress,
            operation,
            path: path.display().to_string(),
            total,
            started: now,
            last_report: now,
            transferred: 0,
        };
        if progress.enabled() {
            match total {
                Some(total) => progress.info(format!(
                    "{}: {} ({})",
                    operation,
                    meter.path,
                    format_bytes(total)
                )),
                None => progress.info(format!("{}: {}", operation, meter.path)),
            }
        }
        meter
    }

    pub(crate) fn advance(&mut self, bytes: u64) {
        self.transferred += bytes;
        if !self.progress.enabled() || self.last_report.elapsed() < Duration::from_secs(2) {
            return;
        }

        self.report_progress();
        self.last_report = Instant::now();
    }

    pub(crate) fn finish(&mut self) {
        if self.progress.enabled() {
            self.report_finished();
        }
    }

    pub(crate) fn report_progress(&self) {
        let elapsed = self.started.elapsed();
        let rate = transfer_rate_label(self.transferred, elapsed);
        match self.total {
            Some(total) if total > 0 => {
                let percent = (self.transferred as f64 / total as f64 * 100.0).min(100.0);
                self.progress.info(format!(
                    "{}: {} {} / {} ({:.1}%, {})",
                    self.operation,
                    self.path,
                    format_bytes(self.transferred),
                    format_bytes(total),
                    percent,
                    rate
                ));
            }
            Some(_) | None => self.progress.info(format!(
                "{}: {} {} ({})",
                self.operation,
                self.path,
                format_bytes(self.transferred),
                rate
            )),
        }
    }

    pub(crate) fn report_finished(&self) {
        let elapsed = self.started.elapsed();
        let rate = transfer_rate_label(self.transferred, elapsed);
        match self.total {
            Some(total) if total > 0 => {
                let percent = (self.transferred as f64 / total as f64 * 100.0).min(100.0);
                self.progress.info(format!(
                    "{} done: {} {} / {} ({:.1}%, {}, {:.2}s)",
                    self.operation,
                    self.path,
                    format_bytes(self.transferred),
                    format_bytes(total),
                    percent,
                    rate,
                    elapsed.as_secs_f64()
                ));
            }
            Some(_) | None => self.progress.info(format!(
                "{} done: {} {} ({}, {:.2}s)",
                self.operation,
                self.path,
                format_bytes(self.transferred),
                rate,
                elapsed.as_secs_f64()
            )),
        }
    }
}

pub(crate) const RSYNC31_MUX_FRAME_SIZE: usize = 32 * 1024;
pub(crate) const REMOTE_FILE_LIST_BATCH_ENTRIES: usize = 4096;

pub(crate) struct RemoteTransferRuntime<'a> {
    pub(crate) compression: Option<&'a RemoteCompressionConfig>,
    pub(crate) progress: ProgressLog,
    pub(crate) max_alloc: Option<u64>,
    pub(crate) stop_deadline: Option<Instant>,
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteCompressionConfig {
    pub(crate) mode: RsyncDeflatedTokenMode,
    pub(crate) level: u32,
    pub(crate) skip_suffixes: Vec<String>,
}

impl RemoteCompressionConfig {
    pub(crate) fn for_plan(plan: &TransferPlan) -> Result<Option<Self>> {
        if !plan.compress {
            return Ok(None);
        }
        let mode =
            RsyncDeflatedTokenMode::from_choice(plan.compress_choice.as_deref()).map_err(|_| {
                anyhow::anyhow!(
                    "unsupported compression choice; rsync-win currently supports zlibx and zlib"
                )
            })?;
        Ok(Some(Self {
            mode,
            level: plan.compress_level.unwrap_or(6).min(9),
            skip_suffixes: plan.skip_compress.clone(),
        }))
    }

    pub(crate) fn remote_choice(&self) -> &'static str {
        self.mode.remote_choice()
    }

    pub(crate) fn level_for_path(&self, path: &Path) -> u32 {
        if self.should_skip_path(path) {
            0
        } else {
            self.level
        }
    }

    pub(crate) fn should_skip_path(&self, path: &Path) -> bool {
        let path = path.to_string_lossy().to_ascii_lowercase();
        self.skip_suffixes
            .iter()
            .map(|suffix| {
                suffix
                    .trim()
                    .trim_start_matches("*.")
                    .trim_start_matches('.')
            })
            .filter(|suffix| !suffix.is_empty())
            .any(|suffix| path.ends_with(&format!(".{}", suffix.to_ascii_lowercase())))
    }
}
