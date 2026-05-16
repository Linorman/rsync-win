use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::Cli;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct DaemonLogRecord {
    pub(super) message: String,
    pub(super) module: Option<String>,
    pub(super) operation: Option<String>,
    pub(super) path: Option<String>,
    pub(super) bytes: Option<u64>,
    pub(super) client: Option<String>,
}

pub(super) fn log_daemon_message(cli: &Cli, message: &str) -> Result<()> {
    log_daemon_record(
        cli,
        DaemonLogRecord {
            message: message.to_string(),
            ..DaemonLogRecord::default()
        },
    )
}

pub(super) fn log_daemon_record(cli: &Cli, record: DaemonLogRecord) -> Result<()> {
    let Some(path) = &cli.daemon_log_file else {
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open daemon log file {}", path.display()))?;
    let line = if let Some(format) = &cli.daemon_log_file_format {
        render_daemon_log_format(format, &record)
    } else {
        record.message
    };
    writeln!(file, "{line}")?;
    Ok(())
}

pub(super) fn render_daemon_log_format(format: &str, record: &DaemonLogRecord) -> String {
    let mut output = String::with_capacity(format.len() + record.message.len());
    let mut chars = format.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            output.push(ch);
            continue;
        }
        let Some(token) = chars.next() else {
            output.push('%');
            break;
        };
        match token {
            '%' => output.push('%'),
            'm' => output.push_str(record.module.as_deref().unwrap_or("-")),
            'o' => output.push_str(record.operation.as_deref().unwrap_or("-")),
            'f' => output.push_str(record.path.as_deref().unwrap_or("-")),
            'l' => output.push_str(
                &record
                    .bytes
                    .map(|bytes| bytes.to_string())
                    .unwrap_or_else(|| "0".to_string()),
            ),
            'h' | 'a' => output.push_str(record.client.as_deref().unwrap_or("-")),
            'p' => output.push_str(&std::process::id().to_string()),
            't' => output.push_str(&daemon_log_timestamp()),
            'M' => output.push_str(&record.message),
            other => {
                output.push('%');
                output.push(other);
            }
        }
    }
    output
}

fn daemon_log_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}
