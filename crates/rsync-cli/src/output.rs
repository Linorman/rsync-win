use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

// ── Exit codes ──────────────────────────────────────────────────────────────

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_SYNTAX_OR_USAGE: i32 = 1;
pub const EXIT_PROTOCOL: i32 = 2;
pub const EXIT_FILE_SELECT: i32 = 3;
pub const EXIT_UNSUPPORTED: i32 = 4;
pub const EXIT_START_PROTOCOL: i32 = 5;
pub const EXIT_DAEMON_LOG_FILE: i32 = 6;
pub const EXIT_SOCKET_IO: i32 = 10;
pub const EXIT_FILE_IO: i32 = 11;
pub const EXIT_PROTOCOL_STREAM: i32 = 12;
pub const EXIT_DIAGNOSTICS: i32 = 13;
pub const EXIT_IPC: i32 = 14;
pub const EXIT_SIGNAL: i32 = 20;
pub const EXIT_WAITPID: i32 = 21;
pub const EXIT_ALLOC: i32 = 22;
pub const EXIT_PARTIAL: i32 = 23;
pub const EXIT_VANISHED: i32 = 24;
pub const EXIT_MAX_DELETE: i32 = 25;
pub const EXIT_TIMEOUT: i32 = 30;
pub const EXIT_DAEMON_TIMEOUT: i32 = 35;

/// Map an anyhow error to the best available rsync-compatible exit code.
pub fn exit_code_from_error(err: &anyhow::Error) -> i32 {
    let msg = format!("{err:#}");
    let lower = msg.to_lowercase();

    // Specific checks first, broader categories later.

    if lower.contains("timed out") || lower.contains("timeout") {
        return EXIT_TIMEOUT;
    }
    if lower.contains("source") && lower.contains("vanished") {
        return EXIT_VANISHED;
    }
    if lower.contains("daemon")
        && (lower.contains("log-file")
            || lower.contains("log_file")
            || lower.contains("unable to open"))
    {
        return EXIT_DAEMON_LOG_FILE;
    }
    if lower.contains("daemon") && lower.contains("auth") {
        return EXIT_START_PROTOCOL;
    }
    if lower.contains("max-delete") || lower.contains("max_delete") {
        return EXIT_MAX_DELETE;
    }
    if lower.contains("partial") {
        return EXIT_PARTIAL;
    }
    if lower.contains("socket")
        || lower.contains("connection refuse")
        || lower.contains("connect error")
    {
        return EXIT_SOCKET_IO;
    }
    if lower.contains("no such file") || lower.contains("not found") {
        return EXIT_FILE_SELECT;
    }
    if lower.contains("unknown option") || lower.contains("syntax") || lower.contains("usage") {
        return EXIT_SYNTAX_OR_USAGE;
    }
    if lower.contains("unsupported") {
        return EXIT_UNSUPPORTED;
    }
    if lower.contains("protocol") && lower.contains("start") {
        return EXIT_START_PROTOCOL;
    }
    if lower.contains("protocol") || lower.contains("multiplex") || lower.contains("checksum") {
        return EXIT_PROTOCOL_STREAM;
    }
    if lower.contains("permission denied") || lower.contains("io error") {
        return EXIT_FILE_IO;
    }
    if lower.contains("file") {
        return EXIT_FILE_IO;
    }
    if lower.contains("diagnostic") {
        return EXIT_DIAGNOSTICS;
    }
    if lower.contains("ipc") {
        return EXIT_IPC;
    }
    if lower.contains("signal") || lower.contains("interrupt") || lower.contains("sigint") {
        return EXIT_SIGNAL;
    }
    if lower.contains("waitpid") {
        return EXIT_WAITPID;
    }
    if lower.contains("alloc") || lower.contains("memory") {
        return EXIT_ALLOC;
    }

    EXIT_SYNTAX_OR_USAGE
}

// ── Stderr routing ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StderrMode {
    Errors,
    All,
    Client,
}

pub fn parse_stderr_mode(value: &str) -> Result<StderrMode> {
    match value.to_ascii_lowercase().as_str() {
        "errors" | "error" | "err" | "e" => Ok(StderrMode::Errors),
        "all" | "a" => Ok(StderrMode::All),
        "client" | "c" => Ok(StderrMode::Client),
        _ => anyhow::bail!("invalid --stderr mode `{value}`; expected errors, all, or client"),
    }
}

// ── Info flags ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InfoFlags(u32);

#[allow(non_upper_case_globals)]
impl InfoFlags {
    pub const BACKUP: InfoFlags = InfoFlags(1 << 0);
    pub const COPY: InfoFlags = InfoFlags(1 << 1);
    pub const DEL: InfoFlags = InfoFlags(1 << 2);
    pub const FLIST: InfoFlags = InfoFlags(1 << 3);
    pub const MISC: InfoFlags = InfoFlags(1 << 4);
    pub const MOUNT: InfoFlags = InfoFlags(1 << 5);
    pub const NAME: InfoFlags = InfoFlags(1 << 6);
    pub const PROGRESS: InfoFlags = InfoFlags(1 << 7);
    pub const REMOVE: InfoFlags = InfoFlags(1 << 8);
    pub const SKIP: InfoFlags = InfoFlags(1 << 9);
    pub const STATS: InfoFlags = InfoFlags(1 << 10);
    pub const SYMSAFE: InfoFlags = InfoFlags(1 << 11);
    pub const ALL: InfoFlags = InfoFlags((1 << 13) - 1);
    pub const NONE: InfoFlags = InfoFlags(0);

    const ALL_MARKER: u32 = 1 << 12;

    pub fn empty() -> Self {
        InfoFlags(0)
    }

    pub fn contains(self, flag: InfoFlags) -> bool {
        if flag == InfoFlags::NONE {
            self.0 == 0
        } else if flag == InfoFlags::ALL {
            self.0 & Self::ALL_MARKER != 0
        } else {
            self.0 & flag.0 != 0
        }
    }

    pub fn insert(&mut self, flag: InfoFlags) {
        if flag == InfoFlags::ALL {
            *self = InfoFlags::ALL;
        } else if flag != InfoFlags::NONE {
            self.0 |= flag.0;
        }
    }

    pub fn remove(&mut self, flag: InfoFlags) {
        if flag == InfoFlags::ALL {
            self.0 = 0;
        } else {
            self.0 &= !flag.0;
        }
    }
}

/// Parse rsync-style --info=FLAGS string into an InfoFlags bitset.
pub fn parse_info_flags(input: &str) -> InfoFlags {
    if input.is_empty() || input.eq_ignore_ascii_case("NONE") {
        return InfoFlags::NONE;
    }
    if input.eq_ignore_ascii_case("ALL") {
        return InfoFlags::ALL;
    }

    let mut flags = InfoFlags::empty();
    let mut negate = false;
    let mut buf = String::new();

    for ch in input.chars() {
        match ch {
            ',' | ' ' => {
                if !buf.is_empty() {
                    add_info_flag(&mut flags, &buf, negate);
                    buf.clear();
                }
                negate = false;
            }
            '-' => negate = !negate,
            '+' => negate = false,
            _ => buf.push(ch),
        }
    }
    if !buf.is_empty() {
        add_info_flag(&mut flags, &buf, negate);
    }
    flags
}

fn add_info_flag(flags: &mut InfoFlags, name: &str, negate: bool) {
    let (name, level) = split_flag_level(name);
    let negate = negate || level == Some(0);
    let flag = match name.to_uppercase().as_str() {
        "BACKUP" => InfoFlags::BACKUP,
        "COPY" => InfoFlags::COPY,
        "DEL" | "DELETE" => InfoFlags::DEL,
        "FLIST" => InfoFlags::FLIST,
        "MISC" => InfoFlags::MISC,
        "MOUNT" => InfoFlags::MOUNT,
        "NAME" => InfoFlags::NAME,
        "PROGRESS" => InfoFlags::PROGRESS,
        "REMOVE" => InfoFlags::REMOVE,
        "SKIP" => InfoFlags::SKIP,
        "STATS" => InfoFlags::STATS,
        "SYMSAFE" => InfoFlags::SYMSAFE,
        "ALL" => InfoFlags::ALL,
        "NONE" => InfoFlags::NONE,
        _ => return,
    };
    if negate {
        flags.remove(flag);
    } else {
        flags.insert(flag);
    }
}

// ── Debug flags ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DebugFlags(u32);

#[allow(non_upper_case_globals)]
impl DebugFlags {
    pub const BACKUP: DebugFlags = DebugFlags(1 << 0);
    pub const BIND: DebugFlags = DebugFlags(1 << 1);
    pub const CWD: DebugFlags = DebugFlags(1 << 2);
    pub const DEL: DebugFlags = DebugFlags(1 << 3);
    pub const DELTASUM: DebugFlags = DebugFlags(1 << 4);
    pub const DUP: DebugFlags = DebugFlags(1 << 5);
    pub const EXCLUDE: DebugFlags = DebugFlags(1 << 6);
    pub const FILTER: DebugFlags = DebugFlags(1 << 7);
    pub const FLIST: DebugFlags = DebugFlags(1 << 8);
    pub const FUZZY: DebugFlags = DebugFlags(1 << 9);
    pub const HLINK: DebugFlags = DebugFlags(1 << 10);
    pub const ICONV: DebugFlags = DebugFlags(1 << 11);
    pub const IO: DebugFlags = DebugFlags(1 << 12);
    pub const MLOCK: DebugFlags = DebugFlags(1 << 13);
    pub const MOUNT: DebugFlags = DebugFlags(1 << 14);
    pub const OWN: DebugFlags = DebugFlags(1 << 15);
    pub const PROTO: DebugFlags = DebugFlags(1 << 16);
    pub const RECV: DebugFlags = DebugFlags(1 << 17);
    pub const SEND: DebugFlags = DebugFlags(1 << 18);
    pub const SOCK: DebugFlags = DebugFlags(1 << 19);
    pub const TIME: DebugFlags = DebugFlags(1 << 20);
    pub const ALL: DebugFlags = DebugFlags((1 << 22) - 1);
    pub const NONE: DebugFlags = DebugFlags(0);

    const ALL_MARKER: u32 = 1 << 21;

    pub fn empty() -> Self {
        DebugFlags(0)
    }

    pub fn contains(self, flag: DebugFlags) -> bool {
        if flag == DebugFlags::NONE {
            self.0 == 0
        } else if flag == DebugFlags::ALL {
            self.0 & Self::ALL_MARKER != 0
        } else {
            self.0 & flag.0 != 0
        }
    }

    pub fn intersects(self, flag: DebugFlags) -> bool {
        if self.contains(DebugFlags::ALL) {
            return true;
        }
        self.0 & flag.0 != 0
    }

    pub fn insert(&mut self, flag: DebugFlags) {
        if flag == DebugFlags::ALL {
            *self = DebugFlags::ALL;
        } else if flag != DebugFlags::NONE {
            self.0 |= flag.0;
        }
    }

    pub fn remove(&mut self, flag: DebugFlags) {
        if flag == DebugFlags::ALL {
            self.0 = 0;
        } else {
            self.0 &= !flag.0;
        }
    }
}

/// Parse rsync-style --debug=FLAGS string into a DebugFlags bitset.
pub fn parse_debug_flags(input: &str) -> DebugFlags {
    if input.is_empty() || input.eq_ignore_ascii_case("NONE") {
        return DebugFlags::NONE;
    }
    if input.eq_ignore_ascii_case("ALL") {
        return DebugFlags::ALL;
    }

    let mut flags = DebugFlags::empty();
    let mut negate = false;
    let mut buf = String::new();

    for ch in input.chars() {
        match ch {
            ',' | ' ' => {
                if !buf.is_empty() {
                    add_debug_flag(&mut flags, &buf, negate);
                    buf.clear();
                }
                negate = false;
            }
            '-' => negate = !negate,
            '+' => negate = false,
            _ => buf.push(ch),
        }
    }
    if !buf.is_empty() {
        add_debug_flag(&mut flags, &buf, negate);
    }
    flags
}

fn add_debug_flag(flags: &mut DebugFlags, name: &str, negate: bool) {
    let (name, level) = split_flag_level(name);
    let negate = negate || level == Some(0);
    let flag = match name.to_uppercase().as_str() {
        "BACKUP" => DebugFlags::BACKUP,
        "BIND" => DebugFlags::BIND,
        "CWD" => DebugFlags::CWD,
        "DEL" | "DELETE" => DebugFlags::DEL,
        "DELTASUM" => DebugFlags::DELTASUM,
        "DUP" => DebugFlags::DUP,
        "EXCLUDE" => DebugFlags::EXCLUDE,
        "FILTER" => DebugFlags::FILTER,
        "FLIST" => DebugFlags::FLIST,
        "FUZZY" => DebugFlags::FUZZY,
        "HLINK" => DebugFlags::HLINK,
        "ICONV" => DebugFlags::ICONV,
        "IO" => DebugFlags::IO,
        "MLOCK" => DebugFlags::MLOCK,
        "MOUNT" => DebugFlags::MOUNT,
        "OWN" => DebugFlags::OWN,
        "PROTO" => DebugFlags::PROTO,
        "RECV" => DebugFlags::RECV,
        "SEND" => DebugFlags::SEND,
        "SOCK" => DebugFlags::SOCK,
        "TIME" => DebugFlags::TIME,
        "ALL" => DebugFlags::ALL,
        "NONE" => DebugFlags::NONE,
        _ => return,
    };
    if negate {
        flags.remove(flag);
    } else {
        flags.insert(flag);
    }
}

fn split_flag_level(name: &str) -> (&str, Option<u8>) {
    let split_at = name
        .char_indices()
        .rev()
        .find(|(_, ch)| !ch.is_ascii_digit())
        .map(|(idx, ch)| idx + ch.len_utf8())
        .unwrap_or(0);
    if split_at == name.len() {
        return (name, None);
    }
    let (base, level) = name.split_at(split_at);
    (base, level.parse::<u8>().ok())
}

// ── Output format ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct OutputFormatConfig {
    pub format: Option<String>,
    pub itemize: bool,
    pub stats: bool,
    pub human_readable: u8,
    pub eight_bit: bool,
}

impl OutputFormatConfig {
    pub fn from_cli(cli: &crate::Cli) -> Self {
        Self {
            format: cli.out_format.clone(),
            itemize: cli.itemize_changes,
            stats: cli.stats,
            human_readable: cli.human_readable,
            eight_bit: cli.eight_bit_output,
        }
    }
}

// ── Transfer log ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct TransferLog {
    pub verbosity: u8,
    pub quiet: u8,
    pub info_flags: InfoFlags,
    pub debug_flags: DebugFlags,
    pub stderr_mode: StderrMode,
    pub format: OutputFormatConfig,
    log_writer: Option<BufWriter<std::fs::File>>,
}

impl TransferLog {
    pub fn from_cli(cli: &crate::Cli) -> Result<Self> {
        let info_flags = cli.info_flags.iter().fold(InfoFlags::empty(), |acc, f| {
            let mut combined = acc;
            combined.insert(parse_info_flags(f));
            combined
        });

        let debug_flags = cli.debug_flags.iter().fold(DebugFlags::empty(), |acc, f| {
            let mut combined = acc;
            combined.insert(parse_debug_flags(f));
            combined
        });

        let stderr_mode = if let Some(mode) = &cli.stderr_mode {
            parse_stderr_mode(mode)?
        } else if cli.no_msgs2stderr {
            StderrMode::Client
        } else if cli.msgs2stderr {
            StderrMode::All
        } else {
            StderrMode::Errors
        };

        let log_writer = match &cli.client_log_file {
            Some(path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| {
                        format!("failed to open client log file {}", path.display())
                    })?;
                Some(BufWriter::new(file))
            }
            None => None,
        };

        Ok(Self {
            verbosity: cli.verbosity,
            quiet: cli.quiet,
            info_flags,
            debug_flags,
            stderr_mode,
            format: OutputFormatConfig::from_cli(cli),
            log_writer,
        })
    }

    pub fn minimal(verbosity: u8) -> Self {
        Self {
            verbosity,
            quiet: 0,
            info_flags: InfoFlags::empty(),
            debug_flags: DebugFlags::empty(),
            stderr_mode: StderrMode::Errors,
            format: OutputFormatConfig::default(),
            log_writer: None,
        }
    }

    fn effective_level(&self) -> i8 {
        self.verbosity as i8 - self.quiet as i8
    }

    pub fn enabled(&self) -> bool {
        self.effective_level() > 0
    }

    pub fn info(&self, message: impl AsRef<str>) {
        if self.effective_level() < 1 {
            return;
        }
        self.emit_stderr(message.as_ref());
    }

    pub fn detail(&self, message: impl AsRef<str>) {
        if self.effective_level() < 2 {
            return;
        }
        self.emit_stderr(message.as_ref());
    }

    pub fn debug(&self, category: DebugFlags, message: impl AsRef<str>) {
        if self.debug_flags.contains(DebugFlags::ALL) || self.debug_flags.intersects(category) {
            self.emit_stderr(message.as_ref());
        }
    }

    pub fn warn(&self, message: impl AsRef<str>) {
        if self.stderr_mode == StderrMode::Client {
            return;
        }
        eprintln!("rsync-win: {}", message.as_ref());
    }

    pub fn error(&self, message: impl AsRef<str>) {
        eprintln!("rsync-win: {}", message.as_ref());
    }

    fn emit_stderr(&self, msg: &str) {
        match self.stderr_mode {
            StderrMode::All | StderrMode::Errors => {
                eprintln!("rsync-win: {msg}");
            }
            StderrMode::Client => {
                println!("rsync-win: {msg}");
            }
        }
    }

    pub fn log_transfer(&mut self, record: &TransferLogRecord) -> Result<()> {
        if let Some(writer) = &mut self.log_writer {
            let format = None::<&str>; // will use message-only format
            let line = render_client_log_format(format, record);
            writeln!(writer, "{line}")?;
            writer.flush()?;
        }
        Ok(())
    }

    pub fn log_transfer_with_format(
        &mut self,
        log_format: Option<&str>,
        record: &TransferLogRecord,
    ) -> Result<()> {
        if let Some(writer) = &mut self.log_writer {
            let line = render_client_log_format(log_format, record);
            writeln!(writer, "{line}")?;
            writer.flush()?;
        }
        Ok(())
    }

    pub fn progress_info(&self, message: impl AsRef<str>) {
        if self.format.itemize || self.format.format.is_some() {
            return;
        }
        self.info(message);
    }
}

// ── Client log record and format rendering ──────────────────────────────────

#[derive(Debug, Clone)]
pub struct TransferLogRecord {
    pub operation: Option<String>,
    pub path: Option<String>,
    pub bytes: Option<u64>,
    pub itemized: Option<String>,
    pub symlink_target: Option<String>,
    pub message: String,
}

pub fn render_client_log_format(format: Option<&str>, record: &TransferLogRecord) -> String {
    let format = match format {
        Some(f) => f,
        None => return record.message.clone(),
    };

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
            'm' => output.push_str(record.operation.as_deref().unwrap_or("-")),
            'o' => output.push_str(record.operation.as_deref().unwrap_or("-")),
            'i' => output.push_str(record.itemized.as_deref().unwrap_or("-")),
            'n' => output.push_str(record.path.as_deref().unwrap_or("-")),
            'f' => output.push_str(record.path.as_deref().unwrap_or("-")),
            'l' => output.push_str(
                &record
                    .bytes
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "0".to_string()),
            ),
            'h' | 'a' => output.push('-'),
            'p' => output.push_str(&std::process::id().to_string()),
            'L' => output.push_str(record.symlink_target.as_deref().unwrap_or("")),
            't' => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_else(|_| "0".to_string());
                output.push_str(&ts);
            }
            'M' => output.push_str(&record.message),
            other => {
                output.push('%');
                output.push(other);
            }
        }
    }
    output
}

// ── Legacy ProgressLog compatibility ────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ProgressLog {
    verbosity: u8,
    quiet: u8,
    progress: bool,
    info_flags: InfoFlags,
    stderr_mode: StderrMode,
}

impl ProgressLog {
    pub fn new(verbosity: u8) -> Self {
        Self {
            verbosity,
            quiet: 0,
            progress: false,
            info_flags: InfoFlags::empty(),
            stderr_mode: StderrMode::Errors,
        }
    }

    pub fn from_cli(cli: &crate::Cli) -> Self {
        let info_flags = cli.info_flags.iter().fold(InfoFlags::empty(), |acc, f| {
            let mut combined = acc;
            combined.insert(parse_info_flags(f));
            combined
        });
        let stderr_mode = if let Some(mode) = &cli.stderr_mode {
            parse_stderr_mode(mode).unwrap_or(StderrMode::Errors)
        } else if cli.no_msgs2stderr {
            StderrMode::Client
        } else if cli.msgs2stderr {
            StderrMode::All
        } else {
            StderrMode::Errors
        };

        Self {
            verbosity: cli.verbosity,
            quiet: cli.quiet,
            progress: cli.progress,
            info_flags,
            stderr_mode,
        }
    }

    fn effective_level(&self) -> i8 {
        self.verbosity as i8 - self.quiet as i8
    }

    fn explicit_progress_enabled(&self) -> bool {
        self.quiet == 0 && (self.progress || self.info_flags.contains(InfoFlags::PROGRESS))
    }

    pub fn info(&self, message: impl AsRef<str>) {
        if self.enabled() {
            self.emit(message.as_ref());
        }
    }

    pub fn detail(&self, message: impl AsRef<str>) {
        if self.effective_level() >= 2 || self.info_flags.contains(InfoFlags::ALL) {
            self.emit(message.as_ref());
        }
    }

    pub fn enabled(&self) -> bool {
        self.effective_level() >= 1 || self.explicit_progress_enabled()
    }

    pub fn verbosity(&self) -> u8 {
        self.verbosity
    }

    fn emit(&self, message: &str) {
        match self.stderr_mode {
            StderrMode::Client => println!("rsync-win: {message}"),
            StderrMode::All | StderrMode::Errors => eprintln!("rsync-win: {message}"),
        }
    }
}

// ── Progress/rate helpers ───────────────────────────────────────────────────

pub fn transfer_rate_label(bytes: u64, elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs_f64();
    if secs < 0.001 || bytes == 0 {
        return "0 B/s".to_string();
    }
    let rate = bytes as f64 / secs;
    if rate >= 1_073_741_824.0 {
        format!("{:.2} GiB/s", rate / 1_073_741_824.0)
    } else if rate >= 1_048_576.0 {
        format!("{:.2} MiB/s", rate / 1_048_576.0)
    } else if rate >= 1_024.0 {
        format!("{:.2} KiB/s", rate / 1_024.0)
    } else {
        format!("{:.0} B/s", rate)
    }
}

pub fn format_bytes_human(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.2} KiB", bytes as f64 / 1_024.0)
    } else {
        format!("{bytes} B")
    }
}

pub fn format_bytes(bytes: u64, human_readable: u8) -> String {
    if human_readable > 0 {
        format_bytes_human(bytes)
    } else {
        format!("{bytes}")
    }
}

pub fn escape_output_name(input: &str, eight_bit_output: bool) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch == '\t' {
            output.push(ch);
        } else if ch.is_control() || (!eight_bit_output && !ch.is_ascii()) {
            let mut encoded = [0_u8; 4];
            for byte in ch.encode_utf8(&mut encoded).as_bytes() {
                output.push_str(&format!("\\#{byte:03o}"));
            }
        } else {
            output.push(ch);
        }
    }
    output
}

// ── Out-format rendering ────────────────────────────────────────────────────

/// Arguments for `render_out_format`.
pub struct OutFormatArgs<'a> {
    pub filename: &'a str,
    pub full_path: &'a str,
    pub length: u64,
    pub perms: &'a str,
    pub owner: &'a str,
    pub group: &'a str,
    pub mtime: i64,
    pub itemized: &'a str,
    pub symlink_target: Option<&'a str>,
    pub checksum: Option<&'a str>,
}

pub fn render_out_format(format: &str, args: &OutFormatArgs) -> String {
    let mut output = String::with_capacity(format.len() + args.full_path.len() + 64);
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
            'n' => output.push_str(args.filename),
            'f' => output.push_str(args.full_path),
            'l' | 'b' | 'c' => output.push_str(&args.length.to_string()),
            'p' => output.push_str(args.perms),
            'o' => output.push_str(args.owner),
            'g' => output.push_str(args.group),
            'm' => output.push_str(&args.mtime.to_string()),
            'i' => output.push_str(args.itemized),
            'L' => output.push_str(args.symlink_target.unwrap_or("")),
            'C' => output.push_str(args.checksum.unwrap_or("")),
            other => {
                output.push('%');
                output.push(other);
            }
        }
    }
    output
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Exit code mapping ──────────────────────────────────────────────

    #[test]
    fn exit_code_syntax() {
        let err = anyhow::anyhow!("unknown option --bogus");
        assert_eq!(exit_code_from_error(&err), EXIT_SYNTAX_OR_USAGE);
    }

    #[test]
    fn exit_code_socket() {
        let err = anyhow::anyhow!("connection refused: socket error");
        assert_eq!(exit_code_from_error(&err), EXIT_SOCKET_IO);
    }

    #[test]
    fn exit_code_timeout() {
        let err = anyhow::anyhow!("read timed out after 60s");
        assert_eq!(exit_code_from_error(&err), EXIT_TIMEOUT);
    }

    #[test]
    fn exit_code_file_io() {
        let err = anyhow::anyhow!("permission denied: cannot open file");
        assert_eq!(exit_code_from_error(&err), EXIT_FILE_IO);
    }

    #[test]
    fn exit_code_protocol() {
        let err = anyhow::anyhow!("protocol version mismatch");
        assert_eq!(exit_code_from_error(&err), EXIT_PROTOCOL_STREAM);
    }

    #[test]
    fn exit_code_partial() {
        let err = anyhow::anyhow!("partial transfer due to error");
        assert_eq!(exit_code_from_error(&err), EXIT_PARTIAL);
    }

    #[test]
    fn exit_code_file_select() {
        let err = anyhow::anyhow!("no such file or directory");
        assert_eq!(exit_code_from_error(&err), EXIT_FILE_SELECT);
    }

    #[test]
    fn exit_code_max_delete() {
        let err = anyhow::anyhow!("--max-delete limit reached");
        assert_eq!(exit_code_from_error(&err), EXIT_MAX_DELETE);
    }

    #[test]
    fn exit_code_unsupported() {
        let err = anyhow::anyhow!("unsupported operation on this platform");
        assert_eq!(exit_code_from_error(&err), EXIT_UNSUPPORTED);
    }

    #[test]
    fn exit_code_daemon_log() {
        let err = anyhow::anyhow!("daemon unable to open log-file /var/log/rsyncd.log");
        assert_eq!(exit_code_from_error(&err), EXIT_DAEMON_LOG_FILE);
    }

    #[test]
    fn exit_code_daemon_auth_failure() {
        let err = anyhow::anyhow!("daemon authentication failed: password rejected");
        assert_eq!(exit_code_from_error(&err), EXIT_START_PROTOCOL);
    }

    #[test]
    fn exit_code_vanished() {
        let err = anyhow::anyhow!("some source files vanished during transfer");
        assert_eq!(exit_code_from_error(&err), EXIT_VANISHED);
    }

    #[test]
    fn exit_code_defaults_to_syntax() {
        let err = anyhow::anyhow!("something completely unexpected happened");
        assert_eq!(exit_code_from_error(&err), EXIT_SYNTAX_OR_USAGE);
    }

    // ── Info flags ─────────────────────────────────────────────────────

    #[test]
    fn info_flags_all() {
        assert_eq!(parse_info_flags("ALL"), InfoFlags::ALL);
    }

    #[test]
    fn info_flags_none() {
        assert_eq!(parse_info_flags("NONE"), InfoFlags::NONE);
        assert_eq!(parse_info_flags(""), InfoFlags::NONE);
    }

    #[test]
    fn info_flags_single() {
        let f = parse_info_flags("COPY");
        assert!(f.contains(InfoFlags::COPY));
        assert!(!f.contains(InfoFlags::DEL));
    }

    #[test]
    fn info_flags_multi() {
        let f = parse_info_flags("COPY,DEL,FLIST");
        assert!(f.contains(InfoFlags::COPY));
        assert!(f.contains(InfoFlags::DEL));
        assert!(f.contains(InfoFlags::FLIST));
    }

    #[test]
    fn info_flags_negate() {
        let f = parse_info_flags("ALL,-DEL,-FLIST");
        assert!(f.contains(InfoFlags::ALL));
        assert!(!f.contains(InfoFlags::DEL));
        assert!(!f.contains(InfoFlags::FLIST));
    }

    #[test]
    fn info_flags_accept_numeric_levels() {
        let f = parse_info_flags("progress2,name0,stats1");
        assert!(f.contains(InfoFlags::PROGRESS));
        assert!(!f.contains(InfoFlags::NAME));
        assert!(f.contains(InfoFlags::STATS));
    }

    #[test]
    fn debug_flags_all() {
        assert_eq!(parse_debug_flags("ALL"), DebugFlags::ALL);
    }

    #[test]
    fn debug_flags_none() {
        assert_eq!(parse_debug_flags("NONE"), DebugFlags::NONE);
        assert_eq!(parse_debug_flags(""), DebugFlags::NONE);
    }

    #[test]
    fn debug_flags_multi() {
        let f = parse_debug_flags("IO,SOCK,PROTO");
        assert!(f.contains(DebugFlags::IO));
        assert!(f.contains(DebugFlags::SOCK));
        assert!(f.contains(DebugFlags::PROTO));
    }

    #[test]
    fn debug_flags_negate() {
        let f = parse_debug_flags("ALL,-IO,-SOCK");
        assert!(f.contains(DebugFlags::ALL));
        assert!(!f.contains(DebugFlags::IO));
        assert!(!f.contains(DebugFlags::SOCK));
    }

    #[test]
    fn debug_flags_accept_numeric_levels() {
        let f = parse_debug_flags("io2,sock0,proto1");
        assert!(f.contains(DebugFlags::IO));
        assert!(!f.contains(DebugFlags::SOCK));
        assert!(f.contains(DebugFlags::PROTO));
    }

    #[test]
    fn stderr_mode_uses_option_values_and_compat_aliases() {
        let all = crate::options::parse_cli(["rsync-win", "--stderr=all", "src", "dst"]).unwrap();
        assert_eq!(
            TransferLog::from_cli(&all).unwrap().stderr_mode,
            StderrMode::All
        );

        let all_abbrev =
            crate::options::parse_cli(["rsync-win", "--stderr=a", "src", "dst"]).unwrap();
        assert_eq!(
            TransferLog::from_cli(&all_abbrev).unwrap().stderr_mode,
            StderrMode::All
        );

        let client =
            crate::options::parse_cli(["rsync-win", "--stderr=client", "src", "dst"]).unwrap();
        assert_eq!(
            TransferLog::from_cli(&client).unwrap().stderr_mode,
            StderrMode::Client
        );

        let errors =
            crate::options::parse_cli(["rsync-win", "--stderr=errors", "src", "dst"]).unwrap();
        assert_eq!(
            TransferLog::from_cli(&errors).unwrap().stderr_mode,
            StderrMode::Errors
        );

        let msgs2stderr =
            crate::options::parse_cli(["rsync-win", "--msgs2stderr", "src", "dst"]).unwrap();
        assert_eq!(
            TransferLog::from_cli(&msgs2stderr).unwrap().stderr_mode,
            StderrMode::All
        );

        let no_msgs2stderr =
            crate::options::parse_cli(["rsync-win", "--no-msgs2stderr", "src", "dst"]).unwrap();
        assert_eq!(
            TransferLog::from_cli(&no_msgs2stderr).unwrap().stderr_mode,
            StderrMode::Client
        );
    }

    #[test]
    fn output_name_escaping_honors_8_bit_mode() {
        assert_eq!(escape_output_name("line\nbreak", false), "line\\#012break");
        assert_eq!(
            escape_output_name("caf\u{00e9}.txt", false),
            "caf\\#303\\#251.txt"
        );
        assert_eq!(
            escape_output_name("caf\u{00e9}.txt", true),
            "caf\u{00e9}.txt"
        );
    }

    // ── Out-format rendering ───────────────────────────────────────────

    fn make_args<'a>(
        fmt: &'a str,
        fp: &'a str,
        l: u64,
        p: &'a str,
        o: &'a str,
        g: &'a str,
        mt: i64,
        it: &'a str,
        sl: Option<&'a str>,
        cs: Option<&'a str>,
    ) -> OutFormatArgs<'a> {
        OutFormatArgs {
            filename: fmt,
            full_path: fp,
            length: l,
            perms: p,
            owner: o,
            group: g,
            mtime: mt,
            itemized: it,
            symlink_target: sl,
            checksum: cs,
        }
    }

    #[test]
    fn out_format_basic() {
        let result = render_out_format(
            "%i %n (%l bytes)",
            &make_args(
                "file.txt",
                "/dest/file.txt",
                1024,
                "-rw-r--r--",
                "OWNER",
                "GROUP",
                1714512000,
                ">f+++++++++",
                None,
                None,
            ),
        );
        assert_eq!(result, ">f+++++++++ file.txt (1024 bytes)");
    }

    #[test]
    fn out_format_all_tokens() {
        let result = render_out_format(
            "%i %f (%b) %p %o:%g %m -> %L [%C]",
            &make_args(
                "file.txt",
                "/dest/file.txt",
                2048,
                "-rwxr-xr-x",
                "admin",
                "staff",
                1714512000,
                ">f.s......",
                Some("/target/link"),
                Some("d41d8cd98f00b204e9800998ecf8427e"),
            ),
        );
        assert_eq!(
            result,
            ">f.s...... /dest/file.txt (2048) -rwxr-xr-x admin:staff 1714512000 -> /target/link [d41d8cd98f00b204e9800998ecf8427e]"
        );
    }

    #[test]
    fn out_format_literal_percent() {
        let result = render_out_format(
            "%% %n done",
            &make_args("file.txt", "/d/file.txt", 0, "", "", "", 0, "", None, None),
        );
        assert_eq!(result, "% file.txt done");
    }

    #[test]
    fn out_format_unknown_passthrough() {
        let result = render_out_format(
            "%X %n",
            &make_args("f", "/d/f", 0, "", "", "", 0, "", None, None),
        );
        assert_eq!(result, "%X f");
    }

    // ── Client log format ──────────────────────────────────────────────

    #[test]
    fn log_format_default() {
        let record = TransferLogRecord {
            operation: Some("send".into()),
            path: Some("/tmp/test.txt".into()),
            bytes: Some(512),
            itemized: Some(">f+++++++++".into()),
            symlink_target: None,
            message: "sent 512 bytes".into(),
        };
        let result = render_client_log_format(Some("%t [%p] %o %f (%l bytes)"), &record);
        assert!(result.contains("send"));
        assert!(result.contains("/tmp/test.txt"));
        assert!(result.contains("512"));
    }

    #[test]
    fn log_format_no_format() {
        let record = TransferLogRecord {
            operation: None,
            path: None,
            bytes: None,
            itemized: None,
            symlink_target: None,
            message: "plain message".into(),
        };
        let result = render_client_log_format(None, &record);
        assert_eq!(result, "plain message");
    }

    // ── Human-readable bytes ───────────────────────────────────────────

    #[test]
    fn format_bytes_human_gib() {
        let s = format_bytes_human(1_073_741_824);
        assert!(s.contains("GiB"));
    }

    #[test]
    fn format_bytes_human_mib() {
        let s = format_bytes_human(1_048_576);
        assert!(s.contains("MiB"));
    }

    #[test]
    fn format_bytes_human_kib() {
        let s = format_bytes_human(1_024);
        assert!(s.contains("KiB"));
    }

    #[test]
    fn format_bytes_human_small() {
        assert_eq!(format_bytes_human(42), "42 B");
    }

    #[test]
    fn format_bytes_raw() {
        assert_eq!(format_bytes(1_048_576, 0), "1048576");
    }

    #[test]
    fn format_bytes_human_mode() {
        assert!(format_bytes(1_048_576, 1).contains("MiB"));
    }

    // ── TransferLog level gating ───────────────────────────────────────

    #[test]
    fn transfer_log_quiet_suppresses_info() {
        let log = TransferLog {
            verbosity: 2,
            quiet: 2,
            ..TransferLog::minimal(2)
        };
        log.info("should not appear");
        log.detail("should not appear either");
    }

    #[test]
    fn transfer_log_enabled() {
        let log = TransferLog {
            verbosity: 2,
            quiet: 0,
            ..TransferLog::minimal(2)
        };
        assert!(log.enabled());
    }

    #[test]
    fn transfer_log_enabled_false() {
        let log = TransferLog {
            verbosity: 0,
            quiet: 0,
            ..TransferLog::minimal(0)
        };
        assert!(!log.enabled());
    }

    #[test]
    fn progress_log_enabled_by_progress_option_and_info_progress() {
        let progress =
            crate::options::parse_cli(["rsync-win", "--progress", "src", "dst"]).unwrap();
        assert!(ProgressLog::from_cli(&progress).enabled());

        let info =
            crate::options::parse_cli(["rsync-win", "--info=progress2", "src", "dst"]).unwrap();
        assert!(ProgressLog::from_cli(&info).enabled());

        let quiet_progress =
            crate::options::parse_cli(["rsync-win", "--quiet", "--progress", "src", "dst"])
                .unwrap();
        assert!(!ProgressLog::from_cli(&quiet_progress).enabled());
    }

    #[test]
    fn transfer_rate_label_formats() {
        let rate = transfer_rate_label(1_048_576, std::time::Duration::from_secs(1));
        assert!(rate.contains("MiB/s"));
    }
}
