use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rsync_core::ChmodRules;
use rsync_filter::{Rule, RuleSet};
use rsync_fs::{
    FileWriteMode, FileWriteOptions, LocalFileSystem, PortableFileSystem, SymlinkMode, SyncAction,
    UpdateMode,
};
use rsync_protocol::{
    read_i32_le, read_rsync31_file_list_with_metadata, read_rsync_index, read_u16_le, write_i32_le,
    write_rsync31_file_list_with_metadata, write_rsync_index, write_u16_le, write_varlong,
    MultiplexReadState, MultiplexedReader, MultiplexedWriter, RsyncFileListOptions,
    RsyncIndexState, WireFileType, DEFAULT_MAX_FILE_LIST_ENTRIES, DEFAULT_MAX_FILE_LIST_PATH_LEN,
    REMOTE_SHELL_MODERN_PROTOCOL, RSYNC_INDEX_DONE,
};
use rsync_transport::tcp::{TcpAddressFamily, TcpSocketOptions};

use crate::{
    checked_file_index, collect_local_source_entries, delete_local_extras, read_multiplexed_i32,
    read_multiplexed_rsync31_index, read_remote_block_signatures_from_reader,
    read_rsync31_optional_item_attrs, read_sum_head, receive_remote_sender_files_protocol31,
    request_remote_sender_files_protocol31, selected_remote_entries, selected_remote_entry_indexes,
    selected_remote_transfer_indexes, sort_remote_entries_for_sender_indexes,
    validate_remote_file_list_paths, windows_destination_path_preflight,
    write_delta_tokens_from_path, write_rsync31_done, write_rsync31_index,
    write_rsync31_optional_item_attrs, write_sum_head, Cli, DeltaWriteRuntime,
    LocalSourceCollectOptions, ProgressLog, RemoteCompressionConfig, RemoteExecutionStats,
    RemoteFileChecksum, RemoteFinalChecksum, RemoteReceiveContext, RemoteSessionError,
    RemoteSourceEntry, RSYNC31_MUX_FRAME_SIZE, RSYNC_ITEM_TRANSFER,
};

#[derive(Debug, Clone)]
struct DaemonServerConfig {
    modules: Vec<DaemonServerModule>,
}

#[derive(Debug, Clone)]
struct DaemonServerModule {
    name: String,
    path: PathBuf,
    comment: String,
    read_only: bool,
    list: bool,
}

#[derive(Debug)]
struct DaemonTransferArgs {
    sender: bool,
    paths: Vec<String>,
    recursive: bool,
    dry_run: bool,
    whole_file: bool,
    preserve_times: bool,
    update_mode: UpdateMode,
    append_verify: bool,
    file_write_options: FileWriteOptions,
    block_size: usize,
    filter_rules: RuleSet,
    flist_options: RsyncFileListOptions,
    preserve_executability: bool,
    chmod_rules: Option<ChmodRules>,
    compression: Option<RemoteCompressionConfig>,
    delete: bool,
}

use rsync_transport::{BandwidthLimit, BandwidthLimitedStream};

#[derive(Debug)]
enum DaemonConnection {
    Plain(TcpStream),
    Limited(BandwidthLimitedStream<TcpStream>),
}

impl DaemonConnection {
    fn new(stream: TcpStream, limit: Option<BandwidthLimit>) -> Self {
        match limit {
            Some(limit) => Self::Limited(BandwidthLimitedStream::new(stream, limit)),
            None => Self::Plain(stream),
        }
    }
}

impl Read for DaemonConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Limited(stream) => stream.read(buf),
        }
    }
}

impl Write for DaemonConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Limited(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Limited(stream) => stream.flush(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DaemonLogRecord {
    message: String,
    module: Option<String>,
    operation: Option<String>,
    path: Option<String>,
    bytes: Option<u64>,
    client: Option<String>,
}

pub fn run(cli: &Cli) -> Result<String> {
    let config_path = cli
        .daemon_config
        .as_ref()
        .context("daemon server mode requires --config pointing at a controlled rsyncd.conf")?;
    let socket_options = cli
        .daemon_sockopts
        .as_deref()
        .map(TcpSocketOptions::parse)
        .transpose()
        .context("invalid daemon --sockopts")?
        .unwrap_or_default();
    let bandwidth_limit = cli
        .daemon_bwlimit
        .as_deref()
        .map(parse_daemon_bwlimit)
        .transpose()
        .context("invalid daemon --bwlimit")?;
    let config_text = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read daemon config {}", config_path.display()))?;
    let mut config = parse_config(&config_text, config_path)?;
    apply_dparams(&mut config, &cli.daemon_params)?;
    validate_config(&config)?;

    let address = daemon_listen_address(cli);
    let port = cli
        .daemon_port
        .unwrap_or(rsync_protocol::DEFAULT_DAEMON_PORT);
    let address_family = daemon_address_family(cli);
    let listener =
        TcpSocketOptions::bind_listener((address.as_str(), port), &socket_options, address_family)
            .with_context(|| format!("failed to bind daemon listener at {address}:{port}"))?;
    log_daemon_message(cli, &format!("listening on {}", listener.local_addr()?))?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let client = stream.peer_addr().ok().map(|addr| addr.to_string());
                if let Err(err) = socket_options.apply_to_stream(&stream) {
                    log_daemon_message(cli, &format!("client socket option error: {err}"))?;
                    continue;
                }
                let stream = DaemonConnection::new(stream, bandwidth_limit);
                if let Err(err) = handle_client(cli, &config, stream, client) {
                    log_daemon_message(cli, &format!("client error: {err:#}"))?;
                }
            }
            Err(err) => log_daemon_message(cli, &format!("accept error: {err}"))?,
        }
    }

    Ok(String::new())
}

fn parse_config(text: &str, path: &Path) -> Result<DaemonServerConfig> {
    let mut modules = Vec::<DaemonServerModule>::new();
    let mut current: Option<DaemonServerModule> = None;

    for (line_index, raw_line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(module) = current.take() {
                modules.push(module);
            }
            let name = line[1..line.len() - 1].trim();
            if name.is_empty() || name.contains(char::is_whitespace) {
                bail!(
                    "{}:{}: daemon module names must be non-empty and contain no whitespace",
                    path.display(),
                    line_number
                );
            }
            current = Some(DaemonServerModule {
                name: name.to_string(),
                path: PathBuf::new(),
                comment: String::new(),
                read_only: true,
                list: true,
            });
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            bail!(
                "{}:{}: daemon config entries must use key = value syntax",
                path.display(),
                line_number
            );
        };
        let key = normalize_key(key);
        let value = value.trim();
        let Some(module) = current.as_mut() else {
            match key.as_str() {
                "motd file" | "pid file" | "lock file" | "log file" | "log format" | "port"
                | "address" | "use chroot" => continue,
                _ => bail!(
                    "{}:{}: unsupported daemon global config key `{key}`",
                    path.display(),
                    line_number
                ),
            }
        };
        if let Err(err) = apply_module_param(module, &key, value) {
            bail!("{}:{line_number}: {err}", path.display());
        }
    }

    if let Some(module) = current.take() {
        modules.push(module);
    }
    Ok(DaemonServerConfig { modules })
}

fn apply_dparams(config: &mut DaemonServerConfig, params: &[String]) -> Result<()> {
    for param in params {
        let (target, value) = param
            .split_once('=')
            .with_context(|| format!("daemon --dparam must use key=value syntax: {param}"))?;
        let (module_name, key) = target
            .split_once('.')
            .or_else(|| target.split_once(':'))
            .with_context(|| {
                format!("daemon --dparam must target a module as module.key=value: {param}")
            })?;
        let module = config
            .modules
            .iter_mut()
            .find(|module| module.name == module_name)
            .with_context(|| format!("daemon --dparam targets unknown module `{module_name}`"))?;
        if let Err(err) = apply_module_param(module, &normalize_key(key), value.trim()) {
            bail!("invalid daemon --dparam `{param}`: {err}");
        }
    }
    Ok(())
}

fn apply_module_param(module: &mut DaemonServerModule, key: &str, value: &str) -> Result<()> {
    match key {
        "path" => module.path = PathBuf::from(value),
        "comment" => module.comment = value.to_string(),
        "read only" => module.read_only = parse_daemon_bool(value)?,
        "list" => module.list = parse_daemon_bool(value)?,
        _ => bail!("unsupported daemon module config key `{key}`"),
    }
    Ok(())
}

fn validate_config(config: &DaemonServerConfig) -> Result<()> {
    if config.modules.is_empty() {
        bail!("daemon config must define at least one module");
    }
    for module in &config.modules {
        if module.path.as_os_str().is_empty() {
            bail!("daemon module `{}` is missing a path", module.name);
        }
        if !module.path.exists() {
            bail!(
                "daemon module `{}` path does not exist: {}",
                module.name,
                module.path.display()
            );
        }
        if !module.path.is_dir() {
            bail!(
                "daemon module `{}` path is not a directory: {}",
                module.name,
                module.path.display()
            );
        }
    }
    Ok(())
}

fn handle_client<T: Read + Write>(
    cli: &Cli,
    config: &DaemonServerConfig,
    mut stream: T,
    client: Option<String>,
) -> Result<()> {
    writeln!(stream, "@RSYNCD: {REMOTE_SHELL_MODERN_PROTOCOL}.0 md5 md4")?;
    stream.flush()?;

    let greeting = read_daemon_line(&mut stream, 1024)?.context("client closed before greeting")?;
    if !greeting.starts_with("@RSYNCD: ") {
        bail!("invalid daemon client greeting `{greeting}`");
    }
    let peer_protocol = parse_client_greeting_protocol(&greeting)?;

    let request = read_daemon_line(&mut stream, 8192)?.context("client closed before request")?;
    if request == "#list" {
        write_module_list(cli, config, &mut stream)?;
        return Ok(());
    }

    let Some(module) = config.modules.iter().find(|module| module.name == request) else {
        writeln!(stream, "@ERROR: Unknown module '{request}'")?;
        stream.flush()?;
        return Ok(());
    };

    writeln!(stream, "@RSYNCD: OK")?;
    stream.flush()?;
    let args = read_daemon_args(&mut stream, peer_protocol)?;
    let transfer = DaemonTransferArgs::parse(&args)?;
    let operation = if transfer.sender { "send" } else { "recv" };
    let path = transfer.paths.first().cloned();
    log_daemon_record(
        cli,
        DaemonLogRecord {
            message: format!("module {} transfer args: {}", module.name, args.join(" ")),
            module: Some(module.name.clone()),
            operation: Some(operation.to_string()),
            path,
            bytes: None,
            client,
        },
    )?;
    if peer_protocol < REMOTE_SHELL_MODERN_PROTOCOL {
        writeln!(
            stream,
            "@ERROR: rsync-win daemon server requires protocol {REMOTE_SHELL_MODERN_PROTOCOL} for transfers"
        )?;
        stream.flush()?;
        return Ok(());
    }

    if !transfer.sender && module.read_only {
        writeln!(stream, "@ERROR: module '{}' is read only", module.name)?;
        stream.flush()?;
        return Ok(());
    }
    if transfer.sender {
        serve_daemon_sender_protocol31(&mut stream, module, &transfer)?;
    } else {
        serve_daemon_receiver_protocol31(&mut stream, module, &transfer)?;
    }
    Ok(())
}

fn serve_daemon_sender_protocol31<T: Read + Write>(
    stream: &mut T,
    module: &DaemonServerModule,
    transfer: &DaemonTransferArgs,
) -> Result<()> {
    send_protocol31_setup(stream)?;
    let mut mux = MultiplexReadState::default();
    let initial = read_multiplexed_i32(stream, &mut mux)?;
    if initial != 0 {
        bail!("daemon receiver sent unexpected initial protocol 31 marker {initial}");
    }

    let sources = transfer.module_paths(module)?;
    let entries = collect_local_source_entries(
        &sources,
        &LocalSourceCollectOptions {
            recursive: transfer.recursive,
            filter_rules: &transfer.filter_rules,
            files_from: None,
            symlink_mode: SymlinkMode::Preserve,
            include_checksums: transfer.update_mode == UpdateMode::Checksum,
            preserve_executability: transfer.preserve_executability,
            preserve_hard_links: false,
            chmod_rules: transfer.chmod_rules.as_ref(),
        },
    )?;
    let wire_entries: Vec<_> = entries.iter().map(|entry| entry.wire.clone()).collect();
    {
        let mut writer = MultiplexedWriter::new(stream, RSYNC31_MUX_FRAME_SIZE);
        write_rsync31_file_list_with_metadata(
            &mut writer,
            &wire_entries,
            transfer.protocol31_flist_options(),
        )?;
        writer.flush()?;
    }

    serve_daemon_sender_requests_protocol31(stream, &mut mux, &entries, transfer)
}

fn serve_daemon_receiver_protocol31<T: Read + Write>(
    stream: &mut T,
    module: &DaemonServerModule,
    transfer: &DaemonTransferArgs,
) -> Result<()> {
    exchange_receiver_protocol31_setup(stream)?;
    let destination = transfer
        .module_paths(module)?
        .into_iter()
        .next()
        .context("daemon push requires a module destination path")?;
    let mut mux = MultiplexReadState::default();
    if transfer.delete {
        let marker = {
            let mut reader = MultiplexedReader::new(stream, &mut mux);
            read_i32_le(&mut reader)?
        };
        if marker != 0 {
            bail!("daemon sender sent unexpected delete marker {marker}");
        }
    }

    let mut entries = {
        let mut reader = MultiplexedReader::new(stream, &mut mux);
        read_rsync31_file_list_with_metadata(
            &mut reader,
            DEFAULT_MAX_FILE_LIST_ENTRIES,
            DEFAULT_MAX_FILE_LIST_PATH_LEN,
            transfer.protocol31_flist_options(),
        )?
    };
    sort_remote_entries_for_sender_indexes(&mut entries);
    validate_remote_file_list_paths(&entries)?;
    let selected_indexes = selected_remote_entry_indexes(&entries, &transfer.filter_rules, None);
    let selected_entries = selected_remote_entries(&entries, &selected_indexes);

    let destination_relatives: Vec<_> = selected_entries
        .iter()
        .filter(|entry| !crate::remote_entry_is_top_dir(entry))
        .map(|entry| entry.path.clone())
        .collect();
    windows_destination_path_preflight(&destination_relatives)?;

    let mut fs = LocalFileSystem;
    let mut actions = Vec::<SyncAction>::new();
    if !fs.exists(&destination) {
        if !transfer.dry_run {
            fs.create_dir_all(&destination)?;
        }
        actions.push(SyncAction::CreateDir(destination.clone()));
    }
    let index_offset = crate::remote_file_index_offset(&entries);
    let transfer_indexes = selected_remote_transfer_indexes(
        &fs,
        &destination,
        &entries,
        &selected_indexes,
        transfer.update_mode,
    )?;
    if transfer.delete {
        delete_local_extras(
            &mut fs,
            &destination,
            &selected_entries,
            &transfer.filter_rules,
            None,
            transfer.dry_run,
            &mut actions,
        )?;
    }
    for entry in &selected_entries {
        if crate::remote_entry_is_top_dir(entry) {
            continue;
        }
        if entry.file_type == WireFileType::Directory {
            let target = destination.join(&entry.path);
            actions.push(SyncAction::CreateDir(target.clone()));
            if !transfer.dry_run {
                fs.create_dir_all(&target)?;
            }
        }
    }

    request_remote_sender_files_protocol31(
        stream,
        &entries,
        &transfer_indexes,
        index_offset,
        transfer.dry_run,
        &destination,
        transfer.block_size,
        transfer.whole_file,
        RemoteFileChecksum::PlainMd4,
        None,
        None,
    )?;
    stream.flush()?;
    receive_remote_sender_files_protocol31(
        stream,
        &mut mux,
        RemoteReceiveContext {
            fs: &mut fs,
            dest: &destination,
            entries: &entries,
            index_offset,
            final_checksum: RemoteFinalChecksum::PlainMd4,
            dry_run: transfer.dry_run,
            progress: ProgressLog::new(0),
            preserve_times: transfer.preserve_times,
            file_write_options: transfer.file_write_options.clone(),
            append_verify: transfer.append_verify,
            compression: transfer.compression.as_ref(),
            max_alloc: None,
            stop_deadline: None,
            actions: &mut actions,
        },
    )?;

    write_rsync31_done(stream)?;
    let phase_ack = read_multiplexed_rsync31_index(stream, &mut mux)?;
    if phase_ack != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidPhaseAck(phase_ack).into());
    }
    write_rsync31_done(stream)?;
    let sender_done = read_multiplexed_rsync31_index(stream, &mut mux)?;
    if sender_done != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(sender_done).into());
    }
    write_rsync31_done(stream)?;
    let goodbye_ack = read_multiplexed_rsync31_index(stream, &mut mux)?;
    if goodbye_ack != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(goodbye_ack).into());
    }
    write_rsync31_done(stream)
}

fn send_protocol31_setup<T: Write>(stream: &mut T) -> Result<()> {
    rsync_protocol::io::write_varint(stream, 0)?;
    write_i32_le(stream, 0)?;
    stream.flush()?;
    Ok(())
}

fn exchange_receiver_protocol31_setup<T: Read + Write>(stream: &mut T) -> Result<()> {
    rsync_protocol::io::write_u32_le(stream, REMOTE_SHELL_MODERN_PROTOCOL)?;
    stream.flush()?;
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix)?;
    let peer_protocol = rsync_protocol::validate_protocol_stream_prefix(&prefix)?;
    if peer_protocol < REMOTE_SHELL_MODERN_PROTOCOL {
        bail!(
            "daemon sender protocol {peer_protocol} is below required protocol {REMOTE_SHELL_MODERN_PROTOCOL}"
        );
    }
    send_protocol31_setup(stream)
}

fn serve_daemon_sender_requests_protocol31<T: Read + Write>(
    stream: &mut T,
    mux: &mut MultiplexReadState,
    entries: &[RemoteSourceEntry],
    transfer: &DaemonTransferArgs,
) -> Result<()> {
    let mut read_index_state = RsyncIndexState::default();
    let mut write_index_state = RsyncIndexState::default();
    let mut phase_markers = 0_usize;
    let mut stats = RemoteExecutionStats::default();

    loop {
        let request = {
            let mut reader = MultiplexedReader::new(stream, mux);
            let index = read_rsync_index(&mut reader, &mut read_index_state)?;
            if index == RSYNC_INDEX_DONE {
                None
            } else {
                let iflags = read_u16_le(&mut reader)?;
                let attrs = read_rsync31_optional_item_attrs(&mut reader, iflags)?;
                if iflags & RSYNC_ITEM_TRANSFER != 0 {
                    let sum_head = read_sum_head(&mut reader)?;
                    let signatures = read_remote_block_signatures_from_reader(
                        &mut reader,
                        sum_head,
                        RemoteFileChecksum::PlainMd4,
                        None,
                    )?;
                    Some((index, iflags, attrs, Some(sum_head), signatures))
                } else {
                    Some((index, iflags, attrs, None, Vec::new()))
                }
            }
        };

        let Some((index, iflags, attrs, sum_head, signatures)) = request else {
            phase_markers += 1;
            if phase_markers > 2 {
                break;
            }
            write_rsync31_index(stream, &mut write_index_state, RSYNC_INDEX_DONE)?;
            continue;
        };

        let entry_index = checked_file_index(index, entries.len())?;
        let entry = &entries[entry_index];
        let wants_transfer = iflags & RSYNC_ITEM_TRANSFER != 0;
        if !wants_transfer {
            let mut writer = MultiplexedWriter::new(stream, RSYNC31_MUX_FRAME_SIZE);
            write_rsync_index(&mut writer, &mut write_index_state, index)?;
            write_u16_le(&mut writer, iflags)?;
            write_rsync31_optional_item_attrs(&mut writer, iflags, &attrs)?;
            writer.flush()?;
            continue;
        }
        if entry.wire.file_type != WireFileType::File {
            return Err(RemoteSessionError::NonFileBlockRequest { index: entry_index }.into());
        }
        if transfer.dry_run {
            let mut writer = MultiplexedWriter::new(stream, RSYNC31_MUX_FRAME_SIZE);
            write_rsync_index(&mut writer, &mut write_index_state, index)?;
            write_u16_le(&mut writer, iflags)?;
            write_rsync31_optional_item_attrs(&mut writer, iflags, &attrs)?;
            writer.flush()?;
            stats.files += 1;
            stats.bytes += entry.wire.len;
            continue;
        }

        let sum_head = sum_head.context("daemon receiver transfer request omitted sum head")?;
        {
            let mut writer = MultiplexedWriter::new(stream, RSYNC31_MUX_FRAME_SIZE);
            write_rsync_index(&mut writer, &mut write_index_state, index)?;
            write_u16_le(&mut writer, iflags)?;
            write_rsync31_optional_item_attrs(&mut writer, iflags, &attrs)?;
            write_sum_head(&mut writer, sum_head)?;
            let delta_stats = write_delta_tokens_from_path(
                &mut writer,
                RemoteFileChecksum::PlainMd4,
                RemoteFinalChecksum::PlainMd4,
                &entry.local_path,
                &signatures,
                DeltaWriteRuntime {
                    compression: transfer.compression.as_ref(),
                    progress: None,
                    max_alloc: None,
                    stop_deadline: None,
                },
            )?;
            writer.flush()?;
            stats.bytes += delta_stats.literal_bytes;
        }
        stats.files += 1;
    }

    write_rsync31_index(stream, &mut write_index_state, RSYNC_INDEX_DONE)?;
    write_daemon_sender_stats(stream, entries, stats)?;
    let first_goodbye = read_multiplexed_rsync31_index(stream, mux)?;
    if first_goodbye != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(first_goodbye).into());
    }
    write_rsync31_done(stream)?;
    let second_goodbye = read_multiplexed_rsync31_index(stream, mux)?;
    if second_goodbye != RSYNC_INDEX_DONE {
        return Err(RemoteSessionError::InvalidFinalAck(second_goodbye).into());
    }
    Ok(())
}

fn write_daemon_sender_stats<T: Write>(
    stream: &mut T,
    entries: &[RemoteSourceEntry],
    stats: RemoteExecutionStats,
) -> Result<()> {
    let total_size = entries
        .iter()
        .filter(|entry| entry.wire.file_type == WireFileType::File)
        .map(|entry| entry.wire.len)
        .sum::<u64>();
    let mut writer = MultiplexedWriter::new(stream, RSYNC31_MUX_FRAME_SIZE);
    for value in [0, stats.bytes, total_size, 0, 0] {
        write_varlong(&mut writer, value, 3)?;
    }
    writer.flush()?;
    Ok(())
}

fn write_module_list<T: Write>(
    cli: &Cli,
    config: &DaemonServerConfig,
    stream: &mut T,
) -> Result<()> {
    if !cli.daemon_no_motd {
        writeln!(stream, "rsync-win daemon")?;
    }
    for module in config.modules.iter().filter(|module| module.list) {
        writeln!(stream, "{}\t{}", module.name, module.comment)?;
    }
    writeln!(stream, "@RSYNCD: EXIT")?;
    stream.flush()?;
    Ok(())
}

fn read_daemon_args<T: Read>(stream: &mut T, protocol: u32) -> Result<Vec<String>> {
    if protocol >= 30 {
        read_null_daemon_args(stream)
    } else {
        read_line_daemon_args(stream)
    }
}

fn read_null_daemon_args<T: Read>(stream: &mut T) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        if byte[0] == 0 {
            if current.is_empty() {
                return decode_args(args);
            }
            args.push(std::mem::take(&mut current));
        } else {
            current.push(byte[0]);
            if current.len() > 8192 || args.len() > 1024 {
                bail!("daemon server argument list is too large");
            }
        }
    }
}

fn read_line_daemon_args<T: Read>(stream: &mut T) -> Result<Vec<String>> {
    let mut args = Vec::new();
    while let Some(line) = read_daemon_line(stream, 8192)? {
        if line.is_empty() {
            return Ok(args);
        }
        args.push(line);
        if args.len() > 1024 {
            bail!("daemon server argument list is too large");
        }
    }
    Ok(args)
}

fn decode_args(raw: Vec<Vec<u8>>) -> Result<Vec<String>> {
    raw.into_iter()
        .map(|arg| String::from_utf8(arg).context("daemon argument was not UTF-8"))
        .collect()
}

impl DaemonTransferArgs {
    fn parse(args: &[String]) -> Result<Self> {
        if !args.iter().any(|arg| arg == "--server") {
            bail!("daemon transfer args are missing --server");
        }
        let sender = args.iter().any(|arg| arg == "--sender");
        let mut filter_rules = RuleSet::empty();
        let mut transfer = Self {
            sender,
            paths: Vec::new(),
            recursive: false,
            dry_run: false,
            whole_file: false,
            preserve_times: false,
            update_mode: UpdateMode::QuickCheck,
            append_verify: false,
            file_write_options: FileWriteOptions::default(),
            block_size: 32 * 1024,
            filter_rules: RuleSet::empty(),
            flist_options: RsyncFileListOptions::default(),
            preserve_executability: false,
            chmod_rules: None,
            compression: None,
            delete: false,
        };

        let mut after_dot = false;
        for arg in args {
            if after_dot {
                transfer.paths.push(arg.clone());
                continue;
            }
            if arg == "." {
                after_dot = true;
                continue;
            }
            transfer.apply_option_arg(arg, &mut filter_rules)?;
        }
        if transfer.paths.is_empty() {
            transfer.paths.push(".".to_string());
        }
        transfer.filter_rules = filter_rules;
        Ok(transfer)
    }

    fn apply_option_arg(&mut self, arg: &str, filter_rules: &mut RuleSet) -> Result<()> {
        match arg {
            "--server" | "--sender" | "--no-inc-recursive" => return Ok(()),
            "--recursive" => self.recursive = true,
            "--dry-run" => self.dry_run = true,
            "--whole-file" => self.whole_file = true,
            "--times" => self.preserve_times = true,
            "--checksum" => self.update_mode = UpdateMode::Checksum,
            "--size-only" => self.update_mode = UpdateMode::SizeOnly,
            "--ignore-times" => self.update_mode = UpdateMode::IgnoreTimes,
            "--append-verify" => self.append_verify = true,
            "--inplace" => self.file_write_options.mode = FileWriteMode::InPlace,
            "--perms" => {}
            "--executability" => self.preserve_executability = true,
            "--owner" => self.flist_options.preserve_owner = true,
            "--group" => self.flist_options.preserve_group = true,
            "--numeric-ids" => self.flist_options.numeric_ids = true,
            "--acls" => self.flist_options.acls = true,
            "--xattrs" => self.flist_options.xattrs = true,
            "--fake-super" => {
                self.flist_options.fake_super = true;
                self.flist_options.xattrs = true;
            }
            "--atimes" => self.flist_options.atimes = true,
            "--crtimes" => self.flist_options.crtimes = true,
            "--omit-dir-times" | "--omit-link-times" => {}
            "--delete" | "--delete-before" | "--delete-during" | "--delete-delay"
            | "--delete-after" => self.delete = true,
            "--compress" | "-z" => {
                self.ensure_compression();
            }
            value if value.starts_with("--include=") => {
                filter_rules.push(
                    Rule::include(value.trim_start_matches("--include="))
                        .context("invalid daemon include rule")?,
                );
            }
            value if value.starts_with("--exclude=") => {
                filter_rules.push(
                    Rule::exclude(value.trim_start_matches("--exclude="))
                        .context("invalid daemon exclude rule")?,
                );
            }
            value if value.starts_with("--filter=") => {
                filter_rules.push(
                    Rule::parse_filter(value.trim_start_matches("--filter="))
                        .context("invalid daemon filter rule")?,
                );
            }
            value if value.starts_with("--chmod=") => {
                self.chmod_rules = Some(
                    value
                        .trim_start_matches("--chmod=")
                        .parse()
                        .context("invalid daemon chmod rule")?,
                );
            }
            value if value.starts_with("--usermap=") => self.flist_options.preserve_owner = true,
            value if value.starts_with("--groupmap=") => self.flist_options.preserve_group = true,
            value if value.starts_with("--chown=") => {
                let chown = value.trim_start_matches("--chown=");
                let (user, group) = chown.split_once(':').unwrap_or((chown, ""));
                if !user.is_empty() {
                    self.flist_options.preserve_owner = true;
                }
                if !group.is_empty() {
                    self.flist_options.preserve_group = true;
                }
            }
            value if value.starts_with("--block-size=") => {
                self.block_size = parse_positive_usize(value.trim_start_matches("--block-size="))?;
            }
            value if value.starts_with("--compress-choice=") => {
                let mode = rsync_protocol::RsyncDeflatedTokenMode::from_choice(Some(
                    value.trim_start_matches("--compress-choice="),
                ))
                .map_err(|_| anyhow::anyhow!("unsupported daemon compression choice"))?;
                let config = self.compression.get_or_insert(RemoteCompressionConfig {
                    mode,
                    level: 6,
                    skip_suffixes: Vec::new(),
                });
                config.mode = mode;
            }
            value if value.starts_with("--compress-level=") => {
                let level = parse_positive_usize(value.trim_start_matches("--compress-level="))?;
                let config = self.compression.get_or_insert(RemoteCompressionConfig {
                    mode: rsync_protocol::RsyncDeflatedTokenMode::Zlibx,
                    level: 6,
                    skip_suffixes: Vec::new(),
                });
                config.level = u32::try_from(level).unwrap_or(9).min(9);
            }
            value if value.starts_with("--skip-compress=") => {
                let suffixes = value
                    .trim_start_matches("--skip-compress=")
                    .split('/')
                    .filter(|suffix| !suffix.trim().is_empty())
                    .map(|suffix| suffix.trim().to_string());
                let config = self.compression.get_or_insert(RemoteCompressionConfig {
                    mode: rsync_protocol::RsyncDeflatedTokenMode::Zlibx,
                    level: 6,
                    skip_suffixes: Vec::new(),
                });
                config.skip_suffixes.extend(suffixes);
            }
            value if value.starts_with('-') => self.apply_short_flags(value)?,
            _ => {}
        }
        Ok(())
    }

    fn apply_short_flags(&mut self, arg: &str) -> Result<()> {
        if !arg.starts_with('-') || arg.starts_with("--") {
            return Ok(());
        }
        for flag in arg.trim_start_matches('-').chars() {
            match flag {
                'r' => self.recursive = true,
                'n' => self.dry_run = true,
                'W' => self.whole_file = true,
                't' => self.preserve_times = true,
                'c' => self.update_mode = UpdateMode::Checksum,
                'z' => {
                    self.ensure_compression();
                }
                '.' | 'e' | 'L' | 's' | 'f' | 'x' | 'C' | 'I' | 'v' | 'u' => {}
                _ => {}
            }
        }
        Ok(())
    }

    fn ensure_compression(&mut self) {
        self.compression.get_or_insert(RemoteCompressionConfig {
            mode: rsync_protocol::RsyncDeflatedTokenMode::Zlibx,
            level: 6,
            skip_suffixes: Vec::new(),
        });
    }

    fn protocol31_flist_options(&self) -> RsyncFileListOptions {
        let mut options = self.flist_options;
        options.include_checksums = self.update_mode == UpdateMode::Checksum;
        if options.fake_super {
            options.xattrs = true;
        }
        options
    }

    fn module_paths(&self, module: &DaemonServerModule) -> Result<Vec<PathBuf>> {
        self.paths
            .iter()
            .map(|path| module_path(module, path))
            .collect()
    }
}

fn module_path(module: &DaemonServerModule, path: &str) -> Result<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "." {
        return Ok(module.path.clone());
    }
    let relative = Path::new(trimmed);
    let mut clean = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                bail!(
                    "daemon module `{}` rejects unsafe path `{}`",
                    module.name,
                    path
                );
            }
        }
    }
    if clean.as_os_str().is_empty() {
        Ok(module.path.clone())
    } else {
        Ok(module.path.join(clean))
    }
}

fn parse_positive_usize(value: &str) -> Result<usize> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .with_context(|| format!("daemon numeric option must be greater than zero: `{value}`"))
}

fn parse_client_greeting_protocol(line: &str) -> Result<u32> {
    let version = line
        .strip_prefix("@RSYNCD: ")
        .context("invalid daemon client greeting")?
        .split_whitespace()
        .next()
        .context("daemon client greeting omitted protocol version")?;
    let protocol = version.split_once('.').map_or(version, |(major, _)| major);
    protocol
        .parse::<u32>()
        .with_context(|| format!("invalid daemon client protocol version `{version}`"))
}

fn read_daemon_line<T: Read>(stream: &mut T, max_len: usize) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                bytes.push(byte[0]);
                if bytes.len() > max_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("daemon line exceeds {max_len} bytes"),
                    ));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "daemon line is not UTF-8"))
}

fn daemon_listen_address(cli: &Cli) -> String {
    cli.daemon_address.clone().unwrap_or_else(|| {
        if cli.ipv6 {
            "::".to_string()
        } else {
            "0.0.0.0".to_string()
        }
    })
}

fn daemon_address_family(cli: &Cli) -> Option<TcpAddressFamily> {
    if cli.ipv4 {
        Some(TcpAddressFamily::Ipv4)
    } else if cli.ipv6 {
        Some(TcpAddressFamily::Ipv6)
    } else {
        None
    }
}

fn parse_daemon_bwlimit(value: &str) -> Result<BandwidthLimit> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("daemon --bwlimit must not be empty");
    }
    let (number, unit) = match trimmed.as_bytes().last().copied() {
        Some(b'B') | Some(b'b') => (&trimmed[..trimmed.len() - 1], 1_f64),
        Some(b'K') | Some(b'k') => (&trimmed[..trimmed.len() - 1], 1024_f64),
        Some(b'M') | Some(b'm') => (&trimmed[..trimmed.len() - 1], 1024_f64 * 1024_f64),
        Some(b'G') | Some(b'g') => (
            &trimmed[..trimmed.len() - 1],
            1024_f64 * 1024_f64 * 1024_f64,
        ),
        _ => (trimmed, 1024_f64),
    };
    let rate = number
        .trim()
        .parse::<f64>()
        .with_context(|| format!("daemon --bwlimit rate `{value}` is invalid"))?;
    if !rate.is_finite() || rate <= 0.0 {
        bail!("daemon --bwlimit rate `{value}` must be greater than zero");
    }
    let bytes_per_second = (rate * unit).round();
    if bytes_per_second < 1.0 || bytes_per_second > u64::MAX as f64 {
        bail!("daemon --bwlimit rate `{value}` is outside the supported range");
    }
    Ok(BandwidthLimit::new(bytes_per_second as u64))
}

fn normalize_key(key: &str) -> String {
    key.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn parse_daemon_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => Ok(true),
        "no" | "false" | "0" => Ok(false),
        _ => bail!("daemon boolean value `{value}` is invalid"),
    }
}

fn log_daemon_message(cli: &Cli, message: &str) -> Result<()> {
    log_daemon_record(
        cli,
        DaemonLogRecord {
            message: message.to_string(),
            ..DaemonLogRecord::default()
        },
    )
}

fn log_daemon_record(cli: &Cli, record: DaemonLogRecord) -> Result<()> {
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

fn render_daemon_log_format(format: &str, record: &DaemonLogRecord) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_module_config() {
        let config = parse_config(
            "[public]\npath = C:/data\ncomment = Public files\nread only = yes\nlist = true\n",
            Path::new("rsyncd.conf"),
        )
        .unwrap();

        assert_eq!(config.modules.len(), 1);
        assert_eq!(config.modules[0].name, "public");
        assert_eq!(config.modules[0].comment, "Public files");
        assert!(config.modules[0].read_only);
        assert!(config.modules[0].list);
    }

    #[test]
    fn rejects_unsupported_module_keys() {
        let err = parse_config(
            "[public]\npath = C:/data\nauth users = alice\n",
            Path::new("rsyncd.conf"),
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("unsupported daemon module config key"));
    }

    #[test]
    fn dparam_overrides_module_values() {
        let mut config = parse_config(
            "[public]\npath = C:/data\ncomment = Old\n",
            Path::new("rsyncd.conf"),
        )
        .unwrap();

        apply_dparams(&mut config, &["public.comment=New".to_string()]).unwrap();

        assert_eq!(config.modules[0].comment, "New");
    }

    #[test]
    fn daemon_log_format_expands_core_tokens() {
        let record = DaemonLogRecord {
            message: "module public transfer args: --server --sender . file.txt".to_string(),
            module: Some("public".to_string()),
            operation: Some("send".to_string()),
            path: Some("file.txt".to_string()),
            bytes: Some(12),
            client: Some("127.0.0.1:8730".to_string()),
        };

        assert_eq!(
            render_daemon_log_format("%m %o %f %l %h %M %% %q", &record),
            "public send file.txt 12 127.0.0.1:8730 module public transfer args: --server --sender . file.txt % %q"
        );
    }

    #[test]
    fn daemon_bwlimit_parses_rsync_rate_units() {
        assert_eq!(
            parse_daemon_bwlimit("128").unwrap().bytes_per_second,
            128 * 1024
        );
        assert_eq!(
            parse_daemon_bwlimit("2M").unwrap().bytes_per_second,
            2 * 1024 * 1024
        );
        assert!(parse_daemon_bwlimit("0").is_err());
        assert!(parse_daemon_bwlimit("nonsense").is_err());
    }

    #[test]
    fn daemon_bandwidth_limiter_computes_required_delay() {
        let limit = BandwidthLimit::new(1024);
        let start = std::time::Instant::now();
        let mut limiter = rsync_transport::BandwidthLimiter::new(limit, start);

        assert_eq!(
            limiter.delay_after_write(512, start),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            limiter.delay_after_write(512, start + std::time::Duration::from_millis(1000)),
            std::time::Duration::ZERO
        );
    }
}
