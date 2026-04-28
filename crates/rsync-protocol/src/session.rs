use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

use thiserror::Error;

use crate::flist::{read_rsync_long, write_rsync_long, FileListError};
use crate::io::{
    read_i32_le, read_varint, read_vstring, write_i32_le, write_u32_le, write_vstring,
};
use crate::version::{
    negotiate_protocol_version_with_local, ProtocolVersion, VersionError, MAX_PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
};

pub const REMOTE_SHELL_MVP_PROTOCOL: u32 = 27;
pub const REMOTE_SHELL_MODERN_PROTOCOL: u32 = 31;
const RSYNC_MULTIPLEX_DATA_TAG: u32 = 7;
const RSYNC_MULTIPLEX_ERROR_CODE: u32 = 1;
const RSYNC_PROTOCOL31_CHECKSUM_LIST: &str = "md4";
const RSYNC_CF_VARINT_FLIST_FLAGS: u32 = 1 << 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Push,
    Pull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteShellOptions {
    pub direction: TransferDirection,
    pub recursive: bool,
    pub preserve_times: bool,
    pub delete: bool,
    pub dry_run: bool,
    pub whole_file: bool,
    pub verbosity: u8,
    pub preserve_permissions: bool,
    pub checksum: bool,
    pub size_only: bool,
    pub ignore_times: bool,
    pub partial: bool,
    pub partial_dir: Option<String>,
    pub inplace: bool,
    pub append_verify: bool,
    pub executability: bool,
    pub numeric_ids: bool,
    pub chmod: Option<String>,
    pub omit_link_times: bool,
    pub copy_links: bool,
    pub safe_links: bool,
    pub copy_unsafe_links: bool,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub filters: Vec<String>,
}

impl Default for RemoteShellOptions {
    fn default() -> Self {
        Self {
            direction: TransferDirection::Push,
            recursive: false,
            preserve_times: false,
            delete: false,
            dry_run: true,
            whole_file: true,
            verbosity: 0,
            preserve_permissions: false,
            checksum: false,
            size_only: false,
            ignore_times: false,
            partial: false,
            partial_dir: None,
            inplace: false,
            append_verify: false,
            executability: false,
            numeric_ids: false,
            chmod: None,
            omit_link_times: false,
            copy_links: false,
            safe_links: false,
            copy_unsafe_links: false,
            includes: Vec::new(),
            excludes: Vec::new(),
            filters: Vec::new(),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("remote path contains a NUL byte")]
    NulByteInPath,
    #[error("operand uses rsync daemon syntax, which belongs to daemon client mode: {0}")]
    DaemonOperand(String),
    #[error("remote-shell operand is missing a host: {0}")]
    MissingRemoteHost(String),
    #[error("remote-shell operand is missing a path: {0}")]
    MissingRemotePath(String),
    #[error("remote shell emitted non-protocol output before version exchange: {0}")]
    NonProtocolOutput(String),
    #[error("protocol stream prefix is incomplete")]
    IncompleteProtocolPrefix,
    #[error("protocol version {0} is outside expected range")]
    InvalidProtocolPrefix(u32),
    #[error("remote shell emitted an rsync error message: {0}")]
    RemoteErrorMessage(String),
    #[error("remote shell emitted an unsupported multiplex message tag {tag} with {len} bytes")]
    UnsupportedMultiplexMessage { tag: u32, len: usize },
}

#[derive(Debug, Error)]
pub enum RemoteSessionError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Version(#[from] VersionError),
    #[error(transparent)]
    FileList(#[from] FileListError),
    #[error(
        "remote-shell MVP supports protocol {supported}, but negotiated protocol {negotiated}"
    )]
    UnsupportedProtocol { negotiated: u32, supported: u32 },
    #[error("remote requested invalid file index {index}; file list has {file_count} entries")]
    InvalidFileIndex { index: i32, file_count: usize },
    #[error("remote requested blocks for non-file entry at index {index}")]
    NonFileBlockRequest { index: usize },
    #[error("remote file checksum mismatch for {path}")]
    FileChecksumMismatch { path: String },
    #[error("remote sent {actual} bytes for {path}, exceeding advertised length {expected}")]
    FileLengthExceeded {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("remote ended {path} after {actual} bytes, below advertised length {expected}")]
    FileLengthShort {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("remote sent invalid phase acknowledgement {0}")]
    InvalidPhaseAck(i32),
    #[error("remote sent invalid final acknowledgement {0}")]
    InvalidFinalAck(i32),
    #[error("remote sent unexpected non-data token {token} while transferring {path}")]
    UnexpectedToken { token: i32, path: String },
    #[error("protocol 31 checksum negotiation did not find a supported algorithm")]
    UnsupportedChecksumNegotiation,
    #[error("remote sent invalid checksum list text")]
    InvalidChecksumList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteShellHandshake {
    pub peer_protocol: u32,
    pub selected_protocol: ProtocolVersion,
    pub checksum_seed: i32,
    pub compat_flags: Option<u32>,
    pub checksum_name: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MultiplexReadState {
    remaining: usize,
    messages: Vec<String>,
}

impl MultiplexReadState {
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

pub struct MultiplexedReader<'a, R> {
    inner: &'a mut R,
    state: &'a mut MultiplexReadState,
}

pub struct MultiplexedWriter<'a, W> {
    inner: &'a mut W,
    frame_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteShellOperand {
    pub host: String,
    pub path: String,
}

impl RemoteShellOperand {
    pub fn parse(operand: &str) -> Result<Option<Self>, SessionError> {
        if operand.starts_with("rsync://") || operand.contains("::") {
            return Err(SessionError::DaemonOperand(operand.to_owned()));
        }

        let Some(index) = operand.find(':') else {
            return Ok(None);
        };

        let host = &operand[..index];
        if host.len() == 1 && host.chars().all(|ch| ch.is_ascii_alphabetic()) {
            return Ok(None);
        }
        if host.contains('/') || host.contains('\\') {
            return Ok(None);
        }
        if host.is_empty() {
            return Err(SessionError::MissingRemoteHost(operand.to_owned()));
        }

        let path = &operand[index + 1..];
        if path.is_empty() {
            return Err(SessionError::MissingRemotePath(operand.to_owned()));
        }

        Ok(Some(Self {
            host: host.to_owned(),
            path: path.to_owned(),
        }))
    }
}

pub fn build_remote_shell_argv(
    options: &RemoteShellOptions,
    path: &Path,
) -> Result<Vec<String>, SessionError> {
    build_remote_shell_argv_for_paths(options, &[path])
}

pub fn build_remote_shell_argv_for_paths(
    options: &RemoteShellOptions,
    paths: &[&Path],
) -> Result<Vec<String>, SessionError> {
    let mut argv = vec!["rsync".to_string(), "--server".to_string()];
    if matches!(options.direction, TransferDirection::Pull) {
        argv.push("--sender".to_string());
    }
    if options.recursive {
        argv.push("--recursive".to_string());
    }
    if options.preserve_times {
        argv.push("--times".to_string());
    }
    if options.delete {
        argv.push("--delete-before".to_string());
    }
    if matches!(options.direction, TransferDirection::Pull) && options.recursive {
        argv.push("--no-inc-recursive".to_string());
    }
    if options.dry_run {
        argv.push("--dry-run".to_string());
    }
    if options.whole_file {
        argv.push("--whole-file".to_string());
    }
    append_remote_shell_long_options(&mut argv, options);
    for _ in 0..options.verbosity {
        argv.push("-v".to_string());
    }
    argv.push(".".to_string());
    append_remote_paths(&mut argv, paths)?;

    Ok(argv)
}

pub fn build_remote_shell_protocol31_argv(
    options: &RemoteShellOptions,
    path: &Path,
) -> Result<Vec<String>, SessionError> {
    build_remote_shell_protocol31_argv_for_paths(options, &[path])
}

pub fn build_remote_shell_protocol31_argv_for_paths(
    options: &RemoteShellOptions,
    paths: &[&Path],
) -> Result<Vec<String>, SessionError> {
    let mut argv = vec!["rsync".to_string(), "--server".to_string()];
    if matches!(options.direction, TransferDirection::Pull) {
        argv.push("--sender".to_string());
    }
    if options.delete {
        argv.push("--delete-before".to_string());
    }
    if matches!(options.direction, TransferDirection::Pull) && options.recursive {
        argv.push("--no-inc-recursive".to_string());
    }
    append_remote_shell_long_options(&mut argv, options);

    let mut short_args = String::from("-");
    for _ in 0..options.verbosity {
        short_args.push('v');
    }
    if options.dry_run {
        short_args.push('n');
    }
    if options.whole_file {
        short_args.push('W');
    }
    if options.preserve_times {
        short_args.push('t');
    }
    if options.recursive {
        short_args.push('r');
    }
    short_args.push_str("e.LsfxCIvu");

    argv.push(short_args);
    argv.push(".".to_string());
    append_remote_paths(&mut argv, paths)?;

    Ok(argv)
}

fn append_remote_paths(argv: &mut Vec<String>, paths: &[&Path]) -> Result<(), SessionError> {
    if paths.is_empty() {
        return Err(SessionError::MissingRemotePath(String::new()));
    }

    for path in paths {
        let path = path.to_string_lossy();
        if path.as_bytes().contains(&0) {
            return Err(SessionError::NulByteInPath);
        }
        argv.push(path.into_owned());
    }
    Ok(())
}

fn append_remote_shell_long_options(argv: &mut Vec<String>, options: &RemoteShellOptions) {
    if options.checksum {
        argv.push("--checksum".to_string());
    }
    if options.preserve_permissions {
        argv.push("--perms".to_string());
    }
    if options.executability {
        argv.push("--executability".to_string());
    }
    if options.size_only {
        argv.push("--size-only".to_string());
    }
    if options.ignore_times {
        argv.push("--ignore-times".to_string());
    }
    if options.partial {
        argv.push("--partial".to_string());
    }
    if let Some(partial_dir) = &options.partial_dir {
        argv.push(format!("--partial-dir={partial_dir}"));
    }
    if options.inplace {
        argv.push("--inplace".to_string());
    }
    if options.append_verify {
        argv.push("--append-verify".to_string());
    }
    if options.numeric_ids {
        argv.push("--numeric-ids".to_string());
    }
    if let Some(chmod) = &options.chmod {
        argv.push(format!("--chmod={chmod}"));
    }
    if options.omit_link_times {
        argv.push("--omit-link-times".to_string());
    }
    if options.copy_links {
        argv.push("--copy-links".to_string());
    }
    if options.safe_links {
        argv.push("--safe-links".to_string());
    }
    if options.copy_unsafe_links {
        argv.push("--copy-unsafe-links".to_string());
    }
    for pattern in &options.includes {
        argv.push(format!("--include={pattern}"));
    }
    for pattern in &options.excludes {
        argv.push(format!("--exclude={pattern}"));
    }
    for filter in &options.filters {
        argv.push(format!("--filter={filter}"));
    }
}

pub fn exchange_remote_shell_handshake<T: Read + Write>(
    transport: &mut T,
    local_protocol: u32,
) -> Result<RemoteShellHandshake, RemoteSessionError> {
    write_u32_le(transport, local_protocol)?;
    transport.flush()?;

    let mut prefix = [0_u8; 4];
    transport.read_exact(&mut prefix)?;
    let peer_protocol = validate_protocol_stream_prefix(&prefix)?;
    let selected_protocol = negotiate_protocol_version_with_local(peer_protocol, local_protocol)?;
    let checksum_seed = read_i32_le(transport)?;

    Ok(RemoteShellHandshake {
        peer_protocol,
        selected_protocol,
        checksum_seed,
        compat_flags: None,
        checksum_name: None,
    })
}

pub fn exchange_remote_shell_mvp_handshake<T: Read + Write>(
    transport: &mut T,
) -> Result<RemoteShellHandshake, RemoteSessionError> {
    let handshake = exchange_remote_shell_handshake(transport, REMOTE_SHELL_MVP_PROTOCOL)?;
    if handshake.selected_protocol.value() != REMOTE_SHELL_MVP_PROTOCOL {
        return Err(RemoteSessionError::UnsupportedProtocol {
            negotiated: handshake.selected_protocol.value(),
            supported: REMOTE_SHELL_MVP_PROTOCOL,
        });
    }
    Ok(handshake)
}

pub fn exchange_remote_shell_protocol31_handshake<T: Read + Write>(
    transport: &mut T,
) -> Result<RemoteShellHandshake, RemoteSessionError> {
    write_u32_le(transport, REMOTE_SHELL_MODERN_PROTOCOL)?;
    transport.flush()?;

    let mut prefix = [0_u8; 4];
    transport.read_exact(&mut prefix)?;
    let peer_protocol = validate_protocol_stream_prefix(&prefix)?;
    let selected_protocol =
        negotiate_protocol_version_with_local(peer_protocol, REMOTE_SHELL_MODERN_PROTOCOL)?;
    if selected_protocol.value() != REMOTE_SHELL_MODERN_PROTOCOL {
        return Err(RemoteSessionError::UnsupportedProtocol {
            negotiated: selected_protocol.value(),
            supported: REMOTE_SHELL_MODERN_PROTOCOL,
        });
    }

    let compat_flags = read_varint(transport)?;
    let checksum_name = if compat_flags & RSYNC_CF_VARINT_FLIST_FLAGS != 0 {
        let checksum_list = read_vstring(transport, 1024)?;
        let checksum_list = String::from_utf8(checksum_list)
            .map_err(|_| RemoteSessionError::InvalidChecksumList)?;
        let checksum_name =
            select_protocol31_checksum(RSYNC_PROTOCOL31_CHECKSUM_LIST, &checksum_list)
                .ok_or(RemoteSessionError::UnsupportedChecksumNegotiation)?;
        write_vstring(transport, checksum_name.as_bytes())?;
        transport.flush()?;
        Some(checksum_name)
    } else {
        None
    };
    let checksum_seed = read_i32_le(transport)?;

    Ok(RemoteShellHandshake {
        peer_protocol,
        selected_protocol,
        checksum_seed,
        compat_flags: Some(compat_flags),
        checksum_name,
    })
}

fn select_protocol31_checksum(client_list: &str, server_list: &str) -> Option<String> {
    let server_names = server_list.split_whitespace().collect::<Vec<_>>();
    client_list
        .split_whitespace()
        .find(|name| server_names.contains(name))
        .map(str::to_owned)
}

impl<'a, R: Read> MultiplexedReader<'a, R> {
    pub fn new(inner: &'a mut R, state: &'a mut MultiplexReadState) -> Self {
        Self { inner, state }
    }
}

impl<R: Read> Read for MultiplexedReader<'_, R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let original_len = buf.len();
        while !buf.is_empty() {
            if self.state.remaining == 0 {
                read_next_multiplex_frame(self.inner, self.state)?;
                if self.state.remaining == 0 {
                    continue;
                }
            }

            let read_len = self.state.remaining.min(buf.len());
            self.inner.read_exact(&mut buf[..read_len])?;
            self.state.remaining -= read_len;
            let (_, rest) = buf.split_at_mut(read_len);
            buf = rest;
        }

        Ok(original_len)
    }
}

impl<'a, W: Write> MultiplexedWriter<'a, W> {
    pub fn new(inner: &'a mut W, frame_size: usize) -> Self {
        Self { inner, frame_size }
    }
}

impl<W: Write> Write for MultiplexedWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.frame_size == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "rsync multiplex frame size must be greater than zero",
            ));
        }

        for chunk in buf.chunks(self.frame_size) {
            write_multiplex_data_frame(self.inner, chunk)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub fn write_multiplex_data_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > 0x00ff_ffff {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "rsync multiplex payload exceeds 24-bit frame length",
        ));
    }

    let header = (RSYNC_MULTIPLEX_DATA_TAG << 24) | payload.len() as u32;
    write_u32_le(writer, header)?;
    writer.write_all(payload)
}

pub fn read_multiplexed_i32<R: Read>(
    reader: &mut R,
    state: &mut MultiplexReadState,
) -> Result<i32, RemoteSessionError> {
    let mut multiplexed = MultiplexedReader::new(reader, state);
    Ok(read_i32_le(&mut multiplexed)?)
}

pub fn read_multiplexed_long<R: Read>(
    reader: &mut R,
    state: &mut MultiplexReadState,
) -> Result<u64, RemoteSessionError> {
    let mut multiplexed = MultiplexedReader::new(reader, state);
    Ok(read_rsync_long(&mut multiplexed)?)
}

pub fn write_rsync_i32<W: Write>(writer: &mut W, value: i32) -> Result<(), RemoteSessionError> {
    write_i32_le(writer, value)?;
    Ok(())
}

pub fn write_rsync_long_value<W: Write>(
    writer: &mut W,
    value: u64,
) -> Result<(), RemoteSessionError> {
    write_rsync_long(writer, value)?;
    Ok(())
}

pub fn rsync_whole_file_checksum(seed: i32, bytes: &[u8]) -> [u8; 16] {
    let mut checksum = RsyncMd4Checksum::seeded(seed);
    checksum.update(bytes);
    checksum.finalize()
}

pub fn rsync_whole_file_checksum_reader<R: Read>(
    seed: i32,
    reader: &mut R,
) -> io::Result<[u8; 16]> {
    let mut checksum = RsyncMd4Checksum::seeded(seed);
    update_md4_from_reader(&mut checksum, reader)?;
    Ok(checksum.finalize())
}

pub fn rsync_plain_md4_checksum(bytes: &[u8]) -> [u8; 16] {
    let mut checksum = RsyncMd4Checksum::plain();
    checksum.update(bytes);
    checksum.finalize()
}

pub fn rsync_plain_md4_checksum_reader<R: Read>(reader: &mut R) -> io::Result<[u8; 16]> {
    let mut checksum = RsyncMd4Checksum::plain();
    update_md4_from_reader(&mut checksum, reader)?;
    Ok(checksum.finalize())
}

pub struct RsyncMd4Checksum {
    hasher: md4::Md4,
}

impl RsyncMd4Checksum {
    pub fn plain() -> Self {
        use digest::Digest;

        Self {
            hasher: md4::Md4::new(),
        }
    }

    pub fn seeded(seed: i32) -> Self {
        let mut checksum = Self::plain();
        checksum.update(&seed.to_le_bytes());
        checksum
    }

    pub fn update(&mut self, bytes: &[u8]) {
        use digest::Digest;

        self.hasher.update(bytes);
    }

    pub fn finalize(self) -> [u8; 16] {
        use digest::Digest;

        let digest = self.hasher.finalize();
        let mut out = [0_u8; 16];
        out.copy_from_slice(&digest);
        out
    }
}

fn update_md4_from_reader<R: Read>(
    checksum: &mut RsyncMd4Checksum,
    reader: &mut R,
) -> io::Result<()> {
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            return Ok(());
        }
        checksum.update(&buf[..read]);
    }
}

fn read_next_multiplex_frame<R: Read>(
    reader: &mut R,
    state: &mut MultiplexReadState,
) -> io::Result<()> {
    loop {
        let mut header = [0_u8; 4];
        reader.read_exact(&mut header)?;
        let raw = u32::from_le_bytes(header);
        let tag = raw >> 24;
        let len = (raw & 0x00ff_ffff) as usize;
        if tag == RSYNC_MULTIPLEX_DATA_TAG {
            state.remaining = len;
            return Ok(());
        }

        let mut payload = vec![0_u8; len];
        if len > 0 {
            reader.read_exact(&mut payload)?;
        }
        let message = String::from_utf8_lossy(&payload)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        let code = tag.saturating_sub(RSYNC_MULTIPLEX_DATA_TAG);
        if code == RSYNC_MULTIPLEX_ERROR_CODE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                SessionError::RemoteErrorMessage(message),
            ));
        }
        if tag < RSYNC_MULTIPLEX_DATA_TAG {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                SessionError::UnsupportedMultiplexMessage { tag, len },
            ));
        }
        if !message.is_empty() {
            state.messages.push(message);
        }
    }
}

pub fn build_ssh_remote_command(
    host: &str,
    server_argv: &[String],
) -> Result<Vec<String>, SessionError> {
    if host.as_bytes().contains(&0) {
        return Err(SessionError::NulByteInPath);
    }

    let argv = vec![host.to_owned(), shell_join(server_argv)?];
    Ok(argv)
}

fn shell_join(argv: &[String]) -> Result<String, SessionError> {
    let mut command = String::new();
    for (index, arg) in argv.iter().enumerate() {
        if arg.as_bytes().contains(&0) {
            return Err(SessionError::NulByteInPath);
        }
        if index > 0 {
            command.push(' ');
        }
        command.push_str(&shell_quote(arg));
    }
    Ok(command)
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '.' | '='))
    {
        return value.to_owned();
    }

    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

pub fn validate_protocol_stream_prefix(bytes: &[u8]) -> Result<u32, SessionError> {
    if bytes.len() < 4 {
        return Err(SessionError::IncompleteProtocolPrefix);
    }

    if bytes[0].is_ascii_graphic() && bytes.iter().take(64).any(|byte| *byte == b'\n') {
        let text = String::from_utf8_lossy(bytes)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        return Err(SessionError::NonProtocolOutput(text));
    }

    if bytes.iter().all(u8::is_ascii) && bytes.iter().any(|byte| byte.is_ascii_alphabetic()) {
        let text = String::from_utf8_lossy(bytes).to_string();
        return Err(SessionError::NonProtocolOutput(text));
    }

    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if !(MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION).contains(&version) {
        return Err(SessionError::InvalidProtocolPrefix(version));
    }

    Ok(version)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn builds_push_server_argv_for_supported_subset() {
        let argv = build_remote_shell_argv(
            &RemoteShellOptions {
                recursive: true,
                preserve_times: true,
                delete: true,
                dry_run: true,
                whole_file: true,
                verbosity: 2,
                ..RemoteShellOptions::default()
            },
            Path::new("dest"),
        )
        .unwrap();

        assert_eq!(
            argv,
            vec![
                "rsync",
                "--server",
                "--recursive",
                "--times",
                "--delete-before",
                "--dry-run",
                "--whole-file",
                "-v",
                "-v",
                ".",
                "dest",
            ]
        );
    }

    #[test]
    fn builds_pull_server_argv_with_sender_marker() {
        let argv = build_remote_shell_argv(
            &RemoteShellOptions {
                direction: TransferDirection::Pull,
                ..RemoteShellOptions::default()
            },
            Path::new("source"),
        )
        .unwrap();

        assert!(argv.contains(&"--sender".to_string()));
    }

    #[test]
    fn builds_protocol31_push_server_argv_with_client_info() {
        let argv = build_remote_shell_protocol31_argv(
            &RemoteShellOptions {
                recursive: true,
                preserve_times: true,
                delete: true,
                dry_run: true,
                whole_file: true,
                verbosity: 1,
                ..RemoteShellOptions::default()
            },
            Path::new("dest"),
        )
        .unwrap();

        assert_eq!(
            argv,
            vec![
                "rsync",
                "--server",
                "--delete-before",
                "-vnWtre.LsfxCIvu",
                ".",
                "dest",
            ]
        );
    }

    #[test]
    fn builds_push_server_argv_with_receiver_filter_args() {
        let options = RemoteShellOptions {
            recursive: true,
            delete: true,
            includes: vec!["src/**".to_string()],
            excludes: vec!["*.tmp".to_string()],
            filters: vec!["protect *.bak".to_string()],
            ..RemoteShellOptions::default()
        };

        let protocol27 = build_remote_shell_argv(&options, Path::new("dest")).unwrap();
        let protocol31 = build_remote_shell_protocol31_argv(&options, Path::new("dest")).unwrap();

        for argv in [protocol27, protocol31] {
            assert!(argv.contains(&"--delete-before".to_string()));
            assert!(argv.contains(&"--include=src/**".to_string()));
            assert!(argv.contains(&"--exclude=*.tmp".to_string()));
            assert!(argv.contains(&"--filter=protect *.bak".to_string()));
        }
    }

    #[test]
    fn builds_protocol31_pull_server_argv_with_sender_marker() {
        let argv = build_remote_shell_protocol31_argv(
            &RemoteShellOptions {
                direction: TransferDirection::Pull,
                recursive: true,
                dry_run: false,
                whole_file: true,
                ..RemoteShellOptions::default()
            },
            Path::new("source"),
        )
        .unwrap();

        assert_eq!(argv[2], "--sender");
        assert_eq!(argv[3], "--no-inc-recursive");
        assert_eq!(argv[4], "-Wre.LsfxCIvu");
    }

    #[test]
    fn builds_protocol31_pull_server_argv_with_multiple_remote_paths() {
        let argv = build_remote_shell_protocol31_argv_for_paths(
            &RemoteShellOptions {
                direction: TransferDirection::Pull,
                recursive: true,
                ..RemoteShellOptions::default()
            },
            &[Path::new("/tmp/one"), Path::new("/tmp/two")],
        )
        .unwrap();

        assert_eq!(argv[2], "--sender");
        assert_eq!(
            &argv[argv.len() - 3..],
            &[
                ".".to_string(),
                "/tmp/one".to_string(),
                "/tmp/two".to_string()
            ]
        );
        assert!(argv.contains(&"--no-inc-recursive".to_string()));
    }

    #[test]
    fn parses_remote_shell_operands_without_treating_windows_drives_as_remote() {
        assert_eq!(
            RemoteShellOperand::parse("user@example:/tmp/dest").unwrap(),
            Some(RemoteShellOperand {
                host: "user@example".to_string(),
                path: "/tmp/dest".to_string(),
            })
        );
        assert_eq!(RemoteShellOperand::parse(r"C:\tmp\file").unwrap(), None);
        assert!(matches!(
            RemoteShellOperand::parse("host::module"),
            Err(SessionError::DaemonOperand(_))
        ));
    }

    #[test]
    fn builds_shell_quoted_ssh_remote_command() {
        let args = build_ssh_remote_command(
            "host",
            &[
                "rsync".to_string(),
                "--server".to_string(),
                ".".to_string(),
                "path with 'quote'".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(args[0], "host");
        assert_eq!(args[1], "rsync --server . 'path with '\\''quote'\\'''");
    }

    #[test]
    fn detects_remote_shell_noise_before_protocol_bytes() {
        let err = validate_protocol_stream_prefix(b"banner text\n\x20\x00\x00\x00").unwrap_err();
        assert!(matches!(err, SessionError::NonProtocolOutput(_)));
    }

    #[test]
    fn accepts_protocol_version_prefix() {
        assert_eq!(
            validate_protocol_stream_prefix(&32_u32.to_le_bytes()).unwrap(),
            32
        );
    }

    #[test]
    fn exchanges_mvp_handshake_with_seed() {
        let mut input = Vec::new();
        input.extend_from_slice(&32_u32.to_le_bytes());
        input.extend_from_slice(&123_i32.to_le_bytes());
        let mut transport = TestTransport::with_input(input);

        let handshake = exchange_remote_shell_mvp_handshake(&mut transport).unwrap();

        assert_eq!(handshake.peer_protocol, 32);
        assert_eq!(handshake.selected_protocol.value(), 27);
        assert_eq!(handshake.checksum_seed, 123);
        assert_eq!(handshake.compat_flags, None);
        assert_eq!(handshake.checksum_name, None);
        assert_eq!(transport.written, 27_u32.to_le_bytes());
    }

    #[test]
    fn exchanges_protocol31_checksum_negotiated_handshake() {
        let mut input = Vec::new();
        input.extend_from_slice(&31_u32.to_le_bytes());
        input.extend_from_slice(&[0x81, 0xff]);
        input.push(35);
        input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
        input.extend_from_slice(&123_i32.to_le_bytes());
        let mut transport = TestTransport::with_input(input);

        let handshake = exchange_remote_shell_protocol31_handshake(&mut transport).unwrap();

        assert_eq!(handshake.peer_protocol, 31);
        assert_eq!(handshake.selected_protocol.value(), 31);
        assert_eq!(handshake.compat_flags, Some(0x1ff));
        assert_eq!(handshake.checksum_name.as_deref(), Some("md4"));
        assert_eq!(handshake.checksum_seed, 123);
        let mut expected = Vec::new();
        expected.extend_from_slice(&31_u32.to_le_bytes());
        expected.push(3);
        expected.extend_from_slice(b"md4");
        assert_eq!(transport.written, expected);
    }

    #[test]
    fn exchanges_protocol31_without_checksum_negotiation_when_not_advertised() {
        let mut input = Vec::new();
        input.extend_from_slice(&31_u32.to_le_bytes());
        input.push(0x06);
        input.extend_from_slice(&123_i32.to_le_bytes());
        let mut transport = TestTransport::with_input(input);

        let handshake = exchange_remote_shell_protocol31_handshake(&mut transport).unwrap();

        assert_eq!(handshake.peer_protocol, 31);
        assert_eq!(handshake.selected_protocol.value(), 31);
        assert_eq!(handshake.compat_flags, Some(0x06));
        assert_eq!(handshake.checksum_name, None);
        assert_eq!(handshake.checksum_seed, 123);
        assert_eq!(transport.written, 31_u32.to_le_bytes());
    }

    #[test]
    fn reads_multiplexed_data_and_messages() {
        let mut bytes = Vec::new();
        write_multiplex_frame(&mut bytes, 9, b"note\n");
        write_multiplex_frame(&mut bytes, 7, &123_i32.to_le_bytes());
        let mut state = MultiplexReadState::default();

        let value = read_multiplexed_i32(&mut bytes.as_slice(), &mut state).unwrap();

        assert_eq!(value, 123);
        assert_eq!(state.messages(), &["note".to_string()]);
    }

    #[test]
    fn writes_multiplexed_data_frames() {
        let mut bytes = Vec::new();
        {
            let mut writer = MultiplexedWriter::new(&mut bytes, 3);
            writer.write_all(b"abcdefg").unwrap();
            writer.flush().unwrap();
        }

        let mut expected = Vec::new();
        write_multiplex_frame(&mut expected, 7, b"abc");
        write_multiplex_frame(&mut expected, 7, b"def");
        write_multiplex_frame(&mut expected, 7, b"g");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn rejects_zero_sized_multiplex_writer_frames() {
        let mut bytes = Vec::new();
        let err = MultiplexedWriter::new(&mut bytes, 0)
            .write(b"x")
            .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn whole_file_checksum_uses_seed_prefix() {
        let checksum = rsync_whole_file_checksum(5, b"abc");
        let checksum_again = rsync_whole_file_checksum(5, b"abc");

        assert_eq!(checksum, checksum_again);
        assert_ne!(checksum, rsync_whole_file_checksum(6, b"abc"));
    }

    #[test]
    fn plain_md4_checksum_does_not_include_seed() {
        assert_eq!(
            rsync_plain_md4_checksum(b"abc"),
            rsync_plain_md4_checksum(b"abc")
        );
        assert_ne!(
            rsync_plain_md4_checksum(b"abc"),
            rsync_whole_file_checksum(0, b"abc")
        );
    }

    fn write_multiplex_frame(out: &mut Vec<u8>, tag: u32, payload: &[u8]) {
        let header = (tag << 24) | payload.len() as u32;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(payload);
    }

    #[derive(Debug)]
    struct TestTransport {
        input: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl TestTransport {
        fn with_input(input: Vec<u8>) -> Self {
            Self {
                input: std::io::Cursor::new(input),
                written: Vec::new(),
            }
        }
    }

    impl Read for TestTransport {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for TestTransport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
