use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protocol31SetupOptions {
    pub checksum_choices: Vec<String>,
    pub checksum_seed: Option<i32>,
}

impl Default for Protocol31SetupOptions {
    fn default() -> Self {
        Self {
            checksum_choices: vec!["md4".to_string()],
            checksum_seed: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompressionConfig {
    pub enabled: bool,
    pub choices: Vec<String>,
    pub level: Option<u32>,
    pub threads: Option<usize>,
    pub skip_suffixes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Zlib,
    Zlibx,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedCompression {
    pub algorithm: CompressionAlgorithm,
    pub level: u32,
    pub threads: Option<usize>,
    pub skip_suffixes: Vec<String>,
}

impl CompressionConfig {
    pub fn negotiate(
        &self,
        peer_choices: &[&str],
    ) -> Result<Option<NegotiatedCompression>, RemoteSessionError> {
        if !self.enabled {
            return Ok(None);
        }

        let local_choices = if self.choices.is_empty() {
            vec!["zlib".to_string()]
        } else {
            normalized_name_list(&self.choices.join(","))
        };
        let peer_choices: Vec<_> = peer_choices
            .iter()
            .map(|choice| normalize_name(choice))
            .collect();

        let selected = local_choices
            .iter()
            .find(|choice| {
                matches!(choice.as_str(), "zlib" | "zlibx")
                    && peer_choices.iter().any(|peer| peer == *choice)
            })
            .ok_or(RemoteSessionError::UnsupportedCompressionNegotiation)?;

        Ok(Some(NegotiatedCompression {
            algorithm: match selected.as_str() {
                "zlibx" => CompressionAlgorithm::Zlibx,
                _ => CompressionAlgorithm::Zlib,
            },
            level: self.level.unwrap_or(6).min(9),
            threads: self.threads,
            skip_suffixes: self.skip_suffixes.clone(),
        }))
    }
}

impl NegotiatedCompression {
    pub fn compress(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        match self.algorithm {
            CompressionAlgorithm::Zlib | CompressionAlgorithm::Zlibx => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(self.level));
                encoder.write_all(bytes)?;
                encoder.finish()
            }
        }
    }

    pub fn decompress(&self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        match self.algorithm {
            CompressionAlgorithm::Zlib | CompressionAlgorithm::Zlibx => {
                let mut decoder = ZlibDecoder::new(bytes);
                let mut output = Vec::new();
                decoder.read_to_end(&mut output)?;
                Ok(output)
            }
        }
    }

    pub fn should_skip_path(&self, path: &Path) -> bool {
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

const RSYNC_DEFLATED_END_FLAG: u8 = 0;
const RSYNC_DEFLATED_TOKEN_LONG: u8 = 0x20;
const RSYNC_DEFLATED_TOKENRUN_LONG: u8 = 0x21;
const RSYNC_DEFLATED_DATA: u8 = 0x40;
const RSYNC_DEFLATED_TOKEN_REL: u8 = 0x80;
const RSYNC_DEFLATED_TOKENRUN_REL: u8 = 0xc0;
const RSYNC_DEFLATED_MAX_DATA_COUNT: usize = 16_383;
const RSYNC_DEFLATED_CHUNK_SIZE: usize = 32 * 1024;
const RSYNC_ZLIB_SYNC_TAIL: [u8; 4] = [0, 0, 0xff, 0xff];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsyncDeflatedTokenMode {
    Zlib,
    Zlibx,
}

impl RsyncDeflatedTokenMode {
    pub fn from_choice(choice: Option<&str>) -> Result<Self, RemoteSessionError> {
        match choice.map(normalize_name).as_deref() {
            None | Some("zlibx") => Ok(Self::Zlibx),
            Some("zlib") => Ok(Self::Zlib),
            _ => Err(RemoteSessionError::UnsupportedCompressionNegotiation),
        }
    }

    pub fn remote_choice(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Zlibx => "zlibx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsyncDeflatedToken {
    Literal(Vec<u8>),
    Copy { block_index: usize },
    End,
}

pub struct RsyncDeflatedTokenWriter {
    compressor: Compress,
    last_token: i32,
    run_start: i32,
    last_run_end: i32,
    flush_pending: bool,
}

impl RsyncDeflatedTokenWriter {
    pub fn new(level: u32) -> Self {
        Self {
            compressor: Compress::new(Compression::new(level.min(9)), false),
            last_token: -1,
            run_start: 0,
            last_run_end: 0,
            flush_pending: false,
        }
    }

    pub fn send_literal<W: Write>(&mut self, writer: &mut W, literal: &[u8]) -> io::Result<()> {
        for chunk in literal.chunks(RSYNC_DEFLATED_CHUNK_SIZE) {
            self.send_token(writer, -2, chunk)?;
        }
        Ok(())
    }

    pub fn send_copy<W: Write>(&mut self, writer: &mut W, block_index: usize) -> io::Result<()> {
        let token = i32::try_from(block_index).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "rsync compressed copy token exceeded i32 range",
            )
        })?;
        self.send_token(writer, token, &[])
    }

    pub fn finish<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        self.send_token(writer, -1, &[])
    }

    fn send_token<W: Write>(&mut self, writer: &mut W, token: i32, data: &[u8]) -> io::Result<()> {
        if self.last_token == -1 {
            self.compressor.reset();
            self.last_run_end = 0;
            self.run_start = token;
            self.flush_pending = false;
        } else if self.last_token == -2 {
            self.run_start = token;
        } else if !data.is_empty()
            || self.last_token.checked_add(1) != Some(token)
            || self
                .run_start
                .checked_add(65_536)
                .map_or(true, |limit| token >= limit)
        {
            self.write_pending_run(writer)?;
            self.last_run_end = self.last_token;
            self.run_start = token;
        }

        self.last_token = token;

        if !data.is_empty() {
            self.write_deflated(writer, data, FlushCompress::None)?;
            self.flush_pending = true;
        } else if self.flush_pending && token != -2 {
            self.write_deflated(writer, &[], FlushCompress::Sync)?;
            self.flush_pending = false;
        }

        if token == -1 {
            writer.write_all(&[RSYNC_DEFLATED_END_FLAG])?;
        }
        Ok(())
    }

    fn write_pending_run<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let relative = self
            .run_start
            .checked_sub(self.last_run_end)
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "rsync compressed token run underflowed",
                )
            })?;
        let run_len = self.last_token.checked_sub(self.run_start).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                "rsync compressed token run length underflowed",
            )
        })?;
        if run_len > u16::MAX as i32 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "rsync compressed token run exceeded u16 range",
            ));
        }

        if (0..=63).contains(&relative) {
            let base = if run_len == 0 {
                RSYNC_DEFLATED_TOKEN_REL
            } else {
                RSYNC_DEFLATED_TOKENRUN_REL
            };
            writer.write_all(&[base + relative as u8])?;
        } else {
            writer.write_all(&[if run_len == 0 {
                RSYNC_DEFLATED_TOKEN_LONG
            } else {
                RSYNC_DEFLATED_TOKENRUN_LONG
            }])?;
            write_i32_le(writer, self.run_start)?;
        }

        if run_len != 0 {
            writer.write_all(&[(run_len & 0xff) as u8, ((run_len >> 8) & 0xff) as u8])?;
        }
        Ok(())
    }

    fn write_deflated<W: Write>(
        &mut self,
        writer: &mut W,
        input: &[u8],
        flush: FlushCompress,
    ) -> io::Result<()> {
        let mut output = Vec::with_capacity(input.len() * 1001 / 1000 + 64);
        let mut offset = 0_usize;
        let mut out = [0_u8; RSYNC_DEFLATED_MAX_DATA_COUNT];
        loop {
            let before_in = self.compressor.total_in();
            let before_out = self.compressor.total_out();
            let status = self
                .compressor
                .compress(&input[offset..], &mut out, flush)
                .map_err(io::Error::from)?;
            let consumed = (self.compressor.total_in() - before_in) as usize;
            let produced = (self.compressor.total_out() - before_out) as usize;
            offset += consumed;
            output.extend_from_slice(&out[..produced]);

            if flush == FlushCompress::Sync && output.ends_with(&RSYNC_ZLIB_SYNC_TAIL) {
                break;
            }
            if flush != FlushCompress::Sync
                && offset == input.len()
                && (produced < out.len() || status == Status::BufError)
            {
                break;
            }
            if consumed == 0 && produced == 0 {
                break;
            }
        }
        if flush == FlushCompress::Sync {
            if output.ends_with(&RSYNC_ZLIB_SYNC_TAIL) {
                output.truncate(output.len() - RSYNC_ZLIB_SYNC_TAIL.len());
            } else {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "rsync compressed sync flush omitted zlib tail",
                ));
            }
        }
        write_deflated_data_chunks(writer, &output)
    }
}

fn write_deflated_data_chunks<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(RSYNC_DEFLATED_MAX_DATA_COUNT) {
        let len = chunk.len();
        writer.write_all(&[RSYNC_DEFLATED_DATA + ((len >> 8) as u8), len as u8])?;
        writer.write_all(chunk)?;
    }
    Ok(())
}

pub struct RsyncDeflatedTokenReader {
    mode: RsyncDeflatedTokenMode,
    decompressor: Decompress,
    rx_token: i32,
    rx_run: u16,
    needs_sync_tail: bool,
    saved_flag: Option<u8>,
    pending: VecDeque<RsyncDeflatedToken>,
}

impl RsyncDeflatedTokenReader {
    pub fn new(mode: RsyncDeflatedTokenMode) -> Self {
        Self {
            mode,
            decompressor: Decompress::new(false),
            rx_token: 0,
            rx_run: 0,
            needs_sync_tail: false,
            saved_flag: None,
            pending: VecDeque::new(),
        }
    }

    pub fn next_token<R: Read>(&mut self, reader: &mut R) -> io::Result<RsyncDeflatedToken> {
        loop {
            if let Some(token) = self.pending.pop_front() {
                return Ok(token);
            }
            if self.rx_run > 0 {
                self.rx_token = self.rx_token.checked_add(1).ok_or_else(|| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "rsync compressed token run overflowed",
                    )
                })?;
                self.rx_run -= 1;
                return self.copy_token(self.rx_token);
            }

            let flag = match self.saved_flag.take() {
                Some(flag) => flag,
                None => read_byte(reader)?,
            };
            if (flag & 0xc0) == RSYNC_DEFLATED_DATA {
                let len = (((flag & 0x3f) as usize) << 8) + read_byte(reader)? as usize;
                let mut compressed = vec![0_u8; len];
                reader.read_exact(&mut compressed)?;
                let literal = self.inflate_bytes(&compressed, FlushDecompress::None)?;
                self.needs_sync_tail = true;
                if !literal.is_empty() {
                    return Ok(RsyncDeflatedToken::Literal(literal));
                }
                continue;
            }

            if self.needs_sync_tail {
                let literal = self.inflate_bytes(&RSYNC_ZLIB_SYNC_TAIL, FlushDecompress::Sync)?;
                self.needs_sync_tail = false;
                if !literal.is_empty() {
                    self.saved_flag = Some(flag);
                    return Ok(RsyncDeflatedToken::Literal(literal));
                }
            }

            if flag == RSYNC_DEFLATED_END_FLAG {
                self.reset_file();
                return Ok(RsyncDeflatedToken::End);
            }

            let token_flag = if flag & RSYNC_DEFLATED_TOKEN_REL != 0 {
                self.rx_token =
                    self.rx_token
                        .checked_add((flag & 0x3f) as i32)
                        .ok_or_else(|| {
                            io::Error::new(
                                ErrorKind::InvalidData,
                                "rsync compressed relative token overflowed",
                            )
                        })?;
                flag >> 6
            } else {
                self.rx_token = read_i32_le(reader)?;
                if self.rx_token < 0 {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "rsync compressed stream contained a negative token number",
                    ));
                }
                flag
            };
            if token_flag & 1 != 0 {
                let lo = read_byte(reader)? as u16;
                let hi = read_byte(reader)? as u16;
                self.rx_run = lo | (hi << 8);
            }
            return self.copy_token(self.rx_token);
        }
    }

    pub fn observe_copy_data(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.mode != RsyncDeflatedTokenMode::Zlib || bytes.is_empty() {
            return Ok(());
        }
        for chunk in bytes.chunks(u16::MAX as usize) {
            let len = chunk.len() as u16;
            let mut stored = Vec::with_capacity(5 + chunk.len());
            stored.push(0);
            stored.push((len & 0xff) as u8);
            stored.push((len >> 8) as u8);
            stored.push(!(len as u8));
            stored.push(!((len >> 8) as u8));
            stored.extend_from_slice(chunk);
            let _ = self.inflate_bytes(&stored, FlushDecompress::Sync)?;
        }
        Ok(())
    }

    fn copy_token(&self, rx_token: i32) -> io::Result<RsyncDeflatedToken> {
        let block_index = usize::try_from(rx_token).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "rsync compressed copy token did not fit usize",
            )
        })?;
        Ok(RsyncDeflatedToken::Copy { block_index })
    }

    fn reset_file(&mut self) {
        self.decompressor.reset(false);
        self.rx_token = 0;
        self.rx_run = 0;
        self.needs_sync_tail = false;
        self.saved_flag = None;
        self.pending.clear();
    }

    fn inflate_bytes(&mut self, input: &[u8], flush: FlushDecompress) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(RSYNC_DEFLATED_CHUNK_SIZE + 64);
        let mut offset = 0_usize;
        loop {
            output.reserve(RSYNC_DEFLATED_CHUNK_SIZE + 64);
            let before_in = self.decompressor.total_in();
            let before_out = self.decompressor.total_out();
            let status = self
                .decompressor
                .decompress_vec(&input[offset..], &mut output, flush)
                .map_err(io::Error::from)?;
            let consumed = (self.decompressor.total_in() - before_in) as usize;
            let produced = (self.decompressor.total_out() - before_out) as usize;
            offset += consumed;
            if offset == input.len() && status != Status::Ok {
                break;
            }
            if offset == input.len() && produced == 0 {
                break;
            }
            if consumed == 0 && produced == 0 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "rsync compressed stream made no inflate progress",
                ));
            }
        }
        Ok(output)
    }
}

fn read_byte<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut byte = [0_u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Push,
    Pull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDeleteMode {
    None,
    Before,
    During,
    Delay,
    After,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteShellOptions {
    pub rsync_path: String,
    pub direction: TransferDirection,
    pub secluded_args: bool,
    pub recursive: bool,
    pub preserve_times: bool,
    pub delete_mode: RemoteDeleteMode,
    pub dry_run: bool,
    pub whole_file: bool,
    pub verbosity: u8,
    pub preserve_permissions: bool,
    pub checksum: bool,
    pub checksum_choice: Option<String>,
    pub checksum_seed: Option<i32>,
    pub size_only: bool,
    pub ignore_times: bool,
    pub partial: bool,
    pub partial_dir: Option<String>,
    pub inplace: bool,
    pub append_verify: bool,
    pub executability: bool,
    pub preserve_owner: bool,
    pub preserve_group: bool,
    pub numeric_ids: bool,
    pub user_maps: Vec<String>,
    pub group_maps: Vec<String>,
    pub chown: Option<String>,
    pub chmod: Option<String>,
    pub acls: bool,
    pub xattrs: bool,
    pub fake_super: bool,
    pub atimes: bool,
    pub crtimes: bool,
    pub omit_dir_times: bool,
    pub omit_link_times: bool,
    pub preserve_links: bool,
    pub copy_links: bool,
    pub copy_dirlinks: bool,
    pub keep_dirlinks: bool,
    pub safe_links: bool,
    pub copy_unsafe_links: bool,
    pub munge_links: bool,
    pub hard_links: bool,
    pub preserve_devices: bool,
    pub preserve_specials: bool,
    pub copy_devices: bool,
    pub write_devices: bool,
    pub block_size: Option<u64>,
    pub compress: bool,
    pub compress_choice: Option<String>,
    pub compress_level: Option<u32>,
    pub compress_threads: Option<usize>,
    pub skip_compress: Vec<String>,
    pub outbuf: Option<String>,
    pub remote_options: Vec<String>,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub filters: Vec<String>,
}

impl Default for RemoteShellOptions {
    fn default() -> Self {
        Self {
            rsync_path: "rsync".to_string(),
            direction: TransferDirection::Push,
            secluded_args: false,
            recursive: false,
            preserve_times: false,
            delete_mode: RemoteDeleteMode::None,
            dry_run: true,
            whole_file: true,
            verbosity: 0,
            preserve_permissions: false,
            checksum: false,
            checksum_choice: None,
            checksum_seed: None,
            size_only: false,
            ignore_times: false,
            partial: false,
            partial_dir: None,
            inplace: false,
            append_verify: false,
            executability: false,
            preserve_owner: false,
            preserve_group: false,
            numeric_ids: false,
            user_maps: Vec::new(),
            group_maps: Vec::new(),
            chown: None,
            chmod: None,
            acls: false,
            xattrs: false,
            fake_super: false,
            atimes: false,
            crtimes: false,
            omit_dir_times: false,
            omit_link_times: false,
            preserve_links: false,
            copy_links: false,
            copy_dirlinks: false,
            keep_dirlinks: false,
            safe_links: false,
            copy_unsafe_links: false,
            munge_links: false,
            hard_links: false,
            preserve_devices: false,
            preserve_specials: false,
            copy_devices: false,
            write_devices: false,
            block_size: None,
            compress: false,
            compress_choice: None,
            compress_level: None,
            compress_threads: None,
            skip_compress: Vec::new(),
            outbuf: None,
            remote_options: Vec::new(),
            includes: Vec::new(),
            excludes: Vec::new(),
            filters: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteShellInvocation {
    pub argv: Vec<String>,
    pub protected_args: Vec<String>,
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
    #[error("protocol 31 compression negotiation did not find a supported algorithm")]
    UnsupportedCompressionNegotiation,
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
    Ok(build_remote_shell_invocation_for_paths(options, paths)?.argv)
}

pub fn build_remote_shell_invocation_for_paths(
    options: &RemoteShellOptions,
    paths: &[&Path],
) -> Result<RemoteShellInvocation, SessionError> {
    let mut argv = vec![options.rsync_path.clone(), "--server".to_string()];
    if matches!(options.direction, TransferDirection::Pull) {
        argv.push("--sender".to_string());
    }
    if options.recursive {
        argv.push("--recursive".to_string());
    }
    if options.preserve_times {
        argv.push("--times".to_string());
    }
    append_remote_delete_option(&mut argv, options.delete_mode);
    if options.recursive {
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

    Ok(remote_shell_invocation_for_argv(options, argv))
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
    Ok(build_remote_shell_protocol31_invocation_for_paths(options, paths)?.argv)
}

pub fn build_remote_shell_protocol31_invocation_for_paths(
    options: &RemoteShellOptions,
    paths: &[&Path],
) -> Result<RemoteShellInvocation, SessionError> {
    let mut argv = vec![options.rsync_path.clone(), "--server".to_string()];
    if matches!(options.direction, TransferDirection::Pull) {
        argv.push("--sender".to_string());
    }
    append_remote_delete_option(&mut argv, options.delete_mode);
    if options.recursive {
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

    Ok(remote_shell_invocation_for_argv(options, argv))
}

fn remote_shell_invocation_for_argv(
    options: &RemoteShellOptions,
    argv: Vec<String>,
) -> RemoteShellInvocation {
    if !options.secluded_args {
        return RemoteShellInvocation {
            argv,
            protected_args: Vec::new(),
        };
    }

    let mut public_argv = vec![options.rsync_path.clone(), "--server".to_string()];
    if matches!(options.direction, TransferDirection::Pull) {
        public_argv.push("--sender".to_string());
    }
    public_argv.push("-s".to_string());

    let mut protected_args = vec!["rsync".to_string()];
    let mut skip = 2;
    if matches!(options.direction, TransferDirection::Pull) {
        skip += 1;
    }
    protected_args.extend(argv.into_iter().skip(skip));

    RemoteShellInvocation {
        argv: public_argv,
        protected_args,
    }
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

fn append_remote_delete_option(argv: &mut Vec<String>, mode: RemoteDeleteMode) {
    match mode {
        RemoteDeleteMode::None => {}
        RemoteDeleteMode::Before => argv.push("--delete-before".to_string()),
        RemoteDeleteMode::During => argv.push("--delete-during".to_string()),
        RemoteDeleteMode::Delay => argv.push("--delete-delay".to_string()),
        RemoteDeleteMode::After => argv.push("--delete-after".to_string()),
    }
}

fn append_remote_shell_long_options(argv: &mut Vec<String>, options: &RemoteShellOptions) {
    argv.extend(options.remote_options.iter().cloned());
    if options.checksum {
        argv.push("--checksum".to_string());
    }
    if let Some(choice) = &options.checksum_choice {
        argv.push(format!("--checksum-choice={choice}"));
    }
    if let Some(seed) = options.checksum_seed {
        argv.push(format!("--checksum-seed={seed}"));
    }
    if options.preserve_permissions {
        argv.push("--perms".to_string());
    }
    if options.executability {
        argv.push("--executability".to_string());
    }
    if options.preserve_owner {
        argv.push("--owner".to_string());
    }
    if options.preserve_group {
        argv.push("--group".to_string());
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
    for map in &options.user_maps {
        argv.push(format!("--usermap={map}"));
    }
    for map in &options.group_maps {
        argv.push(format!("--groupmap={map}"));
    }
    if let Some(chown) = &options.chown {
        argv.push(format!("--chown={chown}"));
    }
    if let Some(chmod) = &options.chmod {
        argv.push(format!("--chmod={chmod}"));
    }
    if options.acls {
        argv.push("--acls".to_string());
    }
    if options.xattrs {
        argv.push("--xattrs".to_string());
    }
    if options.fake_super {
        argv.push("--fake-super".to_string());
    }
    if options.atimes {
        argv.push("--atimes".to_string());
    }
    if options.crtimes {
        argv.push("--crtimes".to_string());
    }
    if options.omit_dir_times {
        argv.push("--omit-dir-times".to_string());
    }
    if options.omit_link_times {
        argv.push("--omit-link-times".to_string());
    }
    if options.preserve_links {
        argv.push("--links".to_string());
    }
    if options.copy_links {
        argv.push("--copy-links".to_string());
    }
    if options.copy_dirlinks {
        argv.push("--copy-dirlinks".to_string());
    }
    if options.keep_dirlinks {
        argv.push("--keep-dirlinks".to_string());
    }
    if options.safe_links {
        argv.push("--safe-links".to_string());
    }
    if options.copy_unsafe_links {
        argv.push("--copy-unsafe-links".to_string());
    }
    if options.munge_links {
        argv.push("--munge-links".to_string());
    }
    if options.hard_links {
        argv.push("--hard-links".to_string());
    }
    if options.preserve_devices {
        argv.push("--devices".to_string());
    }
    if options.preserve_specials {
        argv.push("--specials".to_string());
    }
    if options.copy_devices {
        argv.push("--copy-devices".to_string());
    }
    if options.write_devices {
        argv.push("--write-devices".to_string());
    }
    if let Some(block_size) = options.block_size {
        argv.push(format!("--block-size={block_size}"));
    }
    if options.compress {
        argv.push("--compress".to_string());
    }
    if let Some(choice) = &options.compress_choice {
        argv.push(format!("--compress-choice={choice}"));
    }
    if let Some(level) = options.compress_level {
        argv.push(format!("--compress-level={level}"));
    }
    if let Some(threads) = options.compress_threads {
        argv.push(format!("--compress-threads={threads}"));
    }
    for skip in &options.skip_compress {
        argv.push(format!("--skip-compress={skip}"));
    }
    if let Some(outbuf) = &options.outbuf {
        argv.push(format!("--outbuf={outbuf}"));
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

pub fn write_remote_shell_protected_args<W: Write>(
    writer: &mut W,
    args: &[String],
) -> io::Result<()> {
    if args.is_empty() {
        return Ok(());
    }

    for arg in args {
        if arg.is_empty() {
            writer.write_all(b".\0")?;
        } else {
            writer.write_all(arg.as_bytes())?;
            writer.write_all(&[0])?;
        }
    }
    writer.write_all(&[0])
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
    exchange_remote_shell_protocol31_handshake_with_options(
        transport,
        Protocol31SetupOptions::default(),
    )
}

pub fn exchange_remote_shell_protocol31_handshake_with_options<T: Read + Write>(
    transport: &mut T,
    options: Protocol31SetupOptions,
) -> Result<RemoteShellHandshake, RemoteSessionError> {
    write_u32_le(transport, REMOTE_SHELL_MODERN_PROTOCOL)?;
    transport.flush()?;

    let mut prefix = [0_u8; 4];
    transport.read_exact(&mut prefix)?;
    let peer_protocol = validate_protocol_stream_prefix(&prefix)?;
    exchange_protocol31_setup_with_options(transport, peer_protocol, options)
}

pub fn exchange_protocol31_setup<T: Read + Write>(
    transport: &mut T,
    peer_protocol: u32,
) -> Result<RemoteShellHandshake, RemoteSessionError> {
    exchange_protocol31_setup_with_options(
        transport,
        peer_protocol,
        Protocol31SetupOptions::default(),
    )
}

pub fn exchange_protocol31_setup_with_options<T: Read + Write>(
    transport: &mut T,
    peer_protocol: u32,
    options: Protocol31SetupOptions,
) -> Result<RemoteShellHandshake, RemoteSessionError> {
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
        let client_list = if options.checksum_choices.is_empty() {
            RSYNC_PROTOCOL31_CHECKSUM_LIST.to_string()
        } else {
            normalized_name_list(&options.checksum_choices.join(",")).join(" ")
        };
        let checksum_name = select_protocol31_checksum(&client_list, &checksum_list)
            .ok_or(RemoteSessionError::UnsupportedChecksumNegotiation)?;
        write_vstring(transport, checksum_name.as_bytes())?;
        transport.flush()?;
        Some(checksum_name)
    } else {
        None
    };
    let remote_checksum_seed = read_i32_le(transport)?;
    let checksum_seed = options.checksum_seed.unwrap_or(remote_checksum_seed);

    Ok(RemoteShellHandshake {
        peer_protocol,
        selected_protocol,
        checksum_seed,
        compat_flags: Some(compat_flags),
        checksum_name,
    })
}

fn select_protocol31_checksum(client_list: &str, server_list: &str) -> Option<String> {
    let server_names = normalized_name_list(server_list);
    normalized_name_list(client_list)
        .into_iter()
        .find(|name| server_names.contains(name))
}

fn normalized_name_list(list: &str) -> Vec<String> {
    list.split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .map(normalize_name)
        .filter(|name| !name.is_empty() && name != "auto")
        .collect()
}

fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
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
    seed: Option<i32>,
}

impl RsyncMd4Checksum {
    pub fn plain() -> Self {
        use digest::Digest;

        Self {
            hasher: md4::Md4::new(),
            seed: None,
        }
    }

    pub fn seeded(seed: i32) -> Self {
        let mut checksum = Self::plain();
        checksum.seed = (seed != 0).then_some(seed);
        checksum
    }

    pub fn seeded_prefix(seed: i32) -> Self {
        let mut checksum = Self::plain();
        if seed != 0 {
            checksum.update(&seed.to_le_bytes());
        }
        checksum
    }

    pub fn update(&mut self, bytes: &[u8]) {
        use digest::Digest;

        self.hasher.update(bytes);
    }

    pub fn finalize(mut self) -> [u8; 16] {
        use digest::Digest;

        if let Some(seed) = self.seed {
            self.hasher.update(seed.to_le_bytes());
        }
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
                delete_mode: RemoteDeleteMode::Before,
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
                "--no-inc-recursive",
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
                delete_mode: RemoteDeleteMode::Before,
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
                "--no-inc-recursive",
                "-vnWtre.LsfxCIvu",
                ".",
                "dest",
            ]
        );
    }

    #[test]
    fn builds_server_argv_with_custom_rsync_path_and_remote_options() {
        let options = RemoteShellOptions {
            rsync_path: "sudo rsync".to_string(),
            remote_options: vec![
                "--fake-super".to_string(),
                "--log-file=/tmp/remote rsync.log".to_string(),
            ],
            ..RemoteShellOptions::default()
        };

        for argv in [
            build_remote_shell_argv(&options, Path::new("dest path")).unwrap(),
            build_remote_shell_protocol31_argv(&options, Path::new("dest path")).unwrap(),
        ] {
            assert_eq!(argv[0], "sudo rsync");
            assert!(argv.contains(&"--fake-super".to_string()));
            assert!(argv.contains(&"--log-file=/tmp/remote rsync.log".to_string()));
            assert_eq!(argv.last().map(String::as_str), Some("dest path"));
        }
    }

    #[test]
    fn builds_secluded_protocol31_invocation_with_protected_args() {
        let invocation = build_remote_shell_protocol31_invocation_for_paths(
            &RemoteShellOptions {
                direction: TransferDirection::Pull,
                secluded_args: true,
                recursive: true,
                dry_run: false,
                whole_file: true,
                remote_options: vec!["--fake-super".to_string()],
                ..RemoteShellOptions::default()
            },
            &[Path::new("path with spaces;name")],
        )
        .unwrap();

        assert_eq!(invocation.argv, vec!["rsync", "--server", "--sender", "-s"]);
        assert_eq!(
            invocation.protected_args,
            vec![
                "rsync",
                "--no-inc-recursive",
                "--fake-super",
                "-Wre.LsfxCIvu",
                ".",
                "path with spaces;name",
            ]
        );
    }

    #[test]
    fn writes_remote_shell_protected_args_as_nul_records() {
        let mut bytes = Vec::new();

        write_remote_shell_protected_args(
            &mut bytes,
            &["rsync".to_string(), String::new(), "path".to_string()],
        )
        .unwrap();

        assert_eq!(bytes, b"rsync\0.\0path\0\0");
    }

    #[test]
    fn builds_push_server_argv_with_receiver_filter_args() {
        let options = RemoteShellOptions {
            recursive: true,
            delete_mode: RemoteDeleteMode::Before,
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
    fn builds_server_argv_with_link_and_special_file_options() {
        let options = RemoteShellOptions {
            recursive: true,
            preserve_links: true,
            copy_dirlinks: true,
            keep_dirlinks: true,
            munge_links: true,
            hard_links: true,
            preserve_devices: true,
            preserve_specials: true,
            copy_devices: true,
            write_devices: true,
            ..RemoteShellOptions::default()
        };

        let argv = build_remote_shell_protocol31_argv(&options, Path::new("dest")).unwrap();

        for expected in [
            "--links",
            "--copy-dirlinks",
            "--keep-dirlinks",
            "--munge-links",
            "--hard-links",
            "--devices",
            "--specials",
            "--copy-devices",
            "--write-devices",
        ] {
            assert!(argv.contains(&expected.to_string()), "{expected}");
        }
    }

    #[test]
    fn builds_server_argv_with_posix_metadata_options() {
        let options = RemoteShellOptions {
            recursive: true,
            preserve_owner: true,
            preserve_group: true,
            acls: true,
            xattrs: true,
            fake_super: true,
            atimes: true,
            crtimes: true,
            omit_dir_times: true,
            numeric_ids: true,
            user_maps: vec!["0:root".to_string(), "*:nobody".to_string()],
            group_maps: vec!["0:root".to_string()],
            chown: Some("deploy:staff".to_string()),
            ..RemoteShellOptions::default()
        };

        let argv = build_remote_shell_protocol31_argv(&options, Path::new("dest")).unwrap();

        for expected in [
            "--owner",
            "--group",
            "--acls",
            "--xattrs",
            "--fake-super",
            "--atimes",
            "--crtimes",
            "--omit-dir-times",
            "--numeric-ids",
            "--usermap=0:root",
            "--usermap=*:nobody",
            "--groupmap=0:root",
            "--chown=deploy:staff",
        ] {
            assert!(argv.contains(&expected.to_string()), "{argv:?}");
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
    fn protocol31_checksum_options_select_requested_algorithm_and_seed() {
        let mut input = Vec::new();
        input.extend_from_slice(&[0x81, 0xff]);
        input.push(35);
        input.extend_from_slice(b"xxh128 xxh3 xxh64 md5 md4 sha1 none");
        input.extend_from_slice(&123_i32.to_le_bytes());
        let mut transport = TestTransport::with_input(input);

        let handshake = exchange_protocol31_setup_with_options(
            &mut transport,
            31,
            Protocol31SetupOptions {
                checksum_choices: vec!["md5".to_string(), "md4".to_string()],
                checksum_seed: Some(77),
            },
        )
        .unwrap();

        assert_eq!(handshake.checksum_name.as_deref(), Some("md5"));
        assert_eq!(handshake.checksum_seed, 77);
        assert_eq!(transport.written, [3, b'm', b'd', b'5']);
    }

    #[test]
    fn protocol31_checksum_options_reject_unsupported_requested_list() {
        let mut input = Vec::new();
        input.extend_from_slice(&[0x81, 0xff]);
        input.push(7);
        input.extend_from_slice(b"md5 md4");
        input.extend_from_slice(&123_i32.to_le_bytes());
        let mut transport = TestTransport::with_input(input);

        let err = exchange_protocol31_setup_with_options(
            &mut transport,
            31,
            Protocol31SetupOptions {
                checksum_choices: vec!["sha1".to_string()],
                ..Protocol31SetupOptions::default()
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            RemoteSessionError::UnsupportedChecksumNegotiation
        ));
    }

    #[test]
    fn compression_codec_roundtrips_skips_and_rejects_corruption() {
        let compression = CompressionConfig {
            enabled: true,
            choices: vec!["zlibx".to_string(), "zlib".to_string()],
            level: Some(6),
            threads: Some(2),
            skip_suffixes: vec!["jpg".to_string(), "zip".to_string()],
        }
        .negotiate(&["zstd", "zlibx", "zlib"])
        .unwrap()
        .unwrap();
        let input = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        assert_eq!(compression.algorithm, CompressionAlgorithm::Zlibx);
        let compressed = compression.compress(input).unwrap();

        assert!(compressed.len() < input.len(), "{compressed:?}");
        assert_eq!(compression.decompress(&compressed).unwrap(), input);
        assert!(compression.should_skip_path(Path::new("photo.JPG")));
        assert!(!compression.should_skip_path(Path::new("notes.txt")));
        assert!(compression.decompress(b"not a zlib stream").is_err());
    }

    #[test]
    fn deflated_token_codec_roundtrips_literals_copy_tokens_and_end() {
        let mut stream = Vec::new();
        let mut writer = RsyncDeflatedTokenWriter::new(6);

        writer
            .send_literal(&mut stream, b"hello hello hello")
            .unwrap();
        writer.send_copy(&mut stream, 0).unwrap();
        writer.finish(&mut stream).unwrap();

        let mut reader = RsyncDeflatedTokenReader::new(RsyncDeflatedTokenMode::Zlibx);
        let mut cursor = stream.as_slice();
        assert_eq!(
            reader.next_token(&mut cursor).unwrap(),
            RsyncDeflatedToken::Literal(b"hello hello hello".to_vec())
        );
        assert_eq!(
            reader.next_token(&mut cursor).unwrap(),
            RsyncDeflatedToken::Copy { block_index: 0 }
        );
        assert_eq!(
            reader.next_token(&mut cursor).unwrap(),
            RsyncDeflatedToken::End
        );
        assert!(cursor.is_empty());
    }

    #[test]
    fn deflated_token_reader_rejects_corrupt_streams() {
        let mut stream = vec![0x40, 0x01, 0x06];
        stream.push(0);
        let mut reader = RsyncDeflatedTokenReader::new(RsyncDeflatedTokenMode::Zlibx);

        assert!(reader.next_token(&mut stream.as_slice()).is_err());
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
    fn whole_file_checksum_appends_seed_like_rsync_md4() {
        use digest::Digest;

        let checksum = rsync_whole_file_checksum(5, b"abc");
        let checksum_again = rsync_whole_file_checksum(5, b"abc");
        let mut expected = md4::Md4::new();
        expected.update(b"abc");
        expected.update(5_i32.to_le_bytes());
        let expected: [u8; 16] = expected.finalize().into();

        assert_eq!(checksum, expected);
        assert_eq!(checksum, checksum_again);
        assert_ne!(checksum, rsync_whole_file_checksum(6, b"abc"));
    }

    #[test]
    fn plain_md4_checksum_does_not_include_seed() {
        assert_eq!(
            rsync_plain_md4_checksum(b"abc"),
            rsync_plain_md4_checksum(b"abc")
        );
        assert_eq!(
            rsync_plain_md4_checksum(b"abc"),
            rsync_whole_file_checksum(0, b"abc")
        );
        assert_ne!(
            rsync_plain_md4_checksum(b"abc"),
            rsync_whole_file_checksum(5, b"abc")
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
