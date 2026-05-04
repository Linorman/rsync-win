use std::io::{self, ErrorKind, Read, Write};

use digest::Digest;
use thiserror::Error;

use crate::version::{MAX_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION};

pub const DEFAULT_DAEMON_PORT: u16 = 873;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOperand {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
    pub module: Option<String>,
    pub path: Option<String>,
}

impl DaemonOperand {
    pub fn parse(input: &str) -> Result<Option<Self>, DaemonError> {
        if let Some(rest) = input.strip_prefix("rsync://") {
            return Ok(Some(parse_rsync_url(rest)?));
        }

        let Some((authority, module_path)) = input.split_once("::") else {
            return Ok(None);
        };
        if authority.is_empty() {
            return Err(DaemonError::InvalidOperand(input.to_string()));
        }
        let (user, host, port) = parse_authority(authority)?;
        let (module, path) = parse_module_path(module_path)?;
        Ok(Some(Self {
            user,
            host,
            port,
            module,
            path,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonGreeting {
    pub peer_protocol: u32,
    pub peer_subprotocol: u32,
    pub auth_checksum: DaemonAuthChecksum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonAuthChecksum {
    Md4,
    Md5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonModule {
    pub name: String,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonModuleList {
    pub motd: Vec<String>,
    pub modules: Vec<DaemonModule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonModuleSelection {
    Ok {
        motd: Vec<String>,
    },
    AuthRequired {
        challenge: String,
        motd: Vec<String>,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DaemonError {
    #[error("invalid daemon operand: {0}")]
    InvalidOperand(String),
    #[error("invalid daemon port: {0}")]
    InvalidPort(String),
    #[error("daemon greeting is invalid: {0}")]
    InvalidGreeting(String),
    #[error("daemon protocol {0} is outside supported range")]
    UnsupportedProtocol(u32),
    #[error("daemon returned error: {0}")]
    RemoteError(String),
    #[error("daemon auth is required")]
    AuthRequired,
    #[error("daemon auth checksum negotiation did not find a supported algorithm")]
    UnsupportedAuthChecksum,
    #[error("daemon module selection ended unexpectedly")]
    UnexpectedEof,
    #[error("daemon line exceeds {0} bytes")]
    LineTooLong(usize),
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<io::Error> for DaemonError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

pub fn exchange_daemon_greeting<T: Read + Write>(
    stream: &mut T,
    local_protocol: u32,
) -> Result<DaemonGreeting, DaemonError> {
    let line = read_daemon_line(stream, 1024)?.ok_or(DaemonError::UnexpectedEof)?;
    let greeting = parse_greeting_line(&line)?;
    if !(MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION).contains(&greeting.peer_protocol) {
        return Err(DaemonError::UnsupportedProtocol(greeting.peer_protocol));
    }
    writeln!(stream, "@RSYNCD: {local_protocol}.0 md5 md4")?;
    stream.flush()?;
    Ok(greeting)
}

pub fn request_module_list<T: Read + Write>(
    stream: &mut T,
) -> Result<DaemonModuleList, DaemonError> {
    stream.write_all(b"#list\n")?;
    stream.flush()?;
    read_module_list(stream)
}

pub fn select_daemon_module<T: Read + Write>(
    stream: &mut T,
    module: &str,
) -> Result<DaemonModuleSelection, DaemonError> {
    if module.is_empty() || module.as_bytes().contains(&0) {
        return Err(DaemonError::InvalidOperand(module.to_string()));
    }
    stream.write_all(module.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut motd = Vec::new();
    while let Some(line) = read_daemon_line(stream, 8192)? {
        if line == "@RSYNCD: OK" {
            return Ok(DaemonModuleSelection::Ok { motd });
        }
        if let Some(challenge) = line.strip_prefix("@RSYNCD: AUTHREQD ") {
            return Ok(DaemonModuleSelection::AuthRequired {
                challenge: challenge.to_string(),
                motd,
            });
        }
        if let Some(message) = daemon_error_message(&line) {
            return Err(DaemonError::RemoteError(message.to_string()));
        }
        motd.push(line);
    }
    Err(DaemonError::UnexpectedEof)
}

pub fn select_no_auth_daemon_module<T: Read + Write>(
    stream: &mut T,
    module: &str,
) -> Result<Vec<String>, DaemonError> {
    match select_daemon_module(stream, module)? {
        DaemonModuleSelection::Ok { motd } => Ok(motd),
        DaemonModuleSelection::AuthRequired { .. } => Err(DaemonError::AuthRequired),
    }
}

pub fn authenticate_daemon_module<T: Read + Write>(
    stream: &mut T,
    user: &str,
    password: &str,
    challenge: &str,
    checksum: DaemonAuthChecksum,
) -> Result<Vec<String>, DaemonError> {
    if user.is_empty() || user.as_bytes().contains(&0) || password.as_bytes().contains(&0) {
        return Err(DaemonError::InvalidOperand(user.to_string()));
    }
    let response = daemon_auth_response(password, challenge, checksum);
    stream.write_all(user.as_bytes())?;
    stream.write_all(b" ")?;
    stream.write_all(response.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut motd = Vec::new();
    while let Some(line) = read_daemon_line(stream, 8192)? {
        if line == "@RSYNCD: OK" {
            return Ok(motd);
        }
        if let Some(message) = daemon_error_message(&line) {
            return Err(DaemonError::RemoteError(message.to_string()));
        }
        motd.push(line);
    }
    Err(DaemonError::UnexpectedEof)
}

pub fn write_daemon_args<T: Write>(
    stream: &mut T,
    protocol: u32,
    args: &[String],
) -> Result<(), DaemonError> {
    for arg in args {
        if arg.as_bytes().contains(&0) {
            return Err(DaemonError::InvalidOperand(arg.clone()));
        }
        stream.write_all(arg.as_bytes())?;
        if protocol >= 30 {
            stream.write_all(&[0])?;
        } else {
            stream.write_all(b"\n")?;
        }
    }
    if protocol >= 30 {
        stream.write_all(&[0])?;
    } else {
        stream.write_all(b"\n")?;
    }
    stream.flush()?;
    Ok(())
}

pub fn daemon_auth_response(
    password: &str,
    challenge: &str,
    checksum: DaemonAuthChecksum,
) -> String {
    match checksum {
        DaemonAuthChecksum::Md4 => {
            let mut hasher = md4::Md4::new();
            hasher.update(password.as_bytes());
            hasher.update(challenge.as_bytes());
            let digest = hasher.finalize();
            base64_no_pad(&digest)
        }
        DaemonAuthChecksum::Md5 => {
            let mut hasher = md5::Md5::new();
            hasher.update(password.as_bytes());
            hasher.update(challenge.as_bytes());
            let digest = hasher.finalize();
            base64_no_pad(&digest)
        }
    }
}

pub fn daemon_auth_response_matches(
    password: &str,
    challenge: &str,
    checksum: DaemonAuthChecksum,
    response: &str,
) -> bool {
    let expected = daemon_auth_response(password, challenge, checksum);
    constant_time_eq(expected.as_bytes(), response.as_bytes())
}

fn parse_rsync_url(rest: &str) -> Result<DaemonOperand, DaemonError> {
    let (authority, module_path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return Err(DaemonError::InvalidOperand(format!("rsync://{rest}")));
    }
    let (user, host, port) = parse_authority(authority)?;
    let (module, path) = parse_module_path(module_path)?;
    Ok(DaemonOperand {
        user,
        host,
        port,
        module,
        path,
    })
}

fn parse_authority(authority: &str) -> Result<(Option<String>, String, u16), DaemonError> {
    let (user, host_port) = authority
        .split_once('@')
        .map(|(user, rest)| (Some(user.to_string()), rest))
        .unwrap_or((None, authority));
    if host_port.is_empty() {
        return Err(DaemonError::InvalidOperand(authority.to_string()));
    }

    if let Some((host, port)) = host_port.rsplit_once(':') {
        if !host.is_empty() && !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
            let port = port
                .parse::<u16>()
                .map_err(|_| DaemonError::InvalidPort(port.to_string()))?;
            return Ok((user, host.to_string(), port));
        }
    }

    Ok((user, host_port.to_string(), DEFAULT_DAEMON_PORT))
}

fn parse_module_path(input: &str) -> Result<(Option<String>, Option<String>), DaemonError> {
    if input.is_empty() {
        return Ok((None, None));
    }
    let (module, path) = input.split_once('/').unwrap_or((input, ""));
    if module.is_empty() {
        return Err(DaemonError::InvalidOperand(input.to_string()));
    }
    Ok((
        Some(module.to_string()),
        (!path.is_empty()).then(|| path.to_string()),
    ))
}

fn parse_greeting_line(line: &str) -> Result<DaemonGreeting, DaemonError> {
    let version = line
        .strip_prefix("@RSYNCD: ")
        .ok_or_else(|| DaemonError::InvalidGreeting(line.to_string()))?;
    let mut fields = version.split_whitespace();
    let version = fields
        .next()
        .ok_or_else(|| DaemonError::InvalidGreeting(line.to_string()))?;
    let offered_checksums = fields.collect::<Vec<_>>();
    let (protocol, subprotocol) = version.split_once('.').unwrap_or((version, "0"));
    let peer_protocol = protocol
        .parse::<u32>()
        .map_err(|_| DaemonError::InvalidGreeting(line.to_string()))?;
    let peer_subprotocol = subprotocol
        .parse::<u32>()
        .map_err(|_| DaemonError::InvalidGreeting(line.to_string()))?;
    let auth_checksum = choose_auth_checksum(peer_protocol, &offered_checksums)?;
    Ok(DaemonGreeting {
        peer_protocol,
        peer_subprotocol,
        auth_checksum,
    })
}

fn choose_auth_checksum(
    peer_protocol: u32,
    offered: &[&str],
) -> Result<DaemonAuthChecksum, DaemonError> {
    if offered.is_empty() {
        return if peer_protocol >= 30 {
            Ok(DaemonAuthChecksum::Md5)
        } else {
            Ok(DaemonAuthChecksum::Md4)
        };
    }
    if offered.contains(&"md5") {
        return Ok(DaemonAuthChecksum::Md5);
    }
    if offered.contains(&"md4") {
        return Ok(DaemonAuthChecksum::Md4);
    }
    Err(DaemonError::UnsupportedAuthChecksum)
}

fn read_module_list<T: Read>(stream: &mut T) -> Result<DaemonModuleList, DaemonError> {
    let mut motd = Vec::new();
    let mut modules = Vec::new();
    while let Some(line) = read_daemon_line(stream, 8192)? {
        if line == "@RSYNCD: EXIT" {
            return Ok(DaemonModuleList { motd, modules });
        }
        if let Some(message) = daemon_error_message(&line) {
            return Err(DaemonError::RemoteError(message.to_string()));
        }
        if let Some(module) = parse_module_line(&line) {
            modules.push(module);
        } else {
            motd.push(line);
        }
    }
    Err(DaemonError::UnexpectedEof)
}

fn parse_module_line(line: &str) -> Option<DaemonModule> {
    let trimmed = line.trim_end();
    if trimmed.is_empty() || trimmed.starts_with('@') {
        return None;
    }
    let (name, comment) = trimmed
        .split_once('\t')
        .or_else(|| trimmed.split_once("  "))?;
    let name = name.trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    Some(DaemonModule {
        name: name.to_string(),
        comment: comment.trim().to_string(),
    })
}

fn daemon_error_message(line: &str) -> Option<&str> {
    line.strip_prefix("@ERROR: ")
        .or_else(|| line.strip_prefix("@RSYNCD: ERROR "))
}

fn read_daemon_line<T: Read>(
    stream: &mut T,
    max_len: usize,
) -> Result<Option<String>, DaemonError> {
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 1];
    loop {
        match stream.read(&mut buf) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => break,
            Ok(_) => {
                if buf[0] == b'\n' {
                    break;
                }
                bytes.push(buf[0]);
                if bytes.len() > max_len {
                    return Err(DaemonError::LineTooLong(max_len));
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(DaemonError::from(err)),
        }
    }
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| DaemonError::InvalidGreeting("non-UTF-8 daemon line".to_string()))
}

fn base64_no_pad(bytes: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let output_len = (bytes.len() * 8).div_ceil(6);
    let mut out = String::with_capacity(output_len);
    for i in 0..output_len {
        let byte_offset = (i * 6) / 8;
        let bit_offset = (i * 6) % 8;
        let index = if bit_offset < 3 {
            (bytes[byte_offset] >> (2 - bit_offset)) & 0x3f
        } else {
            let mut value = (bytes[byte_offset] << (bit_offset - 2)) & 0x3f;
            if byte_offset + 1 < bytes.len() {
                value |= bytes[byte_offset + 1] >> (8 - (bit_offset - 2));
            }
            value
        };
        out.push(B64[index as usize] as char);
    }
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (l, r)| acc | (l ^ r))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_daemon_operands_without_treating_windows_drives_as_daemon() {
        let operand = DaemonOperand::parse("host::module/path").unwrap().unwrap();
        assert_eq!(operand.host, "host");
        assert_eq!(operand.port, DEFAULT_DAEMON_PORT);
        assert_eq!(operand.module.as_deref(), Some("module"));
        assert_eq!(operand.path.as_deref(), Some("path"));

        let url = DaemonOperand::parse("rsync://user@example.test:8873/mod/dir/file")
            .unwrap()
            .unwrap();
        assert_eq!(url.user.as_deref(), Some("user"));
        assert_eq!(url.host, "example.test");
        assert_eq!(url.port, 8873);
        assert_eq!(url.module.as_deref(), Some("mod"));
        assert_eq!(url.path.as_deref(), Some("dir/file"));

        assert!(DaemonOperand::parse(r"C:\data").unwrap().is_none());
    }

    #[test]
    fn exchanges_greeting_and_lists_modules() {
        let input = b"@RSYNCD: 31.0\nwelcome\npublic\tPublic files\n@RSYNCD: EXIT\n".to_vec();
        let mut stream = CursorStream::new(input);

        let greeting = exchange_daemon_greeting(&mut stream, 31).unwrap();
        let listing = request_module_list(&mut stream).unwrap();

        assert_eq!(greeting.peer_protocol, 31);
        assert_eq!(greeting.auth_checksum, DaemonAuthChecksum::Md5);
        assert_eq!(listing.motd, vec!["welcome".to_string()]);
        assert_eq!(
            listing.modules,
            vec![DaemonModule {
                name: "public".to_string(),
                comment: "Public files".to_string()
            }]
        );
        assert_eq!(stream.written, b"@RSYNCD: 31.0 md5 md4\n#list\n");
    }

    #[test]
    fn parses_no_auth_and_auth_required_module_selection() {
        let mut ok = CursorStream::new(b"@RSYNCD: OK\n".to_vec());
        assert_eq!(
            select_daemon_module(&mut ok, "pub").unwrap(),
            DaemonModuleSelection::Ok { motd: Vec::new() }
        );
        assert_eq!(ok.written, b"pub\n");

        let mut auth = CursorStream::new(b"@RSYNCD: AUTHREQD abc123\n".to_vec());
        assert_eq!(
            select_daemon_module(&mut auth, "priv").unwrap(),
            DaemonModuleSelection::AuthRequired {
                challenge: "abc123".to_string(),
                motd: Vec::new()
            }
        );
    }

    #[test]
    fn builds_daemon_auth_response_without_padding() {
        let response = daemon_auth_response("secret", "challenge", DaemonAuthChecksum::Md5);

        assert_eq!(response.len(), 22);
        assert!(!response.contains('='));
    }

    #[test]
    fn verifies_daemon_auth_response() {
        let response = daemon_auth_response("secret", "challenge", DaemonAuthChecksum::Md5);

        assert!(daemon_auth_response_matches(
            "secret",
            "challenge",
            DaemonAuthChecksum::Md5,
            &response
        ));
        assert!(!daemon_auth_response_matches(
            "wrong",
            "challenge",
            DaemonAuthChecksum::Md5,
            &response
        ));
    }

    #[test]
    fn writes_daemon_args_with_protocol_specific_terminator() {
        let args = vec![
            "--server".to_string(),
            "--sender".to_string(),
            ".".to_string(),
            "module/path".to_string(),
        ];
        let mut modern = Vec::new();
        write_daemon_args(&mut modern, 31, &args).unwrap();
        assert_eq!(modern, b"--server\0--sender\0.\0module/path\0\0");

        let mut compat = Vec::new();
        write_daemon_args(&mut compat, 29, &args).unwrap();
        assert_eq!(compat, b"--server\n--sender\n.\nmodule/path\n\n");
    }

    #[derive(Debug)]
    struct CursorStream {
        input: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl CursorStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: std::io::Cursor::new(input),
                written: Vec::new(),
            }
        }
    }

    impl Read for CursorStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for CursorStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
