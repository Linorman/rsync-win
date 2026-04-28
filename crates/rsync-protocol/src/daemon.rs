use std::fmt;
use std::io::{self, Read, Write};

use digest::Digest;
use thiserror::Error;

use crate::io::{read_i32_le, read_varint, read_vstring, write_vstring};
use crate::version::{negotiate_protocol_version_with_local, ProtocolVersion, VersionError};

pub const RSYNC_DAEMON_PORT: u16 = 873;
pub const DAEMON_CLIENT_PROTOCOL: u32 = 31;
const DAEMON_LINE_LIMIT: usize = 32 * 1024;
const CLIENT_AUTH_DIGESTS: &[&str] = &["md4"];
const DAEMON_TRANSFER_CHECKSUMS: &str = "md4";
const RSYNC_CF_VARINT_FLIST_FLAGS: u32 = 1 << 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonEndpoint {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
    pub module: Option<String>,
    pub path: String,
}

impl DaemonEndpoint {
    pub fn parse(operand: &str) -> Result<Option<Self>, DaemonError> {
        if let Some(rest) = operand.strip_prefix("rsync://") {
            return Ok(Some(parse_rsync_url(rest, operand)?));
        }

        let Some((authority, module_path)) = operand.split_once("::") else {
            return Ok(None);
        };
        if authority.is_empty() {
            return Err(DaemonError::InvalidEndpoint(
                "daemon operand is missing a host".to_string(),
            ));
        }

        let (user, host) = split_user_host(authority)?;
        let (module, path) = split_module_path(module_path)?;
        Ok(Some(Self {
            user,
            host,
            port: RSYNC_DAEMON_PORT,
            module,
            path,
        }))
    }

    pub fn module_name(&self) -> Result<&str, DaemonError> {
        self.module.as_deref().ok_or(DaemonError::MissingModule)
    }

    pub fn transfer_path(&self) -> &str {
        if self.path.is_empty() {
            "."
        } else {
            &self.path
        }
    }

    pub fn same_daemon_module(&self, other: &Self) -> bool {
        self.user == other.user
            && self.host == other.host
            && self.port == other.port
            && self.module == other.module
    }

    pub fn display_module(&self) -> String {
        match &self.module {
            Some(module) if self.path.is_empty() => {
                format!("{}::{module}", self.display_authority())
            }
            Some(module) => format!(
                "{}::{module}/{}",
                self.display_authority(),
                self.path.replace('\\', "/")
            ),
            None => format!("{}::", self.display_authority()),
        }
    }

    pub fn display_authority(&self) -> String {
        let host = if self.port == RSYNC_DAEMON_PORT {
            self.host.clone()
        } else if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        }
    }

    pub fn socket_addr(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonGreeting {
    pub peer_protocol: u32,
    pub peer_subprotocol: Option<u32>,
    pub selected_protocol: ProtocolVersion,
    pub digest_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonModule {
    pub name: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonModuleList {
    pub greeting: DaemonGreeting,
    pub motd: Vec<String>,
    pub modules: Vec<DaemonModule>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DaemonAuth<'a> {
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonHandshake {
    pub greeting: DaemonGreeting,
    pub motd: Vec<String>,
    pub auth_used: bool,
    pub digest_name: Option<String>,
    pub compat_flags: Option<u32>,
    pub checksum_name: Option<String>,
    pub checksum_seed: i32,
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Version(#[from] VersionError),
    #[error("invalid daemon endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("daemon endpoint is missing a module")]
    MissingModule,
    #[error("daemon greeting is missing or invalid: {0}")]
    InvalidGreeting(String),
    #[error("daemon protocol {protocol} omitted the required subprotocol")]
    MissingSubprotocol { protocol: u32 },
    #[error("daemon protocol {protocol} omitted the required digest list")]
    MissingDigestList { protocol: u32 },
    #[error("daemon client supports protocol {supported}, but negotiated protocol {negotiated}")]
    UnsupportedProtocol { negotiated: u32, supported: u32 },
    #[error("rsync daemon reported an error: {0}")]
    RemoteError(String),
    #[error("daemon authentication requires a user and --password-file")]
    MissingAuth,
    #[error("daemon authentication requires an md4 digest but server offered: {0}")]
    UnsupportedAuthDigest(String),
    #[error("daemon protocol 31 checksum negotiation did not find a supported algorithm")]
    UnsupportedChecksumNegotiation,
    #[error("daemon sent invalid protocol checksum list text")]
    InvalidChecksumList,
    #[error("daemon sent unexpected command: {0}")]
    UnexpectedCommand(String),
}

pub fn request_daemon_module_list<T: Read + Write>(
    transport: &mut T,
) -> Result<DaemonModuleList, DaemonError> {
    let greeting = exchange_daemon_opening(transport)?;
    write_daemon_line(transport, "#list")?;
    transport.flush()?;

    let mut motd = Vec::new();
    let mut modules = Vec::new();
    loop {
        let line = read_daemon_line(transport)?;
        if matches!(
            line.as_str(),
            "@RSYNCD: EXIT" | "@RSYNC: EXIT" | "@RSYNC EXIT"
        ) {
            break;
        }
        if let Some(message) = parse_daemon_error(&line) {
            return Err(DaemonError::RemoteError(message.to_string()));
        }
        if line.starts_with("@RSYNCD:") {
            return Err(DaemonError::UnexpectedCommand(line));
        }
        if let Some(module) = parse_module_listing(&line) {
            modules.push(module);
        } else if !line.is_empty() {
            motd.push(line);
        }
    }

    Ok(DaemonModuleList {
        greeting,
        motd,
        modules,
    })
}

pub fn setup_daemon_transfer<T: Read + Write>(
    transport: &mut T,
    endpoint: &DaemonEndpoint,
    auth: DaemonAuth<'_>,
    server_args: &[String],
) -> Result<DaemonHandshake, DaemonError> {
    let module = endpoint.module_name()?;
    let greeting = exchange_daemon_opening(transport)?;
    write_daemon_line(transport, module)?;
    transport.flush()?;

    let mut motd = Vec::new();
    let mut auth_used = false;
    let mut selected_digest = None::<String>;
    loop {
        let line = read_daemon_line(transport)?;
        if line == "@RSYNCD: OK" {
            break;
        }
        if let Some(message) = parse_daemon_error(&line) {
            return Err(DaemonError::RemoteError(message.to_string()));
        }
        if let Some(challenge) = line.strip_prefix("@RSYNCD: AUTHREQD ") {
            if auth_used {
                return Err(DaemonError::UnexpectedCommand(line));
            }
            let digest = select_auth_digest(&greeting.digest_names)?;
            let username = auth.username.ok_or(DaemonError::MissingAuth)?;
            let password = auth.password.ok_or(DaemonError::MissingAuth)?;
            let response = daemon_auth_response(&digest, challenge, password)?;
            write_daemon_line(transport, &format!("{username} {response}"))?;
            transport.flush()?;
            auth_used = true;
            selected_digest = Some(digest);
            continue;
        }
        if line.starts_with("@RSYNCD:") {
            return Err(DaemonError::UnexpectedCommand(line));
        }
        if !line.is_empty() {
            motd.push(line);
        }
    }

    write_daemon_args(transport, server_args)?;
    transport.flush()?;
    let (compat_flags, checksum_name, checksum_seed) = read_daemon_transfer_setup(transport)?;

    Ok(DaemonHandshake {
        greeting,
        motd,
        auth_used,
        digest_name: selected_digest,
        compat_flags,
        checksum_name,
        checksum_seed,
    })
}

pub fn write_daemon_args<W: Write>(writer: &mut W, args: &[String]) -> Result<(), DaemonError> {
    for arg in args {
        if arg.as_bytes().contains(&0) || arg.as_bytes().contains(&b'\n') {
            return Err(DaemonError::InvalidEndpoint(
                "daemon server argument contains a NUL byte or newline".to_string(),
            ));
        }
        writer.write_all(arg.as_bytes())?;
        writer.write_all(&[0])?;
    }
    writer.write_all(&[0])?;
    Ok(())
}

fn read_daemon_transfer_setup<T: Read + Write>(
    transport: &mut T,
) -> Result<(Option<u32>, Option<String>, i32), DaemonError> {
    let compat_flags = read_varint(transport)?;
    let checksum_name = if compat_flags & RSYNC_CF_VARINT_FLIST_FLAGS != 0 {
        let checksum_list = read_vstring(transport, 1024)?;
        let checksum_list =
            String::from_utf8(checksum_list).map_err(|_| DaemonError::InvalidChecksumList)?;
        let checksum_name = select_protocol31_checksum(DAEMON_TRANSFER_CHECKSUMS, &checksum_list)
            .ok_or(DaemonError::UnsupportedChecksumNegotiation)?;
        write_vstring(transport, checksum_name.as_bytes())?;
        transport.flush()?;
        Some(checksum_name)
    } else {
        None
    };
    let checksum_seed = read_i32_le(transport)?;
    Ok((Some(compat_flags), checksum_name, checksum_seed))
}

fn select_protocol31_checksum(client_list: &str, server_list: &str) -> Option<String> {
    let server_names = server_list.split_whitespace().collect::<Vec<_>>();
    client_list
        .split_whitespace()
        .find(|name| server_names.contains(name))
        .map(str::to_owned)
}

pub fn daemon_auth_response(
    digest_name: &str,
    challenge: &str,
    password: &str,
) -> Result<String, DaemonError> {
    if digest_name != "md4" {
        return Err(DaemonError::UnsupportedAuthDigest(digest_name.to_string()));
    }

    let mut hasher = md4::Md4::new();
    hasher.update(password.as_bytes());
    hasher.update(challenge.as_bytes());
    Ok(base64_encode(&hasher.finalize()))
}

fn exchange_daemon_opening<T: Read + Write>(
    transport: &mut T,
) -> Result<DaemonGreeting, DaemonError> {
    let greeting = parse_daemon_greeting(&read_daemon_line(transport)?)?;
    let digest_suffix = CLIENT_AUTH_DIGESTS.join(" ");
    write_daemon_line(
        transport,
        &format!(
            "@RSYNCD: {}.0 {}",
            greeting.selected_protocol.value(),
            digest_suffix
        ),
    )?;
    transport.flush()?;
    Ok(greeting)
}

fn parse_daemon_greeting(line: &str) -> Result<DaemonGreeting, DaemonError> {
    let Some(rest) = line.strip_prefix("@RSYNCD: ") else {
        return Err(DaemonError::InvalidGreeting(line.to_string()));
    };

    let mut parts = rest.split_whitespace();
    let Some(version_text) = parts.next() else {
        return Err(DaemonError::InvalidGreeting(line.to_string()));
    };
    let (protocol_text, subprotocol) = match version_text.split_once('.') {
        Some((protocol, subprotocol)) => {
            let subprotocol = subprotocol
                .parse::<u32>()
                .map_err(|_| DaemonError::InvalidGreeting(line.to_string()))?;
            (protocol, Some(subprotocol))
        }
        None => (version_text, None),
    };
    let peer_protocol = protocol_text
        .parse::<u32>()
        .map_err(|_| DaemonError::InvalidGreeting(line.to_string()))?;
    if peer_protocol >= 30 && subprotocol.is_none() {
        return Err(DaemonError::MissingSubprotocol {
            protocol: peer_protocol,
        });
    }

    let digest_names: Vec<String> = parts.map(str::to_string).collect();
    if peer_protocol >= 32 && digest_names.is_empty() {
        return Err(DaemonError::MissingDigestList {
            protocol: peer_protocol,
        });
    }

    let selected_protocol =
        negotiate_protocol_version_with_local(peer_protocol, DAEMON_CLIENT_PROTOCOL)?;
    if selected_protocol.value() != DAEMON_CLIENT_PROTOCOL {
        return Err(DaemonError::UnsupportedProtocol {
            negotiated: selected_protocol.value(),
            supported: DAEMON_CLIENT_PROTOCOL,
        });
    }

    Ok(DaemonGreeting {
        peer_protocol,
        peer_subprotocol: subprotocol.or((peer_protocol < 30).then_some(0)),
        selected_protocol,
        digest_names,
    })
}

fn select_auth_digest(server_digest_names: &[String]) -> Result<String, DaemonError> {
    if server_digest_names.is_empty() {
        return Err(DaemonError::UnsupportedAuthDigest(
            "no digest list".to_string(),
        ));
    }

    for client in CLIENT_AUTH_DIGESTS {
        if server_digest_names.iter().any(|server| server == client) {
            return Ok((*client).to_string());
        }
    }
    Err(DaemonError::UnsupportedAuthDigest(
        server_digest_names.join(" "),
    ))
}

fn parse_daemon_error(line: &str) -> Option<&str> {
    line.strip_prefix("@ERROR: ")
        .or_else(|| line.strip_prefix("@RSYNCD: ERROR "))
}

fn parse_module_listing(line: &str) -> Option<DaemonModule> {
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return None;
    }

    let (name, comment) = trimmed.split_once('\t')?;
    let name = name.trim_end();
    if name.is_empty() {
        return None;
    }
    let comment = comment.trim().to_string();
    Some(DaemonModule {
        name: name.to_string(),
        comment: (!comment.is_empty()).then_some(comment),
    })
}

fn read_daemon_line<R: Read>(reader: &mut R) -> Result<String, DaemonError> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = reader.read(&mut byte)?;
        if read == 0 {
            return Err(DaemonError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed connection while reading line",
            )));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > DAEMON_LINE_LIMIT {
            return Err(DaemonError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon line exceeds safety limit",
            )));
        }
    }
    if line.ends_with(b"\r") {
        line.pop();
    }
    String::from_utf8(line)
        .map_err(|_| DaemonError::InvalidGreeting("daemon line is not UTF-8".to_string()))
}

fn write_daemon_line<W: Write>(writer: &mut W, line: &str) -> io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")
}

fn parse_rsync_url(rest: &str, original: &str) -> Result<DaemonEndpoint, DaemonError> {
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return Err(DaemonError::InvalidEndpoint(format!(
            "rsync URL is missing a host: {original}"
        )));
    }

    let (user, host_port) = split_user_host(authority)?;
    let (host, port) = split_host_port(&host_port)?;
    if host.is_empty() {
        return Err(DaemonError::InvalidEndpoint(
            "daemon host is empty".to_string(),
        ));
    }
    let (module, path) = split_module_path(path)?;
    Ok(DaemonEndpoint {
        user,
        host,
        port,
        module,
        path,
    })
}

fn split_user_host(authority: &str) -> Result<(Option<String>, String), DaemonError> {
    let (user, host) = match authority.rsplit_once('@') {
        Some((user, host)) => {
            if user.is_empty() {
                return Err(DaemonError::InvalidEndpoint(
                    "daemon username is empty".to_string(),
                ));
            }
            (Some(user.to_string()), host.to_string())
        }
        None => (None, authority.to_string()),
    };
    if host.is_empty() {
        return Err(DaemonError::InvalidEndpoint(
            "daemon host is empty".to_string(),
        ));
    }
    Ok((user, host))
}

fn split_host_port(host_port: &str) -> Result<(String, u16), DaemonError> {
    if let Some(rest) = host_port.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err(DaemonError::InvalidEndpoint(
                "bracketed daemon host is missing ']'".to_string(),
            ));
        };
        let port = if suffix.is_empty() {
            RSYNC_DAEMON_PORT
        } else if let Some(port) = suffix.strip_prefix(':') {
            parse_port(port)?
        } else {
            return Err(DaemonError::InvalidEndpoint(
                "bracketed daemon host has invalid port syntax".to_string(),
            ));
        };
        return Ok((host.to_string(), port));
    }

    if let Some((host, port)) = host_port.rsplit_once(':') {
        if !host.contains(':') && !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
            return Ok((host.to_string(), parse_port(port)?));
        }
    }
    Ok((host_port.to_string(), RSYNC_DAEMON_PORT))
}

fn parse_port(port: &str) -> Result<u16, DaemonError> {
    if port.is_empty() {
        return Err(DaemonError::InvalidEndpoint(
            "daemon port is empty".to_string(),
        ));
    }
    port.parse::<u16>()
        .map_err(|_| DaemonError::InvalidEndpoint(format!("invalid daemon port: {port}")))
}

fn split_module_path(module_path: &str) -> Result<(Option<String>, String), DaemonError> {
    if module_path.is_empty() {
        return Ok((None, String::new()));
    }
    let (module, path) = module_path.split_once('/').unwrap_or((module_path, ""));
    if module.is_empty() {
        return Ok((None, String::new()));
    }
    if module.as_bytes().contains(&0) || path.as_bytes().contains(&0) {
        return Err(DaemonError::InvalidEndpoint(
            "daemon module path contains a NUL byte".to_string(),
        ));
    }
    Ok((Some(module.to_string()), path.to_string()))
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let encoded_len = (bytes.len() * 8).div_ceil(6);
    let mut out = String::with_capacity(encoded_len);
    for index in 0..encoded_len {
        let byte_offset = (index * 6) / 8;
        let bit_offset = (index * 6) % 8;
        let table_index = if bit_offset < 3 {
            (bytes[byte_offset] >> (2 - bit_offset)) & 0x3f
        } else {
            let mut value = (bytes[byte_offset] << (bit_offset - 2)) & 0x3f;
            if byte_offset + 1 < bytes.len() {
                value |= bytes[byte_offset + 1] >> (10 - bit_offset);
            }
            value
        };
        out.push(TABLE[table_index as usize] as char);
    }
    out
}

impl fmt::Display for DaemonEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.display_module())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_double_colon_endpoint() {
        let endpoint = DaemonEndpoint::parse("user@example.test::backup/dir/file")
            .unwrap()
            .unwrap();

        assert_eq!(endpoint.user.as_deref(), Some("user"));
        assert_eq!(endpoint.host, "example.test");
        assert_eq!(endpoint.port, RSYNC_DAEMON_PORT);
        assert_eq!(endpoint.module.as_deref(), Some("backup"));
        assert_eq!(endpoint.path, "dir/file");
        assert_eq!(endpoint.transfer_path(), "dir/file");
    }

    #[test]
    fn parses_rsync_url_with_port() {
        let endpoint = DaemonEndpoint::parse("rsync://user@example.test:10873/backup/path")
            .unwrap()
            .unwrap();

        assert_eq!(endpoint.user.as_deref(), Some("user"));
        assert_eq!(endpoint.host, "example.test");
        assert_eq!(endpoint.port, 10873);
        assert_eq!(endpoint.module.as_deref(), Some("backup"));
        assert_eq!(endpoint.path, "path");
        assert_eq!(endpoint.socket_addr(), "example.test:10873");
    }

    #[test]
    fn parses_module_list_endpoint() {
        let endpoint = DaemonEndpoint::parse("host::").unwrap().unwrap();

        assert_eq!(endpoint.host, "host");
        assert_eq!(endpoint.module, None);
        assert_eq!(endpoint.display_module(), "host::");
    }

    #[test]
    fn parses_and_validates_daemon_greeting() {
        let greeting = parse_daemon_greeting("@RSYNCD: 32.0 sha512 sha256 sha1 md5 md4").unwrap();

        assert_eq!(greeting.peer_protocol, 32);
        assert_eq!(greeting.peer_subprotocol, Some(0));
        assert_eq!(greeting.selected_protocol.value(), DAEMON_CLIENT_PROTOCOL);
        assert_eq!(
            greeting.digest_names.last().map(String::as_str),
            Some("md4")
        );
    }

    #[test]
    fn rejects_modern_greeting_without_subprotocol() {
        let err = parse_daemon_greeting("@RSYNCD: 31").unwrap_err();

        assert!(matches!(
            err,
            DaemonError::MissingSubprotocol { protocol: 31 }
        ));
    }

    #[test]
    fn rejects_protocol32_greeting_without_digest_list() {
        let err = parse_daemon_greeting("@RSYNCD: 32.0").unwrap_err();

        assert!(matches!(
            err,
            DaemonError::MissingDigestList { protocol: 32 }
        ));
    }

    #[test]
    fn requests_module_list() {
        let mut transport = TestTransport::with_input(
            b"@RSYNCD: 31.0 md4\nwelcome with spaces\nfiles          \tpublic files\n@RSYNCD: EXIT\n"
                .to_vec(),
        );

        let list = request_daemon_module_list(&mut transport).unwrap();

        assert_eq!(
            list.greeting.selected_protocol.value(),
            DAEMON_CLIENT_PROTOCOL
        );
        assert_eq!(list.motd, vec!["welcome with spaces"]);
        assert_eq!(
            list.modules,
            vec![DaemonModule {
                name: "files".to_string(),
                comment: Some("public files".to_string())
            }]
        );
        assert_eq!(
            String::from_utf8(transport.written).unwrap(),
            "@RSYNCD: 31.0 md4\n#list\n"
        );
    }

    #[test]
    fn sets_up_no_auth_transfer_and_writes_args() {
        let endpoint = DaemonEndpoint::parse("host::files/path").unwrap().unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(b"@RSYNCD: 31.0 md4\nnotice\n@RSYNCD: OK\n");
        input.extend_from_slice(&[0x81, 0xfe]);
        write_vstring(&mut input, b"xxh128 xxh3 xxh64 md5 md4 sha1 none").unwrap();
        input.extend_from_slice(&123_i32.to_le_bytes());
        let mut transport = TestTransport::with_input(input);

        let handshake = setup_daemon_transfer(
            &mut transport,
            &endpoint,
            DaemonAuth::default(),
            &[
                "--server".to_string(),
                "--sender".to_string(),
                ".".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(handshake.checksum_seed, 123);
        assert_eq!(handshake.compat_flags, Some(0x1fe));
        assert_eq!(handshake.checksum_name.as_deref(), Some("md4"));
        assert_eq!(handshake.motd, vec!["notice"]);
        assert!(!handshake.auth_used);
        assert_eq!(
            String::from_utf8(transport.written).unwrap(),
            "@RSYNCD: 31.0 md4\nfiles\n--server\0--sender\0.\0\0\x03md4"
        );
    }

    #[test]
    fn responds_to_auth_challenge() {
        let endpoint = DaemonEndpoint::parse("user@host::files").unwrap().unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(
            b"@RSYNCD: 31.0 sha256 md4\n@RSYNCD: AUTHREQD abc123\n@RSYNCD: OK\n",
        );
        input.extend_from_slice(&[0x81, 0xfe]);
        write_vstring(&mut input, b"xxh128 xxh3 xxh64 md5 md4 sha1 none").unwrap();
        input.extend_from_slice(&0_i32.to_le_bytes());
        let mut transport = TestTransport::with_input(input);

        let handshake = setup_daemon_transfer(
            &mut transport,
            &endpoint,
            DaemonAuth {
                username: Some("user"),
                password: Some("secret"),
            },
            &["--server".to_string(), ".".to_string()],
        )
        .unwrap();

        assert!(handshake.auth_used);
        assert_eq!(handshake.digest_name.as_deref(), Some("md4"));
        assert_eq!(handshake.checksum_name.as_deref(), Some("md4"));
        let written = String::from_utf8(transport.written).unwrap();
        assert!(written.contains("user "));
        assert!(written.ends_with("--server\0.\0\0\x03md4"));
    }

    #[test]
    fn auth_response_is_stable() {
        assert_eq!(
            daemon_auth_response("md4", "challenge", "password").unwrap(),
            "IxAaiK+XPLUfsWi1hnAHqQ"
        );
        assert_eq!(base64_encode(&[0]), "AA");
        assert_eq!(base64_encode(&[0, 1]), "AAE");
        assert_eq!(base64_encode(&[0, 1, 2]), "AAEC");
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
