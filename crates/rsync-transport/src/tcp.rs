use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};

#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectOptions {
    pub timeout: Duration,
    pub bind_address: Option<IpAddr>,
    pub address_family: Option<TcpAddressFamily>,
    pub socket_options: TcpSocketOptions,
}

impl Default for TcpConnectOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            bind_address: None,
            address_family: None,
            socket_options: TcpSocketOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpSocketOptions {
    pub tcp_nodelay: Option<bool>,
    pub keepalive: Option<bool>,
    pub recv_buffer_size: Option<usize>,
    pub send_buffer_size: Option<usize>,
}

impl TcpSocketOptions {
    pub fn parse(value: &str) -> io::Result<Self> {
        let mut options = Self::default();
        for raw in value.split(',') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            let (name, raw_value) = item.split_once('=').unwrap_or((item, "1"));
            let normalized = name.trim().to_ascii_uppercase();
            match normalized.as_str() {
                "TCP_NODELAY" => options.tcp_nodelay = Some(parse_bool_sockopt(raw_value)?),
                "SO_KEEPALIVE" => options.keepalive = Some(parse_bool_sockopt(raw_value)?),
                "SO_RCVBUF" => options.recv_buffer_size = Some(parse_usize_sockopt(raw_value)?),
                "SO_SNDBUF" => options.send_buffer_size = Some(parse_usize_sockopt(raw_value)?),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unsupported socket option `{name}`"),
                    ));
                }
            }
        }
        Ok(options)
    }

    pub fn apply_to_stream(&self, stream: &TcpStream) -> io::Result<()> {
        let socket = SockRef::from(stream);
        self.apply_to_sock_ref(&socket)
    }

    pub fn bind_listener<A: ToSocketAddrs>(
        addr: A,
        options: &Self,
        address_family: Option<TcpAddressFamily>,
    ) -> io::Result<TcpListener> {
        let mut last_error = None;
        for addr in addr.to_socket_addrs()? {
            if !address_family_matches(addr, address_family) {
                continue;
            }
            match bind_listener_socket(addr, options) {
                Ok(listener) => return Ok(listener),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses resolved")
        }))
    }

    fn apply_to_socket(&self, socket: &Socket) -> io::Result<()> {
        if let Some(value) = self.tcp_nodelay {
            socket.set_nodelay(value)?;
        }
        if let Some(value) = self.keepalive {
            socket.set_keepalive(value)?;
        }
        if let Some(value) = self.recv_buffer_size {
            socket.set_recv_buffer_size(value)?;
        }
        if let Some(value) = self.send_buffer_size {
            socket.set_send_buffer_size(value)?;
        }
        Ok(())
    }

    fn apply_to_sock_ref(&self, socket: &SockRef<'_>) -> io::Result<()> {
        if let Some(value) = self.tcp_nodelay {
            socket.set_nodelay(value)?;
        }
        if let Some(value) = self.keepalive {
            socket.set_keepalive(value)?;
        }
        if let Some(value) = self.recv_buffer_size {
            socket.set_recv_buffer_size(value)?;
        }
        if let Some(value) = self.send_buffer_size {
            socket.set_send_buffer_size(value)?;
        }
        Ok(())
    }

    fn apply_to_listener_socket(&self, socket: &Socket) -> io::Result<()> {
        if let Some(value) = self.recv_buffer_size {
            socket.set_recv_buffer_size(value)?;
        }
        if let Some(value) = self.send_buffer_size {
            socket.set_send_buffer_size(value)?;
        }
        Ok(())
    }
}

impl TcpTransport {
    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        Self::connect_with_options(
            addr,
            &TcpConnectOptions {
                timeout,
                ..TcpConnectOptions::default()
            },
        )
    }

    pub fn connect_with_options<A: ToSocketAddrs>(
        addr: A,
        options: &TcpConnectOptions,
    ) -> io::Result<Self> {
        let mut last_error = None;
        for addr in addr.to_socket_addrs()? {
            if !address_family_matches(addr, options.address_family) {
                continue;
            }
            if let Some(bind_address) = options.bind_address {
                if bind_address.is_ipv4() != addr.is_ipv4() {
                    continue;
                }
            }
            match connect_socket(addr, options) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(options.timeout))?;
                    stream.set_write_timeout(Some(options.timeout))?;
                    return Ok(Self { stream });
                }
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses resolved")
        }))
    }

    pub fn connect_http_proxy<A: ToSocketAddrs>(
        proxy: A,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> io::Result<Self> {
        Self::connect_http_proxy_with_options(
            proxy,
            target_host,
            target_port,
            &TcpConnectOptions {
                timeout,
                ..TcpConnectOptions::default()
            },
        )
    }

    pub fn connect_http_proxy_with_options<A: ToSocketAddrs>(
        proxy: A,
        target_host: &str,
        target_port: u16,
        options: &TcpConnectOptions,
    ) -> io::Result<Self> {
        let mut transport = Self::connect_with_options(proxy, options)?;
        write!(
            transport,
            "CONNECT {target_host}:{target_port} HTTP/1.0\r\n\r\n"
        )?;
        transport.flush()?;
        let response = read_http_proxy_response(&mut transport)?;
        if response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200") {
            return Ok(transport);
        }
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "proxy CONNECT failed: {}",
                response.lines().next().unwrap_or("")
            ),
        ))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }
}

fn connect_socket(addr: SocketAddr, options: &TcpConnectOptions) -> io::Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if let Some(bind_address) = options.bind_address {
        socket.bind(&SockAddr::from(SocketAddr::new(bind_address, 0)))?;
    }
    options.socket_options.apply_to_socket(&socket)?;
    socket.connect_timeout(&SockAddr::from(addr), options.timeout)?;
    let stream: TcpStream = socket.into();
    if options.socket_options.tcp_nodelay.is_none() {
        stream.set_nodelay(true)?;
    }
    Ok(stream)
}

fn bind_listener_socket(addr: SocketAddr, options: &TcpSocketOptions) -> io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    options.apply_to_listener_socket(&socket)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(128)?;
    Ok(socket.into())
}

fn address_family_matches(addr: SocketAddr, family: Option<TcpAddressFamily>) -> bool {
    match family {
        Some(TcpAddressFamily::Ipv4) => addr.is_ipv4(),
        Some(TcpAddressFamily::Ipv6) => addr.is_ipv6(),
        None => true,
    }
}

fn parse_bool_sockopt(value: &str) -> io::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("socket option boolean value `{value}` is invalid"),
        )),
    }
}

fn parse_usize_sockopt(value: &str) -> io::Result<usize> {
    value.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("socket option integer value `{value}` is invalid"),
        )
    })
}

fn read_http_proxy_response<T: Read>(transport: &mut T) -> io::Result<String> {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response exceeded 8192 bytes",
            ));
        }
        let read = transport.read(&mut byte)?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
    }
    String::from_utf8(response)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy response was not UTF-8"))
}

impl Read for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn parses_supported_sockopts() {
        let options =
            TcpSocketOptions::parse("TCP_NODELAY,SO_KEEPALIVE,SO_SNDBUF=4096,SO_RCVBUF=8192")
                .unwrap();

        assert_eq!(options.tcp_nodelay, Some(true));
        assert_eq!(options.keepalive, Some(true));
        assert_eq!(options.send_buffer_size, Some(4096));
        assert_eq!(options.recv_buffer_size, Some(8192));
    }

    #[test]
    fn rejects_unknown_sockopts() {
        let err = TcpSocketOptions::parse("SO_REUSEADDR").unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("unsupported socket option"));
    }

    #[test]
    fn applies_socket_options_to_accepted_stream() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let options = TcpSocketOptions::parse("TCP_NODELAY").unwrap();
            options.apply_to_stream(&stream).unwrap();
            assert!(stream.nodelay().unwrap());
        });

        let _client = TcpStream::connect(addr).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn binds_listener_with_address_family_and_socket_options() {
        let options = TcpSocketOptions::parse("SO_SNDBUF=4096,SO_RCVBUF=4096").unwrap();
        let listener = TcpSocketOptions::bind_listener(
            ("127.0.0.1", 0),
            &options,
            Some(TcpAddressFamily::Ipv4),
        )
        .unwrap();

        assert!(listener.local_addr().unwrap().is_ipv4());
    }

    #[test]
    fn http_proxy_connect_sends_connect_request() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            assert!(String::from_utf8_lossy(&request)
                .starts_with("CONNECT daemon.example:8873 HTTP/1.0\r\n"));
            stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
            let mut ping = [0_u8; 4];
            stream.read_exact(&mut ping).unwrap();
            assert_eq!(&ping, b"ping");
        });

        let mut transport = TcpTransport::connect_http_proxy(
            (proxy_addr.ip().to_string().as_str(), proxy_addr.port()),
            "daemon.example",
            8873,
            Duration::from_secs(5),
        )
        .unwrap();
        transport.write_all(b"ping").unwrap();
        handle.join().unwrap();
    }
}
