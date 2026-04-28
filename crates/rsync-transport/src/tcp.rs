use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Duration) -> io::Result<Self> {
        let mut last_error = None;
        for addr in addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    stream.set_read_timeout(Some(timeout))?;
                    stream.set_write_timeout(Some(timeout))?;
                    return Ok(Self { stream });
                }
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses resolved")
        }))
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        Self { stream }
    }
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
