pub mod process;
pub mod remote_shell;
pub mod tcp;

use std::io::{Read, Write};

pub trait Transport: Read + Write {}

impl<T> Transport for T where T: Read + Write {}

#[derive(Debug, Default)]
pub struct MemoryTransport {
    read_buf: std::io::Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl MemoryTransport {
    pub fn with_input(input: impl Into<Vec<u8>>) -> Self {
        Self {
            read_buf: std::io::Cursor::new(input.into()),
            written: Vec::new(),
        }
    }

    pub fn written(&self) -> &[u8] {
        &self.written
    }
}

impl Read for MemoryTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_buf.read(buf)
    }
}

impl Write for MemoryTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn memory_transport_records_writes_and_serves_input() {
        let mut transport = MemoryTransport::with_input(b"peer".to_vec());
        transport.write_all(b"local").unwrap();

        let mut text = String::new();
        transport.read_to_string(&mut text).unwrap();

        assert_eq!(text, "peer");
        assert_eq!(transport.written(), b"local");
    }
}
