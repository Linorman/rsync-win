use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcessTransportError {
    #[error("child process stdin was not captured")]
    MissingStdin,
    #[error("child process stdout was not captured")]
    MissingStdout,
    #[error("child process stderr was not captured")]
    MissingStderr,
    #[error("child process stderr drain thread panicked")]
    StderrDrainPanicked,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub struct ChildTransport {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: Option<JoinHandle<io::Result<Vec<u8>>>>,
}

#[derive(Debug)]
pub struct ChildProcessReport {
    pub status: std::process::ExitStatus,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

impl ChildTransport {
    pub fn spawn<I, S>(program: &OsStr, args: I) -> Result<Self, ProcessTransportError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or(ProcessTransportError::MissingStdin)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessTransportError::MissingStdout)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(ProcessTransportError::MissingStderr)?;

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr: Some(drain_stderr(stderr)),
        })
    }

    pub fn finish_input(&mut self) {
        self.stdin.take();
    }

    pub fn wait(mut self) -> io::Result<std::process::ExitStatus> {
        self.finish_input();
        let status = self.child.wait()?;
        let _ = self.join_stderr_io()?;
        Ok(status)
    }

    pub fn wait_with_diagnostics(mut self) -> Result<ChildProcessReport, ProcessTransportError> {
        self.finish_input();
        let status = self.child.wait()?;
        let stderr = self.join_stderr()?;

        Ok(ChildProcessReport {
            status,
            stderr,
            timed_out: false,
        })
    }

    pub fn wait_with_diagnostics_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<ChildProcessReport, ProcessTransportError> {
        self.finish_input();
        let deadline = Instant::now() + timeout;

        loop {
            if let Some(status) = self.child.try_wait()? {
                let stderr = self.join_stderr()?;
                return Ok(ChildProcessReport {
                    status,
                    stderr,
                    timed_out: false,
                });
            }

            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let status = self.child.wait()?;
                let stderr = self.join_stderr()?;
                return Ok(ChildProcessReport {
                    status,
                    stderr,
                    timed_out: true,
                });
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(std::cmp::min(remaining, Duration::from_millis(10)));
        }
    }

    fn join_stderr(&mut self) -> Result<Vec<u8>, ProcessTransportError> {
        match self.stderr.take() {
            Some(handle) => Ok(handle
                .join()
                .map_err(|_| ProcessTransportError::StderrDrainPanicked)??),
            None => Ok(Vec::new()),
        }
    }

    fn join_stderr_io(&mut self) -> io::Result<Vec<u8>> {
        match self.stderr.take() {
            Some(handle) => match handle.join() {
                Ok(result) => result,
                Err(_) => Err(io::Error::other("stderr drain thread panicked")),
            },
            None => Ok(Vec::new()),
        }
    }
}

impl Drop for ChildTransport {
    fn drop(&mut self) {
        self.stdin.take();
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(handle) = self.stderr.take() {
            let _ = handle.join();
        }
    }
}

fn drain_stderr(mut stderr: ChildStderr) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

impl Read for ChildTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl Write for ChildTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stdin.as_mut() {
            Some(stdin) => stdin.write(buf),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "child process stdin is closed",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.stdin.as_mut() {
            Some(stdin) => stdin.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn child_transport_round_trips_through_local_echo_process() {
        let (program, args): (&OsStr, Vec<&OsStr>) = echo_process();
        let mut transport = ChildTransport::spawn(program, args).unwrap();

        transport.write_all(b"hello child\n").unwrap();
        transport.flush().unwrap();
        transport.finish_input();

        let mut output = Vec::new();
        transport.read_to_end(&mut output).unwrap();
        let status = transport.wait().unwrap();

        assert!(status.success());
        let normalized = String::from_utf8_lossy(&output).replace("\r\n", "\n");
        assert!(normalized.lines().any(|line| line == "hello child"));
    }

    #[test]
    fn child_transport_drains_stderr_for_diagnostics() {
        let (program, args): (&OsStr, Vec<&OsStr>) = stderr_process();
        let mut transport = ChildTransport::spawn(program, args).unwrap();

        let mut output = Vec::new();
        transport.read_to_end(&mut output).unwrap();
        let report = transport.wait_with_diagnostics().unwrap();

        assert!(report.status.success());
        assert!(String::from_utf8_lossy(&output).contains("protocol-ish stdout"));
        assert!(String::from_utf8_lossy(&report.stderr).contains("diagnostic stderr"));
    }

    #[test]
    fn child_transport_drains_stderr_while_waiting_for_stdout() {
        let (program, args): (&OsStr, Vec<&OsStr>) = stderr_heavy_process();
        let mut transport = ChildTransport::spawn(program, args).unwrap();

        let mut output = Vec::new();
        transport.read_to_end(&mut output).unwrap();
        let status = transport.wait().unwrap();

        assert!(status.success());
        assert!(String::from_utf8_lossy(&output).contains("stdout after stderr"));
    }

    #[cfg(windows)]
    fn echo_process() -> (&'static OsStr, Vec<&'static OsStr>) {
        (
            OsStr::new("cmd"),
            vec![OsStr::new("/C"), OsStr::new("more")],
        )
    }

    #[cfg(not(windows))]
    fn echo_process() -> (&'static OsStr, Vec<&'static OsStr>) {
        (OsStr::new("cat"), Vec::new())
    }

    #[cfg(windows)]
    fn stderr_process() -> (&'static OsStr, Vec<&'static OsStr>) {
        (
            OsStr::new("cmd"),
            vec![
                OsStr::new("/C"),
                OsStr::new("echo diagnostic stderr 1>&2 & echo protocol-ish stdout"),
            ],
        )
    }

    #[cfg(windows)]
    fn stderr_heavy_process() -> (&'static OsStr, Vec<&'static OsStr>) {
        (
            OsStr::new("powershell"),
            vec![
                OsStr::new("-NoProfile"),
                OsStr::new("-Command"),
                OsStr::new(
                    "1..20000 | ForEach-Object { [Console]::Error.WriteLine('stderr-fill') }; [Console]::Out.WriteLine('stdout after stderr')",
                ),
            ],
        )
    }

    #[cfg(not(windows))]
    fn stderr_process() -> (&'static OsStr, Vec<&'static OsStr>) {
        (
            OsStr::new("sh"),
            vec![
                OsStr::new("-c"),
                OsStr::new("echo diagnostic stderr >&2; echo protocol-ish stdout"),
            ],
        )
    }

    #[cfg(not(windows))]
    fn stderr_heavy_process() -> (&'static OsStr, Vec<&'static OsStr>) {
        (
            OsStr::new("sh"),
            vec![
                OsStr::new("-c"),
                OsStr::new(
                    "i=0; while [ $i -lt 20000 ]; do echo stderr-fill >&2; i=$((i+1)); done; echo 'stdout after stderr'",
                ),
            ],
        )
    }
}
