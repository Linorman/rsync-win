use std::ffi::OsString;
use std::path::PathBuf;

use crate::process::{ChildTransport, ProcessTransportError};

const DEFAULT_SSH_OPTIONS: [&str; 4] = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRemoteCommand {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub remote_command: String,
}

impl SshRemoteCommand {
    pub fn display_command(&self) -> String {
        let mut parts = vec![self.program.to_string_lossy().into_owned()];
        parts.extend(
            self.args
                .iter()
                .map(|arg| shell_quote(&arg.to_string_lossy())),
        );
        parts.join(" ")
    }
}

pub fn build_ssh_remote_command(
    ssh_program: impl Into<OsString>,
    host: &str,
    remote_server_argv: &[String],
) -> SshRemoteCommand {
    let remote_command = remote_server_argv
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");

    SshRemoteCommand {
        program: ssh_program.into(),
        args: DEFAULT_SSH_OPTIONS
            .iter()
            .copied()
            .map(OsString::from)
            .chain([OsString::from(host), OsString::from(remote_command.clone())])
            .collect(),
        remote_command,
    }
}

pub fn default_ssh_program() -> PathBuf {
    PathBuf::from("ssh")
}

pub fn spawn_ssh_remote_command(
    command: &SshRemoteCommand,
) -> Result<ChildTransport, ProcessTransportError> {
    ChildTransport::spawn(&command.program, command.args.iter())
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':' | b'@')
    }) {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ssh_command_with_quoted_remote_server_argv() {
        let command = build_ssh_remote_command(
            "ssh",
            "user@example.test",
            &[
                "rsync".to_string(),
                "--server".to_string(),
                ".".to_string(),
                "path with spaces".to_string(),
                "quote'path".to_string(),
            ],
        );

        assert_eq!(command.program, OsString::from("ssh"));
        assert_eq!(
            command.args,
            vec![
                OsString::from("-o"),
                OsString::from("BatchMode=yes"),
                OsString::from("-o"),
                OsString::from("ConnectTimeout=10"),
                OsString::from("user@example.test"),
                OsString::from("rsync --server . 'path with spaces' 'quote'\"'\"'path'"),
            ]
        );
        assert_eq!(
            command.remote_command,
            "rsync --server . 'path with spaces' 'quote'\"'\"'path'"
        );
    }
}
