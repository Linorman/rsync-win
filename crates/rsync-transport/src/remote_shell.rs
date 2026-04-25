use std::ffi::OsString;
use std::path::PathBuf;

use crate::process::{ChildTransport, ProcessTransportError};
use thiserror::Error;

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
    build_remote_shell_command(
        ssh_program,
        DEFAULT_SSH_OPTIONS.iter().copied().map(OsString::from),
        host,
        remote_server_argv,
    )
}

pub fn build_custom_remote_shell_command(
    shell_command: &str,
    host: &str,
    remote_server_argv: &[String],
) -> Result<SshRemoteCommand, RemoteShellCommandParseError> {
    let (program, args) = parse_remote_shell_command(shell_command)?;
    Ok(build_remote_shell_command(
        program,
        args,
        host,
        remote_server_argv,
    ))
}

fn build_remote_shell_command(
    program: impl Into<OsString>,
    args: impl IntoIterator<Item = OsString>,
    host: &str,
    remote_server_argv: &[String],
) -> SshRemoteCommand {
    let remote_command = remote_server_argv
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");

    SshRemoteCommand {
        program: program.into(),
        args: args
            .into_iter()
            .chain([OsString::from(host), OsString::from(remote_command.clone())])
            .collect(),
        remote_command,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteShellCommandParseError {
    #[error("remote shell command is empty")]
    Empty,
    #[error("remote shell command has an unterminated quote")]
    UnterminatedQuote,
    #[error("remote shell command ends with an incomplete escape")]
    IncompleteEscape,
}

pub fn parse_remote_shell_command(
    command: &str,
) -> Result<(OsString, Vec<OsString>), RemoteShellCommandParseError> {
    let mut args = Vec::<OsString>::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut saw_token = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                saw_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                saw_token = true;
            }
            '\\' if !in_single => {
                let Some(next) = chars.next() else {
                    return Err(RemoteShellCommandParseError::IncompleteEscape);
                };
                current.push(next);
                saw_token = true;
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if saw_token {
                    args.push(OsString::from(std::mem::take(&mut current)));
                    saw_token = false;
                }
            }
            _ => {
                current.push(ch);
                saw_token = true;
            }
        }
    }

    if in_single || in_double {
        return Err(RemoteShellCommandParseError::UnterminatedQuote);
    }
    if saw_token {
        args.push(OsString::from(current));
    }

    let mut args = args.into_iter();
    let Some(program) = args.next() else {
        return Err(RemoteShellCommandParseError::Empty);
    };
    Ok((program, args.collect()))
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

    #[test]
    fn builds_custom_remote_shell_command_from_rsync_e_style_string() {
        let command = build_custom_remote_shell_command(
            "ssh -p 10080 -o StrictHostKeyChecking=no",
            "root@example.test",
            &[
                "rsync".to_string(),
                "--server".to_string(),
                ".".to_string(),
                "/tmp/dest".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(command.program, OsString::from("ssh"));
        assert_eq!(
            command.args[..4],
            [
                OsString::from("-p"),
                OsString::from("10080"),
                OsString::from("-o"),
                OsString::from("StrictHostKeyChecking=no")
            ]
        );
        assert_eq!(command.args[4], OsString::from("root@example.test"));
    }

    #[test]
    fn parses_remote_shell_command_quotes() {
        let (program, args) =
            parse_remote_shell_command("ssh -i 'key path' -o \"ProxyCommand=nc host 22\"").unwrap();

        assert_eq!(program, OsString::from("ssh"));
        assert_eq!(
            args,
            vec![
                OsString::from("-i"),
                OsString::from("key path"),
                OsString::from("-o"),
                OsString::from("ProxyCommand=nc host 22"),
            ]
        );
    }
}
