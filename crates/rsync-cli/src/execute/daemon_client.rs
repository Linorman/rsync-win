use std::ffi::OsString;
use std::fs::{self};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rsync_protocol::{
    authenticate_daemon_module, build_remote_shell_argv_for_paths,
    build_remote_shell_protocol31_argv_for_paths, exchange_daemon_greeting,
    exchange_protocol31_sender_setup_with_options, exchange_protocol31_setup_with_options,
    request_module_list, select_daemon_module, write_daemon_args, DaemonModuleSelection,
    DaemonOperand, TransferDirection, REMOTE_SHELL_MODERN_PROTOCOL,
};
use rsync_transport::process::ChildTransport;
use rsync_transport::tcp::{TcpAddressFamily, TcpConnectOptions, TcpSocketOptions, TcpTransport};
use rsync_transport::BandwidthLimitedStream;
use rsync_winfs::to_long_path_safe;

use crate::cli::Cli;
use crate::plan::*;
use crate::remote::pull::{
    execute_remote_pull_protocol27, execute_remote_pull_protocol31_with_handshake,
};
use crate::remote::push::{
    execute_remote_push_protocol27, execute_remote_push_protocol31_with_handshake,
};
use crate::ProgressLog;

pub(crate) fn execute_daemon_sync(cli: &Cli, plan: TransferPlan) -> Result<String> {
    ensure_daemon_execution_options_supported(cli, &plan)?;

    let daemon = plan
        .daemon_operand
        .as_ref()
        .context("daemon operand was not planned")?;
    let progress = ProgressLog::from_cli(cli);
    progress.info(format!(
        "daemon connection started: {}:{}",
        daemon.host, daemon.port
    ));
    if let Some(connect_prog) = std::env::var_os("RSYNC_CONNECT_PROG") {
        return execute_daemon_sync_with_connect_prog(cli, &plan, daemon, connect_prog);
    }

    let tcp_options = daemon_tcp_connect_options(cli)?;
    let mut transport = if let Some(proxy) = std::env::var_os("RSYNC_PROXY") {
        let proxy = proxy.to_string_lossy();
        let (proxy_host, proxy_port) = parse_daemon_proxy(&proxy)?;
        TcpTransport::connect_http_proxy_with_options(
            (proxy_host.as_str(), proxy_port),
            &daemon.host,
            daemon.port,
            &tcp_options,
        )
        .with_context(|| {
            format!(
                "failed to connect to {}:{} through RSYNC_PROXY={proxy}",
                daemon.host, daemon.port
            )
        })?
    } else {
        TcpTransport::connect_with_options((daemon.host.as_str(), daemon.port), &tcp_options)
            .with_context(|| format!("failed to connect to {}:{}", daemon.host, daemon.port))?
    };
    if let Some(limit) = bandwidth_limit_from_plan(&plan) {
        let mut limited = BandwidthLimitedStream::new(&mut transport, limit);
        execute_daemon_sync_with_transport(cli, &plan, &mut limited)
    } else {
        execute_daemon_sync_with_transport(cli, &plan, &mut transport)
    }
}

fn execute_daemon_sync_with_connect_prog(
    cli: &Cli,
    plan: &TransferPlan,
    daemon: &DaemonOperand,
    connect_prog: OsString,
) -> Result<String> {
    let command = render_connect_prog(&connect_prog.to_string_lossy(), &daemon.host, daemon.port);
    let (program, args) = shell_command_for_connect_prog(&command);
    let mut transport = ChildTransport::spawn(&program, args.iter())
        .with_context(|| format!("failed to spawn RSYNC_CONNECT_PROG command `{command}`"))?;
    let session_result = if let Some(limit) = bandwidth_limit_from_plan(plan) {
        let mut limited = BandwidthLimitedStream::new(&mut transport, limit);
        execute_daemon_sync_with_transport(cli, plan, &mut limited)
    } else {
        execute_daemon_sync_with_transport(cli, plan, &mut transport)
    };
    transport.finish_input();
    let child_report = transport
        .wait_with_diagnostics()
        .context("failed to wait for RSYNC_CONNECT_PROG child process")?;
    if !child_report.status.success() {
        let stderr = String::from_utf8_lossy(&child_report.stderr)
            .trim()
            .to_string();
        if stderr.is_empty() {
            bail!(
                "RSYNC_CONNECT_PROG exited with status {}",
                child_report.status
            );
        }
        bail!(
            "RSYNC_CONNECT_PROG exited with status {}; stderr: {}",
            child_report.status,
            stderr
        );
    }
    session_result
}

fn daemon_tcp_connect_options(cli: &Cli) -> Result<TcpConnectOptions> {
    let bind_address = cli
        .daemon_address
        .as_deref()
        .map(str::parse::<IpAddr>)
        .transpose()
        .context("--address must be an IPv4 or IPv6 address for daemon client mode")?;
    let socket_options = cli
        .daemon_sockopts
        .as_deref()
        .map(TcpSocketOptions::parse)
        .transpose()
        .context("invalid --sockopts value")?
        .unwrap_or_default();
    let address_family = if cli.ipv4 {
        Some(TcpAddressFamily::Ipv4)
    } else if cli.ipv6 {
        Some(TcpAddressFamily::Ipv6)
    } else {
        None
    };
    let timeout_secs = cli
        .daemon_connect_timeout_secs
        .or(cli.timeout_secs)
        .unwrap_or(30);
    Ok(TcpConnectOptions {
        timeout: Duration::from_secs(timeout_secs),
        bind_address,
        address_family,
        socket_options,
    })
}

fn parse_daemon_proxy(value: &str) -> Result<(String, u16)> {
    let trimmed = value.trim();
    let (host, port) = trimmed
        .rsplit_once(':')
        .context("RSYNC_PROXY must be in host:port form")?;
    if host.is_empty() || port.is_empty() {
        bail!("RSYNC_PROXY must be in host:port form");
    }
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid RSYNC_PROXY port `{port}`"))?;
    Ok((host.to_string(), port))
}

fn render_connect_prog(template: &str, host: &str, port: u16) -> String {
    template
        .replace("%H", host)
        .replace("%P", &port.to_string())
}

fn shell_command_for_connect_prog(command: &str) -> (OsString, Vec<OsString>) {
    if cfg!(windows) {
        (
            OsString::from("cmd"),
            vec![OsString::from("/C"), OsString::from(command)],
        )
    } else {
        (
            OsString::from("sh"),
            vec![OsString::from("-c"), OsString::from(command)],
        )
    }
}

pub(crate) fn execute_daemon_sync_with_transport<T: Read + Write>(
    cli: &Cli,
    plan: &TransferPlan,
    mut transport: &mut T,
) -> Result<String> {
    ensure_daemon_execution_options_supported(cli, plan)?;

    let daemon = plan
        .daemon_operand
        .as_ref()
        .context("daemon operand was not planned")?;
    let progress = ProgressLog::from_cli(cli);
    let greeting = exchange_daemon_greeting(&mut transport, REMOTE_SHELL_MODERN_PROTOCOL)
        .context("failed to exchange daemon greeting")?;
    progress.detail(format!(
        "daemon protocol: {}.{}",
        greeting.peer_protocol, greeting.peer_subprotocol
    ));

    if daemon.module.is_none() {
        let listing =
            request_module_list(&mut transport).context("failed to list daemon modules")?;
        let mut output = String::new();
        output.push_str("rsync-win daemon module list\n");
        output.push_str(&format!("endpoint: {}:{}\n", daemon.host, daemon.port));
        output.push_str(&format!(
            "protocol: {}.{}\n",
            greeting.peer_protocol, greeting.peer_subprotocol
        ));
        if !cli.daemon_no_motd && !listing.motd.is_empty() {
            output.push_str("motd:\n");
            for line in listing.motd {
                output.push_str(&format!("- {line}\n"));
            }
        }
        output.push_str("modules:\n");
        if listing.modules.is_empty() {
            output.push_str("- <none>\n");
        } else {
            for module in listing.modules {
                output.push_str(&format!("- {}\t{}\n", module.name, module.comment));
            }
        }
        return Ok(output);
    }

    let module = daemon.module.as_deref().expect("checked module");
    match select_daemon_module(&mut transport, module).context("failed to select daemon module")? {
        DaemonModuleSelection::Ok { .. } => {}
        DaemonModuleSelection::AuthRequired { challenge, motd: _ } => {
            let password = daemon_password(cli)?;
            let user = daemon_auth_user(daemon)?;
            authenticate_daemon_module(
                &mut transport,
                &user,
                &password,
                &challenge,
                greeting.auth_checksum,
            )
            .context("daemon authentication failed")?;
        }
    }

    write_daemon_early_input(cli, transport)?;

    let direction = plan
        .daemon_direction
        .context("daemon transfer direction was not planned")?;
    let daemon_wire_protocol = daemon_wire_protocol_from_plan(plan, greeting.peer_protocol)?;
    let args = daemon_server_args_for_direction(
        cli,
        plan,
        daemon,
        daemon_wire_protocol.protocol_number(),
        direction,
    )?;
    progress.detail(format!("daemon args: {} argument(s)", args.len()));
    write_daemon_args(
        &mut transport,
        daemon_wire_protocol.protocol_number(),
        &args,
    )
    .context("failed to send daemon server args")?;

    if direction == TransferDirection::Push {
        return if daemon_wire_protocol == RemoteWireProtocol::Modern31 {
            let handshake = exchange_protocol31_sender_setup_with_options(
                transport,
                greeting.peer_protocol,
                protocol31_setup_options_from_plan(plan),
            )
            .context("daemon protocol 31 setup failed")?;
            execute_remote_push_protocol31_with_handshake(cli, plan, transport, handshake)
        } else {
            execute_remote_push_protocol27(cli, plan, transport)
        };
    }

    if daemon_wire_protocol == RemoteWireProtocol::Modern31 {
        let handshake = exchange_protocol31_setup_with_options(
            transport,
            greeting.peer_protocol,
            protocol31_setup_options_from_plan(plan),
        )
        .context("daemon protocol 31 setup failed")?;
        execute_remote_pull_protocol31_with_handshake(cli, plan, transport, handshake)
    } else {
        execute_remote_pull_protocol27(cli, plan, transport)
    }
}

fn write_daemon_early_input<T: Write>(cli: &Cli, transport: &mut T) -> Result<()> {
    let Some(path) = &cli.early_input else {
        return Ok(());
    };
    let path = Path::new(path);
    let bytes = fs::read(to_long_path_safe(path))
        .with_context(|| format!("failed to read --early-input file {}", path.display()))?;
    if bytes.len() > 5 * 1024 {
        bail!(
            "--early-input file {} exceeds the 5 KiB daemon early-exec input limit",
            path.display()
        );
    }
    transport
        .write_all(&bytes)
        .with_context(|| format!("failed to send --early-input file {}", path.display()))?;
    transport.flush()?;
    Ok(())
}

fn daemon_wire_protocol_from_plan(
    plan: &TransferPlan,
    peer_protocol: u32,
) -> Result<RemoteWireProtocol> {
    match plan.protocol_version {
        Some(27) => Ok(RemoteWireProtocol::Compat27),
        Some(31) if peer_protocol >= REMOTE_SHELL_MODERN_PROTOCOL => Ok(RemoteWireProtocol::Modern31),
        Some(31) => bail!(
            "--protocol=31 was requested, but the daemon only advertised protocol {peer_protocol}"
        ),
        Some(protocol) => bail!(
            "--protocol={protocol} is not supported by this build; supported execution protocols are 27 and 31"
        ),
        None if peer_protocol >= REMOTE_SHELL_MODERN_PROTOCOL => Ok(RemoteWireProtocol::Modern31),
        None => Ok(RemoteWireProtocol::Compat27),
    }
}

fn daemon_server_args_for_direction(
    cli: &Cli,
    plan: &TransferPlan,
    daemon: &DaemonOperand,
    protocol: u32,
    direction: TransferDirection,
) -> Result<Vec<String>> {
    match direction {
        TransferDirection::Pull => daemon_server_args_for_pull(cli, plan, daemon, protocol),
        TransferDirection::Push => daemon_server_args_for_push(cli, plan, daemon, protocol),
    }
}

fn daemon_server_args_for_pull(
    cli: &Cli,
    plan: &TransferPlan,
    daemon: &DaemonOperand,
    protocol: u32,
) -> Result<Vec<String>> {
    let path_arg = daemon_module_path_arg(daemon)?;
    let options = daemon_remote_shell_options_from_cli(
        cli,
        TransferDirection::Pull,
        plan.recursive,
        plan.preserve_times,
        plan.symlink_mode,
    );
    let argv = if protocol < REMOTE_SHELL_MODERN_PROTOCOL {
        build_remote_shell_argv_for_paths(&options, &[Path::new(&path_arg)])?
    } else {
        build_remote_shell_protocol31_argv_for_paths(&options, &[Path::new(&path_arg)])?
    };
    Ok(argv.into_iter().skip(1).collect())
}

fn daemon_server_args_for_push(
    cli: &Cli,
    plan: &TransferPlan,
    daemon: &DaemonOperand,
    protocol: u32,
) -> Result<Vec<String>> {
    let path_arg = daemon_module_path_arg(daemon)?;
    let options = daemon_remote_shell_options_from_cli(
        cli,
        TransferDirection::Push,
        plan.recursive,
        plan.preserve_times,
        plan.symlink_mode,
    );
    let argv = if protocol < REMOTE_SHELL_MODERN_PROTOCOL {
        build_remote_shell_argv_for_paths(&options, &[Path::new(&path_arg)])?
    } else {
        build_remote_shell_protocol31_argv_for_paths(&options, &[Path::new(&path_arg)])?
    };
    Ok(argv.into_iter().skip(1).collect())
}

fn daemon_module_path_arg(daemon: &DaemonOperand) -> Result<String> {
    daemon
        .module
        .as_ref()
        .context("daemon pull requires a module")?;
    Ok(match &daemon.path {
        Some(path) => path.clone(),
        None => ".".to_string(),
    })
}

pub(crate) fn daemon_auth_user(daemon: &DaemonOperand) -> Result<String> {
    if let Some(user) = daemon.user.as_deref() {
        return normalize_daemon_auth_user(user)
            .context("daemon auth username is empty or contains a NUL byte");
    }

    local_daemon_auth_user().context(
        "daemon module requires auth but no username was supplied; use user@host::module or set USER, LOGNAME, or USERNAME",
    )
}

fn local_daemon_auth_user() -> Option<String> {
    daemon_auth_user_from_vars([
        ("USER", std::env::var("USER").ok()),
        ("LOGNAME", std::env::var("LOGNAME").ok()),
        ("USERNAME", std::env::var("USERNAME").ok()),
    ])
}

pub(crate) fn daemon_auth_user_from_vars<I, K>(vars: I) -> Option<String>
where
    I: IntoIterator<Item = (K, Option<String>)>,
{
    vars.into_iter()
        .filter_map(|(_, value)| value)
        .find_map(|value| normalize_daemon_auth_user(&value))
}

fn daemon_password(cli: &Cli) -> Result<String> {
    if let Some(password_file) = cli.password_file.as_ref() {
        return read_password_file(password_file);
    }
    daemon_password_from_vars([("RSYNC_PASSWORD", std::env::var("RSYNC_PASSWORD").ok())])
        .context("daemon module requires auth; pass --password-file or set RSYNC_PASSWORD")
}

pub(crate) fn daemon_password_from_vars<I, K>(vars: I) -> Option<String>
where
    I: IntoIterator<Item = (K, Option<String>)>,
    K: AsRef<str>,
{
    vars.into_iter()
        .filter(|(key, _)| key.as_ref() == "RSYNC_PASSWORD")
        .filter_map(|(_, value)| value)
        .find_map(|value| normalize_daemon_password(&value))
}

fn normalize_daemon_auth_user(value: &str) -> Option<String> {
    let user = value.trim();
    if user.is_empty() || user.as_bytes().contains(&0) {
        None
    } else {
        Some(user.to_string())
    }
}

fn normalize_daemon_password(value: &str) -> Option<String> {
    if value.is_empty() || value.as_bytes().contains(&0) {
        None
    } else {
        Some(value.to_string())
    }
}

pub(crate) fn read_password_file(path: &Path) -> Result<String> {
    validate_password_file(path)?;
    let mut password = fs::read_to_string(path)
        .with_context(|| format!("failed to read daemon password file {}", path.display()))?;
    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }
    Ok(password)
}

fn validate_password_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect daemon password file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "daemon password file must be a regular file: {}",
            path.display()
        );
    }
    validate_password_file_permissions(path, &metadata)
}

#[cfg(unix)]
fn validate_password_file_permissions(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "daemon password file must not be accessible by group or other users: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_password_file_permissions(path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    if rsync_winfs::password_file_has_broad_access(path).with_context(|| {
        format!(
            "failed to inspect daemon password file ACL {}",
            path.display()
        )
    })? {
        bail!(
            "daemon password file must not grant read access to broad Windows principals: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_password_file_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}
