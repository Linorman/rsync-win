use super::*;

#[test]
fn daemon_operands_route_to_daemon_plan_without_remote_shell_argv() {
    let output = parse_and_render(["rsync-win", "--plan", "host::module/path", "dest"]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon endpoint: host:873"));
    assert!(output.contains("daemon direction: download (daemon -> local)"));
    assert!(output.contains("daemon module: module"));
    assert!(output.contains("daemon path: path"));
    assert!(!output.contains("E_REMOTE_OPERAND"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_url_operands_route_to_daemon_plan() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "rsync://user@example.test:8873/pub/dir",
        "dest",
    ]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon endpoint: example.test:8873"));
    assert!(output.contains("daemon module: pub"));
    assert!(output.contains("daemon path: dir"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_module_listing_plan_uses_daemon_mode() {
    let output = parse_and_render(["rsync-win", "--plan", "--list-only", "host::"]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon module: <list>"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn windows_drive_operands_are_not_daemon_operands() {
    let output = parse_and_render(["rsync-win", "--plan", r"C:\src", "dest"]);

    assert!(!output.contains("daemon mode: client"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_password_file_does_not_render_secret_or_path() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--password-file",
        "secret-password.txt",
        "user@host::module/path",
        "dest",
    ]);

    assert!(output.contains("daemon auth: password-file configured"));
    assert!(!output.contains("secret-password"));
    assert!(!output.contains("remote ssh argv:"));
}

#[test]
fn daemon_auth_user_prefers_operand_and_uses_local_env_fallback_order() {
    let daemon = DaemonOperand::parse("alice@host::module").unwrap().unwrap();

    assert_eq!(daemon_auth_user(&daemon).unwrap(), "alice");
    assert_eq!(
        daemon_auth_user_from_vars([
            ("USER", Some(String::new())),
            ("LOGNAME", Some(" logname ".to_string())),
            ("USERNAME", Some("winuser".to_string())),
        ]),
        Some("logname".to_string())
    );
    assert_eq!(
        daemon_auth_user_from_vars([
            ("USER", Some("bad\0user".to_string())),
            ("LOGNAME", None),
            ("USERNAME", Some("winuser".to_string())),
        ]),
        Some("winuser".to_string())
    );
}

#[test]
fn daemon_password_falls_back_to_rsync_password_env() {
    assert_eq!(
        daemon_password_from_vars([("RSYNC_PASSWORD", Some("env-secret".to_string()))]).unwrap(),
        "env-secret"
    );
    assert_eq!(
        daemon_password_from_vars([
            ("RSYNC_PASSWORD", Some(String::new())),
            ("OTHER", Some("ignored".to_string())),
        ]),
        None
    );
}

#[test]
fn daemon_password_file_rejects_non_regular_paths() {
    let root = unique_temp_dir("rsync-cli-password-file-dir");
    fs::create_dir_all(&root).unwrap();

    let err = read_password_file(&root).unwrap_err();

    assert!(err.to_string().contains("must be a regular file"));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn daemon_password_file_rejects_group_or_other_access() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_temp_dir("rsync-cli-password-file-perms");
    fs::create_dir_all(&root).unwrap();
    let password_file = root.join("pw.txt");
    fs::write(&password_file, "secret\n").unwrap();
    fs::set_permissions(&password_file, fs::Permissions::from_mode(0o644)).unwrap();

    let err = read_password_file(&password_file).unwrap_err();

    assert!(err
        .to_string()
        .contains("must not be accessible by group or other users"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn daemon_module_listing_executes_over_in_memory_transport() {
    let cli = Cli::parse_from(["rsync-win", "--list-only", "host::"]);
    let plan = TransferPlan::from_cli(&cli);
    let mut transport = TestTransport::with_input(
        b"@RSYNCD: 31.0\nhello\npublic\tPublic files\n@RSYNCD: EXIT\n".to_vec(),
    );

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win daemon module list"));
    assert!(output.contains("endpoint: host:873"));
    assert!(output.contains("- hello"));
    assert!(output.contains("- public\tPublic files"));
    assert_eq!(transport.written, b"@RSYNCD: 31.0 md5 md4\n#list\n");
}

#[test]
fn daemon_no_auth_pull_uses_remote_pull_receive_path() {
    let root = unique_temp_dir("rsync-cli-daemon-pull");
    let dest = root.join("dest");
    let cli = Cli::parse_from([
        "rsync-win",
        "--dry-run",
        "host::module/file.txt",
        &dest.to_string_lossy(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut input = b"@RSYNCD: 31.0\n@RSYNCD: OK\n".to_vec();
    input.extend_from_slice(&daemon_protocol31_setup_input());
    input.extend_from_slice(&daemon_pull_dry_run_input());
    let mut transport = TestTransport::with_input(input);

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win daemon pull"));
    assert!(output.contains("source: host::module/file.txt"));
    assert!(output.contains("dry run: true"));
    assert!(transport
        .written
        .starts_with(b"@RSYNCD: 31.0 md5 md4\nmodule\n--server\0--sender\0"));
    assert!(transport
        .written
        .windows(b"file.txt\0".len())
        .any(|window| window == b"file.txt\0"));
    if root.exists() {
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn daemon_destination_operands_route_to_push_plan() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "-r",
        "local-src",
        "host::module/upload",
    ]);

    assert!(output.contains("daemon mode: client"));
    assert!(output.contains("daemon direction: upload (local -> daemon)"));
    assert!(output.contains("daemon module: module"));
    assert!(output.contains("daemon path: upload"));
    assert!(!output.contains("E_DAEMON_PUSH_UNSUPPORTED"));
}

#[test]
fn daemon_client_plan_applies_connection_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--port",
        "8873",
        "--address",
        "127.0.0.1",
        "--sockopts",
        "TCP_NODELAY,SO_KEEPALIVE",
        "--contimeout",
        "7",
        "--no-motd",
        "host::module/path",
        "dest",
    ]);

    assert!(output.contains("daemon endpoint: host:8873"));
    assert!(output.contains("daemon bind address: 127.0.0.1"));
    assert!(output.contains("daemon socket options: TCP_NODELAY,SO_KEEPALIVE"));
    assert!(output.contains("daemon connect timeout: 7s"));
    assert!(output.contains("daemon motd: disabled"));
    assert!(!output.contains("W_UNSUPPORTED_OPTION"));
}

#[test]
fn daemon_push_uses_remote_receiver_path() {
    let root = unique_temp_dir("rsync-cli-daemon-push");
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"hello").unwrap();
    let cli = options::parse_cli([
        "rsync-win",
        "-n",
        "-r",
        &source.to_string_lossy(),
        "host::module/upload",
    ])
    .unwrap();
    let plan = TransferPlan::from_cli(&cli);
    let mut input = b"@RSYNCD: 31.0\n@RSYNCD: OK\n".to_vec();
    input.extend_from_slice(&daemon_push_dry_run_input());
    let mut transport = TestTransport::with_input(input);

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();

    assert!(output.contains("rsync-win daemon push"));
    assert!(output.contains("direction: upload (local -> daemon)"));
    assert!(output.contains("destination: host::module/upload"));
    assert!(transport
        .written
        .starts_with(b"@RSYNCD: 31.0 md5 md4\nmodule\n--server\0"));
    assert!(
        transport
            .written
            .windows(b"md4".len())
            .filter(|window| *window == b"md4")
            .count()
            >= 2
    );
    assert!(!transport
        .written
        .windows(b"--sender".len())
        .any(|window| window == b"--sender"));
    assert!(transport
        .written
        .windows(b"--no-inc-recursive".len())
        .any(|window| window == b"--no-inc-recursive"));
    assert!(transport
        .written
        .windows(b"e.LsfxCIvu".len())
        .any(|window| window == b"e.LsfxCIvu"));
    assert!(!transport
        .written
        .windows(b"e.iLsfxCIvu".len())
        .any(|window| window == b"e.iLsfxCIvu"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn daemon_server_plan_accepts_core_daemon_options() {
    let output = parse_and_render([
        "rsync-win",
        "--plan",
        "--daemon",
        "--no-detach",
        "--config",
        "rsyncd.conf",
        "--dparam",
        "public.comment=Overridden",
        "--address",
        "127.0.0.1",
        "--port",
        "0",
        "--sockopts",
        "TCP_NODELAY",
        "--log-file",
        "daemon.log",
        "--log-file-format",
        "%m %f",
        "--bwlimit",
        "128",
    ]);

    assert!(output.contains("daemon mode: server"));
    assert!(output.contains("daemon config: rsyncd.conf"));
    assert!(output.contains("daemon dparam: public.comment=Overridden"));
    assert!(output.contains("daemon listen: 127.0.0.1:0"));
    assert!(output.contains("daemon no detach: true"));
    assert!(output.contains("daemon log file: daemon.log"));
    assert!(output.contains("daemon bwlimit: 128"));
    assert!(!output.contains("E_UNSUPPORTED_MODE"));
    assert!(!output.contains("W_UNSUPPORTED_OPTION"));
}

#[test]
fn daemon_password_file_auth_hashes_without_logging_secret() {
    let root = unique_temp_dir("rsync-cli-daemon-auth");
    fs::create_dir_all(&root).unwrap();
    let password_file = root.join("pw.txt");
    let dest = root.join("dest");
    write_test_password_file(&password_file, "secret\n");
    let cli = Cli::parse_from([
        "rsync-win",
        "--dry-run",
        "--password-file",
        &password_file.to_string_lossy(),
        "alice@host::module/file.txt",
        &dest.to_string_lossy(),
    ]);
    let plan = TransferPlan::from_cli(&cli);
    let mut input = b"@RSYNCD: 31.0\n@RSYNCD: AUTHREQD challenge\n@RSYNCD: OK\n".to_vec();
    input.extend_from_slice(&daemon_protocol31_setup_input());
    input.extend_from_slice(&daemon_pull_dry_run_input());
    let mut transport = TestTransport::with_input(input);

    let output = execute_daemon_sync_with_transport(&cli, &plan, &mut transport).unwrap();
    let written = String::from_utf8_lossy(&transport.written);

    assert!(output.contains("rsync-win daemon pull"));
    assert!(written.contains("alice "));
    assert!(!written.contains("secret"));
    fs::remove_dir_all(root).unwrap();
}
