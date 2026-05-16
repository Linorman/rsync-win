use super::*;

#[test]
fn parses_minimal_module_config() {
    let config = parse_config(
        "[public]\npath = C:/data\ncomment = Public files\nread only = yes\nlist = true\n",
        Path::new("rsyncd.conf"),
    )
    .unwrap();

    assert_eq!(config.modules.len(), 1);
    assert_eq!(config.modules[0].name, "public");
    assert_eq!(config.modules[0].comment, "Public files");
    assert!(config.modules[0].read_only);
    assert!(config.modules[0].list);
}

#[test]
fn parses_daemon_auth_and_safe_subset_keys() {
    let config = parse_config(
        "[private]\npath = C:/data\nauth users = alice, bob\nsecrets file = C:/secrets/rsyncd.secrets\nread only = no\nwrite only = yes\nlist = false\nuid = nobody\ngid = nogroup\n",
        Path::new("rsyncd.conf"),
    )
    .unwrap();

    let module = &config.modules[0];
    assert_eq!(module.auth_users, vec!["alice", "bob"]);
    assert_eq!(
        module.secrets_file.as_deref(),
        Some(Path::new("C:/secrets/rsyncd.secrets"))
    );
    assert!(!module.read_only);
    assert!(module.write_only);
    assert!(!module.list);
    assert_eq!(module.uid.as_deref(), Some("nobody"));
    assert_eq!(module.gid.as_deref(), Some("nogroup"));
}

#[test]
fn daemon_auth_challenge_accepts_valid_user_and_rejects_bad_credentials() {
    let temp =
        std::env::temp_dir().join(format!("rsync-win-daemon-auth-unit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    let module_root = temp.join("module");
    fs::create_dir_all(&module_root).unwrap();
    let secrets_file = temp.join("rsyncd.secrets");
    fs::write(&secrets_file, "alice:secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secrets_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = parse_config(
        &format!(
            "[private]\npath = {}\nauth users = alice\nsecrets file = {}\n",
            module_root.display(),
            secrets_file.display()
        ),
        Path::new("rsyncd.conf"),
    )
    .unwrap();
    validate_config(&config).unwrap();

    let challenge = daemon_auth_challenge("private", Some("127.0.0.1:8730"));
    let response = rsync_protocol::daemon_auth_response(
        "secret",
        &challenge,
        rsync_protocol::DaemonAuthChecksum::Md5,
    );
    authenticate_daemon_client(
        &config.modules[0],
        Some("127.0.0.1:8730".to_string()),
        rsync_protocol::DaemonAuthChecksum::Md5,
        &mut CursorStream::new(format!("alice {response}\n").into_bytes()),
        Some(challenge.clone()),
    )
    .unwrap();

    let bad_response = rsync_protocol::daemon_auth_response(
        "wrong",
        &challenge,
        rsync_protocol::DaemonAuthChecksum::Md5,
    );
    let err = authenticate_daemon_client(
        &config.modules[0],
        Some("127.0.0.1:8730".to_string()),
        rsync_protocol::DaemonAuthChecksum::Md5,
        &mut CursorStream::new(format!("alice {bad_response}\n").into_bytes()),
        Some(challenge),
    )
    .unwrap_err();
    assert!(err.to_string().contains("daemon authentication failed"));

    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn dparam_overrides_module_values() {
    let mut config = parse_config(
        "[public]\npath = C:/data\ncomment = Old\n",
        Path::new("rsyncd.conf"),
    )
    .unwrap();

    apply_dparams(&mut config, &["public.comment=New".to_string()]).unwrap();

    assert_eq!(config.modules[0].comment, "New");
}

#[test]
fn daemon_log_format_expands_core_tokens() {
    let record = DaemonLogRecord {
        message: "module public transfer args: --server --sender . file.txt".to_string(),
        module: Some("public".to_string()),
        operation: Some("send".to_string()),
        path: Some("file.txt".to_string()),
        bytes: Some(12),
        client: Some("127.0.0.1:8730".to_string()),
    };

    assert_eq!(
        render_daemon_log_format("%m %o %f %l %h %M %% %q", &record),
        "public send file.txt 12 127.0.0.1:8730 module public transfer args: --server --sender . file.txt % %q"
    );
}

#[test]
fn daemon_bwlimit_parses_rsync_rate_units() {
    assert_eq!(
        parse_daemon_bwlimit("128").unwrap().bytes_per_second,
        128 * 1024
    );
    assert_eq!(
        parse_daemon_bwlimit("2M").unwrap().bytes_per_second,
        2 * 1024 * 1024
    );
    assert!(parse_daemon_bwlimit("0").is_err());
    assert!(parse_daemon_bwlimit("nonsense").is_err());
}

#[test]
fn daemon_bandwidth_limiter_computes_required_delay() {
    let limit = BandwidthLimit::new(1024);
    let start = std::time::Instant::now();
    let mut limiter = rsync_transport::BandwidthLimiter::new(limit, start);

    assert_eq!(
        limiter.delay_after_write(512, start),
        std::time::Duration::from_millis(500)
    );
    assert_eq!(
        limiter.delay_after_write(512, start + std::time::Duration::from_millis(1000)),
        std::time::Duration::ZERO
    );
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
