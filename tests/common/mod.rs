use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Available {
        path: PathBuf,
        version: Option<String>,
    },
    Unavailable {
        reason: String,
    },
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Available { path, .. } => Some(path),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Available { .. } => None,
            Self::Unavailable { reason } => Some(reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDiscovery {
    pub rsync: Availability,
    pub ssh: Availability,
    pub powershell: Availability,
}

pub fn discover_tools() -> ToolDiscovery {
    ToolDiscovery {
        rsync: discover_command(&["rsync"], &["--version"]),
        ssh: discover_command(&["ssh"], &["-V"]),
        powershell: discover_command(
            &["pwsh", "powershell"],
            &[
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "$PSVersionTable.PSVersion.ToString()",
            ],
        ),
    }
}

pub fn discover_command(candidates: &[&str], version_args: &[&str]) -> Availability {
    let Some(path) = find_in_path(candidates) else {
        return Availability::Unavailable {
            reason: format!("none of these commands were found in PATH: {candidates:?}"),
        };
    };

    let version = Command::new(&path)
        .args(version_args)
        .output()
        .ok()
        .map(|output| {
            let mut text = String::new();
            text.push_str(&String::from_utf8_lossy(&output.stdout));
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text.trim().to_string()
        })
        .filter(|text| !text.is_empty());

    Availability::Available { path, version }
}

pub fn find_in_path(candidates: &[&str]) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    let extensions = executable_extensions();

    for directory in env::split_paths(&path_var) {
        for candidate in candidates {
            let candidate_path = Path::new(candidate);
            if candidate_path.components().count() > 1 && is_executable_file(candidate_path) {
                return Some(candidate_path.to_path_buf());
            }

            for extension in &extensions {
                let mut file_name = OsString::from(candidate);
                if !extension.is_empty()
                    && candidate_path.extension().is_none()
                    && !candidate.ends_with(extension)
                {
                    file_name.push(extension);
                }

                let path = directory.join(file_name);
                if is_executable_file(&path) {
                    return Some(path);
                }
            }
        }
    }

    None
}

#[cfg(windows)]
fn executable_extensions() -> Vec<String> {
    let pathext = env::var_os("PATHEXT")
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_string());

    let mut extensions = vec![String::new()];
    extensions.extend(
        pathext
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(|extension| extension.to_ascii_lowercase()),
    );
    extensions
}

#[cfg(not(windows))]
fn executable_extensions() -> Vec<String> {
    vec![String::new()]
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityStatus {
    Available,
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub os: &'static str,
    pub symlink_files: CapabilityStatus,
    pub hardlinks: CapabilityStatus,
    pub long_paths: CapabilityStatus,
    pub case_sensitive_names: CapabilityStatus,
}

pub fn discover_platform_capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        os: env::consts::OS,
        symlink_files: detect_symlink_file_capability(),
        hardlinks: detect_hardlink_capability(),
        long_paths: detect_long_path_capability(),
        case_sensitive_names: detect_case_sensitive_name_capability(),
    }
}

fn detect_symlink_file_capability() -> CapabilityStatus {
    let Ok(temp) = FixtureTempDir::new("rsync-win-symlink") else {
        return CapabilityStatus::Unavailable {
            reason: "could not create temporary directory".to_string(),
        };
    };

    let target = temp.path().join("target.txt");
    let link = temp.path().join("link.txt");
    if let Err(err) = fs::write(&target, b"target") {
        return CapabilityStatus::Unavailable {
            reason: format!("could not create symlink probe target: {err}"),
        };
    }

    match create_file_symlink(&target, &link) {
        Ok(()) => CapabilityStatus::Available,
        Err(err) => CapabilityStatus::Unavailable {
            reason: err.to_string(),
        },
    }
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(any(windows, unix)))]
fn create_file_symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file symlink probe is not implemented for this platform",
    ))
}

fn detect_hardlink_capability() -> CapabilityStatus {
    let Ok(temp) = FixtureTempDir::new("rsync-win-hardlink") else {
        return CapabilityStatus::Unavailable {
            reason: "could not create temporary directory".to_string(),
        };
    };

    let source = temp.path().join("source.txt");
    let link = temp.path().join("link.txt");
    if let Err(err) = fs::write(&source, b"source") {
        return CapabilityStatus::Unavailable {
            reason: format!("could not create hardlink probe source: {err}"),
        };
    }

    match fs::hard_link(&source, &link) {
        Ok(()) => CapabilityStatus::Available,
        Err(err) => CapabilityStatus::Unavailable {
            reason: err.to_string(),
        },
    }
}

#[cfg(windows)]
fn detect_long_path_capability() -> CapabilityStatus {
    let Ok(temp) = FixtureTempDir::new("rsync-win-long-path") else {
        return CapabilityStatus::Unavailable {
            reason: "could not create temporary directory".to_string(),
        };
    };

    let mut long_path = temp.path().to_path_buf();
    while long_path.as_os_str().to_string_lossy().len() < 280 {
        long_path.push("segment0123456789");
    }

    match fs::create_dir_all(&long_path) {
        Ok(()) => CapabilityStatus::Available,
        Err(err) => CapabilityStatus::Unavailable {
            reason: err.to_string(),
        },
    }
}

#[cfg(not(windows))]
fn detect_long_path_capability() -> CapabilityStatus {
    CapabilityStatus::Available
}

fn detect_case_sensitive_name_capability() -> CapabilityStatus {
    let Ok(temp) = FixtureTempDir::new("rsync-win-case") else {
        return CapabilityStatus::Unavailable {
            reason: "could not create temporary directory".to_string(),
        };
    };

    let lower = temp.path().join("case-probe");
    let upper = temp.path().join("CASE-PROBE");

    if let Err(err) = fs::write(&lower, b"case") {
        return CapabilityStatus::Unavailable {
            reason: format!("could not create case-sensitivity probe file: {err}"),
        };
    }

    if upper.exists() {
        CapabilityStatus::Unavailable {
            reason: "temporary directory resolves names case-insensitively".to_string(),
        }
    } else {
        CapabilityStatus::Available
    }
}

#[derive(Debug)]
pub struct FixtureTempDir {
    path: PathBuf,
}

impl FixtureTempDir {
    pub fn new(prefix: &str) -> io::Result<Self> {
        let base = env::temp_dir();
        let process_id = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();

        for attempt in 0..100_u32 {
            let path = base.join(format!("{prefix}-{process_id}-{nanos}-{attempt}"));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique fixture temp directory",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FixtureTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn skip_external_test(name: &str, reason: Option<&str>) {
    eprintln!(
        "skipping external interop test `{name}`: {}",
        reason.unwrap_or("required command is unavailable")
    );
}
