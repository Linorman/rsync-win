use std::path::PathBuf;

use rsync_fs::FileType;
use thiserror::Error;

use crate::security::SecurityDescriptorSummary;
use crate::streams::AlternateDataStream;
use crate::vss::{vss_snapshot_status, VssSnapshotStatus};

pub const NTFS_SIDECAR_HEADER: &str = "rsync-win ntfs-native sidecar v1";
pub const POSIX_FAKE_SUPER_SIDECAR_HEADER: &str = "rsync-win posix fake-super sidecar v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsNativeSidecar {
    pub path: PathBuf,
    pub file_type: FileType,
    pub len: u64,
    pub modified_unix_nanos: Option<i128>,
    pub creation_time_unix_nanos: Option<i128>,
    pub attributes: Option<u32>,
    pub sparse_file: bool,
    pub reparse_tag: Option<u32>,
    pub file_id: Option<u64>,
    pub volume_serial: Option<u32>,
    pub link_count: Option<u64>,
    pub security: SecurityDescriptorSummary,
    pub streams: Vec<AlternateDataStream>,
    pub vss: VssSnapshotStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsNativeSidecarManifest {
    pub sidecar: NtfsNativeSidecar,
    pub unknown_fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixAclRecord {
    pub tag: String,
    pub qualifier: Option<String>,
    pub perms: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixXattrRecord {
    pub name: String,
    pub value_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixFakeSuperSidecar {
    pub path: PathBuf,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub user_name: Option<String>,
    pub group_name: Option<String>,
    pub access_time_unix_nanos: Option<i128>,
    pub creation_time_unix_nanos: Option<i128>,
    pub acls: Vec<PosixAclRecord>,
    pub xattrs: Vec<PosixXattrRecord>,
    pub fake_super: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixFakeSuperSidecarManifest {
    pub sidecar: PosixFakeSuperSidecar,
    pub unknown_fields: Vec<(String, String)>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SidecarParseError {
    #[error("missing or invalid NTFS sidecar header")]
    InvalidHeader,
    #[error("missing required NTFS sidecar field `{0}`")]
    MissingField(&'static str),
    #[error("invalid NTFS sidecar field `{field}`: {value}")]
    InvalidField { field: &'static str, value: String },
    #[error("invalid NTFS sidecar line: {0}")]
    InvalidLine(String),
}

impl NtfsNativeSidecar {
    pub fn manifest(&self) -> String {
        let mut output = String::new();
        output.push_str(NTFS_SIDECAR_HEADER);
        output.push('\n');
        output.push_str(&format!("path={}\n", self.path.display()));
        output.push_str(&format!("file_type={}\n", file_type_label(self.file_type)));
        output.push_str(&format!("len={}\n", self.len));
        output.push_str(&format!(
            "modified={}\n",
            format_option(self.modified_unix_nanos)
        ));
        output.push_str(&format!(
            "creation_time={}\n",
            format_option(self.creation_time_unix_nanos)
        ));
        output.push_str(&format!("attributes={}\n", format_option(self.attributes)));
        output.push_str(&format!("sparse_file={}\n", self.sparse_file));
        output.push_str(&format!(
            "reparse_tag={}\n",
            format_option(self.reparse_tag)
        ));
        output.push_str(&format!("file_id={}\n", format_option(self.file_id)));
        output.push_str(&format!(
            "volume_serial={}\n",
            format_option(self.volume_serial)
        ));
        output.push_str(&format!("link_count={}\n", format_option(self.link_count)));
        output.push_str(&format!("security_captured={}\n", self.security.captured));
        output.push_str(&format!(
            "security_len={}\n",
            format_option(self.security.byte_len)
        ));
        output.push_str(&format!(
            "security_hash={}\n",
            self.security.stable_hash.as_deref().unwrap_or("none")
        ));
        output.push_str(&format!("streams={}\n", self.streams.len()));
        for stream in &self.streams {
            output.push_str(&format!("stream={},{}\n", stream.name, stream.size));
        }
        output.push_str(&format!("vss_requested={}\n", self.vss.requested));
        output.push_str(&format!("vss_available={}\n", self.vss.available));
        output
    }
}

impl PosixFakeSuperSidecar {
    pub fn manifest(&self) -> String {
        let mut output = String::new();
        output.push_str(POSIX_FAKE_SUPER_SIDECAR_HEADER);
        output.push('\n');
        output.push_str(&format!("path={}\n", self.path.display()));
        output.push_str(&format!("mode={}\n", format_octal_option(self.mode)));
        output.push_str(&format!("uid={}\n", format_option(self.uid)));
        output.push_str(&format!("gid={}\n", format_option(self.gid)));
        output.push_str(&format!(
            "user_name={}\n",
            format_string_option(&self.user_name)
        ));
        output.push_str(&format!(
            "group_name={}\n",
            format_string_option(&self.group_name)
        ));
        output.push_str(&format!(
            "access_time={}\n",
            format_option(self.access_time_unix_nanos)
        ));
        output.push_str(&format!(
            "creation_time={}\n",
            format_option(self.creation_time_unix_nanos)
        ));
        output.push_str(&format!("acls={}\n", self.acls.len()));
        for acl in &self.acls {
            output.push_str(&format!(
                "acl={},{},{}\n",
                acl.tag,
                acl.qualifier.as_deref().unwrap_or("none"),
                acl.perms
            ));
        }
        output.push_str(&format!("xattrs={}\n", self.xattrs.len()));
        for xattr in &self.xattrs {
            output.push_str(&format!("xattr={},{}\n", xattr.name, xattr.value_hex));
        }
        output.push_str(&format!("fake_super={}\n", self.fake_super));
        output
    }
}

pub fn parse_ntfs_native_sidecar_manifest(
    input: &str,
) -> Result<NtfsNativeSidecarManifest, SidecarParseError> {
    let mut lines = input.lines();
    if lines.next() != Some(NTFS_SIDECAR_HEADER) {
        return Err(SidecarParseError::InvalidHeader);
    }

    let mut fields = ParsedFields::default();
    let mut streams = Vec::new();
    let mut unknown_fields = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| SidecarParseError::InvalidLine(line.to_string()))?;
        match key {
            "path" => fields.path = Some(PathBuf::from(value)),
            "file_type" => fields.file_type = Some(parse_file_type(value)?),
            "len" => fields.len = Some(parse_u64("len", value)?),
            "modified" => fields.modified = parse_option_i128("modified", value)?,
            "creation_time" => {
                fields.creation_time = parse_option_i128("creation_time", value)?;
            }
            "attributes" => fields.attributes = parse_option_u32("attributes", value)?,
            "sparse_file" => fields.sparse_file = Some(parse_bool("sparse_file", value)?),
            "reparse_tag" => fields.reparse_tag = parse_option_u32("reparse_tag", value)?,
            "file_id" => fields.file_id = parse_option_u64("file_id", value)?,
            "volume_serial" => fields.volume_serial = parse_option_u32("volume_serial", value)?,
            "link_count" => fields.link_count = parse_option_u64("link_count", value)?,
            "security_captured" => {
                fields.security_captured = Some(parse_bool("security_captured", value)?);
            }
            "security_len" => fields.security_len = parse_option_u32("security_len", value)?,
            "security_hash" => fields.security_hash = parse_option_string(value),
            "streams" => fields.stream_count = Some(parse_u64("streams", value)? as usize),
            "stream" => streams.push(parse_stream(value)?),
            "vss_requested" => fields.vss_requested = Some(parse_bool("vss_requested", value)?),
            "vss_available" => fields.vss_available = Some(parse_bool("vss_available", value)?),
            _ => unknown_fields.push((key.to_string(), value.to_string())),
        }
    }

    if let Some(expected) = fields.stream_count {
        if expected != streams.len() {
            return Err(SidecarParseError::InvalidField {
                field: "streams",
                value: format!("expected {expected}, found {}", streams.len()),
            });
        }
    }

    let requested = required(fields.vss_requested, "vss_requested")?;
    let available = required(fields.vss_available, "vss_available")?;
    let mut vss = vss_snapshot_status(requested);
    vss.available = available;

    Ok(NtfsNativeSidecarManifest {
        sidecar: NtfsNativeSidecar {
            path: required(fields.path, "path")?,
            file_type: required(fields.file_type, "file_type")?,
            len: required(fields.len, "len")?,
            modified_unix_nanos: fields.modified,
            creation_time_unix_nanos: fields.creation_time,
            attributes: fields.attributes,
            sparse_file: required(fields.sparse_file, "sparse_file")?,
            reparse_tag: fields.reparse_tag,
            file_id: fields.file_id,
            volume_serial: fields.volume_serial,
            link_count: fields.link_count,
            security: SecurityDescriptorSummary {
                captured: required(fields.security_captured, "security_captured")?,
                byte_len: fields.security_len,
                stable_hash: fields.security_hash,
                message: None,
            },
            streams,
            vss,
        },
        unknown_fields,
    })
}

pub fn parse_posix_fake_super_sidecar_manifest(
    input: &str,
) -> Result<PosixFakeSuperSidecarManifest, SidecarParseError> {
    let mut lines = input.lines();
    if lines.next() != Some(POSIX_FAKE_SUPER_SIDECAR_HEADER) {
        return Err(SidecarParseError::InvalidHeader);
    }

    let mut fields = PosixParsedFields::default();
    let mut acls = Vec::new();
    let mut xattrs = Vec::new();
    let mut unknown_fields = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| SidecarParseError::InvalidLine(line.to_string()))?;
        match key {
            "path" => fields.path = Some(PathBuf::from(value)),
            "mode" => fields.mode = parse_option_octal_u32("mode", value)?,
            "uid" => fields.uid = parse_option_u32("uid", value)?,
            "gid" => fields.gid = parse_option_u32("gid", value)?,
            "user_name" => fields.user_name = parse_option_string(value),
            "group_name" => fields.group_name = parse_option_string(value),
            "access_time" => fields.access_time = parse_option_i128("access_time", value)?,
            "creation_time" => {
                fields.creation_time = parse_option_i128("creation_time", value)?;
            }
            "acls" => fields.acl_count = Some(parse_u64("acls", value)? as usize),
            "acl" => acls.push(parse_acl(value)?),
            "xattrs" => fields.xattr_count = Some(parse_u64("xattrs", value)? as usize),
            "xattr" => xattrs.push(parse_xattr(value)?),
            "fake_super" => fields.fake_super = Some(parse_bool("fake_super", value)?),
            _ => unknown_fields.push((key.to_string(), value.to_string())),
        }
    }

    if let Some(expected) = fields.acl_count {
        if expected != acls.len() {
            return Err(SidecarParseError::InvalidField {
                field: "acls",
                value: format!("expected {expected}, found {}", acls.len()),
            });
        }
    }
    if let Some(expected) = fields.xattr_count {
        if expected != xattrs.len() {
            return Err(SidecarParseError::InvalidField {
                field: "xattrs",
                value: format!("expected {expected}, found {}", xattrs.len()),
            });
        }
    }

    Ok(PosixFakeSuperSidecarManifest {
        sidecar: PosixFakeSuperSidecar {
            path: required(fields.path, "path")?,
            mode: fields.mode,
            uid: fields.uid,
            gid: fields.gid,
            user_name: fields.user_name,
            group_name: fields.group_name,
            access_time_unix_nanos: fields.access_time,
            creation_time_unix_nanos: fields.creation_time,
            acls,
            xattrs,
            fake_super: required(fields.fake_super, "fake_super")?,
        },
        unknown_fields,
    })
}

#[derive(Debug, Default)]
struct ParsedFields {
    path: Option<PathBuf>,
    file_type: Option<FileType>,
    len: Option<u64>,
    modified: Option<i128>,
    creation_time: Option<i128>,
    attributes: Option<u32>,
    sparse_file: Option<bool>,
    reparse_tag: Option<u32>,
    file_id: Option<u64>,
    volume_serial: Option<u32>,
    link_count: Option<u64>,
    security_captured: Option<bool>,
    security_len: Option<u32>,
    security_hash: Option<String>,
    stream_count: Option<usize>,
    vss_requested: Option<bool>,
    vss_available: Option<bool>,
}

#[derive(Debug, Default)]
struct PosixParsedFields {
    path: Option<PathBuf>,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    user_name: Option<String>,
    group_name: Option<String>,
    access_time: Option<i128>,
    creation_time: Option<i128>,
    acl_count: Option<usize>,
    xattr_count: Option<usize>,
    fake_super: Option<bool>,
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, SidecarParseError> {
    value.ok_or(SidecarParseError::MissingField(field))
}

fn file_type_label(file_type: FileType) -> &'static str {
    match file_type {
        FileType::File => "File",
        FileType::Directory => "Directory",
        FileType::Symlink => "Symlink",
        FileType::Hardlink => "Hardlink",
        FileType::Device => "Device",
        FileType::Special => "Special",
        FileType::Other => "Other",
    }
}

fn parse_file_type(value: &str) -> Result<FileType, SidecarParseError> {
    match value {
        "File" => Ok(FileType::File),
        "Directory" => Ok(FileType::Directory),
        "Symlink" => Ok(FileType::Symlink),
        "Hardlink" => Ok(FileType::Hardlink),
        "Device" => Ok(FileType::Device),
        "Special" => Ok(FileType::Special),
        "Other" => Ok(FileType::Other),
        _ => Err(invalid("file_type", value)),
    }
}

fn format_option<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn format_octal_option(value: Option<u32>) -> String {
    value
        .map(|value| format!("{value:o}"))
        .unwrap_or_else(|| "none".to_string())
}

fn format_string_option(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("none")
}

fn parse_option_string(value: &str) -> Option<String> {
    if value == "none" || value == "None" {
        None
    } else if let Some(inner) = value.strip_prefix("Some(\"") {
        inner.strip_suffix("\")").map(str::to_string)
    } else {
        Some(value.to_string())
    }
}

fn parse_option_i128(field: &'static str, value: &str) -> Result<Option<i128>, SidecarParseError> {
    parse_option_with(field, value, |inner| {
        inner.parse::<i128>().map_err(|_| invalid(field, value))
    })
}

fn parse_option_u64(field: &'static str, value: &str) -> Result<Option<u64>, SidecarParseError> {
    parse_option_with(field, value, |inner| {
        inner.parse::<u64>().map_err(|_| invalid(field, value))
    })
}

fn parse_option_u32(field: &'static str, value: &str) -> Result<Option<u32>, SidecarParseError> {
    parse_option_with(field, value, |inner| {
        inner.parse::<u32>().map_err(|_| invalid(field, value))
    })
}

fn parse_option_octal_u32(
    field: &'static str,
    value: &str,
) -> Result<Option<u32>, SidecarParseError> {
    parse_option_with(field, value, |inner| {
        u32::from_str_radix(inner, 8).map_err(|_| invalid(field, value))
    })
}

fn parse_option_with<T>(
    field: &'static str,
    value: &str,
    parse: impl FnOnce(&str) -> Result<T, SidecarParseError>,
) -> Result<Option<T>, SidecarParseError> {
    if value == "none" || value == "None" {
        return Ok(None);
    }
    if let Some(inner) = value
        .strip_prefix("Some(")
        .and_then(|v| v.strip_suffix(')'))
    {
        return parse(inner).map(Some);
    }
    parse(value).map(Some).map_err(|_| invalid(field, value))
}

fn parse_u64(field: &'static str, value: &str) -> Result<u64, SidecarParseError> {
    value.parse::<u64>().map_err(|_| invalid(field, value))
}

fn parse_bool(field: &'static str, value: &str) -> Result<bool, SidecarParseError> {
    value.parse::<bool>().map_err(|_| invalid(field, value))
}

fn parse_stream(value: &str) -> Result<AlternateDataStream, SidecarParseError> {
    let (name, size) = value
        .rsplit_once(',')
        .ok_or_else(|| invalid("stream", value))?;
    if name.is_empty() {
        return Err(invalid("stream", value));
    }
    Ok(AlternateDataStream {
        name: name.to_string(),
        size: parse_u64("stream", size)?,
    })
}

fn parse_acl(value: &str) -> Result<PosixAclRecord, SidecarParseError> {
    let parts = value.split(',').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0].is_empty() || parts[2].is_empty() {
        return Err(invalid("acl", value));
    }
    Ok(PosixAclRecord {
        tag: parts[0].to_string(),
        qualifier: (parts[1] != "none").then(|| parts[1].to_string()),
        perms: parts[2].to_string(),
    })
}

fn parse_xattr(value: &str) -> Result<PosixXattrRecord, SidecarParseError> {
    let (name, value_hex) = value
        .rsplit_once(',')
        .ok_or_else(|| invalid("xattr", value))?;
    if name.is_empty()
        || value_hex.len() % 2 != 0
        || !value_hex.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(invalid("xattr", value));
    }
    Ok(PosixXattrRecord {
        name: name.to_string(),
        value_hex: value_hex.to_string(),
    })
}

fn invalid(field: &'static str, value: &str) -> SidecarParseError {
    SidecarParseError::InvalidField {
        field,
        value: value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sidecar() -> NtfsNativeSidecar {
        NtfsNativeSidecar {
            path: PathBuf::from("file.txt"),
            file_type: FileType::File,
            len: 3,
            modified_unix_nanos: Some(123),
            creation_time_unix_nanos: None,
            attributes: Some(32),
            sparse_file: false,
            reparse_tag: None,
            file_id: Some(99),
            volume_serial: Some(7),
            link_count: Some(1),
            security: SecurityDescriptorSummary {
                captured: true,
                byte_len: Some(12),
                stable_hash: Some("abcd".to_string()),
                message: None,
            },
            streams: vec![AlternateDataStream {
                name: "Zone.Identifier".to_string(),
                size: 26,
            }],
            vss: VssSnapshotStatus {
                requested: true,
                available: false,
                message: "not implemented".to_string(),
            },
        }
    }

    #[test]
    fn sidecar_manifest_round_trips_current_fields() {
        let sidecar = sample_sidecar();
        let parsed = parse_ntfs_native_sidecar_manifest(&sidecar.manifest()).unwrap();

        assert_eq!(parsed.sidecar.path, sidecar.path);
        assert_eq!(parsed.sidecar.file_type, sidecar.file_type);
        assert_eq!(parsed.sidecar.len, sidecar.len);
        assert_eq!(parsed.sidecar.modified_unix_nanos, Some(123));
        assert_eq!(parsed.sidecar.creation_time_unix_nanos, None);
        assert_eq!(parsed.sidecar.attributes, Some(32));
        assert_eq!(parsed.sidecar.streams, sidecar.streams);
        assert_eq!(parsed.sidecar.vss.requested, sidecar.vss.requested);
        assert_eq!(parsed.sidecar.vss.available, sidecar.vss.available);
        assert!(parsed.unknown_fields.is_empty());
    }

    #[test]
    fn sidecar_parser_accepts_old_option_spellings_and_unknown_fields() {
        let manifest = "\
rsync-win ntfs-native sidecar v1
path=file.txt
file_type=File
len=3
modified=Some(123)
creation_time=None
attributes=Some(32)
sparse_file=false
reparse_tag=None
file_id=Some(99)
volume_serial=Some(7)
link_count=Some(1)
security_captured=true
security_len=Some(12)
security_hash=Some(\"abcd\")
streams=1
stream=Zone.Identifier,26
future_field=value
vss_requested=false
vss_available=false
";

        let parsed = parse_ntfs_native_sidecar_manifest(manifest).unwrap();

        assert_eq!(parsed.sidecar.modified_unix_nanos, Some(123));
        assert_eq!(parsed.sidecar.creation_time_unix_nanos, None);
        assert_eq!(parsed.sidecar.security.stable_hash.as_deref(), Some("abcd"));
        assert_eq!(
            parsed.unknown_fields,
            vec![("future_field".to_string(), "value".to_string())]
        );
    }

    #[test]
    fn sidecar_parser_rejects_missing_required_fields_and_bad_numbers() {
        assert!(matches!(
            parse_ntfs_native_sidecar_manifest(NTFS_SIDECAR_HEADER),
            Err(SidecarParseError::MissingField("vss_requested"))
        ));

        let mut manifest = sample_sidecar().manifest();
        manifest = manifest.replace("len=3", "len=abc");
        assert!(matches!(
            parse_ntfs_native_sidecar_manifest(&manifest),
            Err(SidecarParseError::InvalidField { field: "len", .. })
        ));
    }

    #[test]
    fn posix_fake_super_sidecar_round_trips_acl_xattr_and_time_fields() {
        let sidecar = PosixFakeSuperSidecar {
            path: PathBuf::from("dir/file.txt"),
            mode: Some(0o100640),
            uid: Some(1000),
            gid: Some(100),
            user_name: Some("alice".to_string()),
            group_name: Some("staff".to_string()),
            access_time_unix_nanos: Some(1_700_000_000_000_000_001),
            creation_time_unix_nanos: Some(1_700_000_000_000_000_002),
            acls: vec![PosixAclRecord {
                tag: "user".to_string(),
                qualifier: Some("alice".to_string()),
                perms: "rwx".to_string(),
            }],
            xattrs: vec![PosixXattrRecord {
                name: "user.comment".to_string(),
                value_hex: "68656c6c6f".to_string(),
            }],
            fake_super: true,
        };

        let parsed = parse_posix_fake_super_sidecar_manifest(&sidecar.manifest()).unwrap();

        assert_eq!(parsed.sidecar, sidecar);
        assert!(parsed.unknown_fields.is_empty());
    }
}
