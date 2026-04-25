use std::fmt;
use std::path::{Component, Path};

use crate::matcher::normalize_filter_path;

pub fn parse_files_from(input: &str) -> Vec<String> {
    parse_line_records(input)
}

pub fn parse_files_from0(input: &[u8]) -> Result<Vec<String>, FilesFromError> {
    parse_files_from_bytes(input, true)
}

pub fn parse_files_from_bytes(input: &[u8], from0: bool) -> Result<Vec<String>, FilesFromError> {
    if from0 {
        parse_nul_records(input)
    } else {
        if let Some(offset) = input.iter().position(|byte| *byte == 0) {
            return Err(FilesFromError::UnexpectedNul { offset });
        }

        let text = std::str::from_utf8(input).map_err(|source| FilesFromError::InvalidUtf8 {
            offset: source.valid_up_to(),
        })?;
        Ok(parse_line_records(text))
    }
}

pub fn normalize_files_from_records<I, S>(records: I) -> Result<Vec<String>, FilesFromPathError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    records
        .into_iter()
        .map(|record| normalize_files_from_record(record.as_ref()))
        .collect()
}

pub fn normalize_files_from_record(record: &str) -> Result<String, FilesFromPathError> {
    let mut normalized = normalize_filter_path(record);
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped.to_owned();
    }
    if normalized.is_empty() {
        return Err(FilesFromPathError::Empty);
    }
    if normalized.as_bytes().contains(&0) {
        return Err(FilesFromPathError::NulByte {
            record: record.to_owned(),
        });
    }
    if normalized.starts_with('/') || normalized.contains(':') {
        return Err(FilesFromPathError::RootEscape {
            record: record.to_owned(),
        });
    }

    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FilesFromPathError::RootEscape {
                    record: record.to_owned(),
                });
            }
        }
    }

    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesFromError {
    InvalidUtf8 { offset: usize },
    UnexpectedNul { offset: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesFromPathError {
    Empty,
    NulByte { record: String },
    RootEscape { record: String },
}

impl fmt::Display for FilesFromError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilesFromError::InvalidUtf8 { offset } => {
                write!(f, "files-from input is not valid UTF-8 at byte {offset}")
            }
            FilesFromError::UnexpectedNul { offset } => {
                write!(
                    f,
                    "files-from input contains NUL at byte {offset}; use --from0"
                )
            }
        }
    }
}

impl std::error::Error for FilesFromError {}

impl fmt::Display for FilesFromPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilesFromPathError::Empty => write!(f, "files-from record is empty"),
            FilesFromPathError::NulByte { record } => {
                write!(f, "files-from record contains a NUL byte: `{record}`")
            }
            FilesFromPathError::RootEscape { record } => {
                write!(
                    f,
                    "files-from record must stay within the transfer root: `{record}`"
                )
            }
        }
    }
}

impl std::error::Error for FilesFromPathError {}

fn parse_line_records(input: &str) -> Vec<String> {
    input
        .split('\n')
        .map(strip_single_trailing_carriage_return)
        .filter(|record| !record.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_nul_records(input: &[u8]) -> Result<Vec<String>, FilesFromError> {
    let mut records = Vec::new();
    let mut offset = 0;

    for record in input.split(|byte| *byte == 0) {
        if !record.is_empty() {
            let text =
                std::str::from_utf8(record).map_err(|source| FilesFromError::InvalidUtf8 {
                    offset: offset + source.valid_up_to(),
                })?;
            records.push(text.to_owned());
        }
        offset += record.len() + 1;
    }

    Ok(records)
}

fn strip_single_trailing_carriage_return(record: &str) -> &str {
    record.strip_suffix('\r').unwrap_or(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_newline_separated_files_from_records() {
        let records = parse_files_from("src/lib.rs\nassets/logo.png\n");

        assert_eq!(records, vec!["src/lib.rs", "assets/logo.png"]);
    }

    #[test]
    fn preserves_spaces_and_strips_crlf_only() {
        let records = parse_files_from("My Documents/file name.txt\r\n trailing-space \n");

        assert_eq!(
            records,
            vec!["My Documents/file name.txt", " trailing-space "]
        );
    }

    #[test]
    fn parses_from0_records_without_treating_newline_specially() {
        let records = parse_files_from0(b"one\nline\0two words\0").unwrap();

        assert_eq!(records, vec!["one\nline", "two words"]);
    }

    #[test]
    fn ignores_empty_records() {
        assert!(parse_files_from("\n\r\n").is_empty());
        assert!(parse_files_from0(b"\0\0").unwrap().is_empty());
    }

    #[test]
    fn bytes_parser_rejects_nul_without_from0() {
        let error = parse_files_from_bytes(b"one\0two", false).unwrap_err();

        assert_eq!(error, FilesFromError::UnexpectedNul { offset: 3 });
    }

    #[test]
    fn bytes_parser_reports_utf8_offsets() {
        let line_error = parse_files_from_bytes(b"ok\n\xff", false).unwrap_err();
        let nul_error = parse_files_from0(b"ok\0\xff").unwrap_err();

        assert_eq!(line_error, FilesFromError::InvalidUtf8 { offset: 3 });
        assert_eq!(nul_error, FilesFromError::InvalidUtf8 { offset: 3 });
    }

    #[test]
    fn normalizes_files_from_paths_and_rejects_root_escape() {
        let records = normalize_files_from_records(["src\\main.rs", "./assets/logo.png"]).unwrap();

        assert_eq!(records, vec!["src/main.rs", "assets/logo.png"]);
        assert_eq!(
            normalize_files_from_record("../outside").unwrap_err(),
            FilesFromPathError::RootEscape {
                record: "../outside".to_owned()
            }
        );
        assert_eq!(
            normalize_files_from_record("/absolute").unwrap_err(),
            FilesFromPathError::RootEscape {
                record: "/absolute".to_owned()
            }
        );
        assert_eq!(
            normalize_files_from_record("C:/absolute").unwrap_err(),
            FilesFromPathError::RootEscape {
                record: "C:/absolute".to_owned()
            }
        );
    }
}
