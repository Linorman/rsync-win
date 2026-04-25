use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsPathError {
    #[error("path must be relative and portable: {0}")]
    NotPortable(PathBuf),
    #[error("empty path component is not valid")]
    EmptyComponent,
    #[error("path component `{component}` contains invalid Windows character `{character}`")]
    InvalidCharacter { component: String, character: char },
    #[error("path component `{0}` is a reserved Windows device name")]
    ReservedName(String),
    #[error("path component `{0}` ends with a space or dot")]
    TrailingSpaceOrDot(String),
    #[error("case/normalization collision between `{first}` and `{second}`")]
    Collision { first: PathBuf, second: PathBuf },
}

pub fn validate_portable_relative_path(path: &Path) -> Result<(), WindowsPathError> {
    if path.as_os_str().is_empty() {
        return Err(WindowsPathError::NotPortable(path.to_path_buf()));
    }

    for component in path.components() {
        match component {
            Component::Normal(name) => validate_portable_component(name)?,
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(WindowsPathError::NotPortable(path.to_path_buf()));
            }
        }
    }

    Ok(())
}

pub fn validate_portable_component(component: &OsStr) -> Result<(), WindowsPathError> {
    let component = component.to_string_lossy();
    if component.is_empty() {
        return Err(WindowsPathError::EmptyComponent);
    }

    for character in component.chars() {
        if is_invalid_windows_character(character) || character.is_control() {
            return Err(WindowsPathError::InvalidCharacter {
                component: component.into_owned(),
                character,
            });
        }
    }

    if component.ends_with(' ') || component.ends_with('.') {
        return Err(WindowsPathError::TrailingSpaceOrDot(component.into_owned()));
    }

    if is_reserved_name(&component) {
        return Err(WindowsPathError::ReservedName(component.into_owned()));
    }

    Ok(())
}

pub fn preflight_destination_paths<I, P>(paths: I) -> Result<(), WindowsPathError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut seen = BTreeMap::<String, PathBuf>::new();

    for path in paths {
        let path = path.as_ref();
        validate_portable_relative_path(path)?;
        let key = collision_key(path);
        if let Some(first) = seen.get(&key) {
            return Err(WindowsPathError::Collision {
                first: first.clone(),
                second: path.to_path_buf(),
            });
        }
        seen.insert(key, path.to_path_buf());
    }

    Ok(())
}

pub fn to_long_path_safe(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::Prefix;

        let text = path.as_os_str().to_string_lossy();
        if text.starts_with(r"\\?\") {
            return path.to_path_buf();
        }

        if let Ok(stripped) = path.strip_prefix(r"\\") {
            return PathBuf::from(format!(r"\\?\UNC\{}", stripped.display()));
        }

        if path.is_absolute() {
            return PathBuf::from(format!(r"\\?\{}", path.display()));
        }

        if let Some(Component::Prefix(prefix)) = path.components().next() {
            if matches!(prefix.kind(), Prefix::Verbatim(_) | Prefix::VerbatimDisk(_)) {
                return path.to_path_buf();
            }
        }
    }

    path.to_path_buf()
}

fn collision_key(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(
                name.to_string_lossy()
                    .nfc()
                    .flat_map(char::to_lowercase)
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_invalid_windows_character(character: char) -> bool {
    matches!(
        character,
        '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
    )
}

fn is_reserved_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(component)
        .trim_end_matches(' ')
        .to_ascii_uppercase();

    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || is_numbered_reserved(&stem, "COM")
        || is_numbered_reserved(&stem, "LPT")
}

fn is_numbered_reserved(stem: &str, prefix: &str) -> bool {
    let Some(number) = stem.strip_prefix(prefix) else {
        return false;
    };
    matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_reserved_and_invalid_names() {
        assert!(matches!(
            validate_portable_relative_path(Path::new("CON.txt")),
            Err(WindowsPathError::ReservedName(_))
        ));
        assert!(matches!(
            validate_portable_relative_path(Path::new("bad:name.txt")),
            Err(WindowsPathError::InvalidCharacter { .. })
        ));
        assert!(matches!(
            validate_portable_relative_path(Path::new("bad.")),
            Err(WindowsPathError::TrailingSpaceOrDot(_))
        ));
    }

    #[test]
    fn rejects_root_and_parent_escape() {
        assert!(matches!(
            validate_portable_relative_path(Path::new("../x")),
            Err(WindowsPathError::NotPortable(_))
        ));
        assert!(matches!(
            validate_portable_relative_path(Path::new(r"\absolute")),
            Err(WindowsPathError::NotPortable(_))
        ));
    }

    #[test]
    fn detects_case_and_unicode_normalization_collisions() {
        let err = preflight_destination_paths([
            PathBuf::from("dir/Foo.txt"),
            PathBuf::from("dir/foo.txt"),
        ])
        .unwrap_err();
        assert!(matches!(err, WindowsPathError::Collision { .. }));

        let err = preflight_destination_paths([
            PathBuf::from("caf\u{00e9}.txt"),
            PathBuf::from("cafe\u{0301}.txt"),
        ])
        .unwrap_err();
        assert!(matches!(err, WindowsPathError::Collision { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn prefixes_absolute_paths_for_long_path_safe_access() {
        let path = to_long_path_safe(Path::new(r"C:\temp\rsync-win\file.txt"));

        assert!(path.as_os_str().to_string_lossy().starts_with(r"\\?\"));
    }
}
