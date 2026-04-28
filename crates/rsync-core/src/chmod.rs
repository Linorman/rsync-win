use std::str::FromStr;

use crate::{Result, RsyncCoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChmodRules {
    rules: Vec<ChmodRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChmodRule {
    target: ChmodTarget,
    mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChmodTarget {
    All,
    Files,
    Directories,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChmodFileKind {
    File,
    Directory,
}

impl ChmodRules {
    pub fn apply(&self, wire_mode: u32, kind: ChmodFileKind) -> u32 {
        let type_bits = wire_mode & !0o7777;
        let mut permissions = wire_mode & 0o7777;
        for rule in &self.rules {
            if rule.matches(kind) {
                permissions = rule.mode;
            }
        }
        type_bits | permissions
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl ChmodRule {
    fn matches(self, kind: ChmodFileKind) -> bool {
        matches!(
            (self.target, kind),
            (ChmodTarget::All, _)
                | (ChmodTarget::Files, ChmodFileKind::File)
                | (ChmodTarget::Directories, ChmodFileKind::Directory)
        )
    }
}

impl FromStr for ChmodRules {
    type Err = RsyncCoreError;

    fn from_str(value: &str) -> Result<Self> {
        let mut rules = Vec::new();
        for raw_part in value.split(',') {
            let part = raw_part.trim();
            if part.is_empty() {
                return Err(invalid_chmod(value, "empty chmod component"));
            }
            rules.push(parse_numeric_rule(value, part)?);
        }
        Ok(Self { rules })
    }
}

fn parse_numeric_rule(full: &str, part: &str) -> Result<ChmodRule> {
    let (target, digits) = match part.as_bytes().first().copied() {
        Some(b'F') | Some(b'f') => (ChmodTarget::Files, &part[1..]),
        Some(b'D') | Some(b'd') => (ChmodTarget::Directories, &part[1..]),
        _ => (ChmodTarget::All, part),
    };
    if !(3..=4).contains(&digits.len()) || !digits.chars().all(|ch| matches!(ch, '0'..='7')) {
        return Err(invalid_chmod(
            full,
            "supported subset accepts only numeric modes like 600, 0644, F600, or D755",
        ));
    }
    let mode = u32::from_str_radix(digits, 8).map_err(|_| {
        invalid_chmod(
            full,
            "supported subset accepts only octal permission digits",
        )
    })? & 0o7777;
    Ok(ChmodRule { target, mode })
}

fn invalid_chmod(value: &str, reason: impl Into<String>) -> RsyncCoreError {
    RsyncCoreError::InvalidArgument {
        name: "chmod",
        reason: format!("{}: `{value}`", reason.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chmod_accepts_supported_numeric_forms() {
        let all = "0644".parse::<ChmodRules>().unwrap();
        assert_eq!(all.apply(0o100755, ChmodFileKind::File), 0o100644);
        assert_eq!(all.apply(0o040755, ChmodFileKind::Directory), 0o040644);

        let split = "F600,D755".parse::<ChmodRules>().unwrap();
        assert_eq!(split.apply(0o100755, ChmodFileKind::File), 0o100600);
        assert_eq!(split.apply(0o040700, ChmodFileKind::Directory), 0o040755);
    }

    #[test]
    fn chmod_rejects_complex_symbolic_forms() {
        for expr in ["u+rw", "go-w", "Fugo+x", "F", "999"] {
            assert!(
                expr.parse::<ChmodRules>().is_err(),
                "{expr} should be rejected"
            );
        }
    }
}
