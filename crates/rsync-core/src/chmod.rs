use std::str::FromStr;

use crate::{Result, RsyncCoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChmodRules {
    rules: Vec<ChmodRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChmodRule {
    target: ChmodTarget,
    action: ChmodAction,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChmodAction {
    Numeric(u32),
    Symbolic(SymbolicMode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SymbolicMode {
    who: WhoMask,
    op: SymbolicOp,
    perms: PermissionMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolicOp {
    Add,
    Remove,
    Set,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WhoMask(u8);

impl WhoMask {
    const USER: u8 = 0b001;
    const GROUP: u8 = 0b010;
    const OTHER: u8 = 0b100;
    const ALL: u8 = Self::USER | Self::GROUP | Self::OTHER;

    fn all() -> Self {
        Self(Self::ALL)
    }

    fn contains(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    fn permission_bits(self) -> u32 {
        let mut bits = 0;
        if self.contains(Self::USER) {
            bits |= 0o700;
        }
        if self.contains(Self::GROUP) {
            bits |= 0o070;
        }
        if self.contains(Self::OTHER) {
            bits |= 0o007;
        }
        bits
    }

    fn setid_bits(self) -> u32 {
        let mut bits = 0;
        if self.contains(Self::USER) {
            bits |= 0o4000;
        }
        if self.contains(Self::GROUP) {
            bits |= 0o2000;
        }
        bits
    }

    fn sticky_bits(self) -> u32 {
        if self.contains(Self::OTHER) || self.0 == Self::ALL {
            0o1000
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PermissionMask {
    read: bool,
    write: bool,
    exec: bool,
    conditional_exec: bool,
    setid: bool,
    sticky: bool,
    copy_user: bool,
    copy_group: bool,
    copy_other: bool,
}

impl ChmodRules {
    pub fn apply(&self, wire_mode: u32, kind: ChmodFileKind) -> u32 {
        let type_bits = wire_mode & !0o7777;
        let mut permissions = wire_mode & 0o7777;
        for rule in &self.rules {
            if rule.matches(kind) {
                permissions = rule.apply(permissions, kind);
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

    fn apply(self, permissions: u32, kind: ChmodFileKind) -> u32 {
        match self.action {
            ChmodAction::Numeric(mode) => mode,
            ChmodAction::Symbolic(symbolic) => symbolic.apply(permissions, kind),
        }
    }
}

impl SymbolicMode {
    fn apply(self, permissions: u32, kind: ChmodFileKind) -> u32 {
        let set_bits = self.perms.to_bits(self.who, permissions, kind);
        match self.op {
            SymbolicOp::Add => permissions | set_bits,
            SymbolicOp::Remove => permissions & !set_bits,
            SymbolicOp::Set => {
                let clear_bits =
                    self.who.permission_bits() | self.perms.special_clear_bits(self.who);
                (permissions & !clear_bits) | set_bits
            }
        }
    }
}

impl PermissionMask {
    fn is_empty(self) -> bool {
        !self.read
            && !self.write
            && !self.exec
            && !self.conditional_exec
            && !self.setid
            && !self.sticky
            && !self.copy_user
            && !self.copy_group
            && !self.copy_other
    }

    fn to_bits(self, who: WhoMask, permissions: u32, kind: ChmodFileKind) -> u32 {
        let mut bits = 0;
        if self.read {
            bits |= class_bits(who, 0o400, 0o040, 0o004);
        }
        if self.write {
            bits |= class_bits(who, 0o200, 0o020, 0o002);
        }
        if self.exec
            || (self.conditional_exec
                && (kind == ChmodFileKind::Directory || permissions & 0o111 != 0))
        {
            bits |= class_bits(who, 0o100, 0o010, 0o001);
        }
        if self.setid {
            bits |= who.setid_bits();
        }
        if self.sticky {
            bits |= who.sticky_bits();
        }
        if self.copy_user {
            bits |= copy_class_bits(who, permissions, 6);
        }
        if self.copy_group {
            bits |= copy_class_bits(who, permissions, 3);
        }
        if self.copy_other {
            bits |= copy_class_bits(who, permissions, 0);
        }
        bits
    }

    fn special_clear_bits(self, who: WhoMask) -> u32 {
        let mut bits = 0;
        if self.setid {
            bits |= who.setid_bits();
        }
        if self.sticky {
            bits |= who.sticky_bits();
        }
        bits
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
    if (1..=4).contains(&digits.len()) && digits.chars().all(|ch| matches!(ch, '0'..='7')) {
        let mode = u32::from_str_radix(digits, 8).map_err(|_| {
            invalid_chmod(
                full,
                "numeric modes must contain only octal permission digits",
            )
        })? & 0o7777;
        return Ok(ChmodRule {
            target,
            action: ChmodAction::Numeric(mode),
        });
    }

    parse_symbolic_rule(full, part)
}

fn parse_symbolic_rule(full: &str, part: &str) -> Result<ChmodRule> {
    let (target, expression) = match part.as_bytes().first().copied() {
        Some(b'F') | Some(b'f') => (ChmodTarget::Files, &part[1..]),
        Some(b'D') | Some(b'd') => (ChmodTarget::Directories, &part[1..]),
        _ => (ChmodTarget::All, part),
    };
    if expression.is_empty() {
        return Err(invalid_chmod(
            full,
            "missing chmod expression after file type prefix",
        ));
    }

    let (who, rest) = parse_who(expression);
    let Some(op_char) = rest.chars().next() else {
        return Err(invalid_chmod(full, "missing chmod operation"));
    };
    let permissions = &rest[op_char.len_utf8()..];
    let op = match op_char {
        '+' => SymbolicOp::Add,
        '-' => SymbolicOp::Remove,
        '=' => SymbolicOp::Set,
        _ => return Err(invalid_chmod(full, "expected chmod operation +, -, or =")),
    };
    let perms = parse_permissions(full, permissions)?;
    if perms.is_empty() && op != SymbolicOp::Set {
        return Err(invalid_chmod(
            full,
            "chmod + and - operations require at least one permission",
        ));
    }

    Ok(ChmodRule {
        target,
        action: ChmodAction::Symbolic(SymbolicMode { who, op, perms }),
    })
}

fn parse_who(expression: &str) -> (WhoMask, &str) {
    let mut who = 0;
    let mut split = 0;
    for (index, ch) in expression.char_indices() {
        match ch {
            'u' => who |= WhoMask::USER,
            'g' => who |= WhoMask::GROUP,
            'o' => who |= WhoMask::OTHER,
            'a' => who |= WhoMask::ALL,
            _ => {
                split = index;
                break;
            }
        }
        split = index + ch.len_utf8();
    }
    let who = if who == 0 {
        WhoMask::all()
    } else {
        WhoMask(who)
    };
    (who, &expression[split..])
}

fn parse_permissions(full: &str, permissions: &str) -> Result<PermissionMask> {
    let mut mask = PermissionMask::default();
    for ch in permissions.chars() {
        match ch {
            'r' => mask.read = true,
            'w' => mask.write = true,
            'x' => mask.exec = true,
            'X' => mask.conditional_exec = true,
            's' => mask.setid = true,
            't' => mask.sticky = true,
            'u' => mask.copy_user = true,
            'g' => mask.copy_group = true,
            'o' => mask.copy_other = true,
            _ => {
                return Err(invalid_chmod(
                    full,
                    format!("unsupported chmod permission `{ch}`"),
                ));
            }
        }
    }
    Ok(mask)
}

fn class_bits(who: WhoMask, user: u32, group: u32, other: u32) -> u32 {
    let mut bits = 0;
    if who.contains(WhoMask::USER) {
        bits |= user;
    }
    if who.contains(WhoMask::GROUP) {
        bits |= group;
    }
    if who.contains(WhoMask::OTHER) {
        bits |= other;
    }
    bits
}

fn copy_class_bits(who: WhoMask, permissions: u32, source_shift: u32) -> u32 {
    let source = (permissions >> source_shift) & 0o7;
    let mut bits = 0;
    if who.contains(WhoMask::USER) {
        bits |= source << 6;
    }
    if who.contains(WhoMask::GROUP) {
        bits |= source << 3;
    }
    if who.contains(WhoMask::OTHER) {
        bits |= source;
    }
    bits
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
    fn chmod_accepts_upstream_symbolic_examples() {
        let split = "Dug=rwx,Dgo=rx,Fu=rw,Fgo=r".parse::<ChmodRules>().unwrap();
        assert_eq!(split.apply(0o040700, ChmodFileKind::Directory), 0o040755);
        assert_eq!(split.apply(0o100777, ChmodFileKind::File), 0o100644);

        let layered = "u=rw,go=r,u+x,g-w,o-r".parse::<ChmodRules>().unwrap();
        assert_eq!(layered.apply(0o100000, ChmodFileKind::File), 0o100740);
    }

    #[test]
    fn chmod_symbolic_supports_conditional_execute_special_bits_and_copying() {
        let conditional = "a+X".parse::<ChmodRules>().unwrap();
        assert_eq!(conditional.apply(0o100644, ChmodFileKind::File), 0o100644);
        assert_eq!(conditional.apply(0o100744, ChmodFileKind::File), 0o100755);
        assert_eq!(
            conditional.apply(0o040644, ChmodFileKind::Directory),
            0o040755
        );

        let special = "u+s,g+s,o+t,a-st".parse::<ChmodRules>().unwrap();
        assert_eq!(special.apply(0o100777, ChmodFileKind::File), 0o100777);

        let copy = "g=u,o=g".parse::<ChmodRules>().unwrap();
        assert_eq!(copy.apply(0o100750, ChmodFileKind::File), 0o100777);
    }

    #[test]
    fn chmod_accepts_short_numeric_modes() {
        let rule = "F0,D755".parse::<ChmodRules>().unwrap();
        assert_eq!(rule.apply(0o100644, ChmodFileKind::File), 0o100000);
        assert_eq!(rule.apply(0o040000, ChmodFileKind::Directory), 0o040755);
    }

    #[test]
    fn chmod_rejects_invalid_forms() {
        for expr in ["F", "999", "u+q", "u", "+", "u+", "z+r"] {
            assert!(
                expr.parse::<ChmodRules>().is_err(),
                "{expr} should be rejected"
            );
        }
    }
}
