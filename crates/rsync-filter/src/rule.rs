use std::fmt;

use crate::matcher::{glob_matches, normalize_filter_path, EntryKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Include,
    Exclude,
    Hide,
    Show,
    Protect,
    Risk,
    ClearList,
    Merge,
    DirMerge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSide {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    action: RuleAction,
    pattern: Option<Pattern>,
    sender_side: bool,
    receiver_side: bool,
    perishable: bool,
}

impl Rule {
    pub fn include(pattern: impl Into<String>) -> Result<Self, ParseRuleError> {
        Self::new(RuleAction::Include, pattern)
    }

    pub fn exclude(pattern: impl Into<String>) -> Result<Self, ParseRuleError> {
        Self::new(RuleAction::Exclude, pattern)
    }

    pub fn protect(pattern: impl Into<String>) -> Result<Self, ParseRuleError> {
        Self::new(RuleAction::Protect, pattern)
    }

    pub fn risk(pattern: impl Into<String>) -> Result<Self, ParseRuleError> {
        Self::new(RuleAction::Risk, pattern)
    }

    pub fn new(action: RuleAction, pattern: impl Into<String>) -> Result<Self, ParseRuleError> {
        let (sender_side, receiver_side) = default_sides(action);
        Ok(Self {
            action,
            pattern: Some(Pattern::parse(pattern.into())?),
            sender_side,
            receiver_side,
            perishable: false,
        })
    }

    pub fn parse_filter(input: &str) -> Result<Self, ParseRuleError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ParseRuleError::EmptyRule);
        }

        if trimmed == "!" {
            return Ok(Self::without_pattern(
                RuleAction::ClearList,
                ModifierState::default(),
            ));
        }

        let (head, pattern) = split_rule_head(trimmed)?;
        let (action, modifiers) = parse_rule_head(head)?;
        if action == RuleAction::ClearList {
            return Ok(Self::without_pattern(action, modifiers));
        }
        Self::with_modifiers(action, pattern, modifiers)
    }

    pub fn parse_filter_file(
        input: &[u8],
        from0: bool,
        default_action: RuleAction,
    ) -> Result<Vec<Self>, ParseRuleError> {
        let records = parse_filter_records(input, from0)?;
        let mut rules = Vec::new();
        for record in records {
            let Some(record) = normalize_filter_record(&record) else {
                continue;
            };
            let rule = if starts_with_explicit_rule(&record) {
                Self::parse_filter(&record)?
            } else {
                Self::new(default_action, record)?
            };
            rules.push(rule);
        }
        Ok(rules)
    }

    pub fn action(&self) -> RuleAction {
        self.action
    }

    pub fn pattern(&self) -> &Pattern {
        self.pattern
            .as_ref()
            .expect("filter rule action does not carry a pattern")
    }

    pub fn is_sender_side(&self) -> bool {
        self.sender_side
    }

    pub fn is_receiver_side(&self) -> bool {
        self.receiver_side
    }

    pub fn is_perishable(&self) -> bool {
        self.perishable
    }

    pub fn applies_to(&self, side: RuleSide) -> bool {
        match side {
            RuleSide::Sender => self.sender_side,
            RuleSide::Receiver => self.receiver_side,
        }
    }

    pub fn matches(&self, path: &str, kind: EntryKind) -> bool {
        self.pattern
            .as_ref()
            .is_some_and(|pattern| pattern.matches(path, kind))
    }

    fn with_modifiers(
        action: RuleAction,
        pattern: &str,
        modifiers: ModifierState,
    ) -> Result<Self, ParseRuleError> {
        let (mut sender_side, mut receiver_side) = default_sides(action);
        if modifiers.sender_side || modifiers.receiver_side {
            sender_side = modifiers.sender_side;
            receiver_side = modifiers.receiver_side;
        }
        Ok(Self {
            action,
            pattern: Some(Pattern::parse(pattern.to_owned())?),
            sender_side,
            receiver_side,
            perishable: modifiers.perishable,
        })
    }

    fn without_pattern(action: RuleAction, modifiers: ModifierState) -> Self {
        let (mut sender_side, mut receiver_side) = default_sides(action);
        if modifiers.sender_side || modifiers.receiver_side {
            sender_side = modifiers.sender_side;
            receiver_side = modifiers.receiver_side;
        }
        Self {
            action,
            pattern: None,
            sender_side,
            receiver_side,
            perishable: modifiers.perishable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    raw: String,
    body: String,
    anchored: bool,
    directory_only: bool,
    has_path_separator: bool,
    match_directory_prefix: Option<String>,
}

impl Pattern {
    pub fn parse(raw: String) -> Result<Self, ParseRuleError> {
        let raw = raw.trim().to_owned();
        if raw.is_empty() {
            return Err(ParseRuleError::MissingPattern);
        }

        let mut body = normalize_filter_path(&raw);
        let anchored = body.starts_with('/');
        if anchored {
            body.remove(0);
        }

        let directory_only = body.ends_with('/');
        if directory_only {
            body.pop();
        }

        while let Some(stripped) = body.strip_prefix("./") {
            body = stripped.to_owned();
        }

        if body.is_empty() {
            return Err(ParseRuleError::EmptyPattern);
        }

        let match_directory_prefix = body.strip_suffix("/***").map(str::to_owned);
        Ok(Self {
            raw,
            has_path_separator: body.contains('/'),
            body,
            anchored,
            directory_only,
            match_directory_prefix,
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn is_anchored(&self) -> bool {
        self.anchored
    }

    pub fn is_directory_only(&self) -> bool {
        self.directory_only
    }

    pub fn has_path_separator(&self) -> bool {
        self.has_path_separator
    }

    pub fn matches(&self, path: &str, kind: EntryKind) -> bool {
        if self.directory_only && kind != EntryKind::Directory {
            return false;
        }

        let path = normalize_candidate_path(path);
        if path.is_empty() {
            return false;
        }

        if kind == EntryKind::Directory
            && self
                .match_directory_prefix
                .as_ref()
                .is_some_and(|prefix| path == *prefix)
        {
            return true;
        }

        if self.anchored {
            return glob_matches(&self.body, &path);
        }

        if self.has_path_separator || self.body.contains("**") {
            return path_suffixes(&path).any(|suffix| glob_matches(&self.body, suffix));
        }

        path.rsplit('/')
            .next()
            .is_some_and(|basename| glob_matches(&self.body, basename))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseRuleError {
    EmptyRule,
    MissingPattern,
    EmptyPattern,
    UnknownRule(String),
    InvalidModifier(char),
    InvalidUtf8 { offset: usize },
    UnexpectedNul { offset: usize },
}

impl fmt::Display for ParseRuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseRuleError::EmptyRule => write!(f, "filter rule is empty"),
            ParseRuleError::MissingPattern => write!(f, "filter rule is missing a pattern"),
            ParseRuleError::EmptyPattern => write!(f, "filter rule pattern is empty"),
            ParseRuleError::UnknownRule(rule) => {
                write!(f, "unknown filter rule syntax `{rule}`")
            }
            ParseRuleError::InvalidModifier(modifier) => {
                write!(f, "invalid filter rule modifier `{modifier}`")
            }
            ParseRuleError::InvalidUtf8 { offset } => {
                write!(f, "filter file input is not valid UTF-8 at byte {offset}")
            }
            ParseRuleError::UnexpectedNul { offset } => {
                write!(
                    f,
                    "filter file input contains NUL at byte {offset}; use --from0"
                )
            }
        }
    }
}

impl std::error::Error for ParseRuleError {}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ModifierState {
    sender_side: bool,
    receiver_side: bool,
    perishable: bool,
}

fn default_sides(action: RuleAction) -> (bool, bool) {
    match action {
        RuleAction::Hide | RuleAction::Show => (true, false),
        RuleAction::Protect | RuleAction::Risk => (false, true),
        RuleAction::Include
        | RuleAction::Exclude
        | RuleAction::ClearList
        | RuleAction::Merge
        | RuleAction::DirMerge => (true, true),
    }
}

fn split_rule_head(input: &str) -> Result<(&str, &str), ParseRuleError> {
    let Some((head, pattern)) = input.split_once(char::is_whitespace) else {
        return Err(ParseRuleError::MissingPattern);
    };
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(ParseRuleError::MissingPattern);
    }
    Ok((head, pattern))
}

fn parse_rule_head(head: &str) -> Result<(RuleAction, ModifierState), ParseRuleError> {
    let mut chars = head.chars();
    let first = chars.next().ok_or(ParseRuleError::EmptyRule)?;
    if let Some(action) = short_action(first) {
        let modifiers = chars.as_str().trim_start_matches(',');
        return Ok((action, parse_modifiers(modifiers)?));
    }

    let (keyword, modifiers) = head.split_once(',').unwrap_or((head, ""));
    let action =
        long_action(keyword).ok_or_else(|| ParseRuleError::UnknownRule(head.to_owned()))?;
    Ok((action, parse_modifiers(modifiers)?))
}

fn short_action(marker: char) -> Option<RuleAction> {
    match marker {
        '+' => Some(RuleAction::Include),
        '-' => Some(RuleAction::Exclude),
        'H' => Some(RuleAction::Hide),
        'S' => Some(RuleAction::Show),
        'P' => Some(RuleAction::Protect),
        'R' => Some(RuleAction::Risk),
        '!' => Some(RuleAction::ClearList),
        '.' => Some(RuleAction::Merge),
        ':' => Some(RuleAction::DirMerge),
        _ => None,
    }
}

fn long_action(keyword: &str) -> Option<RuleAction> {
    match keyword {
        "include" => Some(RuleAction::Include),
        "exclude" => Some(RuleAction::Exclude),
        "hide" => Some(RuleAction::Hide),
        "show" => Some(RuleAction::Show),
        "protect" => Some(RuleAction::Protect),
        "risk" => Some(RuleAction::Risk),
        "clear" | "clear-list" => Some(RuleAction::ClearList),
        "merge" => Some(RuleAction::Merge),
        "dir-merge" => Some(RuleAction::DirMerge),
        _ => None,
    }
}

fn parse_modifiers(input: &str) -> Result<ModifierState, ParseRuleError> {
    let mut modifiers = ModifierState::default();
    for ch in input.chars().filter(|ch| *ch != ',') {
        match ch {
            's' => modifiers.sender_side = true,
            'r' => modifiers.receiver_side = true,
            'p' => modifiers.perishable = true,
            'e' | 'n' | 'w' | 'x' | '-' | '+' | '!' => {}
            other => return Err(ParseRuleError::InvalidModifier(other)),
        }
    }
    Ok(modifiers)
}

fn parse_filter_records(input: &[u8], from0: bool) -> Result<Vec<String>, ParseRuleError> {
    if from0 {
        let mut records = Vec::new();
        let mut offset = 0;
        for record in input.split(|byte| *byte == 0) {
            if !record.is_empty() {
                let text =
                    std::str::from_utf8(record).map_err(|source| ParseRuleError::InvalidUtf8 {
                        offset: offset + source.valid_up_to(),
                    })?;
                records.push(text.to_owned());
            }
            offset += record.len() + 1;
        }
        return Ok(records);
    }

    if let Some(offset) = input.iter().position(|byte| *byte == 0) {
        return Err(ParseRuleError::UnexpectedNul { offset });
    }
    let text = std::str::from_utf8(input).map_err(|source| ParseRuleError::InvalidUtf8 {
        offset: source.valid_up_to(),
    })?;
    Ok(text
        .split('\n')
        .map(|record| record.strip_suffix('\r').unwrap_or(record).to_owned())
        .collect())
}

fn normalize_filter_record(record: &str) -> Option<String> {
    let trimmed = record.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    if let Some(stripped) = trimmed.strip_prefix("\\#") {
        return Some(format!("#{stripped}"));
    }
    if let Some(stripped) = trimmed.strip_prefix("\\ ") {
        return Some(format!(" {stripped}"));
    }
    Some(trimmed.to_owned())
}

fn starts_with_explicit_rule(record: &str) -> bool {
    let Some(first) = record.chars().next() else {
        return false;
    };
    short_action(first).is_some()
        || record
            .split_once(char::is_whitespace)
            .and_then(|(head, _)| {
                head.split_once(',')
                    .map(|(keyword, _)| keyword)
                    .or(Some(head))
            })
            .and_then(long_action)
            .is_some()
}

fn normalize_candidate_path(path: &str) -> String {
    let mut path = normalize_filter_path(path);
    while let Some(stripped) = path.strip_prefix('/') {
        path = stripped.to_owned();
    }
    while let Some(stripped) = path.strip_prefix("./") {
        path = stripped.to_owned();
    }
    while path.ends_with('/') {
        path.pop();
    }
    path
}

fn path_suffixes(path: &str) -> impl Iterator<Item = &str> {
    std::iter::once(path).chain(path.match_indices('/').map(|(index, _)| &path[index + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_include_and_exclude_rules() {
        let include = Rule::parse_filter("+ *.rs").unwrap();
        let exclude = Rule::parse_filter("- /target/").unwrap();

        assert_eq!(include.action(), RuleAction::Include);
        assert_eq!(include.pattern().body(), "*.rs");
        assert!(!include.pattern().is_anchored());

        assert_eq!(exclude.action(), RuleAction::Exclude);
        assert_eq!(exclude.pattern().body(), "target");
        assert!(exclude.pattern().is_anchored());
        assert!(exclude.pattern().is_directory_only());
    }

    #[test]
    fn parses_long_filter_rule_names() {
        let include = Rule::parse_filter("include /src/**").unwrap();
        let exclude = Rule::parse_filter("exclude *.tmp").unwrap();
        let protect = Rule::parse_filter("protect important/").unwrap();
        let risk = Rule::parse_filter("risk scratch/**").unwrap();

        assert_eq!(include.action(), RuleAction::Include);
        assert_eq!(include.pattern().body(), "src/**");
        assert!(include.pattern().is_anchored());
        assert_eq!(exclude.action(), RuleAction::Exclude);
        assert_eq!(protect.action(), RuleAction::Protect);
        assert!(protect.pattern().is_directory_only());
        assert_eq!(risk.action(), RuleAction::Risk);
    }

    #[test]
    fn rejects_rules_without_patterns() {
        assert_eq!(Rule::parse_filter(""), Err(ParseRuleError::EmptyRule));
        assert_eq!(Rule::parse_filter("+"), Err(ParseRuleError::MissingPattern));
        assert_eq!(
            Rule::parse_filter("include"),
            Err(ParseRuleError::MissingPattern)
        );
        assert_eq!(Rule::parse_filter("- /"), Err(ParseRuleError::EmptyPattern));
    }

    #[test]
    fn anchored_patterns_match_from_transfer_root_only() {
        let rule = Rule::exclude("/src/*.tmp").unwrap();

        assert!(rule.matches("src/cache.tmp", EntryKind::File));
        assert!(!rule.matches("nested/src/cache.tmp", EntryKind::File));
    }

    #[test]
    fn unanchored_basename_patterns_match_at_any_depth() {
        let rule = Rule::exclude("*.tmp").unwrap();

        assert!(rule.matches("cache.tmp", EntryKind::File));
        assert!(rule.matches("nested/cache.tmp", EntryKind::File));
        assert!(!rule.matches("nested/cache.tmp.keep", EntryKind::File));
    }

    #[test]
    fn directory_only_patterns_do_not_match_files() {
        let rule = Rule::exclude("build/").unwrap();

        assert!(rule.matches("build", EntryKind::Directory));
        assert!(rule.matches("src/build", EntryKind::Directory));
        assert!(!rule.matches("build", EntryKind::File));
    }

    #[test]
    fn unanchored_path_patterns_can_match_suffix_paths() {
        let rule = Rule::include("foo/bar/*.rs").unwrap();

        assert!(rule.matches("foo/bar/lib.rs", EntryKind::File));
        assert!(rule.matches("nested/foo/bar/lib.rs", EntryKind::File));
        assert!(!rule.matches("foo/bar/baz/lib.rs", EntryKind::File));
    }

    #[test]
    fn parses_full_filter_rule_actions_and_modifiers() {
        let hide = Rule::parse_filter("hide,s *.obj").unwrap();
        let show = Rule::parse_filter("show,r public/***").unwrap();
        let protect = Rule::parse_filter("Pp *.bak").unwrap();
        let risk = Rule::parse_filter("Rr scratch/**").unwrap();
        let clear = Rule::parse_filter("!").unwrap();
        let merge = Rule::parse_filter(". .rsync-filter").unwrap();
        let dir_merge = Rule::parse_filter(":e .rules").unwrap();

        assert_eq!(hide.action(), RuleAction::Hide);
        assert!(hide.is_sender_side());
        assert!(!hide.is_receiver_side());
        assert_eq!(show.action(), RuleAction::Show);
        assert!(!show.is_sender_side());
        assert!(show.is_receiver_side());
        assert_eq!(protect.action(), RuleAction::Protect);
        assert!(protect.is_perishable());
        assert_eq!(risk.action(), RuleAction::Risk);
        assert_eq!(clear.action(), RuleAction::ClearList);
        assert_eq!(merge.action(), RuleAction::Merge);
        assert_eq!(merge.pattern().body(), ".rsync-filter");
        assert_eq!(dir_merge.action(), RuleAction::DirMerge);
        assert!(dir_merge.matches("nested/.rules", EntryKind::File));
    }

    #[test]
    fn parses_filter_file_records_with_comments_escaping_and_from0() {
        let newline = Rule::parse_filter_file(
            b"
# comment
+ keep/**
- *.tmp
\\#literal
",
            false,
            RuleAction::Exclude,
        )
        .unwrap();

        assert_eq!(newline.len(), 3);
        assert_eq!(newline[0].action(), RuleAction::Include);
        assert_eq!(newline[1].action(), RuleAction::Exclude);
        assert_eq!(newline[2].pattern().raw(), "#literal");

        let nul =
            Rule::parse_filter_file(b"*.obj\0\\#hash\0\0", true, RuleAction::Include).unwrap();
        assert_eq!(nul.len(), 2);
        assert!(nul.iter().all(|rule| rule.action() == RuleAction::Include));
        assert_eq!(nul[1].pattern().raw(), "#hash");
    }
}
