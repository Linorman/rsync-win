use std::fmt;

use crate::matcher::{glob_matches, normalize_filter_path, EntryKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Include,
    Exclude,
    Protect,
    Risk,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    action: RuleAction,
    pattern: Pattern,
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
        Ok(Self {
            action,
            pattern: Pattern::parse(pattern.into())?,
        })
    }

    pub fn parse_filter(input: &str) -> Result<Self, ParseRuleError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ParseRuleError::EmptyRule);
        }

        if let Some(pattern) = strip_long_rule(trimmed, "include") {
            return Self::include(pattern);
        }

        if let Some(pattern) = strip_long_rule(trimmed, "exclude") {
            return Self::exclude(pattern);
        }

        if let Some(pattern) = strip_long_rule(trimmed, "protect") {
            return Self::protect(pattern);
        }

        if let Some(pattern) = strip_long_rule(trimmed, "risk") {
            return Self::risk(pattern);
        }

        let mut chars = trimmed.chars();
        let marker = chars.next().ok_or(ParseRuleError::EmptyRule)?;
        let pattern = chars.as_str().trim();
        match marker {
            '+' => Self::include(pattern),
            '-' => Self::exclude(pattern),
            'P' => Self::protect(pattern),
            'R' => Self::risk(pattern),
            _ => Err(ParseRuleError::UnknownRule(trimmed.to_owned())),
        }
    }

    pub fn action(&self) -> RuleAction {
        self.action
    }

    pub fn pattern(&self) -> &Pattern {
        &self.pattern
    }

    pub fn matches(&self, path: &str, kind: EntryKind) -> bool {
        self.pattern.matches(path, kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    raw: String,
    body: String,
    anchored: bool,
    directory_only: bool,
    has_path_separator: bool,
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

        Ok(Self {
            raw,
            has_path_separator: body.contains('/'),
            body,
            anchored,
            directory_only,
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
        }
    }
}

impl std::error::Error for ParseRuleError {}

fn strip_long_rule<'a>(input: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = input.strip_prefix(keyword)?;
    if rest.is_empty() {
        return Some("");
    }

    rest.chars()
        .next()
        .filter(|ch| ch.is_ascii_whitespace())
        .map(|_| rest.trim())
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
}
