use std::collections::HashMap;

use crate::rule::{Rule, RuleAction, RuleSide};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchDecision {
    action: RuleAction,
    matched_rule_index: Option<usize>,
}

impl MatchDecision {
    pub fn new(action: RuleAction, matched_rule_index: Option<usize>) -> Self {
        Self {
            action,
            matched_rule_index,
        }
    }

    pub fn action(&self) -> RuleAction {
        self.action
    }

    pub fn matched_rule_index(&self) -> Option<usize> {
        self.matched_rule_index
    }

    pub fn is_included(&self) -> bool {
        !matches!(self.action, RuleAction::Exclude | RuleAction::Hide)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn push(&mut self, rule: Rule) {
        if rule.action() == RuleAction::ClearList {
            self.rules.clear();
            return;
        }
        self.rules.push(rule);
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn decide(&self, path: &str, kind: EntryKind) -> MatchDecision {
        for (index, rule) in self.rules.iter().enumerate() {
            if is_merge_directive(rule.action()) {
                continue;
            }
            if rule.matches(path, kind) {
                return MatchDecision::new(rule.action(), Some(index));
            }
        }

        MatchDecision::new(RuleAction::Include, None)
    }

    pub fn is_included(&self, path: &str, kind: EntryKind) -> bool {
        self.decide(path, kind).is_included()
    }

    pub fn decide_for_side(&self, path: &str, kind: EntryKind, side: RuleSide) -> MatchDecision {
        for (index, rule) in self.rules.iter().enumerate() {
            if is_merge_directive(rule.action()) {
                continue;
            }
            if rule.applies_to(side) && rule.matches(path, kind) {
                return MatchDecision::new(rule.action(), Some(index));
            }
        }

        MatchDecision::new(RuleAction::Include, None)
    }

    pub fn is_included_for_side(&self, path: &str, kind: EntryKind, side: RuleSide) -> bool {
        self.decide_for_side(path, kind, side).is_included()
    }
}

fn is_merge_directive(action: RuleAction) -> bool {
    matches!(action, RuleAction::Merge | RuleAction::DirMerge)
}

pub fn normalize_filter_path(path: &str) -> String {
    let mut normalized = String::with_capacity(path.len());
    let mut previous_was_separator = false;

    for ch in path.chars() {
        let ch = if ch == '\\' { '/' } else { ch };
        if ch == '/' {
            if previous_was_separator {
                continue;
            }
            previous_was_separator = true;
        } else {
            previous_was_separator = false;
        }
        normalized.push(ch);
    }

    normalized
}

pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<_> = normalize_filter_path(pattern).chars().collect();
    let text: Vec<_> = normalize_filter_path(text).chars().collect();
    let mut memo = HashMap::new();
    glob_matches_at(&pattern, 0, &text, 0, &mut memo)
}

fn glob_matches_at(
    pattern: &[char],
    pattern_pos: usize,
    text: &[char],
    text_pos: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(pattern_pos, text_pos)) {
        return *result;
    }

    let result = if pattern_pos == pattern.len() {
        text_pos == text.len()
    } else {
        match pattern[pattern_pos] {
            '*' => match_star(pattern, pattern_pos, text, text_pos, memo),
            '?' => {
                text.get(text_pos).is_some_and(|ch| *ch != '/')
                    && glob_matches_at(pattern, pattern_pos + 1, text, text_pos + 1, memo)
            }
            '[' => match_class(pattern, pattern_pos, text, text_pos, memo),
            '\\' => match_escaped(pattern, pattern_pos, text, text_pos, memo),
            literal => {
                text.get(text_pos) == Some(&literal)
                    && glob_matches_at(pattern, pattern_pos + 1, text, text_pos + 1, memo)
            }
        }
    };

    memo.insert((pattern_pos, text_pos), result);
    result
}

fn match_star(
    pattern: &[char],
    pattern_pos: usize,
    text: &[char],
    text_pos: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    let mut end = pattern_pos;
    while pattern.get(end) == Some(&'*') {
        end += 1;
    }

    let recursive = end - pattern_pos >= 2;
    if glob_matches_at(pattern, end, text, text_pos, memo) {
        return true;
    }

    let mut consume_pos = text_pos;
    while let Some(ch) = text.get(consume_pos) {
        if !recursive && *ch == '/' {
            break;
        }

        consume_pos += 1;
        if glob_matches_at(pattern, end, text, consume_pos, memo) {
            return true;
        }
    }

    false
}

fn match_escaped(
    pattern: &[char],
    pattern_pos: usize,
    text: &[char],
    text_pos: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    let Some(literal) = pattern.get(pattern_pos + 1) else {
        return text.get(text_pos) == Some(&'\\')
            && glob_matches_at(pattern, pattern_pos + 1, text, text_pos + 1, memo);
    };

    text.get(text_pos) == Some(literal)
        && glob_matches_at(pattern, pattern_pos + 2, text, text_pos + 1, memo)
}

fn match_class(
    pattern: &[char],
    pattern_pos: usize,
    text: &[char],
    text_pos: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    let Some((class, next_pattern_pos)) = CharacterClass::parse(pattern, pattern_pos) else {
        return text.get(text_pos) == Some(&'[')
            && glob_matches_at(pattern, pattern_pos + 1, text, text_pos + 1, memo);
    };

    let Some(ch) = text.get(text_pos) else {
        return false;
    };

    *ch != '/'
        && class.matches(*ch)
        && glob_matches_at(pattern, next_pattern_pos, text, text_pos + 1, memo)
}

#[derive(Debug)]
struct CharacterClass {
    negated: bool,
    ranges: Vec<(char, char)>,
}

impl CharacterClass {
    fn parse(pattern: &[char], open_pos: usize) -> Option<(Self, usize)> {
        let mut pos = open_pos + 1;
        let negated = matches!(pattern.get(pos), Some('!') | Some('^'));
        if negated {
            pos += 1;
        }

        let mut ranges = Vec::new();
        let mut saw_item = false;
        while let Some(ch) = pattern.get(pos).copied() {
            if ch == ']' && saw_item {
                return Some((Self { negated, ranges }, pos + 1));
            }

            let start = ch;
            if pattern.get(pos + 1) == Some(&'-') {
                if let Some(end) = pattern.get(pos + 2).copied() {
                    if end != ']' {
                        ranges.push((start, end));
                        saw_item = true;
                        pos += 3;
                        continue;
                    }
                }
            }

            ranges.push((start, start));
            saw_item = true;
            pos += 1;
        }

        None
    }

    fn matches(&self, ch: char) -> bool {
        let matched = self
            .ranges
            .iter()
            .any(|(start, end)| *start <= ch && ch <= *end);
        matched != self.negated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rule;

    #[test]
    fn glob_star_does_not_cross_path_separators() {
        assert!(glob_matches("src/*.rs", "src/lib.rs"));
        assert!(!glob_matches("src/*.rs", "src/nested/lib.rs"));
    }

    #[test]
    fn glob_double_star_crosses_path_separators() {
        assert!(glob_matches("src/**/mod.rs", "src/a/b/mod.rs"));
        assert!(glob_matches("src/**", "src/a/b/mod.rs"));
        assert!(glob_matches("src/**", "src/"));
    }

    #[test]
    fn glob_supports_question_mark_and_character_classes() {
        assert!(glob_matches("file-?.[ch]", "file-a.c"));
        assert!(glob_matches("file-[!0-9].rs", "file-x.rs"));
        assert!(!glob_matches("file-[!0-9].rs", "file-7.rs"));
        assert!(!glob_matches("file-?.rs", "file-/.rs"));
    }

    #[test]
    fn rule_set_uses_first_matching_rule() {
        let rules = RuleSet::new(vec![
            Rule::include("keep.tmp").unwrap(),
            Rule::exclude("*.tmp").unwrap(),
        ]);

        let keep = rules.decide("nested/keep.tmp", EntryKind::File);
        let drop = rules.decide("nested/cache.tmp", EntryKind::File);
        let other = rules.decide("nested/readme.md", EntryKind::File);

        assert_eq!(keep.action(), RuleAction::Include);
        assert_eq!(keep.matched_rule_index(), Some(0));
        assert_eq!(drop.action(), RuleAction::Exclude);
        assert_eq!(drop.matched_rule_index(), Some(1));
        assert_eq!(other.action(), RuleAction::Include);
        assert_eq!(other.matched_rule_index(), None);
    }

    #[test]
    fn upstream_include_only_c_sources_example_keeps_directories() {
        let rules = RuleSet::new(vec![
            Rule::parse_filter("+ */").unwrap(),
            Rule::parse_filter("+ *.c").unwrap(),
            Rule::parse_filter("- *").unwrap(),
        ]);

        assert!(rules.is_included("src", EntryKind::Directory));
        assert!(rules.is_included("src/main.c", EntryKind::File));
        assert!(!rules.is_included("src/main.o", EntryKind::File));
        assert!(!rules.is_included("README.md", EntryKind::File));
    }

    #[test]
    fn upstream_hide_and_protect_examples_are_side_specific() {
        let rules = RuleSet::new(vec![
            Rule::parse_filter("hide *.o").unwrap(),
            Rule::parse_filter("protect *.bak").unwrap(),
        ]);

        assert_eq!(
            rules
                .decide_for_side("build/main.o", EntryKind::File, RuleSide::Sender)
                .action(),
            RuleAction::Hide
        );
        assert_eq!(
            rules
                .decide_for_side("archive/old.bak", EntryKind::File, RuleSide::Receiver)
                .action(),
            RuleAction::Protect
        );
        assert!(rules.is_included_for_side("archive/old.bak", EntryKind::File, RuleSide::Sender));
    }

    #[test]
    fn rule_set_exposes_delete_protection_actions() {
        let rules = RuleSet::new(vec![
            Rule::protect("*.bak").unwrap(),
            Rule::risk("scratch/**").unwrap(),
        ]);

        assert_eq!(
            rules.decide("archive/old.bak", EntryKind::File).action(),
            RuleAction::Protect
        );
        assert!(rules.is_included("archive/old.bak", EntryKind::File));
        assert_eq!(
            rules.decide("scratch/tmp.bin", EntryKind::File).action(),
            RuleAction::Risk
        );
    }

    #[test]
    fn normalizes_windows_separators_for_matching() {
        let rules = RuleSet::new(vec![Rule::exclude("/src/*.obj").unwrap()]);

        assert!(!rules.is_included("src\\main.obj", EntryKind::File));
    }

    #[test]
    fn rule_set_honors_sender_receiver_side_modifiers_and_clear_list() {
        let mut rules = RuleSet::empty();
        rules.push(Rule::parse_filter("-s *.obj").unwrap());
        rules.push(Rule::parse_filter("-r *.bak").unwrap());
        rules.push(Rule::parse_filter("!").unwrap());
        rules.push(Rule::parse_filter("+ keep/***").unwrap());
        rules.push(Rule::parse_filter("- *").unwrap());

        assert!(!rules.is_included_for_side("main.obj", EntryKind::File, RuleSide::Sender));
        assert!(!rules.is_included_for_side("main.bak", EntryKind::File, RuleSide::Receiver));
        assert!(rules.is_included_for_side(
            "keep/nested/file.txt",
            EntryKind::File,
            RuleSide::Sender
        ));
        assert!(!rules.is_included_for_side("drop.txt", EntryKind::File, RuleSide::Sender));
    }

    #[test]
    fn trailing_triple_star_matches_directory_and_descendants() {
        let rule = Rule::include("vendor/***").unwrap();

        assert!(rule.matches("vendor", EntryKind::Directory));
        assert!(rule.matches("vendor/lib.rs", EntryKind::File));
        assert!(rule.matches("nested/vendor/lib.rs", EntryKind::File));
    }
}
