pub mod files_from;
pub mod matcher;
pub mod rule;

pub use files_from::{
    normalize_files_from_record, normalize_files_from_records, parse_files_from, parse_files_from0,
    parse_files_from_bytes, FilesFromError, FilesFromPathError,
};
pub use matcher::{glob_matches, normalize_filter_path, EntryKind, MatchDecision, RuleSet};
pub use rule::{ParseRuleError, Pattern, Rule, RuleAction, RuleSide};
