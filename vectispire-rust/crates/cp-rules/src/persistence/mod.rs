//! Database persistence for `t_semgrep_rule_set`.

mod repository;

pub use repository::{
    NewSemgrepRuleSet, SemgrepRuleSetRecord, SemgrepRuleSetRepository, SemgrepRuleSetSummary, StoreError,
};
