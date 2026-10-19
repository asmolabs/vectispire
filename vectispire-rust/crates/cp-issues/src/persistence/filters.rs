//! Backlog query criteria and filters.

use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use vectispire_cp_db::{ScanTarget, Visibility};

/// Lifetime date boundaries for issue history filtering.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lifetime {
    pub open_at: Option<OffsetDateTime>,
    pub first_seen_from: Option<OffsetDateTime>,
    pub first_seen_before: Option<OffsetDateTime>,
    pub resolved_from: Option<OffsetDateTime>,
    pub resolved_before: Option<OffsetDateTime>,
    pub reopened_from: Option<OffsetDateTime>,
    pub reopened_before: Option<OffsetDateTime>,
}

impl Lifetime {
    pub fn asks_anything(&self) -> bool {
        self.open_at.is_some()
            || self.first_seen_from.is_some()
            || self.first_seen_before.is_some()
            || self.resolved_from.is_some()
            || self.resolved_before.is_some()
            || self.reopened_from.is_some()
            || self.reopened_before.is_some()
    }
}

/// Backlog criteria, visibility included.
#[derive(Debug, Clone, PartialEq)]
pub struct IssueFilters {
    pub state: Option<String>,
    pub severity: Option<String>,
    pub type_: Option<String>,
    pub triage_status: Option<String>,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub only_direct: bool,
    pub only_kev: bool,
    pub search: Option<String>,
    pub exclude_settled: bool,
    pub overdue_before: BTreeMap<String, OffsetDateTime>,
    pub visibility: Visibility,
    pub touching_since: Option<OffsetDateTime>,
    pub cve_only: bool,
    pub targets_within: Option<BTreeSet<ScanTarget>>,
    pub owasp_category: Option<String>,
    pub lifetime: Option<Lifetime>,
    pub identifier: Option<String>,
}

impl IssueFilters {
    pub fn new(visibility: Visibility) -> Self {
        Self {
            state: Some("open".to_owned()),
            severity: None,
            type_: None,
            triage_status: None,
            repo_id: None,
            container_id: None,
            only_direct: false,
            only_kev: false,
            search: None,
            exclude_settled: false,
            overdue_before: BTreeMap::new(),
            visibility,
            touching_since: None,
            cve_only: false,
            targets_within: None,
            owasp_category: None,
            lifetime: None,
            identifier: None,
        }
    }

    pub fn touching(mut self, window_start: OffsetDateTime) -> Self {
        self.touching_since = Some(window_start);
        self
    }

    pub fn only_cves(mut self) -> Self {
        self.cve_only = true;
        self
    }

    pub fn within(mut self, targets: impl IntoIterator<Item = ScanTarget>) -> Self {
        let incoming: BTreeSet<ScanTarget> = targets.into_iter().collect();
        self.targets_within = Some(match self.targets_within {
            Some(existing) => existing.intersection(&incoming).copied().collect(),
            None => incoming,
        });
        self
    }

    pub fn identifier_key(identifier: Option<&str>) -> Option<String> {
        identifier.map(|s| s.to_lowercase())
    }
}
