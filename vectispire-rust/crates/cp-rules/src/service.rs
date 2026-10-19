//! Service layer for rule sets: storage, activation, costing and coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_protocol::StoredFile;

use crate::catalogue::{self, RuleCatalogueFetcher};
use crate::coverage::{self, Assessment, BUNDLED_PYTHON_RULE, BUNDLED_RULES, rule_tree_path};
use crate::persistence::{
    NewSemgrepRuleSet, SemgrepRuleSetRecord, SemgrepRuleSetRepository, SemgrepRuleSetSummary, StoreError,
};
use crate::ports::{InventoryEcosystems, IssueRuleCounts};
use crate::ruleset::{self, TriageImpact, UploadedFile, validate_activation_note, validate_name};

/// A stored rule set representation in the service layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetView {
    pub id: i64,
    pub name: String,
    pub content_hash: String,
    pub rule_count: i32,
    pub file_count: i32,
    pub size_bytes: i64,
    #[serde(rename = "isActive")]
    pub is_active: Option<bool>,
    pub uploaded_by: Option<String>,
    #[serde(with = "time::serde::iso8601")]
    pub uploaded_at: OffsetDateTime,
    pub activation_note: Option<String>,
}

impl From<SemgrepRuleSetRecord> for RuleSetView {
    fn from(r: SemgrepRuleSetRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            content_hash: r.content_hash,
            rule_count: r.rule_count,
            file_count: r.file_count,
            size_bytes: r.size_bytes,
            is_active: r.is_active,
            uploaded_by: r.uploaded_by,
            uploaded_at: r.uploaded_at,
            activation_note: r.activation_note,
        }
    }
}

/// A listing summary of a rule set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetSummary {
    pub id: i64,
    pub name: String,
    pub content_hash: String,
    pub rule_count: i32,
    pub file_count: i32,
    pub size_bytes: String,
    #[serde(rename = "isActive")]
    pub active: Option<bool>,
    pub uploaded_by: Option<String>,
    #[serde(with = "time::serde::iso8601")]
    pub uploaded_at: OffsetDateTime,
    pub activation_note: Option<String>,
}

impl From<SemgrepRuleSetSummary> for RuleSetSummary {
    fn from(s: SemgrepRuleSetSummary) -> Self {
        Self {
            id: s.id,
            name: s.name,
            content_hash: s.content_hash,
            rule_count: s.rule_count,
            file_count: s.file_count,
            size_bytes: s.size_bytes,
            active: s.active,
            uploaded_by: s.uploaded_by,
            uploaded_at: s.uploaded_at,
            activation_note: s.activation_note,
        }
    }
}

/// The response to a listing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetListing {
    pub rule_sets: Vec<RuleSetSummary>,
}

/// Service-level error enumeration.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("No rule set with id {0}.")]
    NotFound(i64),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{detail}")]
    RuleSetLosesIssues { affected_issues: i64, losing_issues: Vec<String>, detail: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("{0}")]
    Other(String),
}

/// Core service for rule sets: storage, queries, activation and costing.
#[derive(Clone)]
pub struct RuleSetService {
    repo: Arc<SemgrepRuleSetRepository>,
    issues: Arc<dyn IssueRuleCounts>,
}

impl std::fmt::Debug for RuleSetService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSetService").finish_non_exhaustive()
    }
}

impl RuleSetService {
    pub fn new(repo: Arc<SemgrepRuleSetRepository>, issues: Arc<dyn IssueRuleCounts>) -> Self {
        Self { repo, issues }
    }

    pub fn repository(&self) -> &Arc<SemgrepRuleSetRepository> {
        &self.repo
    }

    /// Stores an uploaded rule set. Does not activate it.
    pub async fn store(
        &self,
        files: &[UploadedFile],
        name: &str,
        uploaded_by: Option<&str>,
    ) -> Result<RuleSetView, ServiceError> {
        let label = validate_name(name).map_err(|e| ServiceError::InvalidInput(e.0))?;
        let stored_files = ruleset::accept(files).map_err(|e| ServiceError::InvalidInput(e.0))?;
        let content_hash = ruleset::content_hash(&stored_files);
        let rule_count = i32::try_from(ruleset::rule_ids_of(&stored_files).len()).unwrap_or(i32::MAX);
        let file_count = i32::try_from(stored_files.len()).unwrap_or(i32::MAX);
        let size_bytes: i64 = stored_files
            .iter()
            .map(|f| i64::try_from(f.content.len()).unwrap_or(i64::MAX))
            .fold(0i64, |acc, x| acc.saturating_add(x));
        let files_json = serde_json::to_string(&stored_files)
            .map_err(|e| ServiceError::Other(format!("Failed to serialize stored files: {e}")))?;

        let row = NewSemgrepRuleSet {
            name: label,
            files: files_json,
            content_hash,
            rule_count,
            file_count,
            size_bytes,
            is_active: None,
            uploaded_by: uploaded_by.map(str::to_owned),
            uploaded_at: OffsetDateTime::now_utc(),
            activation_note: None,
        };

        let id = self.repo.insert(&row).await?;
        let stored = self.repo.find_by_id(id).await?.ok_or(ServiceError::NotFound(id))?;

        Ok(RuleSetView::from(stored))
    }

    pub async fn list(&self) -> Result<Vec<RuleSetSummary>, ServiceError> {
        let rows = self.repo.summaries().await?;
        Ok(rows.into_iter().map(RuleSetSummary::from).collect())
    }

    pub async fn active(&self) -> Result<Option<RuleSetView>, ServiceError> {
        let row = self.repo.find_active().await?;
        Ok(row.map(RuleSetView::from))
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<RuleSetView>, ServiceError> {
        let row = self.repo.find_by_id(id).await?;
        Ok(row.map(RuleSetView::from))
    }

    pub async fn by_hash(&self, content_hash: &str) -> Result<Option<RuleSetView>, ServiceError> {
        let row = self.repo.find_first_by_content_hash_order_by_id_asc(content_hash).await?;
        Ok(row.map(RuleSetView::from))
    }

    /// The decoded files of a stored set.
    pub async fn files_of(&self, id: i64) -> Result<Vec<StoredFile>, ServiceError> {
        let row = self.repo.find_by_id(id).await?.ok_or(ServiceError::NotFound(id))?;
        serde_json::from_str(&row.files).map_err(|e| {
            ServiceError::InvalidInput(format!("The stored rules of set {} cannot be read back: {e}", row.id))
        })
    }

    /// The decoded files of a stored set by content hash.
    pub async fn files_by_hash(&self, content_hash: &str) -> Result<Vec<StoredFile>, ServiceError> {
        let Some(row) = self.repo.find_first_by_content_hash_order_by_id_asc(content_hash).await? else {
            return Ok(Vec::new());
        };
        serde_json::from_str(&row.files).map_err(|e| {
            ServiceError::InvalidInput(format!("The stored rules of set {} cannot be read back: {e}", row.id))
        })
    }

    /// What activating this candidate set would do to the open issues backlog.
    pub async fn impact_of(&self, candidate_id: i64) -> Result<TriageImpact, ServiceError> {
        let candidate_files = self.files_of(candidate_id).await?;
        let next_ids: BTreeSet<String> = ruleset::rule_ids_of(&candidate_files).into_iter().collect();
        self.impact_of_replacing_with(&next_ids).await
    }

    /// What deactivating all uploaded sets (returning to bundled rules alone) would do to backlog.
    pub async fn deactivation_impact(&self) -> Result<TriageImpact, ServiceError> {
        self.impact_of_replacing_with(&BTreeSet::new()).await
    }

    async fn impact_of_replacing_with(&self, uploaded: &BTreeSet<String>) -> Result<TriageImpact, ServiceError> {
        let bundled_ids = bundled_rule_ids();
        let mut current = bundled_ids.clone();

        if let Some(active_row) = self.repo.find_active().await? {
            let files: Vec<StoredFile> = serde_json::from_str(&active_row.files)
                .map_err(|e| ServiceError::InvalidInput(format!("Could not read active rule set files: {e}")))?;
            for id in ruleset::rule_ids_of(&files) {
                current.insert(id);
            }
        }

        let mut next = bundled_ids;
        next.extend(uploaded.iter().cloned());

        let open_counts = self
            .issues
            .open_sast_issues_by_rule()
            .await
            .map_err(|e| ServiceError::Other(format!("Failed to count open SAST issues: {e}")))?;

        Ok(ruleset::impact(&current, &next, &open_counts))
    }

    /// Activates a rule set. Refused if it resolves open issues and `accept_losing` is not their exact number.
    pub async fn activate(
        &self,
        id: i64,
        note: Option<&str>,
        accept_losing: Option<i64>,
    ) -> Result<(RuleSetView, TriageImpact), ServiceError> {
        let candidate = self.repo.find_by_id(id).await?.ok_or(ServiceError::NotFound(id))?;

        let valid_note = validate_activation_note(note).map_err(|e| ServiceError::InvalidInput(e.0))?;
        let impact = self.impact_of(candidate.id).await?;

        refuse_unless_accepted(&impact, accept_losing, "Activating this rule set")?;

        self.repo.activate(candidate.id, valid_note.as_deref()).await?;

        let updated = self.repo.find_by_id(candidate.id).await?.ok_or(ServiceError::NotFound(candidate.id))?;

        Ok((RuleSetView::from(updated), impact))
    }

    /// Deactivates all uploaded rule sets. Refused if it resolves open issues and `accept_losing` is not their exact number.
    pub async fn deactivate_all(&self, accept_losing: Option<i64>) -> Result<TriageImpact, ServiceError> {
        let impact = self.deactivation_impact().await?;
        refuse_unless_accepted(&impact, accept_losing, "Returning to the bundled rules")?;
        self.repo.deactivate_all().await?;
        Ok(impact)
    }
}

fn bundled_rule_ids() -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for id in ruleset::rule_ids_in(BUNDLED_PYTHON_RULE) {
        ids.insert(id);
    }
    ids
}

const NAMED_IN_DETAIL: usize = 10;

fn refuse_unless_accepted(
    impact: &TriageImpact,
    accept_losing: Option<i64>,
    gesture: &str,
) -> Result<(), ServiceError> {
    let affected = impact.affected_issues;
    if affected == 0 || accept_losing == Some(affected) {
        return Ok(());
    }

    let rules = &impact.losing_issues;
    let limit = NAMED_IN_DETAIL.min(rules.len());
    let mut named = rules.get(..limit).unwrap_or(rules.as_slice()).join(", ");
    if let Some(remaining) = rules.len().checked_sub(NAMED_IN_DETAIL).filter(|&r| r > 0) {
        named.push_str(&format!(" and {remaining} more"));
    }

    let stale = match accept_losing {
        None => String::new(),
        Some(accepted) => format!(" You accepted {accepted}; the backlog reads {affected} now."),
    };

    let detail = format!(
        "{gesture} resolves {affected} open issue(s) at the next scan, with their triage: {} rule(s) holding them leave — {named}.{stale} Send acceptLosing: {affected} to go ahead.",
        rules.len()
    );

    Err(ServiceError::RuleSetLosesIssues { affected_issues: affected, losing_issues: rules.clone(), detail })
}

/// Administrative coordinator: auditing, catalogue imports, activation orchestration.
#[derive(Clone)]
pub struct RuleSetAdministrationService {
    rules: RuleSetService,
    fetcher: RuleCatalogueFetcher,
    audit: Arc<AuditLog>,
}

impl std::fmt::Debug for RuleSetAdministrationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSetAdministrationService").finish_non_exhaustive()
    }
}

impl RuleSetAdministrationService {
    pub fn new(rules: RuleSetService, fetcher: RuleCatalogueFetcher, audit: Arc<AuditLog>) -> Self {
        Self { rules, fetcher, audit }
    }

    pub fn rules(&self) -> &RuleSetService {
        &self.rules
    }

    pub fn fetcher(&self) -> &RuleCatalogueFetcher {
        &self.fetcher
    }

    pub async fn list(&self) -> Result<RuleSetListing, ServiceError> {
        let rule_sets = self.rules.list().await?;
        Ok(RuleSetListing { rule_sets })
    }

    pub async fn impact(&self, id: i64) -> Result<TriageImpact, ServiceError> {
        self.rules.impact_of(id).await
    }

    pub async fn upload(
        &self,
        files: &[UploadedFile],
        name: &str,
        actor: &RequestActor,
    ) -> Result<RuleSetView, ServiceError> {
        let stored = self.rules.store(files, name, actor.username.as_deref()).await?;
        let res_id = stored.id.to_string();
        let desc =
            format!("Rule set \"{}\" uploaded: {} files, {} rules.", stored.name, stored.file_count, stored.rule_count);
        self.audit.record(actor.entry(AuditOperation::RuleSetUploaded, &res_id, &desc)).await;
        Ok(stored)
    }

    pub async fn import_catalogue(
        &self,
        commit: &str,
        requested_languages: &[String],
        licence_sha256: &str,
        include_gitleaks_duplicates: Option<bool>,
        actor: &RequestActor,
    ) -> Result<RuleSetView, ServiceError> {
        catalogue::require_commit(commit).map_err(|e| ServiceError::InvalidInput(e.0))?;
        let fetched = self.fetcher.fetch().map_err(|e| ServiceError::InvalidInput(e.0))?;

        if !fetched.commit.eq_ignore_ascii_case(commit) {
            return Err(ServiceError::InvalidInput(format!(
                "The upstream moved between the preview and this request: you read {}, it is now {}. Read the catalogue again.",
                commit, fetched.commit
            )));
        }
        if fetched.licence_sha256 != licence_sha256 {
            return Err(ServiceError::InvalidInput(
                "The licence changed between the preview and this request. Read it again before accepting: what you agreed to is not what this commit carries.".to_owned(),
            ));
        }

        let languages: BTreeSet<String> = requested_languages.iter().cloned().collect();
        let with_duplicates = include_gitleaks_duplicates.unwrap_or(false);
        let files = catalogue::select(&fetched.contents, &languages, with_duplicates)
            .map_err(|e| ServiceError::InvalidInput(e.0))?;
        let duplicates_reached = catalogue::reaches_gitleaks_duplicates(&fetched.contents, &languages);

        let set_name = catalogue::name_for(&fetched.commit, &languages, with_duplicates && duplicates_reached);
        let stored = self.rules.store(&files, &set_name, actor.username.as_deref()).await?;

        let sorted_langs: Vec<&str> = languages.iter().map(String::as_str).collect();
        let duplicates_note = if !duplicates_reached {
            ""
        } else if with_duplicates {
            " gitleaks duplicates included on request."
        } else {
            " gitleaks duplicates left out."
        };

        let res_id = stored.id.to_string();
        let desc = format!(
            "Fetched {} at commit {}: {} rules. Licence {} accepted, sha256 {}.{} Languages: {}.",
            catalogue::UPSTREAM,
            fetched.commit,
            stored.rule_count,
            catalogue::LICENCE,
            fetched.licence_sha256,
            duplicates_note,
            sorted_langs.join(", ")
        );
        self.audit.record(actor.entry(AuditOperation::RuleSetUploaded, &res_id, &desc)).await;

        Ok(stored)
    }

    pub async fn deactivation_impact(&self) -> Result<TriageImpact, ServiceError> {
        self.rules.deactivation_impact().await
    }

    pub async fn activate(
        &self,
        id: i64,
        note: Option<&str>,
        accept_losing: Option<i64>,
        actor: &RequestActor,
    ) -> Result<RuleSetView, ServiceError> {
        let (activated, accepted) = self.rules.activate(id, note, accept_losing).await?;
        let note_text = activated.activation_note.as_deref().unwrap_or("No impact recorded.");

        let res_id = activated.id.to_string();
        let desc =
            format!("Rule set \"{}\" activated. {} {}", activated.name, accepted_loss_summary(&accepted), note_text);
        self.audit.record(actor.entry(AuditOperation::RuleSetActivated, &res_id, &desc)).await;

        Ok(activated)
    }

    pub async fn deactivate(&self, accept_losing: Option<i64>, actor: &RequestActor) -> Result<(), ServiceError> {
        let accepted = self.rules.deactivate_all(accept_losing).await?;
        let desc = format!(
            "Uploaded rule sets deactivated; scans fall back to the bundled rules. {}",
            accepted_loss_summary(&accepted)
        );
        self.audit.record(actor.entry(AuditOperation::RuleSetDeactivated, "all", &desc)).await;
        Ok(())
    }
}

fn accepted_loss_summary(accepted: &TriageImpact) -> String {
    if accepted.affected_issues == 0 {
        "No open issue resolves.".to_owned()
    } else {
        format!(
            "Accepted loss: {} open issue(s), {} rule(s): {}.",
            accepted.affected_issues,
            accepted.losing_issues.len(),
            accepted.losing_issues.join(", ")
        )
    }
}

/// Rule coverage analysis service.
#[derive(Clone)]
pub struct RuleCoverageService {
    rules: RuleSetService,
    components: Arc<dyn InventoryEcosystems>,
}

impl std::fmt::Debug for RuleCoverageService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleCoverageService").finish_non_exhaustive()
    }
}

impl RuleCoverageService {
    pub fn new(rules: RuleSetService, components: Arc<dyn InventoryEcosystems>) -> Self {
        Self { rules, components }
    }

    pub async fn assess(&self) -> Result<Assessment, ServiceError> {
        let paths = self.installed_rule_paths().await?;
        let purls = self
            .components
            .distinct_purls()
            .await
            .map_err(|e| ServiceError::Other(format!("Failed to query distinct purls: {e}")))?;
        Ok(coverage::assess(&paths, &purls))
    }

    pub async fn uncovered_ecosystems_by_target(&self) -> Result<BTreeMap<String, Vec<String>>, ServiceError> {
        let paths = self.installed_rule_paths().await?;
        let target_rows = self
            .components
            .distinct_purls_by_target()
            .await
            .map_err(|e| ServiceError::Other(format!("Failed to query purls by target: {e}")))?;

        let mut purls_by_target: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (repo_id, container_id, purl) in target_rows {
            let key = if let Some(r) = repo_id {
                format!("repository:{r}")
            } else if let Some(c) = container_id {
                format!("container:{c}")
            } else {
                continue;
            };
            purls_by_target.entry(key).or_default().push(purl);
        }

        let mut uncovered = BTreeMap::new();
        for (key, purls) in purls_by_target {
            let gaps = coverage::assess(&paths, &purls).uncovered;
            if !gaps.is_empty() {
                uncovered.insert(key, gaps.into_iter().collect());
            }
        }
        Ok(uncovered)
    }

    pub async fn declared_owasp_categories(&self) -> Result<BTreeSet<String>, ServiceError> {
        let mut contents = vec![BUNDLED_PYTHON_RULE];
        let active_files = if let Some(active) = self.rules.active().await? {
            self.rules.files_of(active.id).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        for f in &active_files {
            contents.push(&f.content);
        }
        Ok(coverage::declared_owasp_categories(contents))
    }

    pub async fn declared_owasp_categories_by_language(
        &self,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, ServiceError> {
        let mut pairs: Vec<(&str, &str)> = vec![("semgrep/python/dangerous-eval.yaml", BUNDLED_PYTHON_RULE)];
        let active_files = if let Some(active) = self.rules.active().await? {
            self.rules.files_of(active.id).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let tree_paths: Vec<String> = active_files.iter().map(rule_tree_path).collect();
        for (path, file) in tree_paths.iter().zip(active_files.iter()) {
            pairs.push((path.as_str(), file.content.as_str()));
        }
        Ok(coverage::declared_owasp_categories_by_language(pairs))
    }

    async fn installed_rule_paths(&self) -> Result<Vec<String>, ServiceError> {
        let mut paths: Vec<String> = BUNDLED_RULES.iter().map(|s| (*s).to_owned()).collect();
        if let Some(active) = self.rules.active().await? {
            for file in &self.rules.files_of(active.id).await.unwrap_or_default() {
                paths.push(rule_tree_path(file));
            }
        }
        Ok(paths)
    }
}
