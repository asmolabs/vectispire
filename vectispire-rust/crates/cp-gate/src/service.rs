//! Gate services: policy management, evaluation, and verdict register.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_issues::IssueCatalog;
use vectispire_cp_issues::triage::TriageStatus;
use vectispire_cp_issues::views::IssueView;
use vectispire_cp_outbox::{RaiseError, SecurityEvents};
use vectispire_cp_rules::RuleCoverageService;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_targets::{Clock, Targets};
use vectispire_domain::instant::Instant;
use vectispire_domain::siem::{CefEvent, SecurityEventType};
use vectispire_domain::{FindingType, ScanStatus, Severity, bounded_text};

use crate::cursor::RegisterCursor;
use crate::error::GateError;
use crate::fields::GatePolicyFields;
use crate::gate::PolicyGate;
use crate::issue::GateIssue;
use crate::observation::Observation;
use crate::overview::{self, LatestScan, NamedTarget, SecurityOverview};
use crate::persistence::repository::{GatePolicyRepository, GateVerdictRepository};
use crate::persistence::{GatePolicyRow, GateVerdictRow, NewGatePolicyRow, StoreError};
use crate::policy::GatePolicy;
use crate::resolution::{
    PolicyLookup, PolicyResolution, PolicyScopeChoice, RequestedPolicy, ResolvedPolicy, StoredPolicy,
};
use crate::verdict::{Coverage, GateVerdict};

/// Which policy a write is about: the global one, or one target's override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyScope {
    pub kind: String,
    pub id: i64,
}

impl PolicyScope {
    pub const SCOPE_GLOBAL: &'static str = "global";
    pub const NO_TARGET: i64 = 0;

    pub fn global() -> Self {
        Self { kind: Self::SCOPE_GLOBAL.to_owned(), id: Self::NO_TARGET }
    }

    pub fn of_target(target: ScanTarget) -> Self {
        match target {
            ScanTarget::Repository(id) => Self { kind: "repository".to_owned(), id },
            ScanTarget::Container(id) => Self { kind: "container".to_owned(), id },
        }
    }

    pub fn of(kind: &str, id: i64) -> Result<Self, GateError> {
        match kind {
            "repository" => Ok(Self { kind: "repository".to_owned(), id }),
            "container" => Ok(Self { kind: "container".to_owned(), id }),
            _ => Err(GateError::InvalidInput(format!("Unknown target kind: \"{kind}\". Use repository or container."))),
        }
    }

    pub fn is_global(&self) -> bool {
        self.kind == Self::SCOPE_GLOBAL
    }
}

pub fn scope_key(target: ScanTarget) -> String {
    match target {
        ScanTarget::Repository(id) => format!("repository:{id}"),
        ScanTarget::Container(id) => format!("container:{id}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub verdict: GateVerdict,
    pub policy: ResolvedPolicy,
}

#[derive(Debug, Clone, Default)]
pub struct Caller {
    pub principal: Option<String>,
    pub ip_address: Option<String>,
}

impl Caller {
    pub fn new(principal: Option<String>, ip_address: Option<String>) -> Self {
        Self { principal, ip_address }
    }

    pub fn unattributed() -> Self {
        Self::default()
    }
}

/// A stored gate policy view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGatePolicyView {
    pub id: i64,
    pub target_kind: String,
    pub target_id: Option<i64>,
    pub version: i32,
    pub is_active: Option<bool>,
    pub fail_on_severity: Option<String>,
    pub fail_on_kev: bool,
    pub fixable_only: bool,
    pub include_triaged: bool,
    pub include_ai_review: bool,
    pub fail_on_uncovered_languages: bool,
    pub include_plugins: bool,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub policy: GatePolicy,
}

impl StoredGatePolicyView {
    pub fn of(row: &GatePolicyRow) -> Self {
        let global = row.target_kind == "global";
        Self {
            id: row.id,
            target_kind: row.target_kind.clone(),
            target_id: if global { None } else { Some(row.target_id) },
            version: row.version,
            is_active: row.is_active,
            fail_on_severity: row.fail_on_severity.clone(),
            fail_on_kev: row.fail_on_kev,
            fixable_only: row.fixable_only,
            include_triaged: row.include_triaged,
            include_ai_review: row.include_ai_review,
            fail_on_uncovered_languages: row.fail_on_uncovered_languages,
            include_plugins: row.include_plugins,
            note: row.note.clone(),
            created_by: row.created_by.clone(),
            created_at: Some(row.created_at),
            policy: ActiveGatePolicies::stored_policy(row).policy,
        }
    }
}

/// A gate verdict view for register and reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdictView {
    pub id: String,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub passed: bool,
    pub evaluated: i32,
    pub violations: i32,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub fail_on_severity: Option<String>,
    pub policy_source: String,
    pub policy_version: Option<i64>,
    pub relaxations_ignored: bool,
    pub decided_at: OffsetDateTime,
    pub decided_by: Option<String>,
    pub ip_address: Option<String>,
}

impl GateVerdictView {
    pub fn target(&self) -> Option<ScanTarget> {
        if let Some(repo_id) = self.repo_id {
            Some(ScanTarget::Repository(repo_id))
        } else {
            self.container_id.map(ScanTarget::Container)
        }
    }
}

impl From<&GateVerdictRow> for GateVerdictView {
    fn from(row: &GateVerdictRow) -> Self {
        Self {
            id: row.id.clone(),
            repo_id: row.repo_id,
            container_id: row.container_id,
            passed: row.passed,
            evaluated: row.evaluated,
            violations: row.violations,
            critical_count: row.critical_count,
            high_count: row.high_count,
            medium_count: row.medium_count,
            low_count: row.low_count,
            fail_on_severity: row.fail_on_severity.clone(),
            policy_source: row.policy_source.clone(),
            policy_version: row.policy_version,
            relaxations_ignored: row.relaxations_ignored,
            decided_at: row.decided_at,
            decided_by: row.decided_by.clone(),
            ip_address: row.ip_address.clone(),
        }
    }
}

/// Active gate policies helper.
pub struct ActiveGatePolicies {
    db: Db,
}

impl ActiveGatePolicies {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn by_scope(&self) -> Result<HashMap<String, StoredPolicy>, GateError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let rows = GatePolicyRepository::find_active(&mut tx).await?;
        crate::persistence::commit(tx).await?;

        let mut by_scope = HashMap::new();
        for row in rows {
            let key = format!("{}:{}", row.target_kind, row.target_id);
            by_scope.insert(key, Self::stored_policy(&row));
        }
        Ok(by_scope)
    }

    pub fn stored_policy(row: &GatePolicyRow) -> StoredPolicy {
        StoredPolicy {
            policy: GatePolicy {
                fail_on_severity: Self::threshold_of(row.fail_on_severity.as_deref()),
                fail_on_kev: row.fail_on_kev,
                fixable_only: row.fixable_only,
                include_triaged: row.include_triaged,
                include_ai_review: row.include_ai_review,
                fail_on_uncovered_languages: row.fail_on_uncovered_languages,
                include_plugins: row.include_plugins,
            },
            version: row.version,
        }
    }

    fn threshold_of(stored: Option<&str>) -> Option<Severity> {
        let stored = stored?.trim();
        if stored.is_empty() {
            return None;
        }
        let severity = Severity::of(Some(stored));
        if severity == Severity::Unknown { GatePolicy::BUILT_IN.fail_on_severity } else { Some(severity) }
    }
}

/// `BoundedText.within(note, TEXT_MAX, "The note")`: Java's ceiling for every stored text, in UTF-16 units. The bound
/// here was MySQL's 65,535 bytes, so a note Java refuses — 16,001 characters — was stored.
fn note_within_bounds(note: Option<&str>) -> Result<(), GateError> {
    if let Some(note) = note {
        bounded_text::within(note, bounded_text::TEXT_MAX, "The note")
            .map_err(|refused| GateError::InvalidInput(refused.0))?;
    }
    Ok(())
}

/// The observation the newest finished scan's stored status stands for; no scan, or a status this version cannot
/// read, is [`Observation::NeverScanned`] — never "no observation", which the gate does not refuse.
fn observation_of(newest_finished: Option<&str>) -> Observation {
    Observation::of(newest_finished.and_then(|status| ScanStatus::from_wire_name(Some(status))))
}

/// `GateService`: evaluations, stored policies, and posture overview.
pub struct GateService {
    db: Db,
    issues: Arc<IssueCatalog>,
    scans: Arc<ScanCatalog>,
    targets: Arc<Targets>,
    rule_coverage: Arc<RuleCoverageService>,
    active_policies: ActiveGatePolicies,
    clock: Arc<dyn Clock>,
    /// Where a refusal's `SECURITY_GATE_FAILED` goes: the SIEM export's queue in the binary.
    events: Arc<dyn SecurityEvents>,
}

impl GateService {
    pub fn new(
        db: Db,
        issues: Arc<IssueCatalog>,
        scans: Arc<ScanCatalog>,
        targets: Arc<Targets>,
        rule_coverage: Arc<RuleCoverageService>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn SecurityEvents>,
    ) -> Self {
        Self {
            db: db.clone(),
            issues,
            scans,
            targets,
            rule_coverage,
            active_policies: ActiveGatePolicies::new(db),
            clock,
            events,
        }
    }

    pub fn active_policies(&self) -> &ActiveGatePolicies {
        &self.active_policies
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn verdict_target(repository_id: Option<i64>, container_id: Option<i64>) -> Result<ScanTarget, GateError> {
        match (repository_id, container_id) {
            (Some(repo_id), None) => Ok(ScanTarget::Repository(repo_id)),
            (None, Some(cont_id)) => Ok(ScanTarget::Container(cont_id)),
            _ => Err(GateError::InvalidInput("Give exactly one of \"repository_id\" or \"container_id\".".to_owned())),
        }
    }

    pub async fn evaluate_and_record(
        &self,
        target: ScanTarget,
        requested: &RequestedPolicy,
        caller: &Caller,
    ) -> Result<Decision, GateError> {
        let decision = self.evaluate(target, requested).await?;
        self.record(target, &decision, caller).await;
        Ok(decision)
    }

    pub async fn evaluate(&self, target: ScanTarget, requested: &RequestedPolicy) -> Result<Decision, GateError> {
        let by_scope = self.active_policies.by_scope().await?;
        let target_key = scope_key(target);
        let resolved = PolicyResolution::resolve(
            PolicyLookup { for_target: by_scope.get(&target_key).cloned(), global: by_scope.get("global:0").cloned() },
            requested,
            PolicyScopeChoice::Target,
        );

        let issues = self.open_issues_of(target).await?;
        let coverage = self.coverage_of(target).await?;
        let examination = self.examination_of(target).await?;

        let verdict = PolicyGate::evaluate(&issues, &resolved.policy, &coverage, Some(examination));
        Ok(Decision { verdict, policy: resolved })
    }

    /// Whether the backlog about to be judged rests on a scan that ran to its end — Java's `examinationOf`.
    ///
    /// **No finished scan is an observation, not the absence of one.** It was answered `None` here, which
    /// `PolicyGate` reads as "no examination to judge": a target never scanned — an empty backlog — passed the gate
    /// it should have failed, and so did one whose only scans were still in flight. A status this version cannot
    /// read is no observation either, as on the Java side: guessing "ok" would be a confident wrong answer.
    async fn examination_of(&self, target: ScanTarget) -> Result<Observation, GateError> {
        let latest = self.scans.latest_finished(target).await.map_err(|e| GateError::Store(StoreError(Box::new(e))))?;
        Ok(observation_of(latest.as_ref().map(|row| row.status.as_str())))
    }

    /// The verdict and, for a refusal, its `SECURITY_GATE_FAILED` — **in one transaction**, or apart if that cannot
    /// commit (decision 0033).
    ///
    /// Together, the two commit or neither does: published after the verdict's own write, a stop between the two left
    /// a refusal in the register that no SOC ever heard of. A gate refusal leaves no audit entry — the verdict register
    /// is its record — so it is raised here rather than signalled.
    ///
    /// **Never at the expense of the answer.** A pipeline waiting on a verdict must get one. If the two cannot commit
    /// together, the verdict is written alone and the event raised on its own; if the verdict cannot be written at
    /// all, that is a hole in the register, logged at error level, and not a reason to fail somebody's build.
    pub(crate) async fn record(&self, target: ScanTarget, decision: &Decision, caller: &Caller) {
        let refusal = if decision.verdict.passed { None } else { self.refusal(target, decision, caller) };
        match self.record_together(target, decision, caller, refusal.as_ref()).await {
            Ok(()) => return,
            Err(together) => tracing::warn!(
                "Gate verdict and its SIEM event could not commit together; recording them apart: {together}"
            ),
        }
        if let Err(failed) = self.record_alone(target, decision, caller).await {
            tracing::error!("Gate verdict could not be recorded: {failed}");
        }
        if let Some(event) = &refusal {
            self.events.raise_apart(event).await;
        }
    }

    async fn record_together(
        &self,
        target: ScanTarget,
        decision: &Decision,
        caller: &Caller,
        refusal: Option<&CefEvent>,
    ) -> Result<(), RaiseError> {
        let mut tx = crate::persistence::write(&self.db).await?;
        GateVerdictRepository::insert(&mut tx, &self.verdict_row(target, decision, caller)).await?;
        if let Some(event) = refusal {
            self.events.raise(&mut tx, event).await?;
        }
        crate::persistence::commit(tx).await?;
        Ok(())
    }

    async fn record_alone(&self, target: ScanTarget, decision: &Decision, caller: &Caller) -> Result<(), StoreError> {
        let mut tx = crate::persistence::write(&self.db).await?;
        GateVerdictRepository::insert(&mut tx, &self.verdict_row(target, decision, caller)).await?;
        crate::persistence::commit(tx).await
    }

    /// The refusal's event. It cannot be refused by its own builder (no extension it sets is invalid); were it, the
    /// verdict would still be recorded, and the reason logged.
    fn refusal(&self, target: ScanTarget, decision: &Decision, caller: &Caller) -> Option<CefEvent> {
        let (kind, id) = match target {
            ScanTarget::Repository(id) => ("repository", id),
            ScanTarget::Container(id) => ("container", id),
        };
        let now = self.clock.now();
        let built = CefEvent::builder(
            SecurityEventType::SecurityGateFailed,
            Instant { epoch_second: now.unix_timestamp(), nano: now.nanosecond() },
        )
        .message(
            format!(
                "{} violation(s) against the {} policy",
                decision.verdict.violations.len(),
                decision.policy.source.name().to_ascii_lowercase()
            )
            .as_str(),
        )
        .user(caller.principal.as_deref())
        .source_ip(caller.ip_address.as_deref())
        .action("GATE_EVALUATED")
        .target(format!("{kind} {id}").as_str())
        .build();
        built.map_err(|refused| tracing::error!("The gate refusal's SIEM event could not be built: {refused}")).ok()
    }

    /// A new row each time, as Java's: the one a failed transaction tried is not reused.
    fn verdict_row(&self, target: ScanTarget, decision: &Decision, caller: &Caller) -> GateVerdictRow {
        let verdict = &decision.verdict;
        let count = |sev: Severity| *verdict.counts_by_severity.get(&sev).unwrap_or(&0);
        GateVerdictRow {
            id: Uuid::new_v4().to_string(),
            repo_id: match target {
                ScanTarget::Repository(id) => Some(id),
                ScanTarget::Container(_) => None,
            },
            container_id: match target {
                ScanTarget::Container(id) => Some(id),
                ScanTarget::Repository(_) => None,
            },
            passed: verdict.passed,
            evaluated: verdict.evaluated,
            violations: i32::try_from(verdict.violations.len()).unwrap_or(0),
            critical_count: count(Severity::Critical),
            high_count: count(Severity::High),
            medium_count: count(Severity::Medium),
            low_count: count(Severity::Low),
            fail_on_severity: decision.policy.policy.fail_on_severity.map(|s| s.wire_name().to_owned()),
            policy_source: decision.policy.source.name().to_owned(),
            policy_version: decision.policy.version.map(i64::from),
            relaxations_ignored: !decision.policy.ignored_relaxations.is_empty(),
            decided_at: self.clock.now(),
            decided_by: caller.principal.clone(),
            ip_address: caller.ip_address.clone(),
        }
    }

    pub async fn stored_policies(&self) -> Result<Vec<StoredGatePolicyView>, GateError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let rows = GatePolicyRepository::find_active(&mut tx).await?;
        crate::persistence::commit(tx).await?;
        Ok(rows.iter().map(StoredGatePolicyView::of).collect())
    }

    pub async fn list_policies_with_names(&self) -> Result<Vec<(StoredGatePolicyView, Option<String>)>, GateError> {
        let stored = self.stored_policies().await?;
        let names = vectispire_cp_targets::naming::all(&self.db)
            .await
            .map_err(|e| GateError::Store(StoreError(Box::new(e))))?;
        let mut list: Vec<(StoredGatePolicyView, Option<String>)> = stored
            .into_iter()
            .map(|policy| {
                let name = if policy.target_kind == "global" {
                    None
                } else if policy.target_kind == "container" {
                    Some(names.of(None, policy.target_id))
                } else {
                    Some(names.of(policy.target_id, None))
                };
                (policy, name)
            })
            .collect();
        list.sort_by(|(p1, n1), (p2, n2)| {
            p1.target_kind
                .cmp(&p2.target_kind)
                .then_with(|| n1.as_deref().unwrap_or("").cmp(n2.as_deref().unwrap_or("")))
        });
        Ok(list)
    }

    pub async fn target_name_of_scope(&self, scope: &PolicyScope) -> Result<Option<String>, GateError> {
        if scope.is_global() {
            Ok(None)
        } else {
            let names = vectispire_cp_targets::naming::all(&self.db)
                .await
                .map_err(|e| GateError::Store(StoreError(Box::new(e))))?;
            let name =
                if scope.kind == "container" { names.of(None, Some(scope.id)) } else { names.of(Some(scope.id), None) };
            Ok(Some(name))
        }
    }

    pub async fn store(
        &self,
        scope: &PolicyScope,
        policy: &GatePolicy,
        note: Option<&str>,
        author: Option<&str>,
    ) -> Result<StoredGatePolicyView, GateError> {
        self.require_scope_exists(scope).await?;

        let mut tx = crate::persistence::write(&self.db).await?;
        GatePolicyRepository::supersede(&mut tx, &scope.kind, scope.id).await?;
        let highest = GatePolicyRepository::highest_version(&mut tx, &scope.kind, scope.id).await?;
        let version = highest.saturating_add(1);

        let new_row = NewGatePolicyRow {
            target_kind: scope.kind.clone(),
            target_id: scope.id,
            version,
            is_active: Some(true),
            fail_on_severity: policy.fail_on_severity.map(|s| s.wire_name().to_owned()),
            fail_on_kev: policy.fail_on_kev,
            fixable_only: policy.fixable_only,
            include_triaged: policy.include_triaged,
            include_ai_review: policy.include_ai_review,
            fail_on_uncovered_languages: policy.fail_on_uncovered_languages,
            include_plugins: policy.include_plugins,
            note: note.and_then(|n| {
                let t = n.trim();
                if t.is_empty() { None } else { Some(t.to_owned()) }
            }),
            created_by: author.map(str::to_owned),
            created_at: self.clock.now(),
        };

        let id = GatePolicyRepository::insert(&mut tx, &new_row).await?;
        crate::persistence::commit(tx).await?;

        Ok(StoredGatePolicyView {
            id,
            target_kind: scope.kind.clone(),
            target_id: if scope.is_global() { None } else { Some(scope.id) },
            version,
            is_active: Some(true),
            fail_on_severity: policy.fail_on_severity.map(|s| s.wire_name().to_owned()),
            fail_on_kev: policy.fail_on_kev,
            fixable_only: policy.fixable_only,
            include_triaged: policy.include_triaged,
            include_ai_review: policy.include_ai_review,
            fail_on_uncovered_languages: policy.fail_on_uncovered_languages,
            include_plugins: policy.include_plugins,
            note: new_row.note,
            created_by: new_row.created_by,
            created_at: Some(new_row.created_at),
            policy: policy.clone(),
        })
    }

    pub async fn clear(&self, scope: &PolicyScope) -> Result<bool, GateError> {
        let mut tx = crate::persistence::write(&self.db).await?;
        let affected = GatePolicyRepository::supersede(&mut tx, &scope.kind, scope.id).await?;
        crate::persistence::commit(tx).await?;
        Ok(affected > 0)
    }

    async fn require_scope_exists(&self, scope: &PolicyScope) -> Result<(), GateError> {
        let exists = match scope.kind.as_str() {
            PolicyScope::SCOPE_GLOBAL => true,
            "repository" => self
                .targets
                .target_exists(ScanTarget::Repository(scope.id))
                .await
                .map_err(|e| GateError::InvalidInput(e.to_string()))?,
            "container" => self
                .targets
                .target_exists(ScanTarget::Container(scope.id))
                .await
                .map_err(|e| GateError::InvalidInput(e.to_string()))?,
            _ => {
                return Err(GateError::InvalidInput(format!(
                    "Unknown policy scope: \"{}\". Use global, repository or container.",
                    scope.kind
                )));
            }
        };
        if !exists {
            return Err(GateError::NotFound { kind: scope.kind.clone(), id: scope.id });
        }
        Ok(())
    }

    pub async fn overview(&self, visibility: &Visibility) -> Result<overview::Overview, GateError> {
        let active = self.active_policies.by_scope().await?;

        let repos = self.targets.catalog_repositories().await.map_err(|e| GateError::InvalidInput(e.to_string()))?;
        let containers = self.targets.catalog_containers().await.map_err(|e| GateError::InvalidInput(e.to_string()))?;

        let mut named_targets = Vec::new();
        let mut policies_by_target = HashMap::new();

        for repo in repos {
            let target = ScanTarget::Repository(repo.id);
            if !visibility.permits(target) {
                continue;
            }
            named_targets.push(NamedTarget { target, name: vectispire_cp_targets::naming::of_repository_view(&repo) });
            let key = format!("repository:{}", repo.id);
            if let Some(p) = active.get(&key) {
                policies_by_target.insert(target, p.clone());
            }
        }

        for cont in containers {
            let target = ScanTarget::Container(cont.id);
            if !visibility.permits(target) {
                continue;
            }
            named_targets.push(NamedTarget { target, name: vectispire_cp_targets::naming::of_container_view(&cont) });
            let key = format!("container:{}", cont.id);
            if let Some(p) = active.get(&key) {
                policies_by_target.insert(target, p.clone());
            }
        }

        let global_policy = active.get("global:0").cloned();
        let open_issues = self.open_issues_by_target().await?;
        let latest_scans = self.latest_scans().await?;
        let latest_finished = self.latest_finished_scans().await?;
        let uncovered = self.uncovered_by_target().await?;

        Ok(SecurityOverview::build(overview::Input {
            targets: named_targets,
            policies_by_target,
            global_policy,
            open_issues,
            latest_scans,
            latest_finished_scans: latest_finished,
            uncovered_ecosystems: uncovered,
        }))
    }

    async fn open_issues_of(&self, target: ScanTarget) -> Result<Vec<GateIssue>, GateError> {
        let issues =
            self.issues.gate_issues_of(target, "open").await.map_err(|e| GateError::InvalidInput(e.to_string()))?;
        Ok(issues.iter().map(Self::view_to_gate_issue).collect())
    }

    async fn open_issues_by_target(&self) -> Result<HashMap<ScanTarget, Vec<GateIssue>>, GateError> {
        let issues = self.issues.in_state("open").await.map_err(|e| GateError::InvalidInput(e.to_string()))?;
        let mut by_target: HashMap<ScanTarget, Vec<GateIssue>> = HashMap::new();
        for issue in issues {
            let target = if let Some(repo_id) = issue.repo_id {
                Some(ScanTarget::Repository(repo_id))
            } else {
                issue.container_id.map(ScanTarget::Container)
            };
            if let Some(t) = target {
                by_target.entry(t).or_default().push(Self::view_to_gate_issue(&issue));
            }
        }
        Ok(by_target)
    }

    fn view_to_gate_issue(v: &IssueView) -> GateIssue {
        GateIssue {
            id: v.id,
            open: v.state == "open",
            type_: FindingType::from_wire_name(Some(&v.type_)),
            severity: Severity::of(Some(&v.severity)),
            identifier: v.identifier.clone(),
            package_name: v.package_name.clone(),
            fix_versions: v.fix_versions.clone(),
            kev: v.is_kev,
            triage: TriageStatus::from_wire_name(&v.triage_status),
        }
    }

    async fn latest_scans(&self) -> Result<HashMap<ScanTarget, LatestScan>, GateError> {
        let mut map = HashMap::new();
        let repos = self.scans.latest_per_repository().await.map_err(|e| GateError::Store(StoreError(Box::new(e))))?;
        for r in repos {
            if let Some(status) = ScanStatus::from_wire_name(Some(&r.status)) {
                map.insert(
                    ScanTarget::Repository(r.target_id),
                    LatestScan { id: r.scan_id, status, created_at: r.created_at },
                );
            }
        }
        let conts = self.scans.latest_per_container().await.map_err(|e| GateError::Store(StoreError(Box::new(e))))?;
        for c in conts {
            if let Some(status) = ScanStatus::from_wire_name(Some(&c.status)) {
                map.insert(
                    ScanTarget::Container(c.target_id),
                    LatestScan { id: c.scan_id, status, created_at: c.created_at },
                );
            }
        }
        Ok(map)
    }

    async fn latest_finished_scans(&self) -> Result<HashMap<ScanTarget, LatestScan>, GateError> {
        let mut map = HashMap::new();
        let repos =
            self.scans.latest_finished_per_repository().await.map_err(|e| GateError::Store(StoreError(Box::new(e))))?;
        for r in repos {
            if let Some(status) = ScanStatus::from_wire_name(Some(&r.status)) {
                map.insert(
                    ScanTarget::Repository(r.target_id),
                    LatestScan { id: r.scan_id, status, created_at: r.created_at },
                );
            }
        }
        let conts =
            self.scans.latest_finished_per_container().await.map_err(|e| GateError::Store(StoreError(Box::new(e))))?;
        for c in conts {
            if let Some(status) = ScanStatus::from_wire_name(Some(&c.status)) {
                map.insert(
                    ScanTarget::Container(c.target_id),
                    LatestScan { id: c.scan_id, status, created_at: c.created_at },
                );
            }
        }
        Ok(map)
    }

    async fn uncovered_by_target(&self) -> Result<HashMap<ScanTarget, Vec<String>>, GateError> {
        let raw = self
            .rule_coverage
            .uncovered_ecosystems_by_target()
            .await
            .map_err(|e| GateError::InvalidInput(e.to_string()))?;
        let mut map = HashMap::new();
        for (key, ecosystems) in raw {
            let mut parts = key.splitn(2, ':');
            let kind = parts.next().unwrap_or("");
            let id_str = parts.next().unwrap_or("");
            if let Ok(id) = id_str.parse::<i64>() {
                let target = if kind == "container" { ScanTarget::Container(id) } else { ScanTarget::Repository(id) };
                map.insert(target, ecosystems);
            }
        }
        Ok(map)
    }

    async fn coverage_of(&self, target: ScanTarget) -> Result<Coverage, GateError> {
        let raw = self
            .rule_coverage
            .uncovered_ecosystems_by_target()
            .await
            .map_err(|e| GateError::InvalidInput(e.to_string()))?;
        let key = scope_key(target);
        let ecosystems = raw.get(&key).cloned().unwrap_or_default();
        Ok(Coverage::new(ecosystems))
    }
}

/// Administrative service for updating gate policies with audit logging.
pub struct GatePolicyAdministrationService {
    gate: Arc<GateService>,
    audit: Arc<AuditLog>,
}

impl GatePolicyAdministrationService {
    pub fn new(gate: Arc<GateService>, audit: Arc<AuditLog>) -> Self {
        Self { gate, audit }
    }

    pub async fn store(
        &self,
        scope: &PolicyScope,
        fields: &GatePolicyFields,
        note: Option<&str>,
        actor: &RequestActor,
    ) -> Result<StoredGatePolicyView, GateError> {
        let policy = fields.as_replacement()?;
        note_within_bounds(note)?;
        let stored = self.gate.store(scope, &policy, note, actor.username.as_deref()).await?;

        let what =
            if scope.is_global() { "the global policy".to_owned() } else { format!("{} {}", scope.kind, scope.id) };
        let desc = format!("Gate policy for {what} set to version {}: {}.", stored.version, Self::describe(&policy));
        let resource_id = format!("{}:{}", scope.kind, scope.id);
        self.audit.record(actor.entry(AuditOperation::GatePolicyUpdated, &resource_id, &desc)).await;

        Ok(stored)
    }

    pub async fn clear(&self, scope: &PolicyScope, actor: &RequestActor) -> Result<bool, GateError> {
        if !self.gate.clear(scope).await? {
            return Ok(false);
        }
        let resource_id = format!("{}:{}", scope.kind, scope.id);
        self.audit
            .record(actor.entry(
                AuditOperation::GatePolicyUpdated,
                &resource_id,
                "Gate policy removed; the target inherits again.",
            ))
            .await;
        Ok(true)
    }

    fn describe(policy: &GatePolicy) -> String {
        let mut parts = Vec::new();
        parts.push(format!("fail on {}", policy.fail_on_severity.map(|s| s.wire_name()).unwrap_or("no severity")));
        if policy.fail_on_kev {
            parts.push("fail on actively exploited".to_owned());
        }
        if policy.fixable_only {
            parts.push("fixable only".to_owned());
        }
        if policy.include_triaged {
            parts.push("triaged findings counted".to_owned());
        }
        if policy.include_ai_review {
            parts.push("model review counted".to_owned());
        }
        if policy.fail_on_uncovered_languages {
            parts.push("fail when no rule covers the target".to_owned());
        }
        if policy.include_plugins {
            parts.push("plugin and imported findings counted".to_owned());
        }
        parts.join(", ")
    }
}

/// A page from the verdict register.
#[derive(Debug, Clone)]
pub struct RegisterPage {
    pub visible: Vec<RegisteredVerdictItem>,
    pub passed: i64,
    pub refused: i64,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegisteredVerdictItem {
    pub verdict: GateVerdictView,
    pub target_name: Option<String>,
}

/// Service for querying the verdict register.
pub struct GateRegisterService {
    db: Db,
}

impl GateRegisterService {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn newest(&self, limit: i32) -> Result<Vec<GateVerdictView>, GateError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let rows = GateVerdictRepository::newest(&mut tx, limit).await?;
        crate::persistence::commit(tx).await?;
        Ok(rows.iter().map(GateVerdictView::from).collect())
    }

    pub async fn last_for_repository(
        &self,
        repo_id: i64,
        from: OffsetDateTime,
        until: Option<OffsetDateTime>,
    ) -> Result<Option<GateVerdictView>, GateError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let row = GateVerdictRepository::last_for_repository(&mut tx, repo_id, from, until).await?;
        crate::persistence::commit(tx).await?;
        Ok(row.as_ref().map(GateVerdictView::from))
    }

    pub async fn last_for_container(
        &self,
        container_id: i64,
        from: OffsetDateTime,
        until: Option<OffsetDateTime>,
    ) -> Result<Option<GateVerdictView>, GateError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let row = GateVerdictRepository::last_for_container(&mut tx, container_id, from, until).await?;
        crate::persistence::commit(tx).await?;
        Ok(row.as_ref().map(GateVerdictView::from))
    }

    pub async fn page(
        &self,
        allowed: &Visibility,
        limit: i32,
        cursor: Option<&str>,
    ) -> Result<RegisterPage, GateError> {
        let capped = limit.clamp(1, 500);
        let parsed_cursor = RegisterCursor::parse(cursor)
            .and_then(|from| Uuid::parse_str(&from.id).ok().map(|uuid| (from.at, uuid.to_string())));

        let mut tx = crate::persistence::read(&self.db).await?;
        let after = parsed_cursor.as_ref().map(|(at, id)| (*at, id.as_str()));
        let read = GateVerdictRepository::page(&mut tx, allowed, after, capped).await?;
        crate::persistence::commit(tx).await?;

        let visible: Vec<GateVerdictView> = read
            .iter()
            .map(GateVerdictView::from)
            .filter(|row| match row.target() {
                Some(t) => allowed.permits(t),
                None => matches!(allowed, Visibility::Everything),
            })
            .collect();

        let repo_ids: BTreeSet<i64> = visible.iter().filter_map(|v| v.repo_id).collect();
        let cont_ids: BTreeSet<i64> = visible.iter().filter_map(|v| v.container_id).collect();
        let names = vectispire_cp_targets::naming::for_ids(&self.db, &repo_ids, &cont_ids)
            .await
            .map_err(|e| GateError::Store(StoreError(Box::new(e))))?;

        let items: Vec<RegisteredVerdictItem> = visible
            .iter()
            .map(|row| {
                let target_name = match row.target() {
                    Some(t) if allowed.permits(t) => Some(names.of(row.repo_id, row.container_id)),
                    _ => None,
                };
                RegisteredVerdictItem { verdict: row.clone(), target_name }
            })
            .collect();

        let passed = i64::try_from(visible.iter().filter(|v| v.passed).count()).unwrap_or(0);
        let refused = i64::try_from(visible.iter().filter(|v| !v.passed).count()).unwrap_or(0);
        let capped_usize = usize::try_from(capped).unwrap_or(usize::MAX);
        let next_cursor = if read.len() < capped_usize {
            None
        } else {
            read.last().map(|last| RegisterCursor::new(last.decided_at, &last.id).encoded())
        };

        Ok(RegisterPage { visible: items, passed, refused, next_cursor })
    }
}

impl std::fmt::Debug for ActiveGatePolicies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ActiveGatePolicies").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for GateService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("GateService").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for GatePolicyAdministrationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("GatePolicyAdministrationService").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for GateRegisterService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("GateRegisterService").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Coverage;

    #[test]
    fn a_target_with_no_finished_scan_was_never_examined() {
        assert_eq!(observation_of(None), Observation::NeverScanned);
        assert_eq!(observation_of(Some("a status from a later version")), Observation::NeverScanned);
        assert_eq!(observation_of(Some("failed")), Observation::LastScanFailed);
        assert_eq!(observation_of(Some("completed")), Observation::Ok);
    }

    /// Java's `DecisionInputBoundsTest.aPolicyNoteIsBounded`: 16,000 characters fit, one more is refused in Java's words.
    #[test]
    fn a_policy_note_is_bounded_as_java_bounds_it() {
        assert!(note_within_bounds(None).is_ok());
        assert!(note_within_bounds(Some(&"n".repeat(16_000))).is_ok());
        match note_within_bounds(Some(&"n".repeat(16_001))) {
            Err(GateError::InvalidInput(message)) => assert_eq!(message, "The note is longer than 16000 characters."),
            other => panic!("{other:?}"),
        }
    }

    /// The pipeline's question on a target never scanned: an empty backlog, refused — Java's
    /// `GateObservationRoutesTest.neverScanned`.
    #[test]
    fn an_empty_backlog_never_examined_fails_the_gate() {
        let verdict =
            PolicyGate::evaluate(&[], &GatePolicy::BUILT_IN, &Coverage::new(Vec::new()), Some(observation_of(None)));
        assert!(!verdict.passed, "{verdict:?}");
        assert_eq!(verdict.violations.len(), 1);
        assert_eq!(verdict.violations[0].rule, crate::verdict::Rule::Observation);
    }
}
