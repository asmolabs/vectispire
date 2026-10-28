//! Folding scan findings into the issue history: `IssueSyncService` and `IssueBacklog`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_outbox::SecurityEvents;
use vectispire_cp_scanning::ingestion::{Backlog, BacklogDelta, Observation, ObservedFinding};
use vectispire_cp_scanning::ports::PortError;
use vectispire_domain::fingerprint::{self, Input};
use vectispire_domain::{FindingType, bounded_text};

use crate::error::IssueError;
use crate::persistence::{IssueRepository, IssueRow, NewIssue, NewTriageEvent};
use crate::signals::{self, Signalled};
use crate::triage::{TriageOrigin, TriageStatus};

pub struct IssueSyncService;

impl IssueSyncService {
    pub const FINGERPRINT_BATCH: usize = 1_000;

    /// Folds one observation into issues.
    #[allow(clippy::too_many_arguments)]
    pub async fn fold(
        events: &dyn SecurityEvents,
        tx: &mut Tx,
        scan_id: Option<i64>,
        target: ScanTarget,
        findings: &[ObservedFinding],
        scanned_types: &BTreeSet<FindingType>,
        scanned_tools: &BTreeSet<String>,
        import_source: Option<&str>,
        descriptions: &BTreeMap<Option<String>, String>,
    ) -> Result<BacklogDelta, IssueError> {
        let now = OffsetDateTime::now_utc();

        // 1. Compute fingerprints for each finding, preserving index positions
        let mut fingerprints = Vec::with_capacity(findings.len());
        let mut by_fingerprint: BTreeMap<String, Vec<usize>> = BTreeMap::new();

        for (idx, finding) in findings.iter().enumerate() {
            let fp = Self::fingerprint_of(target, finding)?;
            fingerprints.push(fp.clone());
            by_fingerprint.entry(fp).or_default().push(idx);
        }

        // 2. Fetch existing issues for these fingerprints in batches
        let sought: Vec<String> = by_fingerprint.keys().cloned().collect();
        let mut existing: BTreeMap<String, IssueRow> = BTreeMap::new();

        for batch in sought.chunks(Self::FINGERPRINT_BATCH) {
            let rows = IssueRepository::find_by_fingerprints(tx, batch).await?;
            for row in rows {
                existing.entry(row.fingerprint.clone()).or_insert(row);
            }
        }

        // 3. Process each distinct fingerprint
        let mut created_count = 0i32;
        let mut reopened_count = 0i32;
        let mut reopen_events = Vec::new();
        let mut id_by_fingerprint: BTreeMap<String, i64> = BTreeMap::new();
        let mut leaks = Vec::new();

        for (fp, indices) in &by_fingerprint {
            let first_idx = indices.first().copied().unwrap_or_default();
            let raw_finding = findings.get(first_idx).cloned().unwrap_or_default();

            let desc = Self::describe(&raw_finding, descriptions);
            let clipped = Self::fit_to_columns(&raw_finding);

            if let Some(mut existing_issue) = existing.remove(fp) {
                // Issue already exists
                let is_resolved = existing_issue.state == "resolved";
                if is_resolved {
                    reopened_count = reopened_count.saturating_add(1);
                    let triage_before = existing_issue.triage_status.clone();
                    let resolved_before = existing_issue.resolved_at;

                    if existing_issue.triage_status == TriageStatus::Fixed.wire_name() {
                        existing_issue.triage_status = TriageStatus::UnderReview.wire_name().to_owned();
                        existing_issue.triage_justification = None;
                        existing_issue.triaged_by = None;
                        existing_issue.triaged_at = None;
                    }

                    reopen_events.push(NewTriageEvent {
                        issue_id: existing_issue.id,
                        from_status: if triage_before.is_empty() {
                            TriageStatus::UnderReview.wire_name().to_owned()
                        } else {
                            triage_before
                        },
                        to_status: existing_issue.triage_status.clone(),
                        justification: existing_issue.triage_justification.clone(),
                        comment: None,
                        actor: None,
                        origin: TriageOrigin::Reopening.wire_name().to_owned(),
                        occurred_at: now,
                        expires_at: existing_issue.triage_expires_at,
                        scan_id,
                        previous_resolved_at: resolved_before,
                        requested_status: None,
                    });
                }

                // Reopen and refresh fields
                existing_issue.state = "open".to_owned();
                existing_issue.resolved_at = None;
                existing_issue.resolution_seconds = None;

                Self::copy_refreshed_fields(&mut existing_issue, &clipped, false);

                if existing_issue.description.is_none() {
                    existing_issue.description = desc;
                }
                existing_issue.last_seen_at = now;
                existing_issue.last_seen_scan_id = scan_id;
                existing_issue.times_seen = existing_issue.times_seen.saturating_add(1);

                IssueRepository::update_issue(tx, &existing_issue).await?;
                id_by_fingerprint.insert(fp.clone(), existing_issue.id);
            } else {
                // New issue
                created_count = created_count.saturating_add(1);
                let (repo_id, container_id) = match target {
                    ScanTarget::Repository(id) => (Some(id), None),
                    ScanTarget::Container(id) => (None, Some(id)),
                };

                let new_issue = NewIssue {
                    repo_id,
                    container_id,
                    fingerprint: fp.clone(),
                    type_: raw_finding.type_.clone(),
                    identifier: clipped.identifier.clone().unwrap_or_default(),
                    package_name: clipped.package_name.clone(),
                    package_version: clipped.package_version.clone(),
                    purl: clipped.purl.clone(),
                    file_path: clipped.file_path.clone(),
                    owasp_category: clipped.owasp_category.clone(),
                    source: clipped.source.clone(),
                    tool: clipped.tool.clone(),
                    tool_name: clipped.tool_name.clone(),
                    tool_version: clipped.tool_version.clone(),
                    import_source: import_source.map(str::to_owned),
                    severity: clipped.severity.clone().unwrap_or_default(),
                    epss_score: clipped.epss_score,
                    is_kev: clipped.kev,
                    cvss_score: clipped.cvss_score,
                    cvss_vector: clipped.cvss_vector.clone(),
                    fix_state: clipped.fix_state.clone(),
                    fix_versions: clipped.fix_versions.clone(),
                    link: clipped.link.clone(),
                    description: desc,
                    reachability: "UNKNOWN".to_owned(),
                    reachable_symbols: None,
                    state: "open".to_owned(),
                    first_seen_at: now,
                    last_seen_at: now,
                    resolved_at: None,
                    resolution_seconds: None,
                    sla_breach_signalled_at: None,
                    first_seen_scan_id: scan_id,
                    last_seen_scan_id: scan_id,
                    times_seen: 1,
                    triage_status: TriageStatus::UnderReview.wire_name().to_owned(),
                    triage_justification: None,
                    triage_comment: None,
                    triaged_by: None,
                    triaged_at: None,
                    triage_expires_at: None,
                    triage_requested_status: None,
                    is_direct_dependency: clipped.direct_dependency,
                    line: clipped.line,
                    ticket_ref: None,
                    ticket_url: None,
                    ticket_attached_by: None,
                    revision: 0,
                };

                let inserted = IssueRepository::insert_issue(tx, &new_issue).await?;
                id_by_fingerprint.insert(fp.clone(), inserted.id);
                if signals::is_leak(&new_issue.type_, &new_issue.severity) {
                    leaks.push((inserted.id, new_issue));
                }
            }
        }

        // A leak is announced once, when its issue is created: one seen again stays quiet, and one that comes back
        // after being resolved reopens its issue — neither is announced again. Queued in this transaction, after the
        // insert gave each issue its number: a scan that rolls back announces nothing, and the event leaves only once
        // the issues it names exist.
        for (id, leak) in &leaks {
            let event = signals::secret_leak(Signalled {
                id: *id,
                identifier: &leak.identifier,
                file_path: leak.file_path.as_deref(),
                package_name: leak.package_name.as_deref(),
                repo_id: leak.repo_id,
                container_id: leak.container_id,
                first_seen_at: leak.first_seen_at,
            })
            .map_err(|refused| IssueError::Store(refused.0))?;
            events.raise(tx, &event).await.map_err(|failed| IssueError::Store(failed.to_string()))?;
        }

        // 4. Record any reopenings into triage history
        if !reopen_events.is_empty() {
            IssueRepository::insert_triage_events(tx, &reopen_events).await?;
        }

        // 5. Resolve disappeared issues
        let types_vec: Vec<String> =
            scanned_types.iter().filter(|t| !t.tool_scoped()).map(|t| t.wire_name().to_owned()).collect();

        let tools_vec: Vec<String> = scanned_tools.iter().cloned().collect();
        let seen_fps: std::collections::BTreeSet<String> = by_fingerprint.keys().cloned().collect();

        let (repo_id, container_id) = match target {
            ScanTarget::Repository(id) => (Some(id), None),
            ScanTarget::Container(id) => (None, Some(id)),
        };

        let mut open_candidates = Vec::new();
        if !types_vec.is_empty() {
            let by_target = IssueRepository::find_open_by_target(tx, "open", &types_vec, repo_id, container_id).await?;
            open_candidates.extend(by_target);
        }
        if !tools_vec.is_empty() {
            let tool_scoped_types: Vec<String> =
                FindingType::ALL.iter().filter(|t| t.tool_scoped()).map(|t| t.wire_name().to_owned()).collect();
            let by_tools = IssueRepository::find_open_by_target_and_tools(
                tx,
                "open",
                &tool_scoped_types,
                &tools_vec,
                repo_id,
                container_id,
            )
            .await?;
            open_candidates.extend(by_tools);
        }

        let disappeared_ids: Vec<i64> = open_candidates
            .into_iter()
            .filter(|i| !seen_fps.contains(&i.fingerprint))
            .map(|i| i.id)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let resolved_count = IssueRepository::resolve_disappeared(tx, &disappeared_ids, now).await?;

        // 6. Map findings to issue ids
        let issue_ids: Vec<Option<i64>> = fingerprints.iter().map(|fp| id_by_fingerprint.get(fp).copied()).collect();

        let distinct_total = i32::try_from(by_fingerprint.len()).unwrap_or(i32::MAX);
        let still_open = distinct_total.saturating_sub(created_count).saturating_sub(reopened_count);

        Ok(BacklogDelta {
            created: created_count,
            resolved: i32::try_from(resolved_count).unwrap_or(i32::MAX),
            reopened: reopened_count,
            still_open,
            issue_ids,
        })
    }

    fn fingerprint_of(target: ScanTarget, finding: &ObservedFinding) -> Result<String, IssueError> {
        let type_str = finding.type_.as_str();
        let finding_type = FindingType::from_wire_name(Some(type_str)).ok_or_else(|| {
            IssueError::InvalidInput(format!(
                "Unknown finding type \"{type_str}\": it would fingerprint as itself and never match an existing issue."
            ))
        })?;

        let domain_target = match target {
            ScanTarget::Repository(id) => vectispire_domain::ScanTarget::Repository(id),
            ScanTarget::Container(id) => vectispire_domain::ScanTarget::Container(id),
        };

        if finding_type.tool_scoped() {
            let tool = finding.tool.as_deref().unwrap_or("");
            if tool.trim().is_empty() {
                return Err(IssueError::InvalidInput(format!(
                    "A {} finding carries no tool key.",
                    finding_type.wire_name()
                )));
            }
            fingerprint::of_tool(
                domain_target,
                finding_type,
                Some(tool),
                finding.identifier.as_deref(),
                finding.file_path.as_deref(),
            )
            .map_err(|e| IssueError::InvalidInput(e.to_string()))
        } else {
            Ok(fingerprint::of(&Input {
                target: domain_target,
                finding_type,
                identifier: finding.identifier.as_deref(),
                purl: finding.purl.as_deref(),
                package_name: finding.package_name.as_deref(),
                file_path: finding.file_path.as_deref(),
            }))
        }
    }

    fn describe(finding: &ObservedFinding, descriptions: &BTreeMap<Option<String>, String>) -> Option<String> {
        if let Some(id) = &finding.identifier
            && let Some(advisory) = descriptions.get(&Some(id.clone()))
            && !advisory.trim().is_empty()
        {
            return bounded_text::clip(Some(advisory), bounded_text::TEXT_MAX).map(str::to_owned);
        }
        finding
            .description
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| bounded_text::clip(Some(s), bounded_text::TEXT_MAX).map(str::to_owned))
    }

    fn fit_to_columns(finding: &ObservedFinding) -> ObservedFinding {
        ObservedFinding {
            type_: finding.type_.clone(),
            source: finding.source.clone(),
            identifier: bounded_text::clip(finding.identifier.as_deref(), 255).map(str::to_owned),
            severity: bounded_text::clip(finding.severity.as_deref(), 50).map(str::to_owned),
            package_name: bounded_text::clip(finding.package_name.as_deref(), 255).map(str::to_owned),
            package_version: bounded_text::clip(finding.package_version.as_deref(), 255).map(str::to_owned),
            purl: bounded_text::clip(finding.purl.as_deref(), 255).map(str::to_owned),
            file_path: bounded_text::clip(finding.file_path.as_deref(), 500).map(str::to_owned),
            line: finding.line,
            direct_dependency: finding.direct_dependency,
            owasp_category: finding.owasp_category.clone(),
            epss_score: finding.epss_score,
            cvss_score: finding.cvss_score,
            cvss_vector: bounded_text::clip(finding.cvss_vector.as_deref(), 255).map(str::to_owned),
            fix_state: bounded_text::clip(finding.fix_state.as_deref(), 50).map(str::to_owned),
            fix_versions: bounded_text::clip(finding.fix_versions.as_deref(), 255).map(str::to_owned),
            link: bounded_text::clip(finding.link.as_deref(), 500).map(str::to_owned),
            kev: finding.kev,
            description: bounded_text::clip(finding.description.as_deref(), bounded_text::TEXT_MAX).map(str::to_owned),
            tool: bounded_text::clip(finding.tool.as_deref(), 200).map(str::to_owned),
            tool_name: bounded_text::clip(finding.tool_name.as_deref(), 100).map(str::to_owned),
            tool_version: bounded_text::clip(finding.tool_version.as_deref(), 100).map(str::to_owned),
        }
    }

    fn copy_refreshed_fields(issue: &mut IssueRow, finding: &ObservedFinding, overwrite_nulls: bool) {
        if finding.package_version.is_some() || overwrite_nulls {
            issue.package_version = finding.package_version.clone();
        }
        if finding.line.is_some() || overwrite_nulls {
            issue.line = finding.line;
        }
        if finding.direct_dependency.is_some() || overwrite_nulls {
            issue.is_direct_dependency = finding.direct_dependency;
        }
        if let Some(sev) = &finding.severity {
            issue.severity = sev.clone();
        } else if overwrite_nulls {
            issue.severity = "UNKNOWN".to_owned();
        }
        if finding.owasp_category.is_some() || overwrite_nulls {
            issue.owasp_category = finding.owasp_category.clone();
        }
        if !finding.source.is_empty() {
            issue.source = Some(finding.source.clone());
        }
        if finding.epss_score.is_some() || overwrite_nulls {
            issue.epss_score = finding.epss_score;
        }
        if finding.cvss_score.is_some() || overwrite_nulls {
            issue.cvss_score = finding.cvss_score;
        }
        if finding.cvss_vector.is_some() || overwrite_nulls {
            issue.cvss_vector = finding.cvss_vector.clone();
        }
        if finding.fix_state.is_some() || overwrite_nulls {
            issue.fix_state = finding.fix_state.clone();
        }
        if finding.fix_versions.is_some() || overwrite_nulls {
            issue.fix_versions = finding.fix_versions.clone();
        }
        if finding.link.is_some() || overwrite_nulls {
            issue.link = finding.link.clone();
        }
        if finding.tool_name.is_some() || overwrite_nulls {
            issue.tool_name = finding.tool_name.clone();
        }
        if finding.tool_version.is_some() || overwrite_nulls {
            issue.tool_version = finding.tool_version.clone();
        }
        if overwrite_nulls || finding.kev {
            issue.is_kev = finding.kev;
        }
    }
}

/// Backlog port implementation for `ScanIngestor`. It holds no database: it folds in the transaction it is handed,
/// and raises the leaks it creates in it.
pub struct IssueBacklog {
    events: Arc<dyn SecurityEvents>,
}

impl IssueBacklog {
    pub fn new(events: Arc<dyn SecurityEvents>) -> Self {
        Self { events }
    }
}

impl Backlog for IssueBacklog {
    fn reconcile<'a>(
        &'a self,
        tx: &'a mut Tx,
        observation: &'a Observation,
    ) -> BoxFuture<'a, Result<BacklogDelta, PortError>> {
        Box::pin(async move {
            let Some(target) = observation.target else {
                return Err(PortError::from(Box::new(IssueError::InvalidInput(format!(
                    "Scan {} belongs to no target.",
                    observation.scan_id
                ))) as Box<dyn std::error::Error + Send + Sync>));
            };

            // Only in the scan's transaction: the fold and the delta it queues commit with the scan's findings, or
            // roll back with them — never in a transaction of its own, which kept a refused result's issues.
            IssueSyncService::fold(
                self.events.as_ref(),
                tx,
                Some(observation.scan_id),
                target,
                &observation.findings,
                &observation.scanned_types,
                &observation.scanned_tools,
                None,
                &observation.descriptions,
            )
            .await
            .map_err(|e| PortError::from(Box::new(e) as Box<dyn std::error::Error + Send + Sync>))
        })
    }
}

opaque_debug!(IssueSyncService, IssueBacklog);
