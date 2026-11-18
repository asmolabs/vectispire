//! The module's ports answered by their owners' APIs: the scans, backlog, inventory and schedules
//! ([`ScanEvidence`]), the projects ([`ProjectDirectory`]), the accounts and what each sees ([`AccountDirectory`]),
//! and the signing key ([`DocumentSigner`]). Each is a method of its owner's API — never a statement here.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_access::account_names;
use vectispire_cp_access::accounts::{AccountStore, UserView};
use vectispire_cp_access::visibility::{AccountRef, Allowance, VisibilityService};
use vectispire_cp_crypto::{KeyStore, SigningKeys};
use vectispire_cp_db::Visibility;
use vectispire_cp_inventory::component_catalog::ComponentCatalog;
use vectispire_cp_issues::IssueCatalog;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_targets::Targets;
use vectispire_domain::checklists::facts::{Component, ScanLanguages};
use vectispire_domain::finding_type::FindingType;
use vectispire_domain::instant::Instant;

use crate::days;
use crate::measurer::{Answer, ExaminingScan, PluginRunRow, ScanEvidence, ScansWithin, ScopeCount};
use crate::ports::{AccountDirectory, DocumentSigner, ProjectDirectory, ProjectMembers};

fn at(instant: Instant) -> OffsetDateTime {
    days::offset(instant)
}

/// [`ScanEvidence`] over `ScanCatalog`, `IssueCatalog`, `ComponentCatalog` and `Targets`' schedules.
#[derive(Clone)]
pub struct OwnerCatalogs {
    pub scans: ScanCatalog,
    pub issues: IssueCatalog,
    pub components: ComponentCatalog,
    pub targets: Arc<Targets>,
}

impl std::fmt::Debug for OwnerCatalogs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OwnerCatalogs").finish_non_exhaustive()
    }
}

impl ScanEvidence for OwnerCatalogs {
    fn newest_examining<'a>(
        &'a self,
        repositories: &'a [i64],
        step: FindingType,
    ) -> Answer<'a, BTreeMap<i64, ExaminingScan>> {
        Box::pin(async move {
            let rows = self
                .scans
                .newest_examining(repositories, step, OffsetDateTime::UNIX_EPOCH)
                .await
                .map_err(|failure| failure.to_string())?;
            Ok(rows
                .into_iter()
                .map(|(repository, row)| {
                    (
                        repository,
                        ExaminingScan {
                            scan_id: row.scan_id,
                            created_at: days::instant(row.created_at),
                            sbom_stored: row.sbom_stored,
                        },
                    )
                })
                .collect())
        })
    }

    fn completed_within<'a>(
        &'a self,
        repositories: &'a [i64],
        since: Instant,
    ) -> Answer<'a, BTreeMap<i64, ScansWithin>> {
        Box::pin(async move {
            let rows =
                self.scans.completed_within(repositories, at(since)).await.map_err(|failure| failure.to_string())?;
            Ok(rows
                .into_iter()
                .map(|(repository, row)| {
                    (repository, ScansWithin { completed: row.completed, unrecorded: row.unrecorded })
                })
                .collect())
        })
    }

    fn plugin_runs_within<'a>(
        &'a self,
        repositories: &'a [i64],
        plugin_id: &'a str,
        since: Instant,
    ) -> Answer<'a, BTreeMap<i64, Vec<PluginRunRow>>> {
        Box::pin(async move {
            let rows = self
                .scans
                .plugin_runs_within(repositories, plugin_id, at(since))
                .await
                .map_err(|failure| failure.to_string())?;
            Ok(rows
                .into_iter()
                .map(|(repository, runs)| {
                    (
                        repository,
                        runs.into_iter()
                            .map(|run| PluginRunRow {
                                scan_id: run.scan_id,
                                created_at: days::instant(run.created_at),
                                state: run.outcome.state.unwrap_or_default(),
                                refusal: run.outcome.refusal,
                                manifest_digest: run.outcome.manifest_digest,
                            })
                            .collect(),
                    )
                })
                .collect())
        })
    }

    fn naming_plugin_before<'a>(
        &'a self,
        repositories: &'a [i64],
        plugin_id: &'a str,
        since: Instant,
    ) -> Answer<'a, BTreeSet<i64>> {
        Box::pin(async move {
            self.scans
                .naming_plugin_before(repositories, plugin_id, at(since))
                .await
                .map_err(|failure| failure.to_string())
        })
    }

    fn languages_of<'a>(&'a self, scan_ids: &'a [i64]) -> Answer<'a, BTreeMap<i64, ScanLanguages>> {
        Box::pin(async move {
            let rows = self.scans.languages_of(scan_ids).await.map_err(|failure| failure.to_string())?;
            Ok(rows
                .into_iter()
                .map(|(scan, recorded)| {
                    (scan, ScanLanguages { detected: recorded.detected, sast_rules: recorded.sast_rules })
                })
                .collect())
        })
    }

    fn count_unsettled_of_type<'a>(
        &'a self,
        step: FindingType,
        repositories: &'a [i64],
    ) -> Answer<'a, Vec<ScopeCount>> {
        Box::pin(async move {
            let rows = self
                .issues
                .count_unsettled_of_type_within(step.wire_name(), repositories)
                .await
                .map_err(|failure| failure.to_string())?;
            Ok(rows.into_iter().map(count).collect())
        })
    }

    fn count_unsettled_of_tool<'a>(
        &'a self,
        tool_key: &'a str,
        repositories: &'a [i64],
    ) -> Answer<'a, Vec<ScopeCount>> {
        Box::pin(async move {
            let rows = self
                .issues
                .count_unsettled_of_tool_within(tool_key, repositories)
                .await
                .map_err(|failure| failure.to_string())?;
            Ok(rows.into_iter().map(count).collect())
        })
    }

    fn components_of<'a>(&'a self, scan_ids: &'a [i64]) -> Answer<'a, BTreeMap<i64, Vec<Component>>> {
        Box::pin(async move {
            let rows = self.components.components_of(scan_ids).await.map_err(|failure| failure.to_string())?;
            Ok(rows
                .into_iter()
                .map(|(scan, components)| {
                    (
                        scan,
                        components
                            .into_iter()
                            .map(|component| Component {
                                name: Some(component.name),
                                version: component.version,
                                purl: component.purl,
                            })
                            .collect(),
                    )
                })
                .collect())
        })
    }

    fn scheduled<'a>(
        &'a self,
        repositories: &'a [i64],
        max_age_days: i32,
        now: Instant,
    ) -> Answer<'a, BTreeMap<i64, bool>> {
        Box::pin(async move {
            self.targets
                .runs_at_least_every(repositories, time::Duration::days(i64::from(max_age_days)), at(now))
                .await
                .map_err(|failure| failure.to_string())
        })
    }
}

fn count(row: vectispire_cp_issues::catalog::ScopeCount) -> ScopeCount {
    ScopeCount {
        repository_id: row.repository_id,
        severity: row.severity.unwrap_or_default(),
        state: row.state,
        count: row.count,
    }
}

/// [`ProjectDirectory`] over `Targets`.
#[derive(Clone, Debug)]
pub struct TargetProjects(pub Arc<Targets>);

impl ProjectDirectory for TargetProjects {
    fn members<'a>(&'a self, project_id: i64) -> Answer<'a, Option<ProjectMembers>> {
        Box::pin(async move {
            let found = self.0.members(project_id).await.map_err(|failure| failure.to_string())?;
            Ok(found.map(|members| ProjectMembers { name: members.name, repository_ids: members.repository_ids }))
        })
    }

    fn project_of<'a>(&'a self, repository_id: i64) -> Answer<'a, Option<i64>> {
        Box::pin(
            async move { Ok(self.0.project_of(repository_id).await.map_err(|failure| failure.to_string())?.flatten()) },
        )
    }

    fn repository_names<'a>(&'a self, repository_ids: &'a [i64]) -> Answer<'a, BTreeMap<i64, String>> {
        Box::pin(async move { self.0.repository_names(repository_ids).await.map_err(|failure| failure.to_string()) })
    }
}

/// [`AccountDirectory`] over `access`'s directory and `VisibilityService`.
pub struct AccessAccounts<S> {
    pub directory: account_names::AccountDirectory<S>,
    pub visibility: VisibilityService,
}

impl<S> std::fmt::Debug for AccessAccounts<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AccessAccounts").finish_non_exhaustive()
    }
}

impl<S: AccountStore + Send + Sync> AccountDirectory for AccessAccounts<S> {
    fn active<'a>(&'a self) -> Answer<'a, Vec<UserView>> {
        Box::pin(async move { self.directory.active().await.map_err(|failure| failure.to_string()) })
    }

    fn by_id<'a>(&'a self, account_id: i64) -> Answer<'a, Option<UserView>> {
        Box::pin(async move { self.directory.by_id(account_id).await.map_err(|failure| failure.to_string()) })
    }

    fn allowance_of<'a>(&'a self, account: &'a UserView) -> Answer<'a, Allowance> {
        Box::pin(async move {
            let reference = AccountRef { id: account.id, role: account.role.clone() };
            self.visibility
                .allowance(Some(&reference), &Visibility::everything())
                .await
                .map_err(|failure| failure.to_string())
        })
    }
}

/// [`DocumentSigner`] over the platform's `SigningKeys`.
pub struct PlatformSigner<S: KeyStore>(pub Arc<SigningKeys<S>>);

impl<S: KeyStore> std::fmt::Debug for PlatformSigner<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PlatformSigner")
    }
}

impl<S: KeyStore + 'static> DocumentSigner for PlatformSigner<S> {
    fn key_id<'a>(&'a self) -> Answer<'a, String> {
        Box::pin(async move { self.0.key_id().await.map_err(|failure| failure.to_string()) })
    }

    fn sign<'a>(&'a self, payload: &'a [u8]) -> Answer<'a, String> {
        Box::pin(async move { self.0.sign(payload).await.map_err(|failure| failure.to_string()) })
    }
}
