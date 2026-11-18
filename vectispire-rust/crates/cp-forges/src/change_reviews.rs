//! `ForgeChangeReviews`: the checklists' port onto the stored readings (decision 0037, lot G3) — what each repository's
//! newest reading said, as the rule reads it, and nothing for a repository never read, a reading claimed and not yet
//! written included, which the rule reads as "no reading yet", never as a pass.
//!
//! **A suspended connection's readings are not handed over** (decision 0040 §2): when the row names a connection whose
//! forge is switched off, the rule is told so, whatever the row says — the registry asked at every read.

use std::collections::{BTreeMap, BTreeSet};

use vectispire_cp_checklists::measurer::{Answer, ReviewEvidence};
use vectispire_cp_db::Db;
use vectispire_domain::checklists::ChangeReviewEvidence;
use vectispire_domain::checklists::facts::{Look, ReviewFacts, Source};
use vectispire_domain::forges::ForgeKind;

use crate::internal::integrations::{self, ForgeIntegrations};
use crate::persistence::{self, StoreError};
use crate::views::instant;

/// The branch a reading of the default branch is stored under.
pub(crate) const DEFAULT_BRANCH: &str = "";

/// The port.
#[derive(Clone)]
pub struct ForgeChangeReviews {
    pub(crate) db: Db,
    pub(crate) integrations: ForgeIntegrations,
}

impl std::fmt::Debug for ForgeChangeReviews {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ForgeChangeReviews")
    }
}

impl ForgeChangeReviews {
    async fn read(&self, repositories: &[i64], branch: Option<&str>) -> Result<BTreeMap<i64, ReviewFacts>, String> {
        let ids: Vec<i64> = repositories.iter().copied().collect::<BTreeSet<_>>().into_iter().collect();
        let disabled = self.integrations.disabled().await.map_err(|failure| failure.to_string())?;
        let mut tx = persistence::read(&self.db).await.map_err(|failure| failure.to_string())?;
        // The connections are an administrator's handful: read whole, and only while a forge is off.
        let suspended: BTreeMap<String, ForgeKind> = if disabled.is_empty() {
            BTreeMap::new()
        } else {
            persistence::connections(&mut tx)
                .await
                .map_err(|failure| failure.to_string())?
                .into_iter()
                .filter_map(|connection| {
                    ForgeKind::parse(Some(&connection.kind))
                        .ok()
                        .filter(|kind| disabled.contains(kind))
                        .map(|kind| (connection.id, kind))
                })
                .collect()
        };
        let rows = persistence::readings_of(&mut tx, branch.unwrap_or(DEFAULT_BRANCH), &ids)
            .await
            .map_err(|failure: StoreError| failure.to_string())?;
        tx.commit().await.map_err(|failure| failure.to_string())?;
        let mut recorded = BTreeMap::new();
        for row in rows {
            let newest = row.read_at.map(|at| Look {
                source: Source::ForgeReview,
                id: row.id,
                at: instant(at),
                digest: row.evidence_sha256.clone(),
            });
            if let Some(kind) = row.connection_id.as_ref().and_then(|connection| suspended.get(connection)) {
                recorded.insert(
                    row.repository_id,
                    ReviewFacts::Suspended { look: newest, why: integrations::suspension(*kind) },
                );
                continue;
            }
            let Some(look) = newest else {
                continue;
            };
            let reason = row.reason.clone().unwrap_or_default();
            let facts = match row.state.as_str() {
                "read" => {
                    let evidence = ChangeReviewEvidence::read(row.evidence.as_deref().unwrap_or(""))
                        .map_err(|defect| format!("{defect:?}"))?;
                    ReviewFacts::Read { look, evidence }
                }
                "unreadable" => ReviewFacts::Unreadable { look, why: reason },
                "unlinked" => ReviewFacts::Unlinked { look, why: reason },
                // Pending, or a state this version does not know: never read.
                _ => continue,
            };
            recorded.insert(row.repository_id, facts);
        }
        Ok(recorded)
    }
}

impl ReviewEvidence for ForgeChangeReviews {
    fn recorded<'a>(
        &'a self,
        repositories: &'a [i64],
        branch: Option<&'a str>,
    ) -> Answer<'a, BTreeMap<i64, ReviewFacts>> {
        Box::pin(self.read(repositories, branch))
    }
}
