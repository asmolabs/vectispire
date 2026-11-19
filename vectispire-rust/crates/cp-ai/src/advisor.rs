//! `AiAdvisorService`: the advisor's explanations, restricted to the issues the caller may see.
//!
//! **An explanation is the finding itself, in prose** — the package, the file, the fix — so each lookup applies the
//! caller's visibility before anything is read from the row, and [`AiReviewService`] only ever receives an issue
//! somebody was allowed to open. **Exploitation is read from the stored feeds, and unknown is said**: the answer for a
//! CVE the estate does not carry was once built on figures made up here.

use std::sync::Arc;

use vectispire_cp_access::rows;
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_issues::IssueCatalog;
use vectispire_cp_issues::views::IssueView;
use vectispire_cp_threatintel::feeds::ThreatIntel;
use vectispire_cp_threatintel::status::{Exploitation, KevListing};

use crate::advice::{self, AdviceLanguage, AiVulnerabilityAdvice};
use crate::review::{AiReviewService, ReviewError};

/// Why the advisor did not answer.
#[derive(Debug, thiserror::Error)]
pub enum AdvisorError {
    /// 400: the language asked for is not one of the interface's.
    #[error("{0}")]
    InvalidInput(String),
    /// 404, absent and hidden alike.
    #[error("{0}")]
    NotFound(String),
    #[error(transparent)]
    Review(#[from] ReviewError),
}

impl AdvisorError {
    fn failed(error: impl std::fmt::Display) -> AdvisorError {
        AdvisorError::Review(ReviewError::Failed(error.to_string()))
    }
}

/// The service.
#[derive(Debug, Clone)]
pub struct AiAdvisorService {
    reviews: AiReviewService,
    issues: Arc<IssueCatalog>,
    feeds: ThreatIntel,
}

/// A row attached to neither target is left to the visibility's own reading, as the entity's is.
fn target_of(issue: &IssueView) -> Option<ScanTarget> {
    match (issue.repo_id, issue.container_id) {
        (Some(repository), _) => Some(ScanTarget::Repository(repository)),
        (None, Some(container)) => Some(ScanTarget::Container(container)),
        (None, None) => None,
    }
}

fn permits(allowed: &Visibility, target: Option<ScanTarget>) -> bool {
    match (allowed, target) {
        (Visibility::Everything, _) => true,
        (Visibility::Only(_), None) => false,
        (Visibility::Only(_), Some(target)) => allowed.permits(target),
    }
}

impl AiAdvisorService {
    pub fn new(reviews: AiReviewService, issues: Arc<IssueCatalog>, feeds: ThreatIntel) -> AiAdvisorService {
        AiAdvisorService { reviews, issues, feeds }
    }

    /// `explainIssue`: **an absent row goes to the same guard as a hidden one** — its own 404, worded apart, told a
    /// restricted reader which sequential ids existed.
    pub async fn explain_issue(
        &self,
        issue_id: i64,
        language: Option<&str>,
        allowed: &Visibility,
    ) -> Result<AiVulnerabilityAdvice, AdvisorError> {
        let asked = AdviceLanguage::parse(language).map_err(AdvisorError::InvalidInput)?;
        let found = self.issues.find_by_id(issue_id).await.map_err(AdvisorError::failed)?;
        let issue = rows::require_visible_issue(found, target_of, allowed)
            .map_err(|refused| AdvisorError::NotFound(refused.to_string()))?;
        let exploitation = self.exploitation_of(&issue).await?;
        Ok(self.reviews.explain_vulnerability(&issue, exploitation, asked).await?)
    }

    /// `explainCve`: from the first visible issue that carries it, or from the stored feeds alone. **Narrowed before
    /// anything is read**, so that a CVE present only in a target the caller was not given gets exactly the answer a
    /// CVE present nowhere gets. **No component from the caller**: an identifier no visible issue carries is explained
    /// by what the feeds hold.
    pub async fn explain_cve(
        &self,
        cve_id: &str,
        language: Option<&str>,
        allowed: &Visibility,
    ) -> Result<AiVulnerabilityAdvice, AdvisorError> {
        let asked = AdviceLanguage::parse(language).map_err(AdvisorError::InvalidInput)?;
        let carried = self.issues.with_identifier(cve_id).await.map_err(AdvisorError::failed)?;
        if let Some(issue) = carried.into_iter().find(|issue| permits(allowed, target_of(issue))) {
            let exploitation = self.exploitation_of(&issue).await?;
            return Ok(self.reviews.explain_vulnerability(&issue, exploitation, asked).await?);
        }
        let stored = self.feeds.exploitation_of(Some(cve_id)).await.map_err(AdvisorError::failed)?;
        Ok(advice::for_identifier_alone(Some(cve_id), Some(stored)))
    }

    /// `exploitationOf`: the issue's own figures where it holds them — what every other screen shows for it — the
    /// feeds' for what the row cannot tell: "not listed" from "nobody looked", or a score it was never given.
    async fn exploitation_of(&self, issue: &IssueView) -> Result<Exploitation, AdvisorError> {
        if let (true, Some(score)) = (issue.is_kev, issue.epss_score) {
            return Ok(Exploitation { kev: KevListing::Listed, epss_score: Some(score) });
        }
        let stored = self.feeds.exploitation_of(Some(&issue.identifier)).await.map_err(AdvisorError::failed)?;
        Ok(Exploitation {
            kev: if issue.is_kev { KevListing::Listed } else { stored.kev },
            epss_score: issue.epss_score.or(stored.epss_score),
        })
    }
}
