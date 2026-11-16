//! `ScorecardBadgeService`: publishing a repository's grade as a README badge, and serving the badges published.
//!
//! **Publishing is a decision somebody makes**, never inherited from the route existing: a published badge says that
//! this repository's posture may be read by anyone holding the link. Idempotent — publishing twice answers the same
//! token rather than rotating it and breaking every README carrying the first — and audited only when it changed
//! something, so the log holds one entry per decision rather than one per click.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use vectispire_cp_access::rows;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_targets::Targets;

use crate::error::PostureError;
use crate::scorecard;
use crate::scorecards::SecurityScorecards;

/// A repository's badge: the published token, absent when none is, and whether this call changed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Badge {
    pub repository_id: i64,
    pub token: Option<String>,
    pub changed: bool,
}

#[derive(Clone)]
pub struct ScorecardBadges {
    targets: Arc<Targets>,
    scorecards: Arc<SecurityScorecards>,
    audit: Arc<AuditLog>,
}

opaque_debug!(ScorecardBadges);

impl ScorecardBadges {
    pub fn new(targets: Arc<Targets>, scorecards: Arc<SecurityScorecards>, audit: Arc<AuditLog>) -> ScorecardBadges {
        ScorecardBadges { targets, scorecards, audit }
    }

    /// The SVG of the repository published under this token, or `None` for a token nobody holds. **An unknown token and
    /// a revoked one are the same absence**: telling them apart would say that a repository once had a badge.
    pub async fn published_svg(&self, token: &str) -> Result<Option<String>, PostureError> {
        let Some(repository) = self.targets.repository_with_badge(token).await.map_err(PostureError::unexpected)?
        else {
            return Ok(None);
        };
        // The published token is the whole of this reader's allowance: the one repository it was issued for.
        let allowance = Visibility::Only(BTreeSet::from([ScanTarget::Repository(repository)]));
        let card = self.scorecards.repository_scorecard(repository, &allowance).await?;
        let (grade, color) = card.map_or(("unknown", "#555"), |card| (card.grade.label(), card.grade.badge_color()));
        Ok(Some(scorecard::badge("security grade", grade, color)))
    }

    /// The badge's state; `None` when the repository does not exist, a hidden one refused before it is looked up.
    pub async fn state(&self, repository: i64, allowed: &Visibility) -> Result<Option<Badge>, PostureError> {
        Ok(self.visible(repository, allowed).await?.map(|(id, token)| Badge {
            repository_id: id,
            token,
            changed: false,
        }))
    }

    /// Publishes, or answers the badge already published.
    pub async fn publish(
        &self,
        repository: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<Option<Badge>, PostureError> {
        let Some((id, token)) = self.visible(repository, allowed).await? else { return Ok(None) };
        if let Some(token) = token {
            return Ok(Some(Badge { repository_id: id, token: Some(token), changed: false }));
        }
        // 32 bytes, url-safe, unpadded: it lives in a README's URL and must survive being copied.
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        self.targets.set_badge_token(repository, Some(&token)).await.map_err(PostureError::unexpected)?;
        self.record(
            actor,
            repository,
            &format!(
                "Security badge published for repository {repository}: its grade is now readable by anyone holding the badge URL."
            ),
        )
        .await;
        Ok(Some(Badge { repository_id: id, token: Some(token), changed: true }))
    }

    /// Revokes the badge: every README carrying the old URL starts answering 404.
    pub async fn revoke(
        &self,
        repository: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<Option<Badge>, PostureError> {
        let Some((id, token)) = self.visible(repository, allowed).await? else { return Ok(None) };
        if token.is_none() {
            return Ok(Some(Badge { repository_id: id, token: None, changed: false }));
        }
        self.targets.set_badge_token(repository, None).await.map_err(PostureError::unexpected)?;
        self.record(actor, repository, &format!("Security badge revoked for repository {repository}.")).await;
        Ok(Some(Badge { repository_id: id, token: None, changed: true }))
    }

    /// The allowance first, then the row: a hidden repository is refused as a hidden target before anything is read.
    async fn visible(
        &self,
        repository: i64,
        allowed: &Visibility,
    ) -> Result<Option<(i64, Option<String>)>, PostureError> {
        rows::require_visible(ScanTarget::Repository(repository), allowed)?;
        Ok(self
            .targets
            .badge_token(repository)
            .await
            .map_err(PostureError::unexpected)?
            .map(|badge| (badge.repository_id, badge.token)))
    }

    async fn record(&self, actor: &RequestActor, repository: i64, description: &str) {
        self.audit
            .record(actor.entry(AuditOperation::BadgePublished, &format!("repository:{repository}:badge"), description))
            .await;
    }
}
