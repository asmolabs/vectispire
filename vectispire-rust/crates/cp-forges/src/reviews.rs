//! `ForgeReviewService`: reads, through each repository's forge connection, how changes reach the branches the
//! checklists' `change_review` lines ask about, and keeps what it read (decision 0037, lot G3). Called by the hourly
//! maintenance turn and by nothing else — never on a request.
//!
//! **Which repositories**: those the lines ask about ([`ChangeReviewDemand`]), each read again once its reading is
//! older than the refresh, or narrower than the window now asked; a reading no line asks about any more is deleted.
//! **Which forge**: the connection that imported the target, otherwise one whose snapshot lists a repository with the
//! target's URL identity; neither, the reading says `unlinked`. **One instance reads each**: a conditional claim first.
//! **No transaction around a forge.** **A reading that did not happen leaves the previous one**; a refusal is a reading.
//! **A suspended connection is not read**: the claim is let go with the link noted, the stored reading kept.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use vectispire_cp_checklists::demand::{ChangeReviewDemand, Wanted};
use vectispire_cp_crypto::{Encryption, SecretState, forge_connection_context};
use vectispire_cp_db::Db;
use vectispire_cp_outbound::json::{OutboundJson, TIMEOUT};
use vectispire_cp_outbound::pager::{PagerClock, PagerCounters, PagerError, Settings};
use vectispire_cp_targets::Clock;
use vectispire_domain::bounded_text;
use vectispire_domain::forges::ForgeKind;
use vectispire_domain::repository_url;

use crate::change_reviews::DEFAULT_BRANCH;
use crate::error::ForgeError;
use crate::internal::integrations::{self, ForgeIntegrations};
use crate::internal::readers::{self, Reading};
use crate::internal::targets;
use crate::persistence::{self, ReadingRow, StoreError};
use crate::views::instant;

/// `ReviewBounds`: `vectispire.forges.reviews.*`.
#[derive(Debug, Clone, Copy)]
pub struct ReviewBounds {
    pub refresh: Duration,
    pub claim: Duration,
    pub reading_duration: Duration,
    pub turn_duration: Duration,
    pub max_readings: usize,
    pub max_changes: usize,
    pub max_rate_limit_wait: Duration,
}

impl Default for ReviewBounds {
    fn default() -> ReviewBounds {
        ReviewBounds {
            refresh: Duration::from_secs(6 * 3600),
            claim: Duration::from_secs(15 * 60),
            reading_duration: Duration::from_secs(120),
            turn_duration: Duration::from_secs(300),
            max_readings: 200,
            max_changes: 500,
            max_rate_limit_wait: Duration::from_secs(60),
        }
    }
}

const UNLINKED: &str = "no forge connection imported this repository, and no repository a discovery listed has its \
                        URL: import it from a forge connection, or run a discovery that lists it";

/// Where a target's forge project is: the connection and the forge's own id.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    connection_id: String,
    forge_id: String,
}

enum Outcome {
    Written,
    LetGo,
    Suspended,
}

/// The service.
pub struct ForgeReviewService {
    pub(crate) db: Db,
    pub(crate) demand: ChangeReviewDemand,
    pub(crate) targets: Arc<vectispire_cp_targets::Targets>,
    pub(crate) encryption: Arc<Encryption>,
    pub(crate) outbound: OutboundJson,
    pub(crate) integrations: ForgeIntegrations,
    pub(crate) bounds: ReviewBounds,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) pager_clock: Arc<dyn PagerClock>,
}

impl std::fmt::Debug for ForgeReviewService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ForgeReviewService").finish_non_exhaustive()
    }
}

fn store(failure: StoreError) -> ForgeError {
    ForgeError::from(failure)
}

fn span(duration: Duration) -> time::Duration {
    time::Duration::try_from(duration).unwrap_or(time::Duration::MAX)
}

impl ForgeReviewService {
    /// One turn: the readings no line asks for deleted, then every due reading read, up to the turn's bounds. How
    /// many readings were written.
    pub async fn read_due(&self) -> Result<usize, ForgeError> {
        let start = self.clock.now();
        let turn_ends = start + span(self.bounds.turn_duration);
        let wanted = self.demand.wanted().await.map_err(ForgeError::Unexpected)?;
        self.sweep(&wanted).await?;
        if wanted.is_empty() {
            return Ok(0);
        }
        let mut linked: Option<BTreeMap<i64, Link>> = None;
        let mut suspended = BTreeSet::new();
        let (mut written, mut skipped) = (0usize, 0usize);
        for want in &wanted {
            let now = self.clock.now();
            if written >= self.bounds.max_readings || now >= turn_ends {
                tracing::info!(
                    "Change-review readings: the turn's bound was reached after {written} readings; the rest at the next."
                );
                break;
            }
            let Some(claimed) = self.claim(want, now).await? else {
                continue;
            };
            if linked.is_none() {
                let ids: Vec<i64> =
                    wanted.iter().map(|want| want.repository_id).collect::<BTreeSet<_>>().into_iter().collect();
                linked = Some(self.links(&ids).await?);
            }
            let link = linked.as_ref().and_then(|linked| linked.get(&want.repository_id)).cloned();
            match self.read(claimed, want, link, &mut suspended, turn_ends).await? {
                Outcome::Written => written += 1,
                Outcome::Suspended => skipped += 1,
                Outcome::LetGo => {}
            }
        }
        if skipped > 0 {
            tracing::info!(
                "Change-review readings: {skipped} not taken, the {} integration(s) disabled; their connections are \
                 suspended and their lines read no data until a governor re-enables them.",
                integrations::keys(&suspended)
            );
        }
        Ok(written)
    }

    /// Deletes the readings of the repositories no line asks about.
    async fn sweep(&self, wanted: &[Wanted]) -> Result<(), ForgeError> {
        let asked: BTreeSet<i64> = wanted.iter().map(|want| want.repository_id).collect();
        let mut tx = persistence::write(&self.db).await.map_err(store)?;
        let unasked: Vec<i64> = persistence::repositories_read(&mut tx)
            .await
            .map_err(store)?
            .into_iter()
            .filter(|id| !asked.contains(id))
            .collect();
        persistence::delete_readings_of_repositories(&mut tx, &unasked).await.map_err(store)?;
        tx.commit().await.map_err(|failure| store(failure.into()))?;
        Ok(())
    }

    /// The link of each target: its provenance first, then the snapshots' URLs, only for the targets left.
    async fn links(&self, repository_ids: &[i64]) -> Result<BTreeMap<i64, Link>, ForgeError> {
        let mut tx = persistence::read(&self.db).await.map_err(store)?;
        let mut linked: BTreeMap<i64, Link> = persistence::links_of_repositories(&mut tx, repository_ids)
            .await
            .map_err(store)?
            .into_iter()
            .map(|link| (link.repository_id, Link { connection_id: link.connection_id, forge_id: link.forge_id }))
            .collect();
        let left: Vec<i64> = repository_ids.iter().copied().filter(|id| !linked.contains_key(id)).collect();
        if left.is_empty() {
            tx.commit().await.map_err(|failure| store(failure.into()))?;
            return Ok(linked);
        }
        // Each snapshot row under the identities of both its clone URLs; the lowest connection id first.
        let mut urls = persistence::current_urls(&mut tx).await.map_err(store)?;
        tx.commit().await.map_err(|failure| store(failure.into()))?;
        urls.sort_by(|left, right| {
            left.connection_id
                .cmp(&right.connection_id)
                .then_with(|| vectispire_domain::java::compare_utf16(&left.forge_id, &right.forge_id))
        });
        let mut by_identity: BTreeMap<String, Link> = BTreeMap::new();
        for row in urls {
            let link = Link { connection_id: row.connection_id.clone(), forge_id: row.forge_id.clone() };
            for url in [row.http_url.as_deref(), row.ssh_url.as_deref()].into_iter().flatten() {
                if let Some(identity) = repository_url::identity(url) {
                    by_identity.entry(identity).or_insert_with(|| link.clone());
                }
            }
        }
        let wanted: BTreeSet<i64> = left.into_iter().collect();
        let repositories = self
            .targets
            .catalog_repositories_by_ids(&wanted)
            .await
            .map_err(|failure| ForgeError::Unexpected(failure.to_string()))?;
        for repository in repositories {
            if let Some(link) =
                repository_url::identity(&repository.url).and_then(|identity| by_identity.get(&identity))
            {
                linked.insert(repository.id, link.clone());
            }
        }
        Ok(linked)
    }

    /// The row, created if absent, and claimed if it is due and free; `None` when another instance has it.
    async fn claim(&self, want: &Wanted, now: OffsetDateTime) -> Result<Option<ReadingRow>, ForgeError> {
        let branch = want.branch.clone().unwrap_or_else(|| DEFAULT_BRANCH.to_owned());
        let mut tx = persistence::read(&self.db).await.map_err(store)?;
        let found = persistence::reading(&mut tx, want.repository_id, &branch).await.map_err(store)?;
        tx.commit().await.map_err(|failure| store(failure.into()))?;
        let row = match found {
            Some(row) => row,
            None => {
                let created = ReadingRow {
                    id: 0,
                    repository_id: want.repository_id,
                    wanted_branch: branch.clone(),
                    state: "pending".to_owned(),
                    connection_id: None,
                    forge_id: None,
                    window_days: want.window_days,
                    read_at: None,
                    reason: None,
                    evidence: None,
                    evidence_sha256: None,
                    claimed_until: None,
                };
                let inserted = async {
                    let mut tx = persistence::write(&self.db).await?;
                    persistence::save_reading(&mut tx, &created).await?;
                    tx.commit().await?;
                    Ok::<_, StoreError>(())
                };
                if let Err(refused) = inserted.await {
                    // Another instance's row, most likely: not a claim lost — the committed row is asked below.
                    tracing::debug!(
                        "Change-review reading of repository {} not created here: {refused}",
                        want.repository_id
                    );
                }
                let mut tx = persistence::read(&self.db).await.map_err(store)?;
                let found = persistence::reading(&mut tx, want.repository_id, &branch).await.map_err(store)?;
                tx.commit().await.map_err(|failure| store(failure.into()))?;
                match found {
                    Some(row) => row,
                    None => return Ok(None),
                }
            }
        };
        let mut tx = persistence::write(&self.db).await.map_err(store)?;
        let claimed = persistence::claim_reading(
            &mut tx,
            row.id,
            now,
            now + span(self.bounds.claim),
            now - span(self.bounds.refresh),
            want.window_days,
        )
        .await
        .map_err(store)?;
        tx.commit().await.map_err(|failure| store(failure.into()))?;
        if claimed != 1 {
            return Ok(None);
        }
        let mut tx = persistence::read(&self.db).await.map_err(store)?;
        let row = persistence::reading(&mut tx, want.repository_id, &branch).await.map_err(store)?;
        tx.commit().await.map_err(|failure| store(failure.into()))?;
        Ok(row)
    }

    async fn read(
        &self,
        row: ReadingRow,
        want: &Wanted,
        link: Option<Link>,
        suspended: &mut BTreeSet<ForgeKind>,
        turn_ends: OffsetDateTime,
    ) -> Result<Outcome, ForgeError> {
        let now = self.clock.now();
        let Some(link) = link else {
            self.write(row, want, now, None, "unlinked", Some(UNLINKED), None).await?;
            return Ok(Outcome::Written);
        };
        let mut tx = persistence::read(&self.db).await.map_err(store)?;
        let connection = persistence::connection(&mut tx, &link.connection_id).await.map_err(store)?;
        tx.commit().await.map_err(|failure| store(failure.into()))?;
        let Some(connection) = connection else {
            self.write(row, want, now, None, "unlinked", Some(UNLINKED), None).await?;
            return Ok(Outcome::Written);
        };
        let kind = ForgeKind::parse(Some(&connection.kind))?;
        // Before the reader is picked and the token decrypted: a disabled forge is handed nothing.
        if !self.integrations.enabled(kind).await? {
            suspended.insert(kind);
            let mut kept = row;
            kept.connection_id = Some(link.connection_id.clone());
            kept.forge_id = Some(link.forge_id.clone());
            kept.claimed_until = None;
            self.save(&kept).await?;
            return Ok(Outcome::Suspended);
        }
        let trust = match targets::stored_ca(&connection, instant(now)) {
            Ok(trust) => trust,
            Err(unusable) => {
                let reason = format!("{} Replace the CA on the connection.", unusable.0);
                self.write(row, want, now, Some(&link), "unreadable", Some(&reason), None).await?;
                return Ok(Outcome::Written);
            }
        };
        let sealed = self.encryption.inspect(&connection.token, &forge_connection_context(&link.connection_id)).await;
        if sealed.state() == SecretState::Unreadable {
            let reason = "the connection's token can no longer be decrypted by any configured key: replace it on the \
                          connection";
            self.write(row, want, now, Some(&link), "unreadable", Some(reason), None).await?;
            return Ok(Outcome::Written);
        }
        let target = targets::of(&connection, connection.internal_network, trust)?;
        let deadline = (now + span(self.bounds.reading_duration)).min(turn_ends);
        let credential = match kind {
            ForgeKind::Gitlab => vec![("PRIVATE-TOKEN".to_owned(), sealed.plain_text().to_owned())],
            ForgeKind::Github => vec![
                ("Authorization".to_owned(), format!("Bearer {}", sealed.plain_text())),
                ("X-GitHub-Api-Version".to_owned(), crate::internal::probes::GITHUB_API_VERSION.to_owned()),
            ],
        };
        let pager = self
            .outbound
            .pager(
                Settings {
                    origin: target.address.api_root.clone(),
                    policy: target.policy,
                    label: target.where_(),
                    credential,
                    trust: target.sending().cloned(),
                    deadline: instant(deadline),
                    max_wait: self.bounds.max_rate_limit_wait,
                    timeout: TIMEOUT,
                    heartbeat: None,
                    counters: Arc::new(PagerCounters::default()),
                },
                self.pager_clock.clone(),
            )
            .map_err(ForgeError::Unexpected)?;
        let since = instant(now).minus_days(i64::from(want.window_days)).unwrap_or(instant(now));
        let api = target.address.api_root.clone();
        let read = match kind {
            ForgeKind::Gitlab => {
                readers::read_gitlab(
                    &pager,
                    &api,
                    &link.forge_id,
                    want.branch.as_deref(),
                    since,
                    want.window_days,
                    self.bounds.max_changes,
                )
                .await
            }
            ForgeKind::Github => {
                readers::read_github(
                    &pager,
                    &api,
                    &link.forge_id,
                    want.branch.as_deref(),
                    since,
                    want.window_days,
                    self.bounds.max_changes,
                )
                .await
            }
        };
        match read {
            Ok(Reading::Read(evidence)) => {
                self.write(row, want, now, Some(&link), "read", None, Some(evidence.json())).await?;
            }
            Ok(Reading::Unreadable(why)) => {
                self.write(row, want, now, Some(&link), "unreadable", Some(&why), None).await?;
            }
            Err(PagerError::Unsafe(refused) | PagerError::CrossOrigin(refused)) => {
                self.write(row, want, now, Some(&link), "unreadable", Some(&refused), None).await?;
            }
            Err(transient) => {
                tracing::warn!(
                    "Change-review reading of repository {} did not happen ({transient}); the previous one stands.",
                    want.repository_id
                );
                let mut tx = persistence::write(&self.db).await.map_err(store)?;
                persistence::release_reading(&mut tx, row.id).await.map_err(store)?;
                tx.commit().await.map_err(|failure| store(failure.into()))?;
                return Ok(Outcome::LetGo);
            }
        }
        Ok(Outcome::Written)
    }

    #[allow(clippy::too_many_arguments)]
    async fn write(
        &self,
        mut row: ReadingRow,
        want: &Wanted,
        at: OffsetDateTime,
        link: Option<&Link>,
        state: &str,
        reason: Option<&str>,
        evidence: Option<String>,
    ) -> Result<(), ForgeError> {
        row.state = state.to_owned();
        row.connection_id = link.map(|link| link.connection_id.clone());
        row.forge_id = link.map(|link| link.forge_id.clone());
        row.window_days = want.window_days;
        row.read_at = Some(at);
        row.reason = reason.and_then(|reason| bounded_text::clip(Some(reason), 1000)).map(str::to_owned);
        row.evidence_sha256 = evidence
            .as_deref()
            .map(|json| Sha256::digest(json.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>());
        row.evidence = evidence;
        row.claimed_until = None;
        self.save(&row).await
    }

    async fn save(&self, row: &ReadingRow) -> Result<(), ForgeError> {
        let mut tx = persistence::write(&self.db).await.map_err(store)?;
        persistence::save_reading(&mut tx, row).await.map_err(store)?;
        tx.commit().await.map_err(|failure| store(failure.into()))?;
        Ok(())
    }
}
