//! The two parts of modules not ported yet that a settings save runs, as Java runs them — and nothing more of those
//! modules.
//!
//! **Why narrow.** `tickets` and `ai` are wave 2: a tracker client, its token's health, the webhook it receives, the
//! review calls, the key they send. A save asks two questions of them, and both answers are pure functions of what
//! this crate can already read:
//!
//! - [`TrackerCaPinning`] is `TicketService.caToPin`: `PinnedCa.parsePasted(pem, now, CA)` with the tracker's
//!   subject — the rule `vectispire_domain::pinned_ca` holds for the forge connections and the SIEM collector, in the
//!   tracker's words. The tracker's state, the pinned CA's description and the calls stay `tickets`'.
//! - [`GuardedAiDestination`] is `AiReviewService`'s `openAiUrl`/`ollamaUrl` (the stored address, trimmed, its
//!   default when empty), `requireLocalUnlessAcknowledged` (the outbound guard under `INTERNAL_REQUIRED`, labelled
//!   with the provider's display name) and `recordRiskAcknowledgement`/`clearRiskAcknowledgement` (two settings,
//!   written in the save's transaction). The provider's calls, its key and the endpoint check stay `ai`'s.
//!
//! When `tickets` and `ai` land they implement [`crate::Tracker`] and [`crate::AiDestination`] themselves, and these
//! two go. Both are held to `reference/platform/settings-save.json`, which Java writes with the real
//! `AiReviewService` over a real guard and with `PinnedCa` itself.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use time::OffsetDateTime;
use vectispire_cp_audit::Clock;
use vectispire_cp_db::Tx;
use vectispire_cp_outbound::{OutboundPolicy, OutboundUrlGuard};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::instant::Instant;
use vectispire_domain::pinned_ca::{PinnedCa, Subject};

use crate::forms::java_trim;
use crate::settings::{AiAfter, AiDestination, CollaboratorError, Tracker};

/// `TicketService.CA`: the words a refused tracker CA is named in.
pub const TRACKER_CA: Subject = Subject { field: "The tracker CA", server: "the tracker" };

/// `AiReview.DEFAULT_OLLAMA_URL`.
pub const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";
/// `AiReview.DEFAULT_OPENAI_URL`.
pub const DEFAULT_OPENAI_URL: &str = "https://api.openai.com/v1";

/// `tickets`' `TicketService.caToPin`, as the save asks it.
#[derive(Debug, Clone)]
pub struct TrackerCaPinning {
    clock: Arc<dyn Clock>,
}

impl TrackerCaPinning {
    pub fn new(clock: Arc<dyn Clock>) -> TrackerCaPinning {
        TrackerCaPinning { clock }
    }
}

impl Tracker for TrackerCaPinning {
    fn refuse_ca(&self, pem: &str) -> Option<String> {
        // `caToPin` reads nothing for a blank PEM; the save never asks it one, and the answer would be "pinnable".
        if vectispire_cp_settings::types::is_blank(pem) {
            return None;
        }
        PinnedCa::parse_pasted(Some(pem), instant(self.clock.now()), &TRACKER_CA).err().map(|refused| refused.0)
    }
}

/// `ai`'s `AiReviewService`, as far as a save reads and writes it.
#[derive(Debug, Clone)]
pub struct GuardedAiDestination {
    settings: Settings,
    guard: OutboundUrlGuard,
}

impl GuardedAiDestination {
    /// `guard` is the binary's, built at start with the reserved endpoints: the one every outbound call asks.
    pub fn new(settings: Settings, guard: OutboundUrlGuard) -> GuardedAiDestination {
        GuardedAiDestination { settings, guard }
    }

    /// `openAiUrl()` / `ollamaUrl()`: the stored address, trimmed, or the default when there is none.
    async fn stored_url(&self, setting: Setting, default: &str) -> Result<String, CollaboratorError> {
        let stored = self.settings.get(setting).await?;
        let configured = java_trim(&stored);
        Ok(if configured.is_empty() { default.to_owned() } else { configured.to_owned() })
    }
}

impl AiDestination for GuardedAiDestination {
    fn refuse_destination<'a>(
        &'a self,
        after: AiAfter<'a>,
    ) -> BoxFuture<'a, Result<Option<String>, CollaboratorError>> {
        Box::pin(async move {
            // `AiProvider.of`: trimmed, lower-cased, anything unknown read as Ollama — the destination that leaks
            // nothing.
            let openai = java_trim(after.provider).to_lowercase() == "openai";
            let (setting, pending, default, display) = if openai {
                (Setting::AiReviewOpenaiUrl, after.openai_url, DEFAULT_OPENAI_URL, "OpenAI")
            } else {
                (Setting::AiReviewOllamaUrl, after.ollama_url, DEFAULT_OLLAMA_URL, "Ollama")
            };
            // `pending.getOrDefault(…, aiReview.openAiUrl())`, then the default for a URL this save clears.
            let url = match pending {
                Some(url) => url.to_owned(),
                None => self.stored_url(setting, default).await?,
            };
            let url = if vectispire_cp_settings::types::is_blank(&url) { default.to_owned() } else { url };
            // `requireLocalUnlessAcknowledged`: nothing to judge once sending off-site was acknowledged.
            if after.allow_remote {
                return Ok(None);
            }
            // The guard resolves the name, which blocks: off the runtime's threads, as the SIEM's sender does.
            let guard = self.guard.clone();
            let label = format!("{display} URL");
            let verdict = tokio::task::spawn_blocking(move || {
                guard.validate(&url, OutboundPolicy::InternalRequired, &label).err().map(|refused| refused.0)
            })
            .await?;
            Ok(verdict)
        })
    }

    fn record_risk_acknowledgement<'a>(
        &'a self,
        tx: &'a mut Tx,
        by: &'a str,
        at: OffsetDateTime,
    ) -> BoxFuture<'a, Result<(), CollaboratorError>> {
        Box::pin(async move {
            self.settings.set(tx, Setting::AiReviewRiskAcknowledgedBy, java_trim(by)).await?;
            self.settings.set(tx, Setting::AiReviewRiskAcknowledgedAt, &vectispire_cp_audit::iso_instant(at)).await?;
            Ok(())
        })
    }

    fn clear_risk_acknowledgement<'a>(&'a self, tx: &'a mut Tx) -> BoxFuture<'a, Result<(), CollaboratorError>> {
        Box::pin(async move {
            self.settings.set(tx, Setting::AiReviewRiskAcknowledgedBy, "").await?;
            self.settings.set(tx, Setting::AiReviewRiskAcknowledgedAt, "").await?;
            Ok(())
        })
    }
}

fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}
