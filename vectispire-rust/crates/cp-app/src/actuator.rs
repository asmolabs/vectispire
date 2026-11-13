//! The actuator in the binary: `cp-runtime`'s pages mounted on `cp-http`'s chain, the scrape token handed to the chain,
//! and the encryption census gathered from the modules that seal something.
//!
//! **The census is Java's `EncryptionCensus` over the stores the port has.** Each line is a module's own
//! (`SealedStore`); [`encryption_census`] is the list, and `tests/actuator_composition.rs` holds it to Java's stores so
//! that a module ported later adds its line here in the same commit — the census otherwise says a rotation is
//! finished while that module's values still need the old key. Java's stores with no Rust module to answer for them
//! yet: the TOTP secrets and backup codes (`TotpService`, the access module's), the forge connection tokens
//! (`ForgeConnectionService`), the tracker's token and inbound webhook secret (`TicketService`), the notification
//! webhook's signing secret (`NotificationService`) and the OpenAI key (`AiReviewService`).

use std::sync::Arc;

use vectispire_cp_crypto::{EncryptionCensus, SealedStore};
use vectispire_cp_http::actuator::{ActuatorPage, ActuatorPages};
use vectispire_cp_http::credentials::{BoxFuture, ScrapeToken};
use vectispire_cp_runtime::actuator::{Actuator, Report, ReportFuture};
use vectispire_domain::secret::Secret;

/// `cp-runtime`'s actuator as the chain's router asks it.
#[derive(Debug)]
pub struct Pages(pub Arc<Actuator>);

impl ActuatorPages for Pages {
    fn page<'a>(
        &'a self,
        path: &'a str,
        query: &'a str,
        base_url: &'a str,
    ) -> BoxFuture<'a, Result<Option<ActuatorPage>, String>> {
        Box::pin(async move {
            let answer = self.0.respond(path, query, base_url).await?;
            Ok(answer.map(|answer| ActuatorPage {
                status: answer.status,
                content_type: answer.content_type,
                body: answer.body,
            }))
        })
    }
}

/// `/actuator/encryption`: the census, read at each request — never at start, which needs no database.
#[derive(Debug)]
pub struct Census(pub EncryptionCensus);

impl Report for Census {
    fn read(&self) -> ReportFuture<'_> {
        Box::pin(self.0.report())
    }
}

/// `vectispire.metrics.scrape-token` / `-file`, read as `ScrapeTokenProperties.token()` reads it: the file at each
/// scrape.
#[derive(Debug)]
pub struct ScrapeTokenOf(pub vectispire_cp_runtime::settings::Metrics);

impl ScrapeToken for ScrapeTokenOf {
    fn token(&self) -> Result<Option<Secret>, String> {
        self.0.scrape_token()
    }
}

/// Every sealed store the port has a module for, as Java's census gathers them: the signing key and its record
/// (crypto), the clone credentials (targets), the SIEM's authorization header (siem).
pub fn encryption_census(
    signing: Arc<dyn SealedStore>,
    targets: Arc<dyn SealedStore>,
    siem: Arc<dyn SealedStore>,
) -> EncryptionCensus {
    EncryptionCensus::new(vec![signing, targets, siem])
}
