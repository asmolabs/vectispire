//! Where the two feeds are read from — Java's `KevCatalogSource`, `EpssFileSource` and `ThreatIntelProperties`.
//!
//! **A property of the deployment, not a setting of the screen.** A closed estate reads both from a mirror on its own
//! network, which means a private address — and a destination that reaches the private network is one nobody but
//! whoever deploys the control plane should choose. **One switch per feed**, not one for both: a deployment that
//! mirrors EPSS internally and reads CISA's catalogue from CISA would otherwise have to open the private network to
//! both.
//!
//! **Never inside a transaction.** The synchronisations fetch before they open the one that writes, and the scans no
//! longer call either: they read what was stored.
//!
//! The two sources are ports ([`KevSource`], [`EpssSource`]) so that a test hands the synchronisation a document
//! without a server — as Java's suite hands it a Mockito stub.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use vectispire_cp_outbound::download::OutboundDownload;
use vectispire_cp_outbound::json::OutboundJson;
use vectispire_cp_outbound::policy::OutboundPolicy;

use crate::epss_file;
use crate::kev_catalog::KevCatalog;

/// What a source answers: the document, or the sentence the status and the audit entry carry.
pub type Fetched<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// `Catalogs.KEV_CATALOG_URL`: CISA's own address.
pub const KEV_CATALOG_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// The catalogue's ceiling — past the ordinary one on purpose: it is about a megabyte and a half and grows with every
/// entry CISA adds; 32 MiB is a decade of growth, not an open door. An answer over it is refused, not truncated.
pub const KEV_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// The EPSS archive's ceiling: twenty times today's.
pub const EPSS_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Each read's timeout for the EPSS file: a few megabytes over a slow link to a mirror, once a day.
pub const EPSS_TIMEOUT: Duration = Duration::from_secs(60);

/// The KEV catalogue, whole — or why not; never an empty one.
pub trait KevSource: Send + Sync {
    fn fetch(&self) -> Fetched<'_, KevCatalog>;
    /// Where it is read from, for the log line an operator reads when it fails.
    fn location(&self) -> &str;
}

/// The EPSS file's bytes, gzip as published — or why not; never an empty file.
pub trait EpssSource: Send + Sync {
    fn fetch(&self) -> Fetched<'_, Vec<u8>>;
    fn location(&self) -> &str;
}

/// `ThreatIntelProperties`: blank reads the publisher's own address; `allow_private` lets a URL resolve to a private
/// or loopback address — a mirror inside the estate. Link-local stays refused whatever it says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedLocations {
    pub kev_url: Option<String>,
    pub kev_allow_private: bool,
    pub epss_url: Option<String>,
    pub epss_allow_private: bool,
}

impl FeedLocations {
    pub fn kev_catalog_url(&self) -> String {
        present(self.kev_url.as_deref()).unwrap_or(KEV_CATALOG_URL).to_owned()
    }

    pub fn kev_policy(&self) -> OutboundPolicy {
        policy(self.kev_allow_private)
    }

    pub fn epss_file_url(&self) -> String {
        present(self.epss_url.as_deref()).unwrap_or(epss_file::DEFAULT_URL).to_owned()
    }

    pub fn epss_policy(&self) -> OutboundPolicy {
        policy(self.epss_allow_private)
    }
}

fn present(url: Option<&str>) -> Option<&str> {
    url.map(str::trim).filter(|url| !url.is_empty())
}

fn policy(allow_private: bool) -> OutboundPolicy {
    if allow_private { OutboundPolicy::InternalAllowed } else { OutboundPolicy::PublicOnly }
}

/// `KevCatalogSource`: through [`OutboundJson`], so through the same guard and the same pinned sender as every other
/// outbound call; a redirect is refused rather than followed.
#[derive(Debug, Clone)]
pub struct KevCatalogSource {
    outbound: OutboundJson,
    url: String,
    policy: OutboundPolicy,
}

impl KevCatalogSource {
    pub fn new(outbound: OutboundJson, locations: &FeedLocations) -> KevCatalogSource {
        KevCatalogSource { outbound, url: locations.kev_catalog_url(), policy: locations.kev_policy() }
    }
}

impl KevSource for KevCatalogSource {
    fn fetch(&self) -> Fetched<'_, KevCatalog> {
        Box::pin(async move {
            let document = self
                .outbound
                .get_bounded(&self.url, self.policy, "KEV catalogue", &[], KEV_MAX_BYTES, None)
                .await
                .map_err(|failure| failure.to_string())?
                // 404 is "absent" to OutboundJson, and for a catalogue that must exist it is a failure: a mirror that
                // lost the file has not published an empty catalogue.
                .ok_or_else(|| "the catalogue was not found at the configured address".to_owned())?;
            KevCatalog::parse(&document).map_err(|unreadable| unreadable.0)
        })
    }

    fn location(&self) -> &str {
        &self.url
    }
}

/// `EpssFileSource`: through [`OutboundDownload`] — the guard, the pinned sender, and one redirect to the same origin
/// at most; FIRST's stable address answers with one, to the day's dated file. **The archive is held, not the file**:
/// the connection is closed before anything is written.
#[derive(Debug, Clone)]
pub struct EpssFileSource {
    outbound: OutboundDownload,
    url: String,
    policy: OutboundPolicy,
}

impl EpssFileSource {
    pub fn new(outbound: OutboundDownload, locations: &FeedLocations) -> EpssFileSource {
        EpssFileSource { outbound, url: locations.epss_file_url(), policy: locations.epss_policy() }
    }
}

impl EpssSource for EpssFileSource {
    fn fetch(&self) -> Fetched<'_, Vec<u8>> {
        Box::pin(async move {
            self.outbound
                .get(&self.url, self.policy, "EPSS file", EPSS_MAX_BYTES, EPSS_TIMEOUT)
                .await
                .map_err(|failure| failure.to_string())?
                // A mirror that lost the file has not published a file without scores.
                .ok_or_else(|| "the file was not found at the configured address".to_owned())
        })
    }

    fn location(&self) -> &str {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_address_reads_the_publishers_and_each_feed_has_its_own_switch() {
        let none = FeedLocations::default();
        assert_eq!(none.kev_catalog_url(), KEV_CATALOG_URL);
        assert_eq!(none.epss_file_url(), epss_file::DEFAULT_URL);
        assert_eq!(none.kev_policy(), OutboundPolicy::PublicOnly);
        assert_eq!(none.epss_policy(), OutboundPolicy::PublicOnly);

        let mirrored = FeedLocations {
            kev_url: Some("  ".to_owned()),
            kev_allow_private: false,
            epss_url: Some(" https://mirror.local/epss.csv.gz ".to_owned()),
            epss_allow_private: true,
        };
        assert_eq!(mirrored.kev_catalog_url(), KEV_CATALOG_URL);
        assert_eq!(mirrored.epss_file_url(), "https://mirror.local/epss.csv.gz");
        assert_eq!(mirrored.kev_policy(), OutboundPolicy::PublicOnly);
        assert_eq!(mirrored.epss_policy(), OutboundPolicy::InternalAllowed);
    }
}
