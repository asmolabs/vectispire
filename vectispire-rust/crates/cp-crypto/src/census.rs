//! Every sealed store in one place — `EncryptionCensus`, `StoreCensus`, `SealedStore` and `EncryptionService.sealOf`:
//! what `docs/en/KEY_ROTATION.md` reads to say a rotation is finished, served at `/actuator/encryption`.
//!
//! **A rotation is finished when no store reports a value under a previous key**, and only the stores know their rows.
//! Java's procedure once named three stores while the signing key, the second factors and the integration secrets went
//! on reading under the old key: removing it then disabled sign-in for every account with a second factor, stopped
//! every signature and dropped the SIEM's authorization header without a word. Each module that seals something answers
//! here ([`SealedStore`]); a module that seals a new kind of value adds its line, or the census says a rotation is
//! finished while its values still need the old key.
//!
//! **It says how many values stand where, never what they hold**: a seal is read without its plain text leaving
//! [`Encryption::seal_of`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use vectispire_domain::java;

use crate::encryption::{Encryption, SecretState};

/// A census contributor's answer, read when asked: with Vault, reading a seal is a call to it.
pub type CensusFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<StoreCensus>, String>> + Send + 'a>>;

/// What a stored value is sealed under — `EncryptionService.Seal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seal {
    Current,
    PreviousKey,
    Unreadable,
    /// Stored before it was encrypted: used as it is (`read_secret`).
    Clear,
    /// Nothing stored.
    Empty,
}

impl Encryption {
    /// What `stored` is sealed under, without handing out what it holds — `sealOf`. Blank (as Java trims) is
    /// [`Seal::Empty`], a value that is no ciphertext of either kind [`Seal::Clear`].
    pub async fn seal_of(&self, stored: Option<&str>, context: &str) -> Seal {
        let value = java::trim(stored.unwrap_or_default());
        if value.is_empty() {
            return Seal::Empty;
        }
        if !Encryption::is_ciphertext(value) {
            return Seal::Clear;
        }
        match self.inspect(value, context).await.state() {
            SecretState::Current => Seal::Current,
            SecretState::PreviousKey => Seal::PreviousKey,
            SecretState::Unreadable => Seal::Unreadable,
        }
    }
}

/// How the values of one sealed store stand against the configured keys — `StoreCensus`, its components in Java's
/// order, which is the order the endpoint writes them in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreCensus {
    /// What it holds, as an operator names it.
    pub store: String,
    /// The gesture that moves a value still under a previous key to the current one.
    pub reseal: String,
    pub current: u64,
    /// Readable only through `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS`: removing that key leaves these unreadable.
    pub previous_key: u64,
    /// No configured key opens them.
    pub unreadable: u64,
    /// Stored before they were encrypted, and still used as they are.
    pub clear: u64,
}

impl StoreCensus {
    /// Whether this store still needs a previous key.
    #[must_use]
    pub fn depends_on_previous_key(&self) -> bool {
        self.previous_key > 0
    }
}

/// Counts values one at a time, by what [`Encryption::seal_of`] says of each — `StoreCensus.Counter`.
#[derive(Clone, Debug)]
pub struct Counter(StoreCensus);

impl Counter {
    #[must_use]
    pub fn new(store: &str, reseal: &str) -> Counter {
        Counter(StoreCensus {
            store: store.to_owned(),
            reseal: reseal.to_owned(),
            current: 0,
            previous_key: 0,
            unreadable: 0,
            clear: 0,
        })
    }

    #[must_use]
    pub fn count(mut self, seal: Seal) -> Counter {
        let column = match seal {
            Seal::Current => &mut self.0.current,
            Seal::PreviousKey => &mut self.0.previous_key,
            Seal::Unreadable => &mut self.0.unreadable,
            Seal::Clear => &mut self.0.clear,
            // Nothing stored: nothing to re-seal.
            Seal::Empty => return self,
        };
        *column = column.saturating_add(1);
        self
    }

    #[must_use]
    pub fn done(self) -> StoreCensus {
        self.0
    }
}

/// What a module keeps sealed under `ENCRYPTION_KEY`, and which key each of its values is sealed under now —
/// `SealedStore`: one line per kind of value.
pub trait SealedStore: Send + Sync {
    fn census(&self) -> CensusFuture<'_>;
}

/// Every store, gathered — `EncryptionCensus`.
#[derive(Clone)]
pub struct EncryptionCensus {
    stores: Vec<Arc<dyn SealedStore>>,
}

impl std::fmt::Debug for EncryptionCensus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("EncryptionCensus").field("contributors", &self.stores.len()).finish()
    }
}

impl EncryptionCensus {
    #[must_use]
    pub fn new(stores: Vec<Arc<dyn SealedStore>>) -> EncryptionCensus {
        EncryptionCensus { stores }
    }

    /// Every store, by name — `take()`. A contributor that cannot be read fails the whole census: a report that left
    /// a store out would say the rotation is finished while that store's values may still need the old key.
    pub async fn take(&self) -> Result<Vec<StoreCensus>, String> {
        let mut all = Vec::new();
        for store in &self.stores {
            all.extend(store.census().await?);
        }
        // `Comparator.comparing(StoreCensus::store)`: `String.compareTo`, UTF-16 code units — the bytes' order for
        // the ASCII names every store has, and stable, as `List.sort` is.
        all.sort_by(|a, b| a.store.encode_utf16().cmp(b.store.encode_utf16()));
        Ok(all)
    }

    /// `GET /actuator/encryption` — `EncryptionEndpoint.Report` as Jackson writes it: `rotationFinished`, then
    /// `stores`, each store's components in the record's order.
    pub async fn report(&self) -> Result<String, String> {
        let stores = self.take().await?;
        Ok(report_document(&stores))
    }

    /// Said at start while a value depends on a previous key — `warnWhileAPreviousKeyIsNeeded`: the previous key is
    /// in the environment for exactly as long as a rotation lasts, and an instance starting with rows still under it
    /// names the stores, so a rotation left half-way is in the log of every restart rather than in the first sign-in
    /// refused the day the old key is removed. A census that cannot be read is said too; a start is not refused over
    /// a report.
    pub async fn warn_while_a_previous_key_is_needed(&self) {
        let census = match self.take().await {
            Ok(census) => census,
            Err(unreadable) => {
                tracing::warn!("Could not take the census of the sealed stores at start: {unreadable}");
                return;
            }
        };
        for store in census.iter().filter(|store| store.depends_on_previous_key()) {
            tracing::warn!(
                "{}: {} value(s) are still sealed under a previous ENCRYPTION_KEY, which must stay in \
                 VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS until they are re-sealed — {}.",
                store.store,
                store.previous_key,
                store.reseal
            );
        }
        for store in census.iter().filter(|store| store.unreadable > 0) {
            tracing::error!(
                "{}: {} value(s) cannot be decrypted by any configured key.",
                store.store,
                store.unreadable
            );
        }
    }
}

/// The report's document, from the stores already taken.
#[must_use]
pub fn report_document(stores: &[StoreCensus]) -> String {
    let finished = !stores.iter().any(StoreCensus::depends_on_previous_key);
    let lines: Vec<String> = stores
        .iter()
        .map(|store| {
            format!(
                "{{\"store\":{},\"reseal\":{},\"current\":{},\"previousKey\":{},\"unreadable\":{},\"clear\":{}}}",
                string(&store.store),
                string(&store.reseal),
                store.current,
                store.previous_key,
                store.unreadable,
                store.clear
            )
        })
        .collect();
    format!("{{\"rotationFinished\":{finished},\"stores\":[{}]}}", lines.join(","))
}

fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    vectispire_domain::wire::write_string(&mut out, text);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(store: &str, previous_key: u64) -> StoreCensus {
        StoreCensus {
            store: store.to_owned(),
            reseal: "r".to_owned(),
            current: 1,
            previous_key,
            unreadable: 0,
            clear: 0,
        }
    }

    struct Fixed(Vec<StoreCensus>);

    impl SealedStore for Fixed {
        fn census(&self) -> CensusFuture<'_> {
            let lines = self.0.clone();
            Box::pin(async move { Ok(lines) })
        }
    }

    struct Broken;

    impl SealedStore for Broken {
        fn census(&self) -> CensusFuture<'_> {
            Box::pin(async { Err("the database is down".to_owned()) })
        }
    }

    #[test]
    fn a_counter_counts_each_seal_in_its_column_and_nothing_for_an_empty_value() {
        let census = Counter::new("S", "r")
            .count(Seal::Current)
            .count(Seal::Current)
            .count(Seal::PreviousKey)
            .count(Seal::Unreadable)
            .count(Seal::Clear)
            .count(Seal::Empty)
            .done();
        assert_eq!((census.current, census.previous_key, census.unreadable, census.clear), (2, 1, 1, 1));
    }

    #[tokio::test]
    async fn the_stores_are_sorted_by_name_and_a_previous_key_anywhere_means_unfinished() {
        let census = EncryptionCensus::new(vec![
            Arc::new(Fixed(vec![line("TOTP secrets", 0), line("SSH deploy keys", 0)])),
            Arc::new(Fixed(vec![line("Document signing key", 0)])),
        ]);
        let names: Vec<String> = census.take().await.unwrap().into_iter().map(|store| store.store).collect();
        assert_eq!(names, ["Document signing key", "SSH deploy keys", "TOTP secrets"]);
        assert!(census.report().await.unwrap().starts_with("{\"rotationFinished\":true,"));

        let unfinished = EncryptionCensus::new(vec![Arc::new(Fixed(vec![line("A", 0), line("B", 1)]))]);
        assert!(unfinished.report().await.unwrap().starts_with("{\"rotationFinished\":false,"));
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_read_fails_the_census_rather_than_leaving_it_out() {
        let census = EncryptionCensus::new(vec![Arc::new(Fixed(vec![line("A", 0)])), Arc::new(Broken)]);
        assert_eq!(census.report().await, Err("the database is down".to_owned()));
    }

    #[test]
    fn the_report_is_written_as_the_java_endpoint_answers() {
        let document = report_document(&[StoreCensus {
            store: "SIEM authorization header".to_owned(),
            reseal: "set the header again on the SIEM settings".to_owned(),
            current: 1,
            previous_key: 2,
            unreadable: 3,
            clear: 4,
        }]);
        assert_eq!(
            document,
            "{\"rotationFinished\":false,\"stores\":[{\"store\":\"SIEM authorization header\",\
             \"reseal\":\"set the header again on the SIEM settings\",\"current\":1,\"previousKey\":2,\
             \"unreadable\":3,\"clear\":4}]}"
        );
    }
}
