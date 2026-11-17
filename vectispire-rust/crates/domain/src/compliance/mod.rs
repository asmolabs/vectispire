//! The pure compliance domain — Java's `vectispire-common` `domain/compliance`: the six frameworks and their
//! controls, the engine that evaluates them from an estate and a platform, the declaration of applicability set
//! against its verdicts, the attributed monthly history, the certified scope's gap and the evidence bundle's
//! manifest.
//!
//! Held to `reference/compliance/`, which `ComplianceReferenceSetTest` writes from the Java classes. The records
//! serialize as the evidence bundle's mapper writes them (`EvidenceVaultService`: field names in component order,
//! nulls written, instants as `Instant.toString`).

pub mod engine;
pub mod framework;
pub mod history;
pub mod manifest;
pub mod scope;
pub mod soa;

pub use engine::{
    ComplianceEvaluation, ControlAssessment, PasswordAccounts, PlatformPosture, PostureInput, evaluate, evaluate_all,
};
pub use framework::{Category, ComplianceControl, ComplianceFramework, Status, UnknownFramework};
pub use history::{ComplianceSnapshot, Movement, Series, Shape, Step};
pub use manifest::{EvidenceBundleManifest, EvidenceFileEntry, WithheldSection};
pub use scope::ScopeCoverage;
pub use soa::{Applicability, Declaration, Divergence, EvidenceSource, Implementation, Line, SoaStatement, reconcile};

/// An instant as Jackson's `JavaTimeModule` writes it with dates as text: `Instant.toString`, and read back by
/// `Instant.parse`. The domain's `Instant` derives its two fields, which is not what any Java record carries.
pub mod instant_text {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::instant::Instant;

    pub fn serialize<S: Serializer>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error> {
        let text = instant
            .to_java_string()
            .ok_or_else(|| serde::ser::Error::custom("an instant outside the years 0000 to 9999"))?;
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Instant, D::Error> {
        let text = String::deserialize(deserializer)?;
        Instant::parse_java(&text).ok_or_else(|| serde::de::Error::custom(format!("not an instant: {text:?}")))
    }

    /// The same for an optional instant, absent written as `null`.
    pub mod option {
        use serde::{Deserialize, Deserializer, Serializer};

        use crate::instant::Instant;

        pub fn serialize<S: Serializer>(instant: &Option<Instant>, serializer: S) -> Result<S::Ok, S::Error> {
            match instant {
                Some(instant) => super::serialize(instant, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Instant>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|text| {
                    Instant::parse_java(&text)
                        .ok_or_else(|| serde::de::Error::custom(format!("not an instant: {text:?}")))
                })
                .transpose()
        }
    }
}
