//! An instant as Jackson's `JavaTimeModule` writes it with dates as text: `Instant.toString`, and read back by
//! `Instant.parse`. The domain's `Instant` derives its two fields, which is not what any Java record carries.
use serde::{Deserialize, Deserializer, Serializer};

use vectispire_domain::instant::Instant;

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

    use vectispire_domain::instant::Instant;

    pub fn serialize<S: Serializer>(instant: &Option<Instant>, serializer: S) -> Result<S::Ok, S::Error> {
        match instant {
            Some(instant) => super::serialize(instant, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Instant>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| {
                Instant::parse_java(&text).ok_or_else(|| serde::de::Error::custom(format!("not an instant: {text:?}")))
            })
            .transpose()
    }
}
