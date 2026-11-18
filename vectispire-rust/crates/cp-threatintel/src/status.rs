//! What a feed's state and an identifier's exploitation are — Java's `ThreatIntelSyncStatus.State`, `KevListing`,
//! `Exploitation` and `ThreatIntelRecord`.

use serde::Serialize;
use vectispire_domain::java;

/// `ThreatIntelSyncStatus.State`: the three states of a feed, under the names the wire has always carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    NeverSynced,
    Synced,
    Failed,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::NeverSynced => "NEVER_SYNCED",
            State::Synced => "SYNCED",
            State::Failed => "FAILED",
        }
    }

    /// `State.of`: nothing stored is never synced; **a stored value this version does not know reads as failed** —
    /// nothing says it worked.
    pub fn of(stored: Option<&str>) -> State {
        match stored {
            None => State::NeverSynced,
            Some(stored) => [State::NeverSynced, State::Synced, State::Failed]
                .into_iter()
                .find(|state| state.name() == stored)
                .unwrap_or(State::Failed),
        }
    }
}

/// `KevListing`: three answers, not a boolean — `false` before the catalogue was read says "nobody looked".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KevListing {
    Listed,
    NotListed,
    Unknown,
}

/// `Exploitation`: what the two stored feeds say about one vulnerability; an unknown score is `None`, never zero.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Exploitation {
    pub kev: KevListing,
    pub epss_score: Option<f64>,
}

impl Exploitation {
    pub fn unknown() -> Exploitation {
        Exploitation { kev: KevListing::Unknown, epss_score: None }
    }

    /// `namesACve`: `String.trim`, upper-cased, `CVE-\d{4}-\d{4,}` whole — the only identifiers either feed lists.
    pub fn names_a_cve(identifier: Option<&str>) -> bool {
        identifier.is_some_and(|identifier| is_cve(&java::to_upper_root(java::trim(identifier))))
    }
}

/// `CVE-\d{4}-\d{4,}` matched whole, `\d` being ASCII's ten digits as Java's default reads it.
pub fn is_cve(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, number)) = rest.split_once('-') else {
        return false;
    };
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    year.len() == 4 && digits(year) && number.len() >= 4 && digits(number)
}
