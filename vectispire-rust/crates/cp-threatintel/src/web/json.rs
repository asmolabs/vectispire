//! The wire shapes of the reads — `ThreatIntelSyncStatus` and `ThreatIntelRecord` as Jackson writes them: members in
//! the record's order, an instant as `Instant.toString`, absent as `null`.

use serde::{Serialize, Serializer};
use time::OffsetDateTime;
use vectispire_domain::instant::Instant;

use crate::feeds::{EpssFeedStatus, SyncStatus, ThreatIntelRecord};
use crate::status::State;

/// An instant as `JavaTimeModule` writes one with dates as text.
#[derive(Debug, Clone, Copy)]
pub(super) struct Stamp(Option<OffsetDateTime>);

impl Serialize for Stamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Some(at) = self.0 else {
            return serializer.serialize_none();
        };
        let text = Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
            .to_java_string()
            .ok_or_else(|| serde::ser::Error::custom("an instant outside the years 0000 to 9999"))?;
        serializer.serialize_str(&text)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EpssFeedJson {
    status: State,
    last_synced_at: Stamp,
    model_version: Option<String>,
    score_date: Stamp,
    total_scored: i64,
    last_attempt_at: Stamp,
    last_error: Option<String>,
    backlog_updated_count: i64,
    in_progress: bool,
}

impl From<EpssFeedStatus> for EpssFeedJson {
    fn from(feed: EpssFeedStatus) -> EpssFeedJson {
        EpssFeedJson {
            status: feed.status,
            last_synced_at: Stamp(feed.last_synced_at),
            model_version: feed.model_version,
            score_date: Stamp(feed.score_date),
            total_scored: feed.total_scored,
            last_attempt_at: Stamp(feed.last_attempt_at),
            last_error: feed.last_error,
            backlog_updated_count: feed.backlog_updated_count,
            in_progress: feed.in_progress,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SyncStatusJson {
    last_synced_at: Stamp,
    total_cves: i64,
    total_kev: i64,
    status: State,
    backlog_updated_count: i64,
    kev_catalog_version: Option<String>,
    kev_released_at: Stamp,
    last_attempt_at: Stamp,
    last_error: Option<String>,
    epss: EpssFeedJson,
}

impl From<SyncStatus> for SyncStatusJson {
    fn from(status: SyncStatus) -> SyncStatusJson {
        SyncStatusJson {
            last_synced_at: Stamp(status.last_synced_at),
            total_cves: status.total_cves,
            total_kev: status.total_kev,
            status: status.status,
            backlog_updated_count: status.backlog_updated_count,
            kev_catalog_version: status.kev_catalog_version,
            kev_released_at: Stamp(status.kev_released_at),
            last_attempt_at: Stamp(status.last_attempt_at),
            last_error: status.last_error,
            epss: status.epss.into(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RecordJson {
    cve_id: String,
    is_kev: bool,
    epss_score: Option<f64>,
    epss_percentile: Option<f64>,
    date_added: Stamp,
    notes: String,
}

impl From<ThreatIntelRecord> for RecordJson {
    fn from(record: ThreatIntelRecord) -> RecordJson {
        RecordJson {
            cve_id: record.cve_id,
            is_kev: record.is_kev,
            epss_score: record.epss_score,
            epss_percentile: record.epss_percentile,
            date_added: Stamp(record.date_added),
            notes: record.notes,
        }
    }
}
