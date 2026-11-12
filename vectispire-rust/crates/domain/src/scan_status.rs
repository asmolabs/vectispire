//! `ScanStatus`: where a scan is in its life.

use serde::Serialize;

/// A scan's status, as stored in `t_scan.status` and sent over the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Scanning,
    Completed,
    Failed,
}

impl ScanStatus {
    /// Java's `values()` order.
    pub const ALL: [ScanStatus; 4] =
        [ScanStatus::Pending, ScanStatus::Scanning, ScanStatus::Completed, ScanStatus::Failed];

    /// The enum's name lower-cased, as stored.
    pub fn wire_name(self) -> &'static str {
        match self {
            ScanStatus::Pending => "pending",
            ScanStatus::Scanning => "scanning",
            ScanStatus::Completed => "completed",
            ScanStatus::Failed => "failed",
        }
    }

    /// Whether the scan is still expected to produce a result.
    pub fn is_in_flight(self) -> bool {
        matches!(self, ScanStatus::Pending | ScanStatus::Scanning)
    }

    /// `ScanStatus.fromWireName`: trimmed as `String.trim` trims (U+001F goes, U+00A0 stays), lower-cased,
    /// matched against the wire names.
    pub fn from_wire_name(value: Option<&str>) -> Option<ScanStatus> {
        let normalized = crate::java::trim(value?).to_lowercase();
        ScanStatus::ALL.into_iter().find(|status| status.wire_name() == normalized)
    }
}
