//! What a target's scans say about how much a verdict on its backlog can be trusted.

use vectispire_domain::ScanStatus;

/// What a target's scans say about how much a verdict on its backlog can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Observation {
    Ok,
    NeverScanned,
    LastScanFailed,
    InProgress,
}

impl Observation {
    /// The observation a scan's status stands for.
    pub fn of(scan: Option<ScanStatus>) -> Self {
        match scan {
            None => Observation::NeverScanned,
            Some(status) => {
                if status.is_in_flight() {
                    Observation::InProgress
                } else if status == ScanStatus::Failed {
                    Observation::LastScanFailed
                } else {
                    Observation::Ok
                }
            }
        }
    }

    /// Whether the backlog rests on a scan that ran to its end.
    pub fn examined(self) -> bool {
        self == Observation::Ok
    }

    /// Why a verdict cannot rest on this observation, in the words a pipeline's log shows.
    pub fn refusal(self) -> Option<&'static str> {
        match self {
            Observation::Ok => None,
            Observation::NeverScanned => Some(
                "no scan of this target has completed — it was never examined, and an empty backlog is not a clean one",
            ),
            Observation::LastScanFailed => {
                Some("the last scan of this target failed — its backlog is not an observation of the code as it is")
            }
            Observation::InProgress => Some("no scan of this target has finished yet"),
        }
    }

    pub fn wire_name(self) -> &'static str {
        match self {
            Observation::Ok => "ok",
            Observation::NeverScanned => "never_scanned",
            Observation::LastScanFailed => "last_scan_failed",
            Observation::InProgress => "in_progress",
        }
    }
}
