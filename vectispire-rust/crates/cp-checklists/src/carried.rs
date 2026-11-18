//! `CarriedRepositories`: the repositories a revision's stored measurements carry, read from the evidence their
//! digest covers, and who may read what was frozen over them (decision 0042's second rule).

use std::collections::BTreeSet;

use vectispire_cp_access::visibility::Allowance;
use vectispire_cp_db::{ScanTarget, Visibility};

use crate::measurement::Measurement;
use crate::persistence::MeasurementRow;

/// Every repository the rows' evidence names, or `None` when one of them cannot be read back — an unreadable
/// evidence says nothing of what it carried, never "no repository" (decision 0007).
pub(crate) fn of<'a>(rows: impl Iterator<Item = &'a MeasurementRow>) -> Option<BTreeSet<i64>> {
    let mut repositories = BTreeSet::new();
    for row in rows {
        let measurement = Measurement::read(&row.evidence).ok()?;
        repositories.extend(measurement.repositories.iter().map(|line| line.repository_id));
    }
    Some(repositories)
}

/// Whether this reader sees every repository carried — or, when that cannot be told, sees everything through a
/// credential that narrows nothing.
pub(crate) fn seen_by(carried: &Option<BTreeSet<i64>>, allowance: &Allowance) -> bool {
    match carried {
        None => matches!(allowance.visibility, Visibility::Everything) && !allowance.narrowed_by_credential,
        Some(ids) => ids.iter().all(|id| allowance.visibility.permits(ScanTarget::Repository(*id))),
    }
}
