//! `VersionTrials`: the trial rendering's verdict on each published version, tried once per version and kept for
//! the process — a published version's workbook, layout and lines never change, and the verdict is this renderer's
//! (a release that learns to write a shared formula's master tries again on its first read). Keyed by the version's
//! id and checked against its workbook's digest; a draft is never kept.

use std::collections::HashMap;
use std::sync::Mutex;

use vectispire_cp_db::Tx;

use crate::error::ChecklistError;
use crate::persistence::VersionRow;
use crate::templates::{self, Refusal};

#[derive(Debug, Default)]
pub struct VersionTrials {
    verdicts: Mutex<HashMap<i64, (String, Option<Refusal>)>>,
}

impl VersionTrials {
    pub fn new() -> VersionTrials {
        VersionTrials::default()
    }

    /// What refused a published version's trial rendering; `None` when a sign-off could fill its workbook in.
    pub(crate) async fn refusal(&self, tx: &mut Tx, version: &VersionRow) -> Result<Option<Refusal>, ChecklistError> {
        if let Some((digest, verdict)) = self.verdicts.lock().ok().and_then(|kept| kept.get(&version.id).cloned())
            && digest == version.source_sha256
        {
            return Ok(verdict);
        }
        // Outside any lock: two readers meeting an untried version may both render it, and agree.
        let verdict = templates::trial(tx, version).await?;
        if let Ok(mut kept) = self.verdicts.lock() {
            kept.insert(version.id, (version.source_sha256.clone(), verdict.clone()));
        }
        Ok(verdict)
    }
}
