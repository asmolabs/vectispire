//! `ForgeImportLinkPurge`: a deleted target's provenance link goes with it, and so do its change-review readings,
//! which name it the same way — in the deleting transaction, first phase. Left behind, the link would mark the
//! repository *already imported* on the selection screen as a target that no longer exists.

use std::sync::Arc;

use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::deletion::PurgeError;
use vectispire_cp_targets::{ListenerName, Phase, PurgeListener, TargetPurge};

use crate::persistence;

/// The listener.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImportLinkPurge;

impl PurgeListener for ImportLinkPurge {
    fn name(&self) -> ListenerName {
        ListenerName { module: "forges", listener: "ForgeImportLinkPurge.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::References
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move {
            if let TargetPurge::Deleted(ScanTarget::Repository(id)) = purge {
                persistence::delete_links_of_repository(tx, *id)
                    .await
                    .map_err(|error| Box::new(error) as PurgeError)?;
                persistence::delete_readings_of_repositories(tx, &[*id])
                    .await
                    .map_err(|error| Box::new(error) as PurgeError)?;
            }
            Ok(())
        })
    }
}

/// The module's purge listeners, for the targets' registry.
pub fn listeners() -> Vec<Arc<dyn PurgeListener>> {
    vec![Arc::new(ImportLinkPurge)]
}
