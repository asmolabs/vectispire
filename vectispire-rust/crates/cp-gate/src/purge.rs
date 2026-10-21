//! Target deletion purge listener for gate policies.

use std::sync::Arc;

use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::deletion::PurgeError;
use vectispire_cp_targets::{ListenerName, Phase, PurgeListener, TargetPurge};

use crate::persistence::repository::GatePolicyRepository;

/// A deleted target's stored gate policies go with it.
#[derive(Debug, Clone, Copy, Default)]
pub struct GatePolicyPurge;

impl PurgeListener for GatePolicyPurge {
    fn name(&self) -> ListenerName {
        ListenerName { module: "gate", listener: "GatePolicyPurge.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::References
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move {
            match purge {
                TargetPurge::Deleted(ScanTarget::Repository(id)) => {
                    GatePolicyRepository::delete_by_target(tx, "repository", *id)
                        .await
                        .map_err(|e| Box::new(e) as PurgeError)?;
                }
                TargetPurge::Deleted(ScanTarget::Container(id)) => {
                    GatePolicyRepository::delete_by_target(tx, "container", *id)
                        .await
                        .map_err(|e| Box::new(e) as PurgeError)?;
                }
                TargetPurge::Orphans => {
                    // GatePolicyPurge only purges on TargetDeleted in Java.
                }
            }
            Ok(())
        })
    }
}

pub fn listeners() -> Vec<Arc<dyn PurgeListener>> {
    vec![Arc::new(GatePolicyPurge)]
}
