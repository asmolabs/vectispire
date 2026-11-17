//! Compliance's two ports, answered from the concrete services the binary composes: the deployment's own controls
//! (`ComplianceService.platformPosture` and the audit chain's bounded check) and the targets holding an inventory.
//! Here because the crypto, audit, access and inventory services are the binary's to hold, and compliance names none
//! of them.

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_access::SqlSignInStore;
use vectispire_cp_access::sign_in::{SignInMethodPolicy, SignInStore};
use vectispire_cp_audit::AuditLog;
use vectispire_cp_compliance::decisions::{PasswordAccounts, PlatformPosture};
use vectispire_cp_compliance::ports::{Inventories, Platform};
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::ScanTarget;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_inventory::inventory_query::InventoryQueryService;
use vectispire_cp_settings::{Setting, Settings};

/// The deployment's controls, read on every evaluation.
pub struct PlatformFacts {
    pub encryption: Arc<Encryption>,
    pub audit: Arc<AuditLog>,
    pub settings: Settings,
    pub sign_in: SignInMethodPolicy,
    pub accounts: SqlSignInStore,
}

impl PlatformFacts {
    /// `passwordAccounts`: two counts, read only where they decide something — with an identity provider the ceiling
    /// does not read them. `TotpService.enrolment`'s clamp: an account created between the two statements is not
    /// reported as "3 of 2".
    async fn password_accounts(&self) -> Result<PasswordAccounts, String> {
        if self.sign_in.single_sign_on_available() {
            return Ok(PasswordAccounts { accounts: 0, without_second_factor: 0 });
        }
        let accounts = self.accounts.count_active_with_password().await.map_err(|e| e.to_string())?;
        let without =
            self.accounts.count_active_with_password_and_no_second_factor().await.map_err(|e| e.to_string())?;
        let long = |count: u64| i64::try_from(count).unwrap_or(i64::MAX);
        Ok(PasswordAccounts { accounts: long(accounts), without_second_factor: long(accounts.min(without)) })
    }
}

impl Platform for PlatformFacts {
    fn posture(&self) -> BoxFuture<'_, Result<PlatformPosture, String>> {
        Box::pin(async move {
            Ok(PlatformPosture {
                encryption_configured: self.encryption.is_configured(),
                external_kms: self.encryption.is_externally_managed(),
                // Whether a second copy exists, not whether it agrees now: that is `/audit-log/verify`.
                audit_mirror_configured: self.audit.mirror_configured(),
                four_eyes_required: self
                    .settings
                    .is_enabled(Setting::FourEyesApprovalRequired)
                    .await
                    .map_err(|e| e.to_string())?,
                single_sign_on_configured: self.sign_in.single_sign_on_available(),
                password_login_open: self.sign_in.password_allowed(),
                password_accounts: self.password_accounts().await?,
            })
        })
    }

    fn audit_chain_valid(&self) -> BoxFuture<'_, Result<bool, String>> {
        Box::pin(async move { self.audit.recent_entries_match_their_hashes().await.map_err(|e| e.to_string()) })
    }
}

/// The targets whose scans produced a component inventory.
pub struct InventoryFacts(pub Arc<InventoryQueryService>);

impl Inventories for InventoryFacts {
    fn targets_with_inventory(&self) -> BoxFuture<'_, Result<BTreeSet<ScanTarget>, String>> {
        Box::pin(async move {
            let mut held = BTreeSet::new();
            for id in self.0.distinct_repositories_with_components().await.map_err(|e| e.to_string())? {
                held.insert(ScanTarget::Repository(id));
            }
            for id in self.0.distinct_containers_with_components().await.map_err(|e| e.to_string())? {
                held.insert(ScanTarget::Container(id));
            }
            Ok(held)
        })
    }
}

impl std::fmt::Debug for PlatformFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PlatformFacts").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for InventoryFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("InventoryFacts").finish_non_exhaustive()
    }
}
