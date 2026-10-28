//! Whether four-eyes could be honoured today — `TriageApprovers`, the questions the settings screen asks of the
//! accounts table before the setting is switched on.
//!
//! - **One approver at all**, or every decision waits in a queue nobody can empty.
//! - **Two governance writers**, or a checklist template could never be published: under four-eyes its author
//!   may not publish it, and writing it takes the same role as publishing it (decision 0032, question 9).
//! - **Two approvers**, or a project checklist its only approver wrote could never be signed off (question 2).
//!
//! Counted in the database, not deduced from a role: the question is about *active* accounts, and an estate may
//! declare a role nobody holds.

use vectispire_cp_db::Db;

use crate::four_eyes::{self, ApproverCounts, SwitchOnRefusal};
use crate::persistence::accounts;
use crate::roles::{approver_roles, name_of, publisher_roles};
use crate::visibility::AccessError;

/// `TriageApprovers`.
#[derive(Clone, Debug)]
pub struct TriageApprovers {
    db: Db,
}

impl TriageApprovers {
    pub fn new(db: Db) -> TriageApprovers {
        TriageApprovers { db }
    }

    pub async fn any_active(&self) -> Result<bool, AccessError> {
        Ok(self.active_holding(&approver_roles()).await? > 0)
    }

    pub async fn two_can_publish_templates(&self) -> Result<bool, AccessError> {
        Ok(self.active_holding(&publisher_roles()).await? >= 2)
    }

    pub async fn two_can_sign_off_checklists(&self) -> Result<bool, AccessError> {
        Ok(self.active_holding(&approver_roles()).await? >= 2)
    }

    /// The three guards of switching four-eyes on, answered from the accounts table now. The counts are asked only
    /// when the value would switch it on, as the Java conditions short-circuit; asked together rather than one by one,
    /// which reads three counts where Java might read one — on a settings save, and with the same answer.
    pub async fn refusal_to_switch_on(&self, value: &str) -> Result<Option<SwitchOnRefusal>, AccessError> {
        if !four_eyes::is_truthy(value) {
            return Ok(None);
        }
        let counts = ApproverCounts {
            any_active: self.any_active().await?,
            two_can_publish_templates: self.two_can_publish_templates().await?,
            two_can_sign_off_checklists: self.two_can_sign_off_checklists().await?,
        };
        Ok(four_eyes::switch_on_refusal(value, counts))
    }

    async fn active_holding(&self, roles: &[crate::roles::Role]) -> Result<i64, AccessError> {
        let names: Vec<&str> = roles.iter().map(|role| name_of(*role)).collect();
        Ok(accounts::count_active_holding(&self.db, &names).await?)
    }
}
