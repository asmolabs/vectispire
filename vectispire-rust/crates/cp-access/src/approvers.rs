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

    async fn active_holding(&self, roles: &[crate::roles::Role]) -> Result<i64, AccessError> {
        let names: Vec<&str> = roles.iter().map(|role| name_of(*role)).collect();
        Ok(accounts::count_active_holding(&self.db, &names).await?)
    }
}
