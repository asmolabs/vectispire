//! What the module asks of the modules beside it, as ports the binary implements: the projects and their
//! repositories (`targets`), the accounts and what each sees (`access`), the platform's signing key (`crypto`), and
//! the mail channel (`notifications`, not ported: [`NoMail`] answers "no relay" until wave 3).

use std::collections::BTreeMap;

use vectispire_cp_access::accounts::UserView;
use vectispire_cp_access::visibility::Allowance;

use crate::measurer::Answer;

/// `SolutionQueryService.ProjectMembers`: a project's name and the repositories filed in it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMembers {
    pub name: String,
    pub repository_ids: Vec<i64>,
}

/// `SolutionQueryService.members` / `projectOf`, and `TargetNaming.repositoryNames`.
pub trait ProjectDirectory: Send + Sync {
    fn members<'a>(&'a self, project_id: i64) -> Answer<'a, Option<ProjectMembers>>;
    fn project_of<'a>(&'a self, repository_id: i64) -> Answer<'a, Option<i64>>;
    fn repository_names<'a>(&'a self, repository_ids: &'a [i64]) -> Answer<'a, BTreeMap<i64, String>>;
}

/// `AccountDirectory`, and `VisibilityService.allowance(account, everything)` — what an account sees as its own.
pub trait AccountDirectory: Send + Sync {
    /// Every active account, by user name.
    fn active<'a>(&'a self) -> Answer<'a, Vec<UserView>>;
    fn by_id<'a>(&'a self, account_id: i64) -> Answer<'a, Option<UserView>>;
    fn allowance_of<'a>(&'a self, account: &'a UserView) -> Answer<'a, Allowance>;
}

/// `SigningKeyService`: the key every document is signed with.
pub trait DocumentSigner: Send + Sync {
    fn key_id<'a>(&'a self) -> Answer<'a, String>;
    /// The detached signature as cosign writes it, base64 text.
    fn sign<'a>(&'a self, payload: &'a [u8]) -> Answer<'a, String>;
}

/// `MailNotificationChannel`, as far as the reminder uses it.
pub trait MailChannel: Send + Sync {
    fn has_relay<'a>(&'a self) -> Answer<'a, bool>;
    fn is_switched_on<'a>(&'a self) -> Answer<'a, bool>;
    fn send_text_to<'a>(&'a self, addresses: &'a [String], subject: &'a str, body: &'a str) -> Answer<'a, ()>;
    /// `ExportProperties.publicUrl`.
    fn public_url(&self) -> Option<String>;
}

/// The notifications module's stand-in until wave 3: no relay, so the reminder prepares nothing and marks nothing
/// sent — the week's reminders go out once a relay exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMail;

impl MailChannel for NoMail {
    fn has_relay<'a>(&'a self) -> Answer<'a, bool> {
        Box::pin(async { Ok(false) })
    }
    fn is_switched_on<'a>(&'a self) -> Answer<'a, bool> {
        Box::pin(async { Ok(false) })
    }
    fn send_text_to<'a>(&'a self, _: &'a [String], _: &'a str, _: &'a str) -> Answer<'a, ()> {
        Box::pin(async { Err("no mail relay in this build".to_owned()) })
    }
    fn public_url(&self) -> Option<String> {
        None
    }
}
