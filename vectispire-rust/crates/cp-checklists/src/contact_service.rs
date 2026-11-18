//! `ChecklistContactService` and `ChecklistReminderService`: a project's checklist profiles — the values of its
//! template's contact column — linked to accounts, each reminded weekly of its lines still to fill in (decision 0044).
//!
//! **A profile is linked to an account that can fill the checklist in** — active, of a role that writes, seeing the
//! project whole as its own account — asked again at every reminder and every read of the list. **The link is kept
//! by the profile's key**, outliving the version it was made on.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use vectispire_cp_access::account_names::display_name_of;
use vectispire_cp_access::accounts::UserView;
use vectispire_cp_access::roles::{Role, role_of};
use vectispire_cp_access::rows::sees_whole_project;
use vectispire_cp_access::visibility::Allowance;
use vectispire_cp_audit::{AuditLog, AuditLogQuery, AuditOperation, Record};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::java;
use vectispire_domain::list_window::ListWindow;

use crate::contacts::{self, Profile};
use crate::error::ChecklistError;
use crate::persistence::{self as rows, ChecklistRow, ItemRow};
use crate::ports::{AccountDirectory, MailChannel, ProjectDirectory};
use crate::project_checklists::{Guarded, Participant, Status, current_of, require_whole};
use crate::reminder::{self, Gap, Line, ProfileLines, Unreached};
use crate::templates::Clock;
use crate::views::{ContactCandidate, ContactView, ContactsView};

type Result<T> = std::result::Result<T, ChecklistError>;

/// What a reader who cannot write is told of an account that would not be reminded: that it would not, not why.
pub const NOT_REMINDED: &str = "not_reminded";

/// The contacts' service.
pub struct ChecklistContacts {
    db: Db,
    projects: Arc<dyn ProjectDirectory>,
    accounts: Arc<dyn AccountDirectory>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ChecklistContacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ChecklistContacts").finish_non_exhaustive()
    }
}

fn failed(why: String) -> ChecklistError {
    ChecklistError::Failed(why)
}

impl ChecklistContacts {
    pub fn new(
        db: Db,
        projects: Arc<dyn ProjectDirectory>,
        accounts: Arc<dyn AccountDirectory>,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> ChecklistContacts {
        ChecklistContacts { db, projects, accounts, audit, clock }
    }

    async fn guard(&self, project_id: i64, allowance: &Allowance) -> Result<Guarded> {
        require_whole(self.projects.as_ref(), project_id, allowance).await
    }

    /// `contacts`: the project's profiles, each with the account linked to it and the lines it has to fill in.
    /// `detailed`: whether the caller may relink, and so is told why an account would not be reminded.
    pub async fn contacts(&self, project_id: i64, allowance: &Allowance, detailed: bool) -> Result<ContactsView> {
        let guarded = self.guard(project_id, allowance).await?;
        self.listed(&guarded, detailed).await
    }

    async fn listed(&self, guarded: &Guarded, detailed: bool) -> Result<ContactsView> {
        let project_id = guarded.project.project_id;
        let mut tx = rows::begin(&self.db, false).await?;
        let Some(checklist) = rows::latest_checklist(&mut tx, project_id).await? else {
            return Ok(ContactsView { project_id, revision: None, draft: false, profiles: Vec::new() });
        };
        let draft = checklist.status == Status::Draft.wire_name();
        let lines = rows::items_of(&mut tx, checklist.template_version_id).await?;
        let open = if draft { unfilled_by_profile(&mut tx, &checklist, &lines).await? } else { HashMap::new() };
        let linked: HashMap<String, rows::ContactRow> = rows::contacts_of(&mut tx, project_id)
            .await?
            .into_iter()
            .map(|link| (link.profile.clone(), link))
            .collect();
        drop(tx);
        let mut profiles = Vec::new();
        for profile in profiles_of(&lines) {
            let open_lines = open.get(&profile.key).map_or(0, Vec::len);
            let Some(link) = linked.get(&profile.key) else {
                profiles.push(ContactView {
                    profile: profile.key,
                    label: profile.label,
                    open_lines,
                    account_id: None,
                    account_name: None,
                    warning: None,
                });
                continue;
            };
            let account = self.accounts.by_id(link.account_id).await.map_err(failed)?;
            let gap = gap_of(self.accounts.as_ref(), account.as_ref(), project_id, &guarded.repository_ids).await?;
            profiles.push(ContactView {
                profile: profile.key,
                label: profile.label,
                open_lines,
                account_id: Some(link.account_id),
                account_name: account.as_ref().and_then(display_name_of),
                warning: gap.map(|gap| if detailed { gap.wire_name() } else { NOT_REMINDED }.to_owned()),
            });
        }
        Ok(ContactsView { project_id, revision: Some(checklist.revision), draft, profiles })
    }

    /// `candidates`: the accounts a profile of this project may be linked to, all of them or one page.
    pub async fn candidates(
        &self,
        project_id: i64,
        allowance: &Allowance,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<ContactCandidate>> {
        let guarded = self.guard(project_id, allowance).await?;
        let window = ListWindow::requested(limit, offset).map_err(ChecklistError::Invalid)?;
        let mut every = Vec::new();
        for account in self.accounts.active().await.map_err(failed)? {
            if can_fill(self.accounts.as_ref(), &account, guarded.project.project_id, &guarded.repository_ids).await? {
                every.push(ContactCandidate { account_id: account.id, name: display_name_of(&account) });
            }
        }
        Ok(window.map_or_else(|| every.clone(), |window| window.of(&every)))
    }

    /// `link`: a profile linked to an account, in place of the one it was linked to.
    pub async fn link(
        &self,
        project_id: i64,
        profile: Option<&str>,
        account_id: Option<i64>,
        allowance: &Allowance,
        who: &Participant,
    ) -> Result<ContactsView> {
        let guarded = self.guard(project_id, allowance).await?;
        let named = self.require_profile(&guarded, profile).await?;
        let Some(account_id) = account_id else {
            return Err(ChecklistError::invalid("Name the account to link the profile to: accountId."));
        };
        // One sentence for an account that does not exist and one that cannot fill the checklist in.
        let refused = || {
            ChecklistError::invalid(format!(
                "Account {account_id} cannot be linked: it does not exist, is deactivated, or cannot fill in this \
                 project's checklist."
            ))
        };
        let account = self.accounts.by_id(account_id).await.map_err(failed)?.ok_or_else(refused)?;
        if !account.is_active
            || !can_fill(self.accounts.as_ref(), &account, project_id, &guarded.repository_ids).await?
        {
            return Err(refused());
        }
        let previous = self.store(project_id, &named.key, account_id, &who.username).await?;
        if previous != Some(account_id) {
            self.audit
                .record(who.actor.entry(
                    AuditOperation::ChecklistContactChanged,
                    &resource(project_id, &named.key),
                    &format!(
                        "Checklist profile {} of project \"{}\" linked to account {}{}.",
                        named.label,
                        guarded.project.name,
                        account.id,
                        previous.map_or_else(String::new, |before| format!(", in place of account {before}"))
                    ),
                ))
                .await;
        }
        self.listed(&guarded, true).await
    }

    /// `unlink`: its lines go to the CISOs until it is linked again; unlinking an unlinked profile is not an error.
    pub async fn unlink(
        &self,
        project_id: i64,
        profile: Option<&str>,
        allowance: &Allowance,
        who: &Participant,
    ) -> Result<ContactsView> {
        let guarded = self.guard(project_id, allowance).await?;
        let key = contacts::key_of(profile);
        if !key.is_empty() {
            let mut tx = rows::begin(&self.db, true).await?;
            let link = rows::contact_of(&mut tx, project_id, &key).await?;
            let removed = match &link {
                Some(_) => rows::delete_contact(&mut tx, project_id, &key).await?,
                None => 0,
            };
            rows::commit(tx).await?;
            if let (Some(link), true) = (link, removed > 0) {
                self.audit
                    .record(who.actor.entry(
                        AuditOperation::ChecklistContactChanged,
                        &resource(project_id, &key),
                        &format!(
                            "Checklist profile {key} of project \"{}\" unlinked from account {}.",
                            guarded.project.name, link.account_id
                        ),
                    ))
                    .await;
            }
        }
        self.listed(&guarded, true).await
    }

    /// A profile the newest version's contact column names, or 404 in the words of a profile that is not there.
    async fn require_profile(&self, guarded: &Guarded, profile: Option<&str>) -> Result<Profile> {
        let key = contacts::key_of(profile);
        let mut tx = rows::begin(&self.db, false).await?;
        let named = match rows::latest_checklist(&mut tx, guarded.project.project_id).await? {
            Some(checklist) => profiles_of(&rows::items_of(&mut tx, checklist.template_version_id).await?),
            None => Vec::new(),
        };
        named.into_iter().find(|named| named.key == key).ok_or_else(|| {
            ChecklistError::not_found(format!(
                "The checklist of project \"{}\" names no profile \"{}\".",
                guarded.project.name,
                java::strip(profile.unwrap_or(""))
            ))
        })
    }

    /// `store`: the link, and the account it replaced; a lost race on the unique key reads again once.
    async fn store(&self, project_id: i64, key: &str, account_id: i64, linked_by: &str) -> Result<Option<i64>> {
        let mut attempt = 0;
        loop {
            let mut tx = rows::begin(&self.db, true).await?;
            let existing = rows::contact_of(&mut tx, project_id, key).await?;
            let previous = existing.as_ref().map(|link| link.account_id);
            if previous == Some(account_id) {
                return Ok(previous);
            }
            let now = rows::at(self.clock.now());
            let written = match &existing {
                Some(link) => rows::update_contact(&mut tx, link.id, account_id, linked_by, now).await,
                None => rows::insert_contact(&mut tx, project_id, key, account_id, linked_by, now).await.map(|_| ()),
            };
            match written {
                Ok(()) => {
                    rows::commit(tx).await?;
                    return Ok(previous);
                }
                Err(raced) if attempt == 0 => {
                    tracing::debug!(error = %raced, "a checklist contact was linked meanwhile; reading again");
                    attempt = 1;
                }
                Err(raced) => return Err(raced.into()),
            }
        }
    }
}

/// The profiles a version's contact column names, but `AUTO`, in the column's order.
fn profiles_of(lines: &[ItemRow]) -> Vec<Profile> {
    contacts::of_all(lines.iter().map(|line| line.contact.as_str()))
}

/// `unfilledByProfile`: the lines of a draft with no current answer, or a carried one waiting for confirmation,
/// under each profile their contact names.
async fn unfilled_by_profile(
    tx: &mut Tx,
    draft: &ChecklistRow,
    lines: &[ItemRow],
) -> Result<HashMap<String, Vec<ItemRow>>> {
    let current = current_of(&rows::answers_of(tx, draft.id).await?);
    let mut open: HashMap<String, Vec<ItemRow>> = HashMap::new();
    for line in lines {
        if current.get(&line.id).is_some_and(|answer| !answer.needs_confirmation) {
            continue;
        }
        for key in contacts::keys_of(&line.contact) {
            open.entry(key).or_default().push(line.clone());
        }
    }
    Ok(open)
}

/// `gapOf`: why an account linked to a profile would not be reminded — gone, deactivated, no longer able to fill the
/// checklist in, or without an address, in that order — or `None` when it would.
async fn gap_of(
    accounts: &dyn AccountDirectory,
    account: Option<&UserView>,
    project_id: i64,
    repository_ids: &[i64],
) -> Result<Option<Gap>> {
    let Some(user) = account else { return Ok(Some(Gap::AccountGone)) };
    if !user.is_active {
        return Ok(Some(Gap::AccountInactive));
    }
    if !can_fill(accounts, user, project_id, repository_ids).await? {
        return Ok(Some(Gap::CannotFill));
    }
    if user.email.as_deref().is_none_or(java::is_blank) {
        return Ok(Some(Gap::NoEmail));
    }
    Ok(None)
}

/// `canFill`: a role that writes, and the project seen whole by the account itself, with no credential narrowing.
async fn can_fill(
    accounts: &dyn AccountDirectory,
    account: &UserView,
    project_id: i64,
    repository_ids: &[i64],
) -> Result<bool> {
    if !role_of(Some(&account.role)).is_some_and(Role::can_cause_effects) {
        return Ok(false);
    }
    let allowance = accounts.allowance_of(account).await.map_err(failed)?;
    Ok(sees_whole_project(project_id, repository_ids, &allowance))
}

fn resource(project_id: i64, key: &str) -> String {
    format!("{project_id}/contacts/{key}")
}

// ------------------------------------------------------------------ the weekly reminder

/// `ChecklistReminderService`: offered every hour, sent once a week to each recipient, the bookkeeping the audit
/// entry the sending writes (`CHECKLIST_REMINDER_SENT`, one per recipient). Never throws.
pub struct ChecklistReminders {
    db: Db,
    projects: Arc<dyn ProjectDirectory>,
    accounts: Arc<dyn AccountDirectory>,
    settings: Arc<Settings>,
    mail: Arc<dyn MailChannel>,
    audit_log: Arc<AuditLogQuery>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
    /// The sends of this week whose mark the audit log refused, held so that they are not sent again every hour.
    sent_unmarked: Mutex<BTreeSet<String>>,
}

impl std::fmt::Debug for ChecklistReminders {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ChecklistReminders").finish_non_exhaustive()
    }
}

/// A message due to one recipient.
struct Pending {
    address: String,
    message: reminder::Message,
    description: String,
}

impl ChecklistReminders {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        projects: Arc<dyn ProjectDirectory>,
        accounts: Arc<dyn AccountDirectory>,
        settings: Arc<Settings>,
        mail: Arc<dyn MailChannel>,
        audit_log: Arc<AuditLogQuery>,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> ChecklistReminders {
        ChecklistReminders {
            db,
            projects,
            accounts,
            settings,
            mail,
            audit_log,
            audit,
            clock,
            sent_unmarked: Mutex::new(BTreeSet::new()),
        }
    }

    /// `runOnce`: this week's reminders not sent yet; how many messages left.
    pub async fn run_once(&self) -> usize {
        match self.send().await {
            Ok(sent) => sent,
            Err(failed) => {
                tracing::warn!(error = %failed, "The weekly checklist reminders could not be prepared; they will be tried again next tick.");
                0
            }
        }
    }

    async fn send(&self) -> Result<usize> {
        let enabled = self
            .settings
            .is_enabled(Setting::ChecklistRemindersEnabled)
            .await
            .map_err(|failure| failed(failure.to_string()))?;
        if !enabled
            || !self.mail.has_relay().await.map_err(failed)?
            || !self.mail.is_switched_on().await.map_err(failed)?
        {
            return Ok(0);
        }
        let today = crate::days::day_of(self.clock.now());
        let monday = today.saturating_sub(time::Duration::days(i64::from(today.weekday().number_days_from_monday())));
        let week = crate::days::written(monday);
        let public_url = self.mail.public_url();
        let due = self.due().await?;

        let mut sends: Vec<(String, Pending)> = Vec::new();
        for (account_id, profiles) in &due.by_account {
            let Some(account) = due.accounts.get(account_id) else { continue };
            let message =
                reminder::to_contact(display_name_of(account).as_deref(), profiles, &week, public_url.as_deref());
            let lines: usize = profiles.iter().map(|profile| profile.lines.len()).sum();
            sends.push((
                format!("{week}/contact/{account_id}"),
                Pending {
                    address: java::strip(account.email.as_deref().unwrap_or("")).to_owned(),
                    message,
                    description: format!(
                        "Weekly checklist reminder sent to account {account_id}: {lines} line(s) on {} profile(s).",
                        profiles.len()
                    ),
                },
            ));
        }
        if !due.unreached.is_empty() {
            let cisos: Vec<UserView> = self
                .accounts
                .active()
                .await
                .map_err(failed)?
                .into_iter()
                .filter(|account| role_of(Some(&account.role)) == Some(Role::Ciso))
                .filter(|account| !account.email.as_deref().is_none_or(java::is_blank))
                .collect();
            for ciso in &cisos {
                let allowance = self.accounts.allowance_of(ciso).await.map_err(failed)?;
                let theirs: Vec<Unreached> = due
                    .unreached
                    .iter()
                    .filter(|gap| {
                        sees_whole_project(
                            gap.project_id,
                            due.repository_ids.get(&gap.project_id).map_or(&[][..], Vec::as_slice),
                            &allowance,
                        )
                    })
                    .cloned()
                    .collect();
                if theirs.is_empty() {
                    continue;
                }
                sends.push((
                    format!("{week}/ciso/{}", ciso.id),
                    Pending {
                        address: java::strip(ciso.email.as_deref().unwrap_or("")).to_owned(),
                        message: reminder::to_ciso(&theirs, &week, public_url.as_deref()),
                        description: format!(
                            "Weekly checklist reminder sent to CISO account {}: {} profile(s) without a contact.",
                            ciso.id,
                            theirs.len()
                        ),
                    },
                ));
            }
            if cisos.is_empty() {
                tracing::info!(
                    profiles = due.unreached.len(),
                    "Checklist profiles have lines to fill in and nobody to remind, and no active CISO account has an \
                     e-mail address to be told."
                );
            }
        }

        // Last week's sends the log refused to mark are of no use this week: the keys name their Monday.
        let this_week = format!("{week}/");
        if let Ok(mut unmarked) = self.sent_unmarked.lock() {
            unmarked.retain(|key| key.starts_with(&this_week));
        }
        let keys: Vec<String> = sends.iter().map(|(key, _)| key.clone()).collect();
        let already_sent: BTreeSet<String> = if keys.is_empty() {
            BTreeSet::new()
        } else {
            self.audit_log
                .resources_named(AuditOperation::ChecklistReminderSent.wire_name(), &keys)
                .await
                .map_err(|failure| failed(failure.to_string()))?
                .into_iter()
                .collect()
        };
        let mut sent = 0;
        for (key, pending) in &sends {
            if already_sent.contains(key) {
                self.forget(key);
                continue;
            }
            if self.unmarked(key) {
                // Sent this week, the mark refused: marked now if the log takes it, never sent again.
                if !self.mark(key, pending).await {
                    return Ok(sent);
                }
                self.forget(key);
                continue;
            }
            let addresses = [pending.address.clone()];
            if let Err(refused) =
                self.mail.send_text_to(&addresses, &pending.message.subject, &pending.message.body).await
            {
                // No entry: the entry is what says it went, and its absence is what retries it next hour.
                tracing::warn!(key = %key, error = %refused, "The weekly checklist reminder could not be sent; it will be retried next tick.");
                continue;
            }
            sent = sent.saturating_add(1);
            if !self.mark(key, pending).await {
                if let Ok(mut unmarked) = self.sent_unmarked.lock() {
                    unmarked.insert(key.clone());
                }
                tracing::warn!("The weekly checklist reminders stopped with the audit log refusing their mark.");
                return Ok(sent);
            }
        }
        Ok(sent)
    }

    fn unmarked(&self, key: &str) -> bool {
        self.sent_unmarked.lock().is_ok_and(|unmarked| unmarked.contains(key))
    }

    fn forget(&self, key: &str) {
        if let Ok(mut unmarked) = self.sent_unmarked.lock() {
            unmarked.remove(key);
        }
    }

    /// Through the call that says when it could not (`append`): a refused mark stops the run.
    async fn mark(&self, key: &str, pending: &Pending) -> bool {
        // No actor: nobody asked for this one.
        match self
            .audit
            .append(Record::of(AuditOperation::ChecklistReminderSent, key, &pending.description, None))
            .await
        {
            Ok(()) => true,
            Err(refused) => {
                tracing::error!(key, error = %refused, "The weekly checklist reminder was sent and could not be recorded; the run stops here, and it is not sent again.");
                false
            }
        }
    }

    async fn due(&self) -> Result<Due> {
        let mut due = Due::default();
        let mut tx = rows::begin(&self.db, false).await?;
        let drafts = rows::checklists_in(&mut tx, Status::Draft.wire_name()).await?;
        for draft in drafts {
            let Some(members) = self.projects.members(draft.project_id).await.map_err(failed)? else {
                continue; // a project deleted since: its rows go with it
            };
            let project_id = draft.project_id;
            let lines = rows::items_of(&mut tx, draft.template_version_id).await?;
            let open = unfilled_by_profile(&mut tx, &draft, &lines).await?;
            if open.is_empty() {
                continue;
            }
            due.repository_ids.insert(project_id, members.repository_ids.clone());
            let links: HashMap<String, rows::ContactRow> = rows::contacts_of(&mut tx, project_id)
                .await?
                .into_iter()
                .map(|link| (link.profile.clone(), link))
                .collect();
            for profile in profiles_of(&lines) {
                let Some(theirs) = open.get(&profile.key) else { continue };
                let link = links.get(&profile.key);
                let account = match link {
                    Some(link) => self.accounts.by_id(link.account_id).await.map_err(failed)?,
                    None => None,
                };
                let gap = match link {
                    None => Some(Gap::NobodyLinked),
                    Some(_) => {
                        gap_of(self.accounts.as_ref(), account.as_ref(), project_id, &members.repository_ids).await?
                    }
                };
                if let Some(gap) = gap {
                    due.unreached.push(Unreached {
                        project_id,
                        project_name: members.name.clone(),
                        profile: profile.label.clone(),
                        lines: i32::try_from(theirs.len()).unwrap_or(i32::MAX),
                        gap,
                    });
                    continue;
                }
                let Some(contact) = account else { continue };
                due.by_account.entry(contact.id).or_default().push(ProfileLines {
                    project_id,
                    project_name: members.name.clone(),
                    profile: profile.label.clone(),
                    lines: theirs
                        .iter()
                        .map(|line| Line { position: line.position, control: line.control.clone() })
                        .collect(),
                });
                due.accounts.insert(contact.id, contact);
            }
        }
        Ok(due)
    }
}

/// What is due this week.
#[derive(Default)]
struct Due {
    by_account: BTreeMap<i64, Vec<ProfileLines>>,
    accounts: HashMap<i64, UserView>,
    unreached: Vec<Unreached>,
    repository_ids: HashMap<i64, Vec<i64>>,
}
