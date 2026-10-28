//! `ChecklistReminder`: the weekly reminder of the lines still to fill in (decision 0044) — to the account a project
//! linked to a profile, that profile's lines; to the CISOs, the profiles nobody can be reminded for.
//!
//! A pure function of what the service read, in plain text and in English, as every message Vectispire mails.

use vectispire_domain::bounded_text::clip;
use vectispire_domain::java;

use crate::text;

/// The lines named per project and profile; the rest are counted, and the page lists them all.
pub const LINES_NAMED: usize = 20;

/// A control is a sentence of the template's, and a mail line is not a page: cut, and marked as cut.
pub const CONTROL_SHOWN: usize = 160;

/// A line to fill in: its place in the checklist, and what it asks.
#[derive(Debug, Clone)]
pub struct Line {
    pub position: i32,
    pub control: String,
}

/// One profile's lines on one project, for the account linked to it there.
#[derive(Debug, Clone)]
pub struct ProfileLines {
    pub project_id: i64,
    pub project_name: String,
    pub profile: String,
    pub lines: Vec<Line>,
}

/// Why a profile with lines to fill in reminds nobody — said to the CISO in these words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gap {
    NobodyLinked,
    AccountGone,
    AccountInactive,
    NoEmail,
    CannotFill,
}

impl Gap {
    pub const ALL: [Gap; 5] =
        [Gap::NobodyLinked, Gap::AccountGone, Gap::AccountInactive, Gap::NoEmail, Gap::CannotFill];

    pub fn words(self) -> &'static str {
        match self {
            Gap::NobodyLinked => "no account is linked to it",
            Gap::AccountGone => "the account linked to it no longer exists",
            Gap::AccountInactive => "the account linked to it is deactivated",
            Gap::NoEmail => "the account linked to it has no e-mail address",
            Gap::CannotFill => "the account linked to it can no longer fill in this project's checklist",
        }
    }

    /// The token a screen receives, lower-case like the other wire values.
    pub fn wire_name(self) -> &'static str {
        match self {
            Gap::NobodyLinked => "nobody_linked",
            Gap::AccountGone => "account_gone",
            Gap::AccountInactive => "account_inactive",
            Gap::NoEmail => "no_email",
            Gap::CannotFill => "cannot_fill",
        }
    }
}

/// A profile with lines to fill in on a project, and why nobody is reminded of them.
#[derive(Debug, Clone)]
pub struct Unreached {
    pub project_id: i64,
    pub project_name: String,
    pub profile: String,
    pub lines: i32,
    pub gap: Gap,
}

/// A message: its subject and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub subject: String,
    pub body: String,
}

/// To the account linked to the profiles: every line of theirs still to fill in, by project.
///
/// `name` is how the account is addressed, `None` when it has no name a message may print; `week_starting` the
/// Monday the reminder is for, as `LocalDate.toString` writes it; `public_url` the deployment's address, for a link
/// to each project's checklist.
pub fn to_contact(
    name: Option<&str>,
    profiles: &[ProfileLines],
    week_starting: &str,
    public_url: Option<&str>,
) -> Message {
    let total: usize = profiles.iter().map(|profile| profile.lines.len()).sum();
    let mut body = String::new();
    body.push_str(&name.map_or_else(|| "Hello,".to_owned(), |person| format!("Hello {person},")));
    body.push_str("\n\n");
    body.push_str(&if total == 1 { "One checklist line".to_owned() } else { format!("{total} checklist lines") });
    body.push_str(" for which you are the contact ");
    body.push_str(if total == 1 { "is" } else { "are" });
    body.push_str(" not filled in yet: unanswered, or carried from an earlier version and waiting for confirmation.\n");
    for profile in profiles {
        body.push_str(&format!(
            "\nProject \"{}\", profile {} — {}\n",
            profile.project_name,
            profile.profile,
            count(profile.lines.len())
        ));
        for line in profile.lines.iter().take(LINES_NAMED) {
            body.push_str(&format!("  Line {}: {}\n", line.position, shown(&line.control)));
        }
        if profile.lines.len() > LINES_NAMED {
            body.push_str(&format!("  … and {} more\n", count(profile.lines.len().saturating_sub(LINES_NAMED))));
        }
        if let Some(url) = link(public_url, profile.project_id) {
            body.push_str(&format!("  {url}\n"));
        }
    }
    body.push_str(&format!(
        "\nYou receive this once a week, for the week of {week_starting}, while lines of a profile a project linked to \
         your account wait to be filled in. Whoever edits the project's checklist can link the profile to somebody \
         else.\n"
    ));
    let subject = if total == 1 {
        "[Vectispire] 1 checklist line waits for you".to_owned()
    } else {
        format!("[Vectispire] {total} checklist lines wait for you")
    };
    Message { subject, body }
}

/// To a CISO: the profiles whose lines remind nobody, by project, each with its reason.
pub fn to_ciso(unreached: &[Unreached], week_starting: &str, public_url: Option<&str>) -> Message {
    let mut body = String::from("Hello,\n\n");
    body.push_str(&if unreached.len() == 1 {
        "One profile has".to_owned()
    } else {
        format!("{} profiles have", unreached.len())
    });
    body.push_str(" checklist lines to fill in that nobody is reminded of:\n\n");
    for profile in unreached {
        body.push_str(&format!(
            "Project \"{}\", profile {} — {}: {}\n",
            profile.project_name,
            profile.profile,
            count(usize::try_from(profile.lines).unwrap_or(0)),
            profile.gap.words()
        ));
        if let Some(url) = link(public_url, profile.project_id) {
            body.push_str(&format!("  {url}\n"));
        }
    }
    body.push_str(&format!(
        "\nLink each profile to an account that can fill in the project's checklist, on the checklist's page, under \
         Contacts. You receive this once a week, for the week of {week_starting}, as a CISO, while a profile with \
         lines to fill in reminds nobody.\n"
    ));
    let subject = if unreached.len() == 1 {
        "[Vectispire] 1 checklist profile without a contact".to_owned()
    } else {
        format!("[Vectispire] {} checklist profiles without a contact", unreached.len())
    };
    Message { subject, body }
}

fn count(lines: usize) -> String {
    if lines == 1 { "1 line".to_owned() } else { format!("{lines} lines") }
}

/// One line of text: a control may hold line breaks, and a long one is cut where the reader sees it is — never
/// between the halves of a surrogate pair, which `clip` drops whole.
fn shown(control: &str) -> String {
    let single = text::normalize(Some(control));
    if java::utf16_len(&single) <= CONTROL_SHOWN {
        return single;
    }
    format!("{}…", java::strip(clip(Some(&single), CONTROL_SHOWN.saturating_sub(1)).unwrap_or("")))
}

fn link(public_url: Option<&str>, project_id: i64) -> Option<String> {
    public_url.map(|url| format!("{}/projects/{project_id}/checklist", url.trim_end_matches('/')))
}
