//! `SelectionFilter`: the filters of the selection table — what a person narrows a discovery's repositories to before
//! ticking them. A filter decides what is shown; what is imported is what was ticked.
//!
//! **Unknown is never judged — either way.** A filter that hides something keeps a repository it cannot judge, one
//! that requires something leaves it out, and either way it is counted against that filter as unjudged.

use std::collections::BTreeSet;

use super::DiscoveredRepository;
use crate::bounded_text::{self, Refused};
use crate::instant::Instant;
use crate::java;

/// Ten years: past that the filter hides nothing a forge still holds.
pub const MAX_INACTIVE_DAYS: i64 = 3_650;

/// Whether a kind of repository is shown, hidden, or the only one shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    Hide,
    Show,
    Only,
}

impl Shown {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Shown::Hide => "hide",
            Shown::Show => "show",
            Shown::Only => "only",
        }
    }

    fn parse(raw: Option<&str>, by_default: Shown, what: &str) -> Result<Shown, Refused> {
        let Some(raw) = raw.filter(|raw| !java::is_blank(raw)) else {
            return Ok(by_default);
        };
        let wanted = java::to_lower_root(java::trim(raw));
        [Shown::Hide, Shown::Show, Shown::Only].into_iter().find(|shown| shown.wire_name() == wanted).ok_or_else(|| {
            Refused(format!(
                "\"{}\" is not a choice for {what}: hide, show or only.",
                bounded_text::clip(Some(java::trim(raw)), 40).unwrap_or_default()
            ))
        })
    }
}

/// The filters that may meet a value the forge did not give — in `EnumSet` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Judged {
    Archived,
    Fork,
    Activity,
    Language,
    Visibility,
}

impl Judged {
    pub const ALL: [Judged; 5] =
        [Judged::Archived, Judged::Fork, Judged::Activity, Judged::Language, Judged::Visibility];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Judged::Archived => "archived",
            Judged::Fork => "fork",
            Judged::Activity => "activity",
            Judged::Language => "language",
            Judged::Visibility => "visibility",
        }
    }
}

/// The filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionFilter {
    pub archived: Shown,
    pub forks: Shown,
    pub inactive_days: Option<i64>,
    pub language: Option<String>,
    pub visibility: Option<String>,
    pub namespace: Option<String>,
    pub path: Option<String>,
    pub personal: Shown,
    pub present: Shown,
}

/// One repository as the filters see it; `present` is already a target, by identity or by an earlier import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate<'a> {
    pub archived: Option<bool>,
    pub fork: Option<bool>,
    pub last_activity_at: Option<Instant>,
    pub language: Option<&'a str>,
    pub visibility: Option<&'a str>,
    pub namespace_path: &'a str,
    pub full_path: &'a str,
    pub personal: bool,
    pub present: bool,
}

/// How the filters judged one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub matches: bool,
    pub unjudged: BTreeSet<Judged>,
}

/// The raw words a request carries.
#[derive(Debug, Clone, Default)]
pub struct Requested<'a> {
    pub archived: Option<&'a str>,
    pub forks: Option<&'a str>,
    pub inactive_days: Option<i64>,
    pub language: Option<&'a str>,
    pub visibility: Option<&'a str>,
    pub namespace: Option<&'a str>,
    pub path: Option<&'a str>,
    pub personal: Option<&'a str>,
    pub present: Option<&'a str>,
}

impl SelectionFilter {
    /// What the table shows before anybody touches a filter: no archived repository, no fork.
    pub fn default_filter() -> SelectionFilter {
        SelectionFilter {
            archived: Shown::Hide,
            forks: Shown::Hide,
            inactive_days: None,
            language: None,
            visibility: None,
            namespace: None,
            path: None,
            personal: Shown::Show,
            present: Shown::Show,
        }
    }

    /// `SelectionFilter.parse`: the filters as a request spells them, each refused in words.
    pub fn parse(requested: &Requested<'_>) -> Result<SelectionFilter, Refused> {
        if let Some(days) = requested.inactive_days
            && !(1..=MAX_INACTIVE_DAYS).contains(&days)
        {
            return Err(Refused(format!("inactiveDays is a number of days between 1 and {MAX_INACTIVE_DAYS}.")));
        }
        Ok(SelectionFilter {
            archived: Shown::parse(requested.archived, Shown::Hide, "archived")?,
            forks: Shown::parse(requested.forks, Shown::Hide, "forks")?,
            inactive_days: requested.inactive_days,
            language: bounded_text::optional(
                requested.language,
                DiscoveredRepository::LANGUAGE_LENGTH,
                "The language",
            )?,
            visibility: bounded_text::optional(
                requested.visibility,
                DiscoveredRepository::VISIBILITY_LENGTH,
                "The visibility",
            )?,
            namespace: bounded_text::optional(requested.namespace, DiscoveredRepository::PATH_LENGTH, "The namespace")?
                .map(|namespace| without_slashes(&namespace).to_owned()),
            path: bounded_text::optional(requested.path, DiscoveredRepository::PATH_LENGTH, "The path pattern")?,
            personal: Shown::parse(requested.personal, Shown::Show, "personal")?,
            present: Shown::parse(requested.present, Shown::Show, "present")?,
        })
    }

    /// Judged at `now`, which places the inactivity cut.
    pub fn judge(&self, candidate: &Candidate<'_>, now: Instant) -> Verdict {
        let mut failed = BTreeSet::new();
        let mut unknown = BTreeSet::new();
        let mut others = true;

        judge_shown(self.archived, candidate.archived, Judged::Archived, &mut failed, &mut unknown);
        judge_shown(self.forks, candidate.fork, Judged::Fork, &mut failed, &mut unknown);
        if let Some(days) = self.inactive_days {
            match candidate.last_activity_at {
                None => {
                    unknown.insert(Judged::Activity);
                }
                Some(at) => {
                    if now.minus_days(days).is_some_and(|cut| at < cut) {
                        failed.insert(Judged::Activity);
                    }
                }
            }
        }
        judge_required(self.language.as_deref(), candidate.language, Judged::Language, &mut failed, &mut unknown);
        judge_required(self.visibility.as_deref(), candidate.visibility, Judged::Visibility, &mut failed, &mut unknown);

        if let Some(namespace) = &self.namespace {
            let wanted = java::to_lower_root(namespace);
            let actual = java::to_lower_root(without_slashes(candidate.namespace_path));
            others &= actual == wanted || actual.starts_with(&format!("{wanted}/"));
        }
        if let Some(pattern) = &self.path {
            others &= path_matches(pattern, candidate.full_path);
        }
        others &= shows(self.personal, candidate.personal);
        others &= shows(self.present, candidate.present);

        let matches = others && failed.is_empty();
        let mut unjudged = BTreeSet::new();
        if others {
            // Counted only where nothing else would have hidden the repository anyway.
            for filter in &unknown {
                if failed.iter().all(|other| other == filter) {
                    unjudged.insert(*filter);
                }
            }
        }
        Verdict { matches, unjudged }
    }
}

fn judge_shown(
    shown: Shown,
    value: Option<bool>,
    filter: Judged,
    failed: &mut BTreeSet<Judged>,
    unknown: &mut BTreeSet<Judged>,
) {
    if shown == Shown::Show {
        return;
    }
    let Some(value) = value else {
        unknown.insert(filter);
        if shown == Shown::Only {
            failed.insert(filter);
        }
        return;
    };
    if if shown == Shown::Hide { value } else { !value } {
        failed.insert(filter);
    }
}

fn judge_required(
    wanted: Option<&str>,
    value: Option<&str>,
    filter: Judged,
    failed: &mut BTreeSet<Judged>,
    unknown: &mut BTreeSet<Judged>,
) {
    let Some(wanted) = wanted else {
        return;
    };
    match value {
        None => {
            unknown.insert(filter);
            failed.insert(filter);
        }
        Some(value) => {
            if java::compare_ignore_case(value, wanted) != std::cmp::Ordering::Equal {
                failed.insert(filter);
            }
        }
    }
}

const fn shows(shown: Shown, value: bool) -> bool {
    match shown {
        Shown::Show => true,
        Shown::Hide => !value,
        Shown::Only => value,
    }
}

/// `acme/payments/*`: a glob over the whole path, `*` crossing slashes, case aside; without a wildcard, a search.
/// **Matched by hand, over UTF-16 units as Java's `charAt` walks them**, at most the pattern's length times the path's.
pub fn path_matches(pattern: &str, full_path: &str) -> bool {
    let path_text = java::to_lower_root(full_path);
    let wanted_text = java::to_lower_root(pattern);
    if !wanted_text.contains('*') && !wanted_text.contains('?') {
        return path_text.contains(&wanted_text);
    }
    let path: Vec<u16> = path_text.encode_utf16().collect();
    let wanted: Vec<u16> = wanted_text.encode_utf16().collect();
    let (star_unit, any_unit) = (u16::from(b'*'), u16::from(b'?'));
    let (mut p, mut w, mut resume) = (0usize, 0usize, 0usize);
    let mut star: Option<usize> = None;
    while p < path.len() {
        if w < wanted.len() && (wanted[w] == any_unit || wanted[w] == path[p]) {
            p += 1;
            w += 1;
        } else if w < wanted.len() && wanted[w] == star_unit {
            star = Some(w);
            w += 1;
            resume = p;
        } else if let Some(at) = star {
            w = at + 1;
            resume += 1;
            p = resume;
        } else {
            return false;
        }
    }
    while w < wanted.len() && wanted[w] == star_unit {
        w += 1;
    }
    w == wanted.len()
}

fn without_slashes(value: &str) -> &str {
    java::trim(value).trim_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate<'a>() -> Candidate<'a> {
        Candidate {
            archived: Some(false),
            fork: None,
            last_activity_at: None,
            language: None,
            visibility: Some("Private"),
            namespace_path: "acme/payments",
            full_path: "acme/payments/api",
            personal: false,
            present: false,
        }
    }

    const NOW: Instant = Instant { epoch_second: 1_800_000_000, nano: 0 };

    #[test]
    fn the_default_keeps_an_unknown_fork_and_counts_it() {
        let verdict = SelectionFilter::default_filter().judge(&candidate(), NOW);
        assert!(verdict.matches);
        assert_eq!(verdict.unjudged, BTreeSet::from([Judged::Fork]));
    }

    #[test]
    fn a_required_value_left_unknown_is_left_out_and_counted() {
        let filter = SelectionFilter::parse(&Requested { language: Some("Java"), ..Requested::default() }).unwrap();
        let verdict = filter.judge(&candidate(), NOW);
        assert!(!verdict.matches);
        assert_eq!(verdict.unjudged, BTreeSet::from([Judged::Language]), "the fork is hidden by the language anyway");
        let filter = SelectionFilter::parse(&Requested {
            language: Some("Java"),
            visibility: Some("public"),
            ..Requested::default()
        })
        .unwrap();
        assert_eq!(filter.judge(&candidate(), NOW).unjudged, BTreeSet::new(), "visibility hides it anyway");
    }

    #[test]
    fn namespaces_by_whole_segments_and_paths_by_glob() {
        let by = |namespace: &str| {
            SelectionFilter::parse(&Requested { namespace: Some(namespace), ..Requested::default() })
                .unwrap()
                .judge(&candidate(), NOW)
                .matches
        };
        assert!(by("/ACME/"));
        assert!(by("acme/payments"));
        assert!(!by("acme/pay"));
        assert!(path_matches("acme/*/api", "acme/payments/api"));
        assert!(path_matches("*", "anything"));
        assert!(path_matches("a?me*", "ACME/x"));
        assert!(!path_matches("acme/*/web", "acme/payments/api"));
        assert!(path_matches("payments", "acme/payments/api"));
        assert!(path_matches(&"*a".repeat(40), &"a".repeat(1000)));
    }

    #[test]
    fn refusals_are_in_words() {
        assert_eq!(
            SelectionFilter::parse(&Requested { inactive_days: Some(0), ..Requested::default() }).unwrap_err().0,
            "inactiveDays is a number of days between 1 and 3650."
        );
        assert_eq!(
            SelectionFilter::parse(&Requested { forks: Some("maybe"), ..Requested::default() }).unwrap_err().0,
            "\"maybe\" is not a choice for forks: hide, show or only."
        );
    }

    #[test]
    fn inactivity_is_cut_at_now_minus_the_days() {
        let filter =
            SelectionFilter::parse(&Requested { inactive_days: Some(30), forks: Some("show"), ..Requested::default() })
                .unwrap();
        let mut old = candidate();
        old.last_activity_at = NOW.minus_days(31);
        assert!(!filter.judge(&old, NOW).matches);
        old.last_activity_at = NOW.minus_days(30);
        assert!(filter.judge(&old, NOW).matches);
        assert_eq!(filter.judge(&candidate(), NOW).unjudged, BTreeSet::from([Judged::Activity]));
    }
}
