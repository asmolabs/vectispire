//! The OWASP grid week by week — Java's `OwaspWeeklyHistoryService`: the weekly record where it was captured, and a
//! reconstruction from the issues' own dates where it was not, never computed now for then.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Serialize, Serializer};
use time::{Date, Duration, Month, OffsetDateTime};
use vectispire_cp_access::Allowance;
use vectispire_cp_db::Db;
use vectispire_cp_issues::queries::{IssueCatalog, IssueFilters};
use vectispire_cp_targets::Clock;
use vectispire_domain::FindingType;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;
use vectispire_domain::owasp_coverage::{self, Split, State};

use crate::coverage::{OwaspCoverageService, StatedScope, at_most_one};
use crate::error::ComplianceError;
use crate::matrix::instant;
use crate::persistence::repository::WeeklyRepository;
use crate::persistence::{self, WeeklyStateCount};

pub const MAX_WEEKS: i64 = 52;
pub const DEFAULT_WEEKS: i64 = 12;
const WEEK: Duration = Duration::days(7);

/// `Request`: the window and the scope as the query named them.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub from: Option<String>,
    pub to: Option<String>,
    pub project_id: Option<i64>,
    pub solution_id: Option<i64>,
}

/// A `LocalDate`, written `YYYY-MM-DD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Day(pub OffsetDateTime);

impl Serialize for Day {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let date = self.0.date();
        serializer.serialize_str(&format!("{:04}-{:02}-{:02}", date.year(), u8::from(date.month()), date.day()))
    }
}

/// An `Instant`, as Jackson writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp(pub Instant);

impl Serialize for Stamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::instant_text::serialize(&self.0, serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwaspWeeklyCoverage {
    pub from: Day,
    pub to: Day,
    pub scope: Option<StatedScope>,
    pub reopened_recorded_from: Option<Day>,
    pub weeks: Vec<OwaspWeek>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwaspWeek {
    pub week_start: Day,
    pub reconstructed: bool,
    pub captured_at: Option<Stamp>,
    pub categories_measured: Option<i32>,
    pub open: i64,
    pub settled: Option<i64>,
    pub opened: i64,
    pub resolved: i64,
    pub reopened: Option<i64>,
    pub categories: Vec<OwaspWeekCategory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwaspWeekCategory {
    pub category: &'static str,
    pub title: &'static str,
    pub state: Option<State>,
    pub open: i64,
    pub settled: Option<i64>,
    pub opened: i64,
    pub resolved: i64,
    pub reopened: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Flow {
    open_at_end: i64,
    opened: i64,
    resolved: i64,
    reopened: i64,
}

impl Flow {
    fn plus(self, other: Flow) -> Flow {
        Flow {
            open_at_end: self.open_at_end.saturating_add(other.open_at_end),
            opened: self.opened.saturating_add(other.opened),
            resolved: self.resolved.saturating_add(other.resolved),
            reopened: self.reopened.saturating_add(other.reopened),
        }
    }
}

#[derive(Clone)]
pub struct OwaspWeeklyHistoryService {
    db: Db,
    issues: Arc<IssueCatalog>,
    coverage: OwaspCoverageService,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for OwaspWeeklyHistoryService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OwaspWeeklyHistoryService").finish_non_exhaustive()
    }
}

impl OwaspWeeklyHistoryService {
    pub fn new(
        db: Db,
        issues: Arc<IssueCatalog>,
        coverage: OwaspCoverageService,
        clock: Arc<dyn Clock>,
    ) -> OwaspWeeklyHistoryService {
        OwaspWeeklyHistoryService { db, issues, coverage, clock }
    }

    /// The refusals in Java's order: both scopes, then the window, then the scope's absence.
    pub async fn weeks(
        &self,
        request: &Request,
        allowance: &Allowance,
    ) -> Result<OwaspWeeklyCoverage, ComplianceError> {
        at_most_one(request.project_id, request.solution_id)?;
        let weeks = self.window(request)?;
        let (Some(first), Some(last)) = (weeks.first().copied(), weeks.last().copied()) else {
            return Err(ComplianceError::unexpected("a window of no week"));
        };
        let scoped = self.coverage.resolve(request.project_id, request.solution_id, allowance).await?;
        let allowed = scoped.visibility;

        let mut tx = persistence::read(&self.db).await?;
        let rows = WeeklyRepository::sum_by_week(&mut tx, first, last, &allowed).await?;
        persistence::commit(tx).await?;
        let mut recorded: HashMap<OffsetDateTime, Vec<WeeklyStateCount>> = HashMap::new();
        for row in rows {
            recorded.entry(row.week_start).or_default().push(row);
        }

        let mut every = IssueFilters::new(allowed);
        every.state = None;
        let mut flows: HashMap<OffsetDateTime, HashMap<&'static str, Flow>> = HashMap::new();
        for row in self.issues.weekly_flows(&every, &weeks).await.map_err(ComplianceError::unexpected)? {
            let placed = FindingType::from_wire_name(Some(&row.type_))
                .and_then(|type_| owasp_coverage::placement_of(type_, row.owasp_category.as_deref()));
            if let Some(category) = placed {
                let flow = Flow {
                    open_at_end: row.open_at_end,
                    opened: row.opened,
                    resolved: row.resolved,
                    reopened: row.reopened,
                };
                let kept = flows.entry(row.week_start).or_default().entry(category).or_default();
                *kept = kept.plus(flow);
            }
        }

        let reopened_from = self
            .issues
            .reopenings_recorded_since()
            .await
            .map_err(ComplianceError::unexpected)?
            .map(first_week_from)
            .transpose()?;
        let answered = weeks
            .iter()
            .map(|week| {
                week_of(
                    *week,
                    recorded.get(week).map(Vec::as_slice).unwrap_or_default(),
                    flows.get(week),
                    reopened_from.is_some_and(|from| *week >= from),
                )
            })
            .collect();
        Ok(OwaspWeeklyCoverage {
            from: Day(first),
            to: Day(last),
            scope: scoped.stated,
            reopened_recorded_from: reopened_from.map(Day),
            weeks: answered,
        })
    }

    /// The Mondays asked for: `to` defaults to the current week and never passes it, `from` to the eleven weeks
    /// before `to`; at most fifty-two.
    fn window(&self, request: &Request) -> Result<Vec<OffsetDateTime>, ComplianceError> {
        let current = monday(self.clock.now())?;
        let mut to = match blank_or(request.to.as_deref()) {
            None => current,
            Some(raw) => week_of_day("to", raw)?,
        };
        if to > current {
            to = current;
        }
        let from = match blank_or(request.from.as_deref()) {
            None => to.checked_sub(Duration::days(7 * (DEFAULT_WEEKS - 1))).ok_or_else(out_of_range)?,
            Some(raw) => week_of_day("from", raw)?,
        };
        if from > to {
            return Err(ComplianceError::Invalid("from comes after to.".to_owned()));
        }
        let days = to.unix_timestamp().saturating_sub(from.unix_timestamp()).div_euclid(86_400);
        let count = days.div_euclid(7).saturating_add(1);
        if count > MAX_WEEKS {
            return Err(ComplianceError::Invalid(format!(
                "At most {MAX_WEEKS} weeks per request; this one spans {count}."
            )));
        }
        let mut weeks = Vec::new();
        let mut week = from;
        while week <= to {
            weeks.push(week);
            week = week.checked_add(WEEK).ok_or_else(out_of_range)?;
        }
        Ok(weeks)
    }
}

fn week_of(
    week: OffsetDateTime,
    recorded: &[WeeklyStateCount],
    flows: Option<&HashMap<&'static str, Flow>>,
    reopenings_known: bool,
) -> OwaspWeek {
    let reconstructed = recorded.is_empty();
    let categories: Vec<OwaspWeekCategory> = owasp_coverage::CATEGORIES
        .iter()
        .map(|(code, title)| {
            let flow = flows.and_then(|flows| flows.get(code)).copied().unwrap_or_default();
            let reopened = reopenings_known.then_some(flow.reopened);
            if reconstructed {
                return OwaspWeekCategory {
                    category: code,
                    title,
                    state: None,
                    open: flow.open_at_end,
                    settled: None,
                    opened: flow.opened,
                    resolved: flow.resolved,
                    reopened,
                };
            }
            // A state name this version does not know is skipped, as Java's `stateOf`.
            let splits: Vec<Split> = recorded
                .iter()
                .filter(|row| row.category == *code)
                .filter_map(|row| {
                    state_of(&row.state).map(|state| Split {
                        id: (*code).to_owned(),
                        state,
                        open: row.open,
                        settled: row.settled,
                    })
                })
                .collect();
            let combined = owasp_coverage::across_targets(code, &splits);
            OwaspWeekCategory {
                category: code,
                title,
                state: combined.as_ref().map(|split| split.state),
                open: combined.as_ref().map_or(0, |split| split.open),
                settled: Some(combined.as_ref().map_or(0, |split| split.settled)),
                opened: flow.opened,
                resolved: flow.resolved,
                reopened,
            }
        })
        .collect();
    let sum = |read: &dyn Fn(&OwaspWeekCategory) -> i64| {
        categories.iter().fold(0i64, |total, line| total.saturating_add(read(line)))
    };
    OwaspWeek {
        week_start: Day(week),
        reconstructed,
        captured_at: recorded.iter().map(|row| row.captured_at).max().map(|at| Stamp(instant(at))),
        categories_measured: (!reconstructed).then(|| {
            let measured =
                categories.iter().filter(|line| matches!(line.state, Some(State::Findings | State::NoFinding))).count();
            i32::try_from(measured).unwrap_or(i32::MAX)
        }),
        open: sum(&|line| line.open),
        settled: (!reconstructed).then(|| sum(&|line| line.settled.unwrap_or(0))),
        opened: sum(&|line| line.opened),
        resolved: sum(&|line| line.resolved),
        reopened: reopenings_known.then(|| sum(&|line| line.reopened.unwrap_or(0))),
        categories,
    }
}

fn state_of(name: &str) -> Option<State> {
    serde_json::from_value(serde_json::Value::String(name.to_owned())).ok()
}

/// `firstWeekFrom`: the Monday of the instant when it is one, else the next Monday — a week reopenings were recorded
/// for from its start.
fn first_week_from(at: OffsetDateTime) -> Result<OffsetDateTime, ComplianceError> {
    let week = monday(at)?;
    if week == at { Ok(week) } else { week.checked_add(WEEK).ok_or_else(out_of_range) }
}

/// `CoverageWeek.startOf`, on the database's instants.
pub fn monday(at: OffsetDateTime) -> Result<OffsetDateTime, ComplianceError> {
    let start = owasp_coverage::week_start(instant(at));
    OffsetDateTime::from_unix_timestamp(start.epoch_second).map_err(ComplianceError::unexpected)
}

fn blank_or(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !java::is_blank(value))
}

/// `weekOf`: an ISO date as `LocalDate.parse` reads it, between 1970 and 9998, as the Monday of its week.
fn week_of_day(name: &str, raw: &str) -> Result<OffsetDateTime, ComplianceError> {
    let trimmed = java::trim(raw);
    let (year, month, day) = iso_date(trimmed)
        .ok_or_else(|| ComplianceError::Invalid(format!("{name} must be an ISO date, YYYY-MM-DD: \"{trimmed}\".")))?;
    if !(1970..=9998).contains(&year) {
        return Err(ComplianceError::Invalid(format!("{name} must be a date between 1970 and 9998.")));
    }
    let date = i32::try_from(year)
        .ok()
        .and_then(|year| Month::try_from(month).ok().and_then(|month| Date::from_calendar_date(year, month, day).ok()))
        .ok_or_else(|| ComplianceError::Invalid(format!("{name} must be an ISO date, YYYY-MM-DD: \"{trimmed}\".")))?;
    monday(date.midnight().assume_utc())
}

/// `DateTimeFormatter.ISO_LOCAL_DATE` under the strict resolver: a year of four digits — more only behind a sign, a
/// `+` refused on four —, a two-digit month and day, and a day the month has. The year's range is checked by the
/// caller, so a valid date outside it is refused in its own sentence.
fn iso_date(text: &str) -> Option<(i64, u8, u8)> {
    let (negative, unsigned, signed) = match text.as_bytes().first() {
        Some(b'+') => (false, text.get(1..)?, true),
        Some(b'-') => (true, text.get(1..)?, true),
        _ => (false, text, false),
    };
    let mut parts = unsigned.rsplitn(3, '-');
    let day = parts.next()?;
    let month = parts.next()?;
    let year = parts.next()?;
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if !digits(year) || !digits(month) || !digits(day) || month.len() != 2 || day.len() != 2 {
        return None;
    }
    if year.len() < 4 || year.len() > 10 || (year.len() == 4 && signed && !negative) || (year.len() > 4 && !signed) {
        return None;
    }
    let magnitude: i64 = year.parse().ok()?;
    let year = if negative { magnitude.checked_neg()? } else { magnitude };
    let month: u8 = month.parse().ok()?;
    let day: u8 = day.parse().ok()?;
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    let length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (1..=length).contains(&day).then_some((year, month, day))
}

fn out_of_range() -> ComplianceError {
    ComplianceError::unexpected("a week outside the calendar")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_date_is_read_as_local_date_parse_reads_it() {
        assert_eq!(iso_date("2026-11-17"), Some((2026, 11, 17)));
        assert_eq!(iso_date("2024-02-29"), Some((2024, 2, 29)));
        assert_eq!(iso_date("2100-02-29"), None, "not a leap year");
        assert_eq!(iso_date("2026-1-17"), None);
        assert_eq!(iso_date("26-11-17"), None);
        assert_eq!(iso_date("+2026-11-17"), None, "a sign on four digits");
        assert_eq!(iso_date("+12026-11-17"), Some((12026, 11, 17)));
        assert_eq!(iso_date("12026-11-17"), None, "five digits need their sign");
        assert_eq!(iso_date("-0001-01-01"), Some((-1, 1, 1)));
        assert_eq!(iso_date("2026-13-01"), None);
        assert_eq!(iso_date("2026-11-17T00:00"), None);
    }

    #[test]
    fn the_window_is_refused_in_java_s_words() {
        let refused = |raw: &str| match week_of_day("from", raw) {
            Err(ComplianceError::Invalid(message)) => message,
            other => panic!("{other:?}"),
        };
        assert_eq!(refused(" soon "), "from must be an ISO date, YYYY-MM-DD: \"soon\".");
        assert_eq!(refused("1969-12-31"), "from must be a date between 1970 and 9998.");
        assert_eq!(refused("+10000-01-01"), "from must be a date between 1970 and 9998.");
        assert!(week_of_day("from", "9998-12-31").is_ok());
        assert!(week_of_day("from", "1970-01-05").is_ok());
    }

    #[test]
    fn a_recorded_week_combines_its_targets_and_a_past_one_is_reconstructed() {
        let week = OffsetDateTime::from_unix_timestamp(1_794_873_600).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let row = |category: &str, state: &str, open: i64| WeeklyStateCount {
            week_start: week,
            category: category.to_owned(),
            state: state.to_owned(),
            targets: 1,
            open,
            settled: 1,
            captured_at: week,
        };
        let recorded = [row("A06", "FINDINGS", 2), row("A06", "NO_FINDING", 0), row("A01", "SOMETHING_NEW", 5)];
        let one = week_of(week, &recorded, None, false);
        assert!(!one.reconstructed);
        assert_eq!(one.open, 2);
        assert_eq!(one.settled, Some(2));
        assert_eq!(one.reopened, None);
        let a06 = one.categories.iter().find(|line| line.category == "A06");
        assert_eq!(a06.and_then(|line| line.state), Some(State::Findings));
        let a01 = one.categories.iter().find(|line| line.category == "A01");
        assert_eq!(a01.and_then(|line| line.state), None, "an unknown state is skipped");
        assert_eq!(a06.and_then(|line| line.reopened), None, "no category says reopened before it was recorded");

        let flows = HashMap::from([("A06", Flow { open_at_end: 3, opened: 1, resolved: 2, reopened: 1 })]);
        let past = week_of(week, &[], Some(&flows), true);
        assert!(past.reconstructed);
        assert_eq!((past.open, past.settled, past.categories_measured, past.reopened), (3, None, None, Some(1)));
    }
}
