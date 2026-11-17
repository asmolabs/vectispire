//! The dates' clauses — Java's `IssueSpecifications.openAt`, `resolvedWithin` and `reopenedWithin` — each half open,
//! and the same clause in the backlog's list ([`super::repository::criteria`]) and in the weekly flows' grouped count
//! ([`super::aggregates::IssueAggregates::weekly_flows`]), so that a figure and the list it opens cannot disagree.
//!
//! **The earlier resolutions come from the triage history**: a reopening is an entry of origin `reopen` carrying the
//! resolution it ended, `previous_resolved_at` (V68). The issue keeps only its latest resolution, so a clause reading
//! the issue alone counts a reopened issue as open from its first sighting on. The port did exactly that until
//! compliance's weekly view needed it — and compared the instant the wrong way at both ends: `first_seen <= at` and
//! `resolved > at`, where Java's half-open intervals read `first_seen < at` and `resolved >= at`.
//!
//! Every instant is a bound value: sea-query sends values as parameters, never as literals, which is where the engines
//! would differ (Java's `Bound`).

use sea_orm::ColumnTrait;
use sea_orm::sea_query::{Condition, Expr, ExprTrait, Query, SelectStatement};
use time::OffsetDateTime;

use super::entities::{IssueColumn, TriageEventColumn, TriageEvents};

/// The origin of the entry a reopening writes — `TriageOrigin.REOPENING`.
const REOPENING: &str = "reopen";

/// The issue's reopenings satisfying `condition`. The issue's id is qualified by its table, so that it correlates from
/// inside the subquery.
fn reopenings_of_the_issue(condition: Condition) -> SelectStatement {
    Query::select()
        .column((TriageEvents, TriageEventColumn::Id))
        .from(TriageEvents)
        .cond_where(
            Condition::all()
                .add(Expr::col((TriageEvents, TriageEventColumn::IssueId)).equals(IssueColumn::Id.as_column_ref()))
                .add(TriageEventColumn::Origin.eq(REOPENING))
                .add(condition),
        )
        .to_owned()
}

/// The issue's reopenings that ended a resolution and satisfy `condition` — Java's `reopenings`.
fn reopenings(condition: Condition) -> SelectStatement {
    reopenings_of_the_issue(Condition::all().add(TriageEventColumn::PreviousResolvedAt.is_not_null()).add(condition))
}

/// `[from, before)` on a column; null is no instant, and a missing bound asks nothing.
fn within(column: impl ColumnTrait, from: Option<OffsetDateTime>, before: Option<OffsetDateTime>) -> Condition {
    let mut bounds = Condition::all().add(column.is_not_null());
    if let Some(from) = from {
        bounds = bounds.add(column.gte(from));
    }
    if let Some(before) = before {
        bounds = bounds.add(column.lt(before));
    }
    bounds
}

/// Open at `at`: seen before it, not resolved before it, and not inside an earlier resolution — `at` in
/// `(previous resolved_at, reopened at]`, Java's code: still open at the instant it was resolved, as with the latest
/// resolution, and not yet back at the instant of the reopening. (Java's javadoc wrote the interval the other way
/// round, `[…)`, against its own sentence and its code; corrected beside this port.)
pub(super) fn open_at(at: OffsetDateTime) -> Condition {
    let inside_an_earlier_resolution =
        Condition::all().add(TriageEventColumn::PreviousResolvedAt.lt(at)).add(TriageEventColumn::OccurredAt.gte(at));
    Condition::all()
        .add(IssueColumn::FirstSeenAt.lt(at))
        .add(Condition::any().add(IssueColumn::ResolvedAt.is_null()).add(IssueColumn::ResolvedAt.gte(at)))
        .add(Expr::exists(reopenings(inside_an_earlier_resolution)).not())
}

/// Resolved within `[from, before)`: its latest resolution, or one a reopening ended. Counted once, however many of
/// its resolutions fall in the interval.
pub(super) fn resolved_within(from: Option<OffsetDateTime>, before: Option<OffsetDateTime>) -> Condition {
    let an_earlier_one = Expr::exists(reopenings(within(TriageEventColumn::PreviousResolvedAt, from, before)));
    Condition::any().add(within(IssueColumn::ResolvedAt, from, before)).add(an_earlier_one)
}

/// Reopened within `[from, before)`: a reopening recorded at an instant of the interval. Unlike the two above it does
/// not ask for the resolution the entry ended — Java's `reopenedWithin` reads the entry alone.
pub(super) fn reopened_within(from: Option<OffsetDateTime>, before: Option<OffsetDateTime>) -> Condition {
    Condition::all().add(Expr::exists(reopenings_of_the_issue(within(TriageEventColumn::OccurredAt, from, before))))
}
