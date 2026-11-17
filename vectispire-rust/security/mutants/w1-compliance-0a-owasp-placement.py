#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, compliance stage 0a: the backlog's `owasp_category` filter places issues as
Java's `IssueSpecifications.placedIn` does — a type placed by rule, or code analysis declaring the category — and not
by the column alone; and the dates' clauses (`openAt`, `resolvedWithin`, `reopenedWithin`) are half open as Java's and
read the reopenings V68 records. See README.md.
"""
import sys

import _runner

E = ["-p", "vectispire-cp-issues", "--lib", "persistence::tests"]
D = ["-p", "vectispire-domain", "--lib", "owasp_coverage"]
R = "crates/cp-issues/src/persistence/repository.rs"
O = "crates/domain/src/owasp_coverage.rs"
L = "crates/cp-issues/src/persistence/lived.rs"
A = "crates/cp-issues/src/persistence/aggregates.rs"

# Equivalent, and removed: `reopenings` asking for a non-null `previous_resolved_at` — every condition handed to it
# compares that column (`< at`, or `within`, which asks it not null), and a null compares to nothing. Kept for Java's
# shape and for the next caller. And the weekly flows' narrowing to issues not resolved before the first week: such an
# issue's latest resolution, and every resolution a reopening ended before it, precede the window, so it is open at no
# week's end and resolved or reopened in none — it adds zeros to a group, and a group of zeros is not listed.
MUTANTS = [
    ("placed by the column alone", R, "    if !types.is_empty() {\n        either = either.add(IssueColumn::Type.is_in(types));\n    }\n", "", E),
    ("any type declaring counts", R, "            .add(IssueColumn::Type.eq(owasp_coverage::DECLARES_ITS_CATEGORY.wire_name()))\n", "", E),
    ("anywhere is any column", R, "(owasp_coverage::types_placed_anywhere(), owasp_coverage::codes().map(str::to_owned).collect())", "(owasp_coverage::types_placed_anywhere(), vec![\"A11\".to_owned()])", E),
    ("eol not outdated", O, "    (FindingType::Eol, \"A06\"),\n", "", [D, E]),
    ("secrets placed in a02", O, "    (FindingType::Secret, \"A07\"),\n", "    (FindingType::Secret, \"A02\"),\n", D),
    # The dates' clauses: half open at both ends, and the reopenings read.
    ("open at the instant first seen", L, ".add(IssueColumn::FirstSeenAt.lt(at))", ".add(IssueColumn::FirstSeenAt.lte(at))", E),
    ("closed at the instant resolved", L, ".add(IssueColumn::ResolvedAt.gte(at)))", ".add(IssueColumn::ResolvedAt.gt(at)))", E),
    ("earlier resolutions ignored", L, "        .add(Expr::exists(reopenings(inside_an_earlier_resolution)).not())\n", "", E),
    ("back at the instant reopened", L, ".add(TriageEventColumn::OccurredAt.gte(at));", ".add(TriageEventColumn::OccurredAt.gt(at));", E),
    ("closed at the earlier resolution", L, ".add(TriageEventColumn::PreviousResolvedAt.lt(at))", ".add(TriageEventColumn::PreviousResolvedAt.lte(at))", E),
    ("resolved reads the issue alone", L, ".add(within(IssueColumn::ResolvedAt, from, before)).add(an_earlier_one)", ".add(within(IssueColumn::ResolvedAt, from, before))", E),
    ("an interval's end included", L, "        bounds = bounds.add(column.lt(before));", "        bounds = bounds.add(column.lte(before));", E),
    # The reads compliance adds.
    ("weeks not deduplicated", A, "        weeks.dedup();\n", "", E),
    ("a figure read from the next week", A, '.try_get("", &format!("w{index}_{figure}"))', '.try_get("", &format!("w{}_{figure}", (index + 1) % weeks.len()))', E),
    ("an empty week listed", A, "if figures.iter().any(|figure| *figure > 0) {", "if true {", E),
    ("opened includes the end", A, "                .add(IssueColumn::FirstSeenAt.lt(end));", "                .add(IssueColumn::FirstSeenAt.lte(end));", E),
    ("a plugin's category counted", A, "            .add(IssueColumn::Type.eq(owasp_coverage::DECLARES_ITS_CATEGORY.wire_name()))\n            .add(IssueColumn::OwaspCategory.is_not_null());", "            .add(IssueColumn::OwaspCategory.is_not_null());", E),
    ("settled triage grouped", A, "            .filter(IssueColumn::TriageStatus.is_not_in(settled.iter().copied()))\n", "", E),
    ("kev not a group", A, "            IssueColumn::Type,\n            IssueColumn::IsKev,\n        ];\n        for column in columns {\n            statement.column(column).add_group_by([Expr::col(column)]);\n        }\n        statement.expr_as(Expr::col(IssueColumn::Id).count(), Alias::new(\"c\"));\n        Ok(orm::fetch_all(tx, &statement).await?)\n    }\n\n    /// `countOpenSast", "            IssueColumn::Type,\n        ];\n        for column in columns {\n            statement.column(column).add_group_by([Expr::col(column)]);\n        }\n        statement.expr_as(Expr::col(IssueColumn::Id).count(), Alias::new(\"c\"));\n        Ok(orm::fetch_all(tx, &statement).await?)\n    }\n\n    /// `countOpenSast", E),
    ("another issue's reopening", L, ".equals(IssueColumn::Id.as_column_ref())", ".equals((TriageEvents, TriageEventColumn::Id))", E),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
