package com.asmolabs.vectispire.core.issues.persistence.queries;

/**
 * The rows the aggregations of {@code IssueAggregateQueries} return.
 *
 * <p>They were nested in the fragment itself. They are what other modules read — the posture
 * scoreboards, the debt report, the OWASP grid — through {@code IssueCatalog}, while the fragment
 * names the entity and stays in the module's {@code persistence}; the records alone are part of the
 * {@code queries} named interface (decision 0029).
 */
public final class IssueAggregates {

    private IssueAggregates() {}

    /** How many issues carry each {@code (severity, type)} pair. At most one row per pair. */
    public record SeverityTypeCount(String severity, String type, long count) {}

    /**
     * How many issues carry each {@code (type, severity, state, triage status)} — the resolved ones too,
     * which a project's export counts rather than lists (decision 0035 §1). At most one row per tuple;
     * {@code triageStatus} null for issues nobody triaged.
     */
    public record StateCount(String type, String severity, String state, String triageStatus, long count) {}

    /**
     * One vulnerable package, and everything the leverage score is computed from.
     *
     * @param distinctIdentifiers CVEs counted once however many targets carry them — the fix is
     *     one upgrade, not one per repository
     */
    public record PackageWeight(
            String packageName, String version, long distinctIdentifiers, long criticalCount, long highCount) {}

    /**
     * One {@code (package, CVE, target)} row, read only for the packages that made the cut.
     *
     * @param fixVersions the versions that fix this finding, as the scanner reported them — a
     *     comma-separated enumeration, often empty. It is the only source of the version to
     *     advise: it is brought back here, with the rows already read for the packages that made
     *     the cut, rather than by one more query.
     */
    public record PackageDetail(
            String packageName, String identifier, Long repoId, Long containerId, String fixVersions) {}

    /**
     * Open issues of one target at one severity. {@code repoId} and {@code containerId} are
     * mutually exclusive, exactly as on the row.
     */
    public record TargetSeverityCount(Long repoId, Long containerId, String severity, long count) {}

    /**
     * The terms a scorecard is graded on, one target at a time: how many of its issues share a
     * {@code (severity, KEV, state)} triple.
     *
     * <p><b>The state is a column of the row, not a clause of the query.</b> The scorecard has
     * always kept an issue whose state is neither {@code closed} nor {@code resolved}, ignoring
     * case, and a null state with it — a test written in Java. Grouping on the state and leaving
     * that test to the reader keeps it one test, read by the card and by the maturity ranking
     * alike, instead of a Java one and a SQL one that could come to disagree about a row.
     *
     * @param severity as stored: the reader upper-cases it, as the scorecard always did
     */
    public record TargetGradingCount(
            Long repoId, Long containerId, String severity, boolean kev, String state, long count) {}

    /**
     * What one target has closed, and how long those took on average.
     *
     * <p><b>An aggregate, since {@code V24}.</b> This was a row per closed issue, because the
     * average needed the difference between two timestamps and the three engines spell that
     * three ways. {@code t_issue.resolution_seconds} is written when the issue is resolved, so
     * the average is now {@code avg} of a number — the same statement everywhere, computed where
     * the rows are.
     *
     * @param averageSeconds null when the target has closed nothing that lived measurably. Not
     *     zero: {@code avg} skips nulls, and so must whoever reads this
     */
    public record TargetResolutions(Long repoId, Long containerId, long resolved, Double averageSeconds) {}

    /**
     * One resolved issue's severity and how long it took, for the issues closed since an instant.
     *
     * <p><b>Rows, because percentiles need the values.</b> A median and a ninetieth percentile
     * cannot be computed from a sum and a count, and no portable SQL across these three engines
     * produces them. The window is what keeps this bounded: it reads the resolutions of a period,
     * not of all history.
     */
    public record ResolvedDuration(String severity, long seconds) {}

    /**
     * One severity's open backlog: how many, how many past their deadline, and the oldest.
     *
     * <p>Aggregated by the database — {@code count}, {@code min} — because none of the three
     * numbers needs the rows themselves, and the open backlog is the half that grows with the
     * estate.
     *
     * @param oldestFirstSeen when the oldest still-open issue of this severity was first seen
     */
    public record OpenBacklog(String severity, long total, java.time.Instant oldestFirstSeen) {}

    /**
     * How many findings each type holds, and how many of them name a package.
     *
     * <p><b>Package naming is measured with the ranking's exact predicate</b> — non-null and
     * non-blank after {@code trim} — and not "roughly the same one". That is what makes the
     * admission checkable: the coverage the screen announces is the complement of what
     * {@code IssueAggregateQueries.weighPackages} accepts, and two neighbouring predicates would end up disagreeing by
     * a finding, which is worse than saying nothing.
     *
     * @param packageNamed how many findings of the type carry a usable package name
     * @param unnamed how many do not
     */
    public record TypePackaging(String type, long packageNamed, long unnamed) {}

    /**
     * How many code-analysis findings are open in each declared OWASP category.
     *
     * <p>Restricted to the {@code sast} type, that is to rules of the "security" category. A
     * quality rule can carry the same metadata; counting it would place in a security grid a
     * finding this repository elsewhere says never fails a gate.
     *
     * @param category never null: rows without a category are dropped by the query, and an absent
     *     category is not an empty one
     */
    public record OwaspCategoryCount(String category, long count) {}

    /**
     * One week's flow of the issues of one {@code (type, owasp_category)} pair, counted from their
     * dates — the weekly OWASP view's reconstruction, and its opened and resolved bars on every week.
     *
     * <p>The week is {@code [weekStart, weekStart + 7 days)}, half open, so an instant belongs to one
     * week only: an issue first seen at the next Monday's midnight was opened in the next week, and one
     * resolved at that instant was still open at this week's end.
     *
     * @param owaspCategory the issue's column as stored, null included — the placement is the reader's
     *     ({@code OwaspCoverage.placementOf}), never restated in the query
     * @param openAtEnd first seen before the week's end, not resolved before it, and not inside an
     *     earlier resolution a reopening recorded in the triage history (V68). <b>A reopening older than
     *     V68 recorded nothing</b>: the row stores one {@code resolved_at}, so the weeks between such an
     *     earlier resolution and its reopening count the issue open
     * @param opened first seen within the week
     * @param resolved resolved within the week — its latest resolution, or an earlier one a reopening
     *     recorded; an issue counts once
     * @param reopened reopened within the week, by a reopening the triage history recorded; an issue counts
     *     once. <b>Zero is not "none" for a week before V68</b>, whose reopenings wrote nothing: the reader
     *     decides which weeks the history covers
     */
    public record WeeklyFlow(
            java.time.Instant weekStart,
            String type,
            String owaspCategory,
            long openAtEnd,
            long opened,
            long resolved,
            long reopened) {}
}
