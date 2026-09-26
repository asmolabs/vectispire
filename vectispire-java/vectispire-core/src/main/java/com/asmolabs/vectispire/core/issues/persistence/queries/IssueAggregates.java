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
}
