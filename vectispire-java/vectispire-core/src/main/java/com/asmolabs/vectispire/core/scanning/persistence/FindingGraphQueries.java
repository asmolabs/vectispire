package com.asmolabs.vectispire.core.scanning.persistence;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.scanning.persistence.queries.PackageImpact;
import java.util.List;

/**
 * The findings a dependency graph is built from, joined to the scan that produced them.
 *
 * <p><b>Why this exists.</b> The blast radius read <em>every</em> finding in the deployment, then
 * looked up each scan one at a time, then matched the caller's query in Java — a whole-table read,
 * an N+1 on top of it, and a filter applied after the data had already crossed the wire.
 * `t_finding` is the raw-findings table the dimensioning view estimates at half a million rows.
 *
 * <p><b>And it answered without applying {@link Visibility} at all.</b> That is the more serious
 * half: a blast-radius answer names repositories, packages and CVE identifiers, so a reader
 * assigned one repository received an inventory of everybody else's. {@code Visibility} says of
 * itself that authorization spread across controllers is one chance per controller to forget one,
 * and the forgotten one is the hole. This was it.
 *
 * <p>A repository fragment rather than {@code @Query} methods, for the reason {@code issues}'
 * {@code IssueAggregateQueries} gives — named, not linked, because {@code scanning} does not depend
 * on {@code issues}: the caller's allowance is a set, the query filter is one of three
 * shapes, and the combinations multiply into methods nobody can keep consistent. Built once, here.
 */
public interface FindingGraphQueries {

    /** One finding and the scan that produced it — the pair the graph is assembled from. */
    record GraphRow(FindingEntity finding, ScanEntity scan) {}

    /**
     * Findings that name a package, from scans of targets the caller may see.
     *
     * @param query what the caller typed; blank matches everything
     * @param cveQuery whether {@code query} is a CVE identifier, which is matched exactly rather
     *     than as a substring — {@code CVE-2021-4} must not drag in {@code CVE-2021-44228}
     * @param excludeSecrets a secret has no package to upgrade, so it has no place in a
     *     dependency graph. The top-impact list never filtered them and does not need to: it
     *     already requires a package name, which a secret finding does not carry
     */
    List<GraphRow> forGraph(String query, boolean cveQuery, boolean excludeSecrets, Visibility allowed);

    /**
     * One row per package, already aggregated — the top-impact list, without the table.
     *
     * <p><b>Why this is not {@code forGraph("")}.</b> It was. The landing list of the blast-radius
     * screen asked for every finding in the deployment that names a package, hydrated a
     * {@link FindingEntity} and a {@link ScanEntity} for each one, grouped them in Java, scored the
     * groups and kept twelve. On the half-million rows the dimensioning view estimates, the screen
     * paid for the whole estate to display a dozen lines, and it paid on every open.
     *
     * <p>The aggregation is the database's work: it is five counts and a maximum over a group, and
     * the answer is one row per distinct package name — a few thousand at worst, small tuples
     * rather than managed entities. <b>The scoring stays in Java</b> on those rows, because
     * {@code BlastRadiusReport.calculateScore} is capped arithmetic that reads as arithmetic and
     * would become three engine-specific {@code least()} expressions here to save nothing: the
     * expensive part was never the scoring, it was carrying the rows to it.
     *
     * <p>Secrets are not excluded, and the omission is deliberate: this list already requires a
     * package name, which a secret finding does not carry.
     */
    List<PackageImpact> packageImpacts(Visibility allowed);
}
