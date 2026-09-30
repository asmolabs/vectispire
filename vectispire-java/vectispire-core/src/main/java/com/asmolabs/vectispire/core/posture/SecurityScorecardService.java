package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.inventory.LicenseGovernanceService;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.SlaService;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueRows;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;

/**
 * Computes security posture scorecards and letter grades (A+ to F) for repositories, containers, and global portfolios.
 */
@Service
public class SecurityScorecardService {

    private final IssueCatalog issuesRepo;
    private final TargetCatalog targets;
    private final ScanCatalog scansRepo;
    private final LicenseGovernanceService licenseService;
    private final SlaService sla;

    public SecurityScorecardService(
            IssueCatalog issuesRepo,
            TargetCatalog targets,
            ScanCatalog scansRepo,
            LicenseGovernanceService licenseService,
            SlaService sla) {
        this.issuesRepo = issuesRepo;
        this.targets = targets;
        this.scansRepo = scansRepo;
        this.licenseService = licenseService;
        this.sla = sla;
    }

    /**
     * A repository's scorecard, for a caller who may see it.
     *
     * <p><b>Refused here, before the row is read.</b> A scorecard is a target's posture in a number,
     * and the number is the interesting part to somebody who was not given the target: it says how
     * exposed a neighbouring team is. The route used to refuse and then call this with the bare id,
     * which answered whoever called it next. A hidden repository is refused as a hidden target — "Target
     * not found." — before any lookup could tell it from an absent one; an absent one the caller
     * could see is empty.
     */
    public Optional<SecurityScorecard> getRepositoryScorecard(long repoId, Visibility allowed) {
        VisibleTarget<ScanTarget.Repository> checked = RowVisibility.requireVisible(new ScanTarget.Repository(repoId), allowed);
        return targets.repository(repoId).map(repo -> {
            // This narrows the *read*, which used to be the whole table filtered down to one
            // repository afterwards.
            List<IssueRows.Posture> openIssues = issuesRepo
                    .rows(openWithin(Visibility.only(List.of(new ScanTarget.Repository(repoId)))), IssueRows.Posture.class)
                    .stream()
                    .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                    .toList();

            // **The filter was passed to the stream and not to the query.** The unfiltered call
            // parsed every SBOM in the deployment to keep one repository's rows.
            List<LicenseEntry> licenses = licenseService.getInventory(checked).stream()
                    .filter(l -> Long.valueOf(repoId).equals(l.targetId()) && "repository".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.hasScanWithStatus(new ScanTarget.Repository(repoId), "completed");
            long overdue = sla.countOverdue(Visibility.only(List.of(new ScanTarget.Repository(repoId))));

            return computeScorecard(repoId, "repository", repo.name(), openIssues, licenses, hasAttestation, overdue,
                    Coverage.ofOne(hasAttestation));
        });
    }

    /** An image's scorecard, for a caller who may see it — refused as {@link #getRepositoryScorecard} is. */
    public Optional<SecurityScorecard> getContainerScorecard(long containerId, Visibility allowed) {
        VisibleTarget<ScanTarget.Container> checked = RowVisibility.requireVisible(new ScanTarget.Container(containerId), allowed);
        return targets.container(containerId).map(container -> {
            // The repository form was narrowed and this one was not, in the same change — which
            // is what a sweep is for and what reading the diff was not enough to catch.
            List<IssueRows.Posture> openIssues = issuesRepo
                    .rows(openWithin(Visibility.only(List.of(new ScanTarget.Container(containerId)))), IssueRows.Posture.class)
                    .stream()
                    .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                    .toList();

            List<LicenseEntry> licenses = licenseService.getInventory(checked).stream()
                    .filter(l -> Long.valueOf(containerId).equals(l.targetId()) && "container".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.hasScanWithStatus(new ScanTarget.Container(containerId), "completed");
            long overdue = sla.countOverdue(Visibility.only(List.of(new ScanTarget.Container(containerId))));

            return computeScorecard(containerId, "container", container.imageName() + ":" + container.tag(), openIssues,
                    licenses, hasAttestation, overdue, Coverage.ofOne(hasAttestation));
        });
    }

    /**
     * The portfolio's posture, <b>within the caller's allowance</b>.
     *
     * <p>"Organization Portfolio" is a fair name for an administrator and a false one for a
     * reader assigned two repositories: the score they were shown was the whole estate's, which
     * is both a leak and a number that means nothing about anything they can act on.
     */
    public SecurityScorecard getGlobalScorecard(Visibility allowed) {
        // **Narrowed after the read, not in the query, and the difference is worth stating.** The
        // issues are filtered in SQL; the licence inventory narrows to an allowance in
        // memory, so the portfolio still parses every SBOM it can reach. Recorded rather than
        // hidden, because a filter applied late is exactly the shape this service has been
        // corrected for twice. The narrowing is the licence service's own since it stopped
        // publishing the unfiltered estate: it used to be done here, on a list anyone could ask for.
        List<ScanTarget> visible = new ArrayList<>();
        targets.repositories().forEach(repository -> visible.add(new ScanTarget.Repository(repository.id())));
        targets.containers().forEach(container -> visible.add(new ScanTarget.Container(container.id())));
        visible.removeIf(target -> !allowed.permits(target));
        return portfolio(allowed, visible, licenseService.getInventory(allowed, null, null), null, "global",
                "Organization Portfolio");
    }

    /**
     * A project's or a solution's scorecard: the portfolio's computation, over the scope's visible
     * targets and nothing else — the same terms, the same weights, no formula of its own. A partial
     * scope is scored on what the caller sees, as the portfolio is for a restricted reader; the scope
     * says {@code partial} beside it.
     *
     * <p><b>The licences are read target by target</b>, each through the per-target inventory the
     * target's own scorecard reads, rather than through the portfolio's, which parses every SBOM of
     * the estate to keep a project's. The two agree: every inventory entry is keyed by its target, so
     * the union of the targets' lists is the portfolio's list narrowed to them.
     *
     * @return {@code targetKind} {@code project} or {@code solution}, {@code targetId} the scope's
     */
    public SecurityScorecard getScopeScorecard(VisibleScope scope) {
        Visibility allowed = scope.visibility();
        List<LicenseEntry> licenses = scope.targets().stream()
                .flatMap(target -> licenseService.getInventory(RowVisibility.requireVisible(target, allowed)).stream())
                .toList();
        return portfolio(allowed, scope.targets(), licenses, scope.id(), scope.kind().wireName(), scope.name());
    }

    private SecurityScorecard portfolio(
            Visibility allowed, List<ScanTarget> visible, List<LicenseEntry> licenses, Long id, String kind, String name) {
        List<IssueRows.Posture> openIssues = issuesRepo
                .rows(openWithin(allowed), IssueRows.Posture.class)
                .stream()
                .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                .toList();

        // The targets in scope holding a completed scan — which is also what the attestation flag
        // asked, over the same allowance, so the two cannot disagree.
        Set<ScanTarget> inScope = new HashSet<>(visible);
        Set<ScanTarget> observed = new HashSet<>();
        scansRepo.targetsWithStatus("completed").forEach(row -> {
            if (row.target() != null && inScope.contains(row.target())) {
                observed.add(row.target());
            }
        });

        long overdue = sla.countOverdue(allowed);

        return computeScorecard(id, kind, name, openIssues, licenses, !observed.isEmpty(), overdue,
                new Coverage(inScope.size(), observed.size()));
    }

    /**
     * How much of the scope the backlog being graded was read from.
     *
     * <p><b>Observed means holding a completed scan</b>, the scan that produced the backlog graded
     * here — not the compliance summary's "the latest scan succeeded". A scan in flight or a later one
     * that failed does not erase the backlog the last completed one left, and a published badge must
     * not flip to "no data" every time a scan starts. A SARIF import alone does not make a target
     * observed, as it does not for compliance: it speaks for one tool, not for the target.
     *
     * <p><b>Not the freshness window</b> compliance also caps by: that window is a deployment setting,
     * and the grade is what a public badge carries — the reason the SLA deadlines are advised on here
     * and not scored. Two installations holding the same estate grade it the same.
     */
    private record Coverage(int total, int observed) {
        static Coverage ofOne(boolean observed) {
            return new Coverage(1, observed ? 1 : 0);
        }
    }

    private SecurityScorecard computeScorecard(
            Long targetId,
            String targetKind,
            String targetName,
            List<IssueRows.Posture> issues,
            List<LicenseEntry> licenses,
            boolean hasAttestation,
            long overdueCount,
            Coverage coverage) {

        int score = 100;
        List<String> recommendations = new ArrayList<>();

        long criticalCount = 0;
        long highCount = 0;
        long kevCount = 0;

        for (IssueRows.Posture issue : issues) {
            String sev = issue.severity() != null ? issue.severity().toUpperCase(Locale.ROOT) : "UNKNOWN";
            boolean isKev = Boolean.TRUE.equals(issue.isKev());

            if (isKev) {
                kevCount++;
                score -= 25;
            }
            if ("CRITICAL".equals(sev)) {
                criticalCount++;
                // **One weight for every critical, since nothing measures reachability.** A
                // reachable critical cost 15 and any other 8, read off a column no analysis
                // writes: every issue reads UNKNOWN, so the 15 was never charged and the term only
                // promised a distinction the grade could not make. Were it charged — a row edited
                // by hand, an import that one day sets the column — it would move a public badge
                // on a claim nobody established.
                score -= 8;
            } else if ("HIGH".equals(sev)) {
                highCount++;
                score -= 4;
            }
        }

        long licenseViolations = licenses.stream().filter(l -> !l.compliant()).count();
        if (licenseViolations > 0) {
            score -= (int) (licenseViolations * 5);
            recommendations.add("Remediate " + licenseViolations + " disallowed open source license violation(s).");
        }

        // **What "attestation" means here, and what the advice used to get wrong.** The in-toto
        // statement is issued on demand, from any completed scan, by `AttestationService`; nothing
        // is generated or stored beforehand. So the flag is true exactly when a scan has
        // completed, and the only way to earn it is to complete one. The recommendation told
        // people to "generate in-toto provenance attestations" — a step that does not exist in
        // this product, sending the reader to look for a button nobody built.
        if (hasAttestation) {
            score += 5;
        } else {
            recommendations.add("Complete a scan: no in-toto attestation can be issued for a target never scanned.");
        }

        if (kevCount > 0) {
            recommendations.add("Urgent: Eliminate " + kevCount + " actively exploited CISA KEV vulnerability(ies).");
        }
        if (criticalCount > 0) {
            recommendations.add("Prioritize resolution of " + criticalCount + " critical severity issue(s).");
        }
        if (highCount > 0) {
            recommendations.add("Schedule remediation of " + highCount + " high severity issue(s).");
        }
        // Counted and advised on, not scored. The grade is what a public badge carries, and a
        // deadline is a deployment's own setting: two installs holding identical backlogs would
        // display different grades, and changing a window would move every badge overnight.
        // The figure is the one `SlaService` gives the dashboard and the overdue list, so the
        // three agree; it used to be declared here, never assigned, and reported as zero.
        if (overdueCount > 0) {
            recommendations.add("Resolve " + overdueCount + " issue(s) past their remediation deadline.");
        }
        // **The coverage cap, the compliance controls' own (`ComplianceEngine.withCoverage`).** The
        // score is a hundred less what was found, so a target nobody scanned weighs as a clean one:
        // ten targets with one scanned clean read A+ for nine that nobody looked at. Capped at the
        // observed share, in the compliance summary's rounding, so the card and the controls beside
        // it on a project's page tell the same story about the same coverage.
        int never = coverage.total() - coverage.observed();
        if (coverage.observed() > 0 && never > 0) {
            recommendations.add(0, "Scan the " + never + " target(s) never scanned: the score covers "
                    + coverage.observed() + "/" + coverage.total() + " target(s), and is capped at that share.");
        }
        if (recommendations.isEmpty()) {
            recommendations.add("Maintain current posture with continuous automated scanning.");
        }

        score = Math.max(0, Math.min(100, score));
        if (never > 0) {
            score = Math.min(score, Math.round(((float) coverage.observed() / coverage.total()) * 100));
        }
        // **Nothing observed is no grade at all** (decision 0007), not the hundred the formula gives
        // an empty backlog: a scope whose only target was never scanned read 100/100, A+, on its card
        // and on the badge. The counts stay, being true of what was read.
        boolean noData = coverage.observed() == 0;
        SecurityGrade grade = noData ? SecurityGrade.NO_DATA : SecurityGrade.fromScore(score);

        return new SecurityScorecard(
                targetId,
                targetKind,
                targetName,
                noData ? null : score,
                grade,
                coverage.total(),
                coverage.observed(),
                criticalCount,
                highCount,
                kevCount,
                overdueCount,
                licenseViolations,
                hasAttestation,
                recommendations);
    }

    /**
     * Every issue the caller may see that still weighs on the grade; the open test stays in Java
     * because it always was there.
     *
     * <p><b>A settled triage is left out</b> — {@code not_affected} or {@code fixed}, the two
     * decisions that already stop an issue failing the gate. Counting them kept a target's grade
     * down after its team had argued each finding away, so the one screen meant to reward triage
     * punished it, and disagreed with the gate about the same rows. {@code pending_approval}
     * still counts: a dismissal nobody has approved is a request, not a decision. Filtered in the
     * clause, as {@code SlaService.overdue} does, so the grade and the overdue figure on the same
     * card leave out the same issues.
     */
    private static IssueFilters openWithin(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, true, Map.of(), allowed);
    }


    /**
     * A scan attached to neither target is unclassifiable, and a restriction does not pass it.
     * Read from a {@code [.., repoId, containerId]} projection row.
     */
    private static ScanTarget targetOf(Object repoId, Object containerId) {
        if (repoId != null) {
            return new ScanTarget.Repository(((Number) repoId).longValue());
        }
        return containerId == null ? null : new ScanTarget.Container(((Number) containerId).longValue());
    }

}
