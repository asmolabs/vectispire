package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
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

            return computeScorecard(repoId, "repository", repo.name(), openIssues, licenses, hasAttestation, overdue);
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

            return computeScorecard(containerId, "container", container.imageName() + ":" + container.tag(), openIssues, licenses, hasAttestation, overdue);
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
        List<IssueRows.Posture> openIssues = issuesRepo
                .rows(openWithin(allowed), IssueRows.Posture.class)
                .stream()
                .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                .toList();

        // **Narrowed after the read, not in the query, and the difference is worth stating.** The
        // issues above are filtered in SQL; the licence inventory narrows to an allowance in
        // memory, so the portfolio still parses every SBOM it can reach. Recorded rather than
        // hidden, because a filter applied late is exactly the shape this service has been
        // corrected for twice. The narrowing is the licence service's own since it stopped
        // publishing the unfiltered estate: it used to be done here, on a list anyone could ask for.
        List<LicenseEntry> licenses = licenseService.getInventory(allowed, null, null);
        // **Still a read of every target, no longer of every scan.** Those above asked "has this
        // target completed a scan" and are one indexed existence check. This asks "has *any target
        // the caller may see* completed one", and the allowance is a set of targets rather than a
        // column, so it is applied in memory — but over the distinct targets with a completed
        // scan, as two columns. It used to load every scan entity, SBOM and CVE payloads included,
        // to read one boolean.
        boolean hasAttestation = scansRepo.targetsWithStatus("completed").stream()
                .anyMatch(row -> allowed.permits(row.target()));

        long overdue = sla.countOverdue(allowed);

        return computeScorecard(null, "global", "Organization Portfolio", openIssues, licenses, hasAttestation, overdue);
    }

    private SecurityScorecard computeScorecard(
            Long targetId,
            String targetKind,
            String targetName,
            List<IssueRows.Posture> issues,
            List<LicenseEntry> licenses,
            boolean hasAttestation,
            long overdueCount) {

        int score = 100;
        List<String> recommendations = new ArrayList<>();

        long criticalCount = 0;
        long highCount = 0;
        long kevCount = 0;

        for (IssueRows.Posture issue : issues) {
            String sev = issue.severity() != null ? issue.severity().toUpperCase(Locale.ROOT) : "UNKNOWN";
            boolean isKev = Boolean.TRUE.equals(issue.isKev());
            boolean isReachable = ReachabilityStatus.REACHABLE.name().equalsIgnoreCase(issue.reachability());

            if (isKev) {
                kevCount++;
                score -= 25;
            }
            if ("CRITICAL".equals(sev)) {
                criticalCount++;
                score -= isReachable ? 15 : 8;
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
        if (recommendations.isEmpty()) {
            recommendations.add("Maintain current posture with continuous automated scanning.");
        }

        score = Math.max(0, Math.min(100, score));
        SecurityGrade grade = SecurityGrade.fromScore(score);

        return new SecurityScorecard(
                targetId,
                targetKind,
                targetName,
                score,
                grade,
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
