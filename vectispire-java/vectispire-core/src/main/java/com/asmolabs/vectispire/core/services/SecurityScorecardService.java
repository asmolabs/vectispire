package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.IssueRows;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.inventory.LicenseGovernanceService;
import java.util.Locale;
import org.springframework.data.jpa.domain.Specification;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Computes security posture scorecards and letter grades (A+ to F) for repositories, containers, and global portfolios.
 */
@Service
public class SecurityScorecardService {

    private final Issues issuesRepo;
    private final GitRepositories gitRepo;
    private final Containers containerRepo;
    private final Scans scansRepo;
    private final LicenseGovernanceService licenseService;
    private final SlaService sla;

    public SecurityScorecardService(
            Issues issuesRepo,
            GitRepositories gitRepo,
            Containers containerRepo,
            Scans scansRepo,
            LicenseGovernanceService licenseService,
            SlaService sla) {
        this.issuesRepo = issuesRepo;
        this.gitRepo = gitRepo;
        this.containerRepo = containerRepo;
        this.scansRepo = scansRepo;
        this.licenseService = licenseService;
        this.sla = sla;
    }

    public Optional<SecurityScorecard> getRepositoryScorecard(Long repoId) {
        return gitRepo.findById(repoId).map(repo -> {
            // The route is guarded by the controller; this narrows the *read*, which used to be
            // the whole table filtered down to one repository afterwards.
            List<IssueRows.Posture> openIssues = issuesRepo
                    .findBy(openWithin(Visibility.only(List.of(new ScanTarget.Repository(repoId)))),
                            query -> query.as(IssueRows.Posture.class).all())
                    .stream()
                    .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                    .toList();

            // **The filter was passed to the stream and not to the query.** The unfiltered call
            // parsed every SBOM in the deployment to keep one repository's rows.
            List<LicenseEntry> licenses = licenseService.getInventory(repoId, null).stream()
                    .filter(l -> repoId.equals(l.targetId()) && "repository".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.existsByRepoIdAndStatusIgnoreCase(repoId, "completed");
            long overdue = sla.countOverdue(Visibility.only(List.of(new ScanTarget.Repository(repoId))));

            return computeScorecard(repoId, "repository", repo.getName(), openIssues, licenses, hasAttestation, overdue);
        });
    }

    public Optional<SecurityScorecard> getContainerScorecard(Long containerId) {
        return containerRepo.findById(containerId).map(container -> {
            // The repository form was narrowed and this one was not, in the same change — which
            // is what a sweep is for and what reading the diff was not enough to catch.
            List<IssueRows.Posture> openIssues = issuesRepo
                    .findBy(openWithin(Visibility.only(List.of(new ScanTarget.Container(containerId)))),
                            query -> query.as(IssueRows.Posture.class).all())
                    .stream()
                    .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                    .toList();

            List<LicenseEntry> licenses = licenseService.getInventory(null, containerId).stream()
                    .filter(l -> containerId.equals(l.targetId()) && "container".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.existsByContainerIdAndStatusIgnoreCase(containerId, "completed");
            long overdue = sla.countOverdue(Visibility.only(List.of(new ScanTarget.Container(containerId))));

            return computeScorecard(containerId, "container", container.getImageName() + ":" + container.getTag(), openIssues, licenses, hasAttestation, overdue);
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
                .findBy(openWithin(allowed), query -> query.as(IssueRows.Posture.class).all())
                .stream()
                .filter(i -> !"closed".equalsIgnoreCase(i.state()) && !"resolved".equalsIgnoreCase(i.state()))
                .toList();

        // **Narrowed here and not in the query, and the difference is worth stating.** The
        // issues above are filtered in SQL; the licence inventory has no allowance parameter —
        // it takes one target or none — so a restricted reader's entries are dropped after the
        // fact. That closes the leak and leaves the read: the portfolio still parses every SBOM
        // it can reach. Recorded rather than hidden, because a filter applied late is exactly
        // the shape this service has been corrected for twice.
        List<LicenseEntry> licenses = licenseService.getInventory().stream()
                .filter(entry -> permits(allowed, entry))
                .toList();
        // **Still a read of every target, no longer of every scan.** Those above asked "has this
        // target completed a scan" and are one indexed existence check. This asks "has *any target
        // the caller may see* completed one", and the allowance is a set of targets rather than a
        // column, so it is applied in memory — but over the distinct targets with a completed
        // scan, as two columns. It used to load every scan entity, SBOM and CVE payloads included,
        // to read one boolean.
        boolean hasAttestation = scansRepo.targetsWithStatus("completed").stream()
                .anyMatch(row -> allowed.permits(targetOf(row[0], row[1])));

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
    private static Specification<IssueEntity> openWithin(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, true, Map.of(), allowed)
                .toSpecification();
    }


    /** Whether a licence entry's target is one the caller may see. */
    private static boolean permits(Visibility allowed, LicenseEntry entry) {
        if (entry.targetId() == null) {
            // "general" — attached to no target. Visible to an unrestricted caller and to nobody
            // else, which is what `Visibility.permits(null)` already answers.
            return allowed.permits(null);
        }
        return allowed.permits("container".equalsIgnoreCase(entry.targetKind())
                ? new ScanTarget.Container(entry.targetId())
                : new ScanTarget.Repository(entry.targetId()));
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
