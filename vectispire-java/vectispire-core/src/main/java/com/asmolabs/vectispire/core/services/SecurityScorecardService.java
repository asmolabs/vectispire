package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import org.springframework.data.jpa.domain.Specification;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.util.ArrayList;
import java.util.List;
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

    public SecurityScorecardService(
            Issues issuesRepo,
            GitRepositories gitRepo,
            Containers containerRepo,
            Scans scansRepo,
            LicenseGovernanceService licenseService) {
        this.issuesRepo = issuesRepo;
        this.gitRepo = gitRepo;
        this.containerRepo = containerRepo;
        this.scansRepo = scansRepo;
        this.licenseService = licenseService;
    }

    public Optional<SecurityScorecard> getRepositoryScorecard(Long repoId) {
        return gitRepo.findById(repoId).map(repo -> {
            // The route is guarded by the controller; this narrows the *read*, which used to be
            // the whole table filtered down to one repository afterwards.
            List<IssueEntity> openIssues = issuesRepo
                    .findAll(openWithin(Visibility.only(List.of(new ScanTarget.Repository(repoId)))))
                    .stream()
                    .filter(i -> !"closed".equalsIgnoreCase(i.getState()) && !"resolved".equalsIgnoreCase(i.getState()))
                    .toList();

            // **The filter was passed to the stream and not to the query.** The unfiltered call
            // parsed every SBOM in the deployment to keep one repository's rows.
            List<LicenseEntry> licenses = licenseService.getInventory(repoId, null).stream()
                    .filter(l -> repoId.equals(l.targetId()) && "repository".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.findAll().stream()
                    .anyMatch(s -> repoId.equals(s.getRepoId()) && "completed".equalsIgnoreCase(s.getStatus()));

            return computeScorecard(repoId, "repository", repo.getName(), openIssues, licenses, hasAttestation);
        });
    }

    public Optional<SecurityScorecard> getContainerScorecard(Long containerId) {
        return containerRepo.findById(containerId).map(container -> {
            // The repository form was narrowed and this one was not, in the same change — which
            // is what a sweep is for and what reading the diff was not enough to catch.
            List<IssueEntity> openIssues = issuesRepo
                    .findAll(openWithin(Visibility.only(List.of(new ScanTarget.Container(containerId)))))
                    .stream()
                    .filter(i -> !"closed".equalsIgnoreCase(i.getState()) && !"resolved".equalsIgnoreCase(i.getState()))
                    .toList();

            List<LicenseEntry> licenses = licenseService.getInventory(null, containerId).stream()
                    .filter(l -> containerId.equals(l.targetId()) && "container".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.findAll().stream()
                    .anyMatch(s -> containerId.equals(s.getContainerId()) && "completed".equalsIgnoreCase(s.getStatus()));

            return computeScorecard(containerId, "container", container.getImageName() + ":" + container.getTag(), openIssues, licenses, hasAttestation);
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
        List<IssueEntity> openIssues = issuesRepo.findAll(openWithin(allowed)).stream()
                .filter(i -> !"closed".equalsIgnoreCase(i.getState()) && !"resolved".equalsIgnoreCase(i.getState()))
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
        boolean hasAttestation = scansRepo.findAll().stream()
                .filter(s -> allowed.permits(targetOf(s)))
                .anyMatch(s -> "completed".equalsIgnoreCase(s.getStatus()));

        return computeScorecard(null, "global", "Organization Portfolio", openIssues, licenses, hasAttestation);
    }

    private SecurityScorecard computeScorecard(
            Long targetId,
            String targetKind,
            String targetName,
            List<IssueEntity> issues,
            List<LicenseEntry> licenses,
            boolean hasAttestation) {

        int score = 100;
        List<String> recommendations = new ArrayList<>();

        long criticalCount = 0;
        long highCount = 0;
        long kevCount = 0;
        long overdueCount = 0;

        for (IssueEntity issue : issues) {
            String sev = issue.getSeverity() != null ? issue.getSeverity().toUpperCase() : "UNKNOWN";
            boolean isKev = issue.isKev();
            boolean isReachable = ReachabilityStatus.REACHABLE.name().equalsIgnoreCase(issue.getReachability());

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

        if (hasAttestation) {
            score += 5;
        } else {
            recommendations.add("Generate in-toto provenance attestations for target scans.");
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

    /** Every issue the caller may see; the open test stays in Java because it always was there. */
    private static Specification<IssueEntity> openWithin(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, allowed)
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

    /** A scan attached to neither target is unclassifiable, and a restriction does not pass it. */
    private static ScanTarget targetOf(ScanEntity scan) {
        if (scan.getRepoId() != null) {
            return new ScanTarget.Repository(scan.getRepoId());
        }
        return scan.getContainerId() == null ? null : new ScanTarget.Container(scan.getContainerId());
    }

}
