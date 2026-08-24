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
import com.asmolabs.vectispire.core.repositories.Issues;
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
            List<IssueEntity> openIssues = issuesRepo.findAll().stream()
                    .filter(i -> repoId.equals(i.getRepoId()) && !"closed".equalsIgnoreCase(i.getState()) && !"resolved".equalsIgnoreCase(i.getState()))
                    .toList();

            List<LicenseEntry> licenses = licenseService.getInventory().stream()
                    .filter(l -> repoId.equals(l.targetId()) && "repository".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.findAll().stream()
                    .anyMatch(s -> repoId.equals(s.getRepoId()) && "completed".equalsIgnoreCase(s.getStatus()));

            return computeScorecard(repoId, "repository", repo.getName(), openIssues, licenses, hasAttestation);
        });
    }

    public Optional<SecurityScorecard> getContainerScorecard(Long containerId) {
        return containerRepo.findById(containerId).map(container -> {
            List<IssueEntity> openIssues = issuesRepo.findAll().stream()
                    .filter(i -> containerId.equals(i.getContainerId()) && !"closed".equalsIgnoreCase(i.getState()) && !"resolved".equalsIgnoreCase(i.getState()))
                    .toList();

            List<LicenseEntry> licenses = licenseService.getInventory().stream()
                    .filter(l -> containerId.equals(l.targetId()) && "container".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.findAll().stream()
                    .anyMatch(s -> containerId.equals(s.getContainerId()) && "completed".equalsIgnoreCase(s.getStatus()));

            return computeScorecard(containerId, "container", container.getImageName() + ":" + container.getTag(), openIssues, licenses, hasAttestation);
        });
    }

    public SecurityScorecard getGlobalScorecard() {
        List<IssueEntity> openIssues = issuesRepo.findAll().stream()
                .filter(i -> !"closed".equalsIgnoreCase(i.getState()) && !"resolved".equalsIgnoreCase(i.getState()))
                .toList();

        List<LicenseEntry> licenses = licenseService.getInventory();
        boolean hasAttestation = scansRepo.findAll().stream()
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
}
