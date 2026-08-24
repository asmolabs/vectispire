package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.remediation.HighImpactFix;
import com.asmolabs.vectispire.common.domain.remediation.SecurityDebtReport;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Quantifies engineering effort required to resolve security debt and discovers high-leverage fixes.
 */
@Service
public class SecurityDebtService {

    private final Issues issues;
    private final GitRepositories repositories;
    private final Containers containers;

    public SecurityDebtService(
            Issues issues,
            GitRepositories repositories,
            Containers containers) {
        this.issues = issues;
        this.repositories = repositories;
        this.containers = containers;
    }

    @Transactional(readOnly = true)
    public SecurityDebtReport calculateDebt(Long repoId, Long containerId, Visibility allowed) {
        // Find all open, unresolved issues
        List<IssueEntity> openIssues = issues.findAll(new IssueFilters(
                IssueState.OPEN.wireName(), null, null, null, repoId, containerId, false, false, null, allowed).toSpecification());

        Map<Long, String> repoNames = repositories.findAll().stream()
                .collect(Collectors.toMap(RepositoryEntity::getId, RepositoryEntity::getName, (a, b) -> a));

        Map<Long, String> containerNames = containers.findAll().stream()
                .collect(Collectors.toMap(ContainerEntity::getId, c -> c.getImageName() + ":" + c.getTag(), (a, b) -> a));

        long criticalCount = 0;
        long highCount = 0;
        long mediumCount = 0;
        long lowCount = 0;

        double vulnHours = 0.0;
        double secretHours = 0.0;
        double sastHours = 0.0;
        double iacHours = 0.0;

        Map<String, PackageGroup> packageGroups = new HashMap<>();

        for (IssueEntity issue : openIssues) {
            Severity sev = Severity.of(issue.getSeverity());
            FindingType type = FindingType.fromWireName(issue.getType()).orElse(FindingType.VULNERABILITY);

            switch (sev) {
                case CRITICAL -> criticalCount++;
                case HIGH -> highCount++;
                case MEDIUM -> mediumCount++;
                case LOW, NEGLIGIBLE, UNKNOWN -> lowCount++;
            }

            switch (type) {
                case VULNERABILITY -> {
                    double effort = (sev == Severity.CRITICAL || sev == Severity.HIGH) ? 1.5 : 0.8;
                    vulnHours += effort;

                    String pkg = issue.getPackageName();
                    if (pkg != null && !pkg.isBlank()) {
                        PackageGroup group = packageGroups.computeIfAbsent(pkg, k -> new PackageGroup(pkg, issue.getPackageVersion()));
                        group.cves.add(issue.getIdentifier() != null ? issue.getIdentifier() : "UNKNOWN-CVE");
                        if (sev == Severity.CRITICAL) group.criticalCount++;
                        if (sev == Severity.HIGH) group.highCount++;

                        if (issue.getRepoId() != null && repoNames.containsKey(issue.getRepoId())) {
                            group.targetNames.add(repoNames.get(issue.getRepoId()));
                        } else if (issue.getContainerId() != null && containerNames.containsKey(issue.getContainerId())) {
                            group.targetNames.add(containerNames.get(issue.getContainerId()));
                        }
                    }
                }
                case SECRET -> secretHours += 2.0;
                case QUALITY -> sastHours += 2.5;
                case IAC -> iacHours += 1.0;
            }
        }

        double totalHours = Math.round((vulnHours + secretHours + sastHours + iacHours) * 10.0) / 10.0;
        double personDays = Math.round((totalHours / 8.0) * 10.0) / 10.0;

        // Build High Impact Fixes
        List<HighImpactFix> highImpactFixes = new ArrayList<>();
        for (PackageGroup group : packageGroups.values()) {
            if (group.cves.isEmpty()) continue;

            double fixEffort = Math.round((1.0 + (group.cves.size() * 0.1)) * 10.0) / 10.0;
            double leverage = Math.round(((group.cves.size() * 2.0 + group.criticalCount * 3.0 + group.highCount * 1.5) / fixEffort) * 10.0) / 10.0;

            String recommendedVersion = "latest-patch";

            highImpactFixes.add(new HighImpactFix(
                    group.packageName,
                    group.version != null ? group.version : "various",
                    recommendedVersion,
                    group.cves.size(),
                    group.criticalCount,
                    group.highCount,
                    fixEffort,
                    leverage,
                    new ArrayList<>(group.cves),
                    new ArrayList<>(group.targetNames)));
        }

        highImpactFixes.sort(Comparator.comparingDouble(HighImpactFix::leverageScore).reversed());
        List<HighImpactFix> topFixes = highImpactFixes.stream().limit(10).toList();

        return new SecurityDebtReport(
                openIssues.size(),
                criticalCount,
                highCount,
                mediumCount,
                lowCount,
                totalHours,
                personDays,
                Math.round(vulnHours * 10.0) / 10.0,
                Math.round(secretHours * 10.0) / 10.0,
                Math.round(sastHours * 10.0) / 10.0,
                Math.round(iacHours * 10.0) / 10.0,
                topFixes);
    }

    private static class PackageGroup {
        final String packageName;
        final String version;
        final Set<String> cves = new HashSet<>();
        final Set<String> targetNames = new HashSet<>();
        long criticalCount = 0;
        long highCount = 0;

        PackageGroup(String packageName, String version) {
            this.packageName = packageName;
            this.version = version;
        }
    }
}
