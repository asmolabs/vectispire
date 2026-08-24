package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.threatintel.EpssRiskMatrix;
import com.asmolabs.zanshin.common.domain.threatintel.EpssRiskMatrix.EpssFleetSummary;
import com.asmolabs.zanshin.common.domain.threatintel.EpssRiskMatrix.EpssPrioritizedIssue;
import com.asmolabs.zanshin.common.domain.threatintel.ThreatIntelRecord;
import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ThreatIntelEntity;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.ThreatIntels;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service orchestrating EPSS (Exploit Prediction Scoring System) and CISA KEV
 * prioritization across all monitored enterprise assets.
 */
@Service
public class EpssPrioritizationService {

    private final Issues issuesRepo;
    private final ThreatIntels intelRepo;
    private final ThreatIntelFeedService threatIntelService;
    private final GitRepositories reposRepo;
    private final Containers containersRepo;

    public EpssPrioritizationService(
            Issues issuesRepo,
            ThreatIntels intelRepo,
            ThreatIntelFeedService threatIntelService,
            GitRepositories reposRepo,
            Containers containersRepo) {
        this.issuesRepo = issuesRepo;
        this.intelRepo = intelRepo;
        this.threatIntelService = threatIntelService;
        this.reposRepo = reposRepo;
        this.containersRepo = containersRepo;
    }

    @Transactional(readOnly = true)
    public EpssFleetSummary getFleetSummary() {
        Map<Long, RepositoryEntity> reposMap = reposRepo.findAll().stream()
                .collect(Collectors.toMap(RepositoryEntity::getId, r -> r));
        Map<Long, ContainerEntity> containersMap = containersRepo.findAll().stream()
                .collect(Collectors.toMap(ContainerEntity::getId, c -> c));

        List<IssueEntity> openIssues = issuesRepo.findAll().stream()
                .filter(i -> !"closed".equalsIgnoreCase(i.getState()) && !"resolved".equalsIgnoreCase(i.getState()))
                .toList();

        List<EpssPrioritizedIssue> prioritized = new ArrayList<>();
        Map<String, Integer> tierBreakdown = new HashMap<>(Map.of(
                "CRITICAL_ARMED", 0,
                "HIGH_PROBABLE", 0,
                "MEDIUM_THEORETICAL", 0,
                "LOW_PROBABILITY", 0));

        int activeKevCount = 0;
        int highEpssCount = 0;
        int reachableEpssCount = 0;
        double totalEpss = 0.0;
        int epssCount = 0;

        for (IssueEntity issue : openIssues) {
            String cveId = issue.getIdentifier();
            Double cvss = issue.getCvssScore();

            // Threat intel lookup
            Optional<ThreatIntelRecord> intel = cveId != null ? threatIntelService.lookupCve(cveId) : Optional.empty();
            boolean isKev = issue.isKev() || (intel.isPresent() && intel.get().isKev());
            Double epssScore = issue.getEpssScore() != null
                    ? issue.getEpssScore()
                    : (intel.map(ThreatIntelRecord::epssScore).orElse(0.01));
            Double epssPercentile = intel.map(ThreatIntelRecord::epssPercentile).orElse(epssScore != null ? Math.min(1.0, epssScore * 1.1) : 0.05);

            String reachability = issue.getReachability() != null ? issue.getReachability() : "UNKNOWN";
            boolean isReachable = "REACHABLE".equalsIgnoreCase(reachability);

            if (isKev) activeKevCount++;
            if (epssScore != null && epssScore >= 0.20) {
                highEpssCount++;
                if (isReachable) reachableEpssCount++;
            }
            if (epssScore != null) {
                totalEpss += epssScore;
                epssCount++;
            }

            int score = EpssRiskMatrix.calculatePriorityScore(cvss, epssScore, isKev, reachability);
            String tier = EpssRiskMatrix.determineTier(cvss, epssScore, isKev, reachability);
            String action = EpssRiskMatrix.determineAction(tier, isKev, reachability);

            tierBreakdown.put(tier, tierBreakdown.getOrDefault(tier, 0) + 1);

            String targetName = issue.getRepoId() != null && reposMap.containsKey(issue.getRepoId())
                    ? reposMap.get(issue.getRepoId()).getName()
                    : (issue.getContainerId() != null && containersMap.containsKey(issue.getContainerId())
                            ? containersMap.get(issue.getContainerId()).getImageName() + ":" + containersMap.get(issue.getContainerId()).getTag()
                            : "target-" + (issue.getRepoId() != null ? issue.getRepoId() : issue.getContainerId()));

            String targetKind = issue.getRepoId() != null ? "REPOSITORY" : "CONTAINER";

            prioritized.add(new EpssPrioritizedIssue(
                    issue.getId(),
                    cveId != null ? cveId : issue.getType(),
                    issue.getDescription() != null ? issue.getDescription() : (issue.getPackageName() != null ? issue.getPackageName() : "Vulnerability " + issue.getId()),
                    issue.getSeverity(),
                    cvss,
                    epssScore,
                    epssPercentile,
                    isKev,
                    reachability,
                    targetName,
                    targetKind,
                    score,
                    tier,
                    action));
        }

        prioritized.sort(Comparator.comparingInt(EpssPrioritizedIssue::priorityScore).reversed());

        double avgEpss = epssCount > 0 ? (totalEpss / epssCount) : 0.0;

        return new EpssFleetSummary(
                openIssues.size(),
                activeKevCount,
                highEpssCount,
                reachableEpssCount,
                Math.round(avgEpss * 1000.0) / 1000.0,
                prioritized,
                tierBreakdown);
    }

    public Optional<ThreatIntelRecord> lookupCve(String cveId) {
        return threatIntelService.lookupCve(cveId);
    }
}
