package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport.TargetImpact;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport.TopImpactPackage;
import com.asmolabs.vectispire.common.domain.graph.DependencyGraph;
import com.asmolabs.vectispire.common.domain.graph.DependencyGraph.GraphEdge;
import com.asmolabs.vectispire.common.domain.graph.DependencyGraph.GraphNode;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
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
 * Builds organizational dependency graphs and calculates vulnerability blast radius across repositories and containers.
 */
@Service
public class BlastRadiusService {

    private final GitRepositories repositoriesRepo;
    private final Containers containersRepo;
    private final Findings findingsRepo;
    private final Issues issuesRepo;
    private final Scans scansRepo;

    public BlastRadiusService(
            GitRepositories repositoriesRepo,
            Containers containersRepo,
            Findings findingsRepo,
            Issues issuesRepo,
            Scans scansRepo) {
        this.repositoriesRepo = repositoriesRepo;
        this.containersRepo = containersRepo;
        this.findingsRepo = findingsRepo;
        this.issuesRepo = issuesRepo;
        this.scansRepo = scansRepo;
    }

    @Transactional(readOnly = true)
    public BlastRadiusReport explore(String rawQuery) {
        String query = rawQuery != null ? rawQuery.trim() : "";
        boolean isCveQuery = query.toUpperCase().startsWith("CVE-");

        Map<Long, RepositoryEntity> reposMap = repositoriesRepo.findAll().stream()
                .collect(Collectors.toMap(RepositoryEntity::getId, r -> r));
        Map<Long, ContainerEntity> containersMap = containersRepo.findAll().stream()
                .collect(Collectors.toMap(ContainerEntity::getId, c -> c));

        List<FindingEntity> allFindings = findingsRepo.findAll();
        List<IssueEntity> allIssues = issuesRepo.findAll();

        List<TargetImpact> targets = new ArrayList<>();
        Map<String, GraphNode> nodesMap = new HashMap<>();
        List<GraphEdge> edges = new ArrayList<>();

        int directCount = 0;
        int transitiveCount = 0;
        Set<String> uniqueCves = new HashSet<>();
        double maxCvss = 0.0;

        // Group findings by scan
        Map<Long, List<FindingEntity>> findingsByScan = allFindings.stream()
                .collect(Collectors.groupingBy(FindingEntity::getScanId));

        for (Map.Entry<Long, List<FindingEntity>> entry : findingsByScan.entrySet()) {
            Long scanId = entry.getKey();
            ScanEntity scan = scansRepo.findById(scanId).orElse(null);
            if (scan == null) continue;

            String targetKind = scan.getRepoId() != null ? "REPOSITORY" : "CONTAINER";
            Long targetId = scan.getRepoId() != null ? scan.getRepoId() : scan.getContainerId();
            if (targetId == null) continue;

            String targetName = scan.getRepoId() != null && reposMap.containsKey(targetId)
                    ? reposMap.get(targetId).getName()
                    : (scan.getContainerId() != null && containersMap.containsKey(targetId)
                            ? containersMap.get(targetId).getImageName() + ":" + containersMap.get(targetId).getTag()
                            : "target-" + targetId);

            String targetContext = scan.getRepoId() != null
                    ? (scan.getBranch() != null ? scan.getBranch() : "main")
                    : (scan.getContainerId() != null && containersMap.containsKey(targetId)
                            ? containersMap.get(targetId).getTag()
                            : "latest");

            String targetNodeId = "target-" + targetKind.toLowerCase() + "-" + targetId;

            List<FindingEntity> scanFindings = entry.getValue();
            for (FindingEntity finding : scanFindings) {
                if (finding.getPackageName() == null || finding.getPackageName().isBlank() || "secret".equalsIgnoreCase(finding.getType())) {
                    continue;
                }

                String pkgName = finding.getPackageName();
                String cveId = finding.getIdentifier();

                boolean matches;
                if (query.isBlank()) {
                    matches = true;
                } else if (isCveQuery) {
                    matches = cveId != null && cveId.equalsIgnoreCase(query);
                } else {
                    matches = pkgName.toLowerCase().contains(query.toLowerCase())
                            || (finding.getPurl() != null && finding.getPurl().toLowerCase().contains(query.toLowerCase()));
                }

                if (!matches) continue;

                boolean isDirect = Boolean.TRUE.equals(finding.getIsDirectDependency());
                if (isDirect) directCount++; else transitiveCount++;

                if (cveId != null && cveId.toUpperCase().startsWith("CVE-")) {
                    uniqueCves.add(cveId);
                }
                if (finding.getCvssScore() != null && finding.getCvssScore() > maxCvss) {
                    maxCvss = finding.getCvssScore();
                }

                String reachability = finding.getReachability() != null ? finding.getReachability() : "UNKNOWN";
                String sourceFile = finding.getFilePath() != null && !finding.getFilePath().isBlank()
                        ? finding.getFilePath()
                        : (finding.getPurl() != null ? extractEcosystem(finding.getPurl()) : "manifest");

                targets.add(new TargetImpact(
                        targetId,
                        targetKind,
                        targetName,
                        targetContext,
                        sourceFile,
                        finding.getPurl(),
                        pkgName,
                        finding.getPackageVersion() != null ? finding.getPackageVersion() : "latest",
                        isDirect,
                        (cveId != null && cveId.toUpperCase().startsWith("CVE-")) ? List.of(cveId) : List.of(),
                        reachability,
                        scan.getId()));

                // Add Target Node
                nodesMap.putIfAbsent(targetNodeId, new GraphNode(
                        targetNodeId, targetName, "TARGET", scan.getBranch() != null ? scan.getBranch() : "main",
                        targetKind, 0, isDirect, List.of()));

                // Add Package Node
                String pkgNodeId = "pkg-" + pkgName + "@" + (finding.getPackageVersion() != null ? finding.getPackageVersion() : "latest");
                nodesMap.putIfAbsent(pkgNodeId, new GraphNode(
                        pkgNodeId, pkgName, "PACKAGE", finding.getPackageVersion(),
                        extractEcosystem(finding.getPurl()), finding.getCvssScore() != null ? (int)(finding.getCvssScore() * 10) : 0,
                        isDirect, cveId != null ? List.of(cveId) : List.of()));

                // Edge Target -> Package
                edges.add(new GraphEdge(targetNodeId, pkgNodeId, isDirect ? "DIRECT_DEPENDENCY" : "TRANSITIVE_DEPENDENCY"));

                // Add CVE Node if present
                if (cveId != null && cveId.toUpperCase().startsWith("CVE-")) {
                    String cveNodeId = "cve-" + cveId;
                    nodesMap.putIfAbsent(cveNodeId, new GraphNode(
                            cveNodeId, cveId, "CVE", null, null,
                            finding.getCvssScore() != null ? (int)(finding.getCvssScore() * 10) : 50,
                            isDirect, List.of(cveId)));

                    edges.add(new GraphEdge(pkgNodeId, cveNodeId, "AFFECTED_BY"));
                }
            }
        }

        int uniqueTargetsCount = (int) targets.stream().map(t -> t.targetKind() + ":" + t.targetId()).distinct().count();
        int score = BlastRadiusReport.calculateScore(uniqueTargetsCount, directCount, transitiveCount, uniqueCves.size(), maxCvss);

        return new BlastRadiusReport(
                query,
                isCveQuery ? "CVE" : "PACKAGE",
                uniqueTargetsCount,
                directCount,
                transitiveCount,
                uniqueCves.size(),
                score,
                targets,
                new DependencyGraph(new ArrayList<>(nodesMap.values()), edges));
    }

    @Transactional(readOnly = true)
    public List<TopImpactPackage> getTopImpactPackages(int limit) {
        List<FindingEntity> allFindings = findingsRepo.findAll();
        Map<String, List<FindingEntity>> byPackage = allFindings.stream()
                .filter(f -> f.getPackageName() != null && !f.getPackageName().isBlank())
                .collect(Collectors.groupingBy(FindingEntity::getPackageName));

        List<TopImpactPackage> topList = new ArrayList<>();

        for (Map.Entry<String, List<FindingEntity>> entry : byPackage.entrySet()) {
            String pkg = entry.getKey();
            List<FindingEntity> list = entry.getValue();

            Set<Long> uniqueScans = list.stream().map(FindingEntity::getScanId).collect(Collectors.toSet());
            int direct = (int) list.stream().filter(f -> Boolean.TRUE.equals(f.getIsDirectDependency())).count();
            int transitive = list.size() - direct;

            Set<String> cves = list.stream()
                    .map(FindingEntity::getIdentifier)
                    .filter(id -> id != null && id.toUpperCase().startsWith("CVE-"))
                    .collect(Collectors.toSet());

            double maxCvss = list.stream()
                    .map(FindingEntity::getCvssScore)
                    .filter(s -> s != null)
                    .max(Double::compareTo)
                    .orElse(0.0);

            String ecosystem = list.stream()
                    .map(FindingEntity::getPurl)
                    .filter(p -> p != null)
                    .map(this::extractEcosystem)
                    .findFirst()
                    .orElse("Generic");

            int score = BlastRadiusReport.calculateScore(uniqueScans.size(), direct, transitive, cves.size(), maxCvss);

            topList.add(new TopImpactPackage(
                    pkg, ecosystem, uniqueScans.size(), direct, transitive, cves.size(), maxCvss, score));
        }

        return topList.stream()
                .sorted(Comparator.comparingInt(TopImpactPackage::blastRadiusScore).reversed())
                .limit(limit > 0 ? limit : 10)
                .toList();
    }

    private String extractEcosystem(String purl) {
        if (purl == null) return "Generic";
        if (purl.startsWith("pkg:maven")) return "Maven";
        if (purl.startsWith("pkg:npm")) return "npm";
        if (purl.startsWith("pkg:pypi")) return "PyPI";
        if (purl.startsWith("pkg:golang")) return "Go";
        if (purl.startsWith("pkg:apk")) return "Alpine";
        if (purl.startsWith("pkg:deb")) return "Debian";
        if (purl.startsWith("pkg:docker") || purl.startsWith("pkg:oci")) return "OCI";
        return "Generic";
    }
}
