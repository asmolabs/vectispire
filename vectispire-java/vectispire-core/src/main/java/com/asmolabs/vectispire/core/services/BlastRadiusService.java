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
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.repositories.FindingGraphQueries;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
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

    /**
     * The graph of what a package or a CVE reaches, <b>within what the caller may see</b>.
     *
     * <p><b>Two defects were repaired here together, and the smaller one was the reason I was
     * sent.</b> The read was unbounded — every finding in the deployment, then a scan looked up
     * one at a time, then the caller's query matched in Java. The other was that no
     * {@link Visibility} was applied at any point, so a reader assigned one repository received an
     * inventory of every other: target names, package names, versions and CVE identifiers.
     *
     * <p>They are repaired in one change because they are the same line. The filter that scopes
     * the read to a target is the filter that authorizes it, and adding an index or a narrower
     * query without the allowance would have made the leak faster.
     */
    @Transactional(readOnly = true)
    public BlastRadiusReport explore(String rawQuery, Visibility allowed) {
        String query = rawQuery != null ? rawQuery.trim() : "";
        boolean isCveQuery = query.toUpperCase().startsWith("CVE-");

        List<FindingGraphQueries.GraphRow> rows = findingsRepo.forGraph(query, isCveQuery, true, allowed);

        // Named only for the targets that actually appeared, rather than by loading both tables.
        Map<Long, RepositoryEntity> reposMap = namedRepositories(rows);
        Map<Long, ContainerEntity> containersMap = namedContainers(rows);

        List<TargetImpact> targets = new ArrayList<>();
        Map<String, GraphNode> nodesMap = new HashMap<>();
        List<GraphEdge> edges = new ArrayList<>();

        int directCount = 0;
        int transitiveCount = 0;
        Set<String> uniqueCves = new HashSet<>();
        double maxCvss = 0.0;

        // The scan arrives with its findings rather than being fetched per group: that lookup
        // was an N+1 sitting on top of a whole-table read.
        Map<ScanEntity, List<FindingEntity>> findingsByScan = new LinkedHashMap<>();
        for (FindingGraphQueries.GraphRow row : rows) {
            findingsByScan.computeIfAbsent(row.scan(), key -> new ArrayList<>()).add(row.finding());
        }

        for (Map.Entry<ScanEntity, List<FindingEntity>> entry : findingsByScan.entrySet()) {
            ScanEntity scan = entry.getKey();

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
                // The package-name and secret filters moved into the query; so did the match
                // below. Kept as a single guard rather than removed, because the query is the
                // contract and this is the assertion that it held.
                String pkgName = finding.getPackageName();
                String cveId = finding.getIdentifier();

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

    /** The packages that reach the most targets, <b>within what the caller may see</b>. */
    @Transactional(readOnly = true)
    public List<TopImpactPackage> getTopImpactPackages(int limit, Visibility allowed) {
        // Blank query, secrets left in: this list never excluded them and does not need to — it
        // already requires a package name, which a secret finding does not carry.
        Map<String, List<FindingEntity>> byPackage = findingsRepo.forGraph("", false, false, allowed).stream()
                .map(FindingGraphQueries.GraphRow::finding)
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

    /** The repositories named by these rows, and no others. */
    private Map<Long, RepositoryEntity> namedRepositories(List<FindingGraphQueries.GraphRow> rows) {
        Set<Long> ids = rows.stream()
                .map(row -> row.scan().getRepoId())
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toSet());
        return ids.isEmpty()
                ? Map.of()
                : repositoriesRepo.findAllById(ids).stream()
                        .collect(Collectors.toMap(RepositoryEntity::getId, r -> r));
    }

    private Map<Long, ContainerEntity> namedContainers(List<FindingGraphQueries.GraphRow> rows) {
        Set<Long> ids = rows.stream()
                .map(row -> row.scan().getContainerId())
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toSet());
        return ids.isEmpty()
                ? Map.of()
                : containersRepo.findAllById(ids).stream()
                        .collect(Collectors.toMap(ContainerEntity::getId, c -> c));
    }

}
