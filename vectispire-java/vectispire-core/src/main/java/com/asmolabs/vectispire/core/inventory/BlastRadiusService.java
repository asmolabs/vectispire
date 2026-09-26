package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport.TargetImpact;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport.TopImpactPackage;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport;
import com.asmolabs.vectispire.common.domain.graph.DependencyGraph.GraphEdge;
import com.asmolabs.vectispire.common.domain.graph.DependencyGraph.GraphNode;
import com.asmolabs.vectispire.common.domain.graph.DependencyGraph;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanFindingView;
import com.asmolabs.vectispire.core.scanning.ScanView;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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

    private final TargetCatalog targets;
    private final ScanCatalog findingsRepo;
    private final Issues issuesRepo;

    public BlastRadiusService(
            TargetCatalog targets,
            ScanCatalog findingsRepo,
            Issues issuesRepo) {
        this.targets = targets;
        this.findingsRepo = findingsRepo;
        this.issuesRepo = issuesRepo;
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
        boolean isCveQuery = query.toUpperCase(Locale.ROOT).startsWith("CVE-");

        List<ScanCatalog.FindingOnScan> rows = findingsRepo.findingsForGraph(query, isCveQuery, true, allowed);

        // Named only for the targets that actually appeared, rather than by loading both tables.
        Map<Long, RepositoryView> reposMap = namedRepositories(rows);
        Map<Long, ContainerView> containersMap = namedContainers(rows);

        List<TargetImpact> targets = new ArrayList<>();
        Map<String, GraphNode> nodesMap = new HashMap<>();
        List<GraphEdge> edges = new ArrayList<>();

        int directCount = 0;
        int transitiveCount = 0;
        Set<String> uniqueCves = new HashSet<>();
        double maxCvss = 0.0;

        // The scan arrives with its findings rather than being fetched per group: that lookup
        // was an N+1 sitting on top of a whole-table read.
        Map<ScanView, List<ScanFindingView>> findingsByScan = new LinkedHashMap<>();
        for (ScanCatalog.FindingOnScan row : rows) {
            findingsByScan.computeIfAbsent(row.scan(), key -> new ArrayList<>()).add(row.finding());
        }

        for (Map.Entry<ScanView, List<ScanFindingView>> entry : findingsByScan.entrySet()) {
            ScanView scan = entry.getKey();

            String targetKind = scan.repoId() != null ? "REPOSITORY" : "CONTAINER";
            Long targetId = scan.repoId() != null ? scan.repoId() : scan.containerId();
            if (targetId == null) continue;

            String targetName = scan.repoId() != null && reposMap.containsKey(targetId)
                    ? reposMap.get(targetId).name()
                    : (scan.containerId() != null && containersMap.containsKey(targetId)
                            ? containersMap.get(targetId).imageName() + ":" + containersMap.get(targetId).tag()
                            : "target-" + targetId);

            String targetContext = scan.repoId() != null
                    ? (scan.branch() != null ? scan.branch() : "main")
                    : (scan.containerId() != null && containersMap.containsKey(targetId)
                            ? containersMap.get(targetId).tag()
                            : "latest");

            String targetNodeId = "target-" + targetKind.toLowerCase(Locale.ROOT) + "-" + targetId;

            List<ScanFindingView> scanFindings = entry.getValue();
            for (ScanFindingView finding : scanFindings) {
                // The package-name and secret filters moved into the query; so did the match
                // below. Kept as a single guard rather than removed, because the query is the
                // contract and this is the assertion that it held.
                String pkgName = finding.packageName();
                String cveId = finding.identifier();

                boolean isDirect = Boolean.TRUE.equals(finding.isDirectDependency());
                if (isDirect) directCount++; else transitiveCount++;

                if (cveId != null && cveId.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                    uniqueCves.add(cveId);
                }
                if (finding.cvssScore() != null && finding.cvssScore() > maxCvss) {
                    maxCvss = finding.cvssScore();
                }

                String reachability = finding.reachability() != null ? finding.reachability() : "UNKNOWN";
                String sourceFile = finding.filePath() != null && !finding.filePath().isBlank()
                        ? finding.filePath()
                        : (finding.purl() != null ? extractEcosystem(finding.purl()) : "manifest");

                targets.add(new TargetImpact(
                        targetId,
                        targetKind,
                        targetName,
                        targetContext,
                        sourceFile,
                        finding.purl(),
                        pkgName,
                        finding.packageVersion() != null ? finding.packageVersion() : "latest",
                        isDirect,
                        (cveId != null && cveId.toUpperCase(Locale.ROOT).startsWith("CVE-")) ? List.of(cveId) : List.of(),
                        reachability,
                        scan.id()));

                // Add Target Node
                nodesMap.putIfAbsent(targetNodeId, new GraphNode(
                        targetNodeId, targetName, "TARGET", scan.branch() != null ? scan.branch() : "main",
                        targetKind, 0, isDirect, List.of()));

                // Add Package Node
                String pkgNodeId = "pkg-" + pkgName + "@" + (finding.packageVersion() != null ? finding.packageVersion() : "latest");
                nodesMap.putIfAbsent(pkgNodeId, new GraphNode(
                        pkgNodeId, pkgName, "PACKAGE", finding.packageVersion(),
                        extractEcosystem(finding.purl()), finding.cvssScore() != null ? (int)(finding.cvssScore() * 10) : 0,
                        isDirect, cveId != null ? List.of(cveId) : List.of()));

                // Edge Target -> Package
                edges.add(new GraphEdge(targetNodeId, pkgNodeId, isDirect ? "DIRECT_DEPENDENCY" : "TRANSITIVE_DEPENDENCY"));

                // Add CVE Node if present
                if (cveId != null && cveId.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                    String cveNodeId = "cve-" + cveId;
                    nodesMap.putIfAbsent(cveNodeId, new GraphNode(
                            cveNodeId, cveId, "CVE", null, null,
                            finding.cvssScore() != null ? (int)(finding.cvssScore() * 10) : 50,
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

    /**
     * The packages that reach the most targets, <b>within what the caller may see</b>.
     *
     * <p>This is the landing list of the blast-radius screen, so it runs on every open — and it
     * used to run by reading every finding in the deployment through {@code forGraph("")},
     * hydrating two entities per row and grouping them here. The grouping is now the database's,
     * and what arrives is one small tuple per distinct package.
     *
     * <p>The scoring stayed: {@code calculateScore} is capped arithmetic over the aggregates, and
     * a few thousand packages cost nothing to score. Sorting stayed with it, because the score is
     * what the list is ordered by and it does not exist until the arithmetic has run.
     *
     * <p><b>The dispersion it scores is a count of targets, and it used to be a count of scans.</b>
     * Those differ by the whole scan history: a package in one repository scanned nightly counted
     * as thirty. The term saturates at five, so within a week of scheduled scanning every package
     * in the estate carried the full forty points and the ranking was decided by CVSS alone — the
     * column headed "Cibles" both overstated the reach and stopped distinguishing anything. It
     * also disagreed with {@link #explore}, which counted targets properly and put a different
     * number under the same word one screen away.
     */
    @Transactional(readOnly = true)
    public List<TopImpactPackage> getTopImpactPackages(int limit, Visibility allowed) {
        return findingsRepo.packageImpacts(allowed).stream()
                .map(impact -> {
                    // Absent is not zero in the aggregate, but it is here: the score treats a
                    // package nobody has scored as carrying no severity, which is what the Java
                    // this replaces did with `orElse(0.0)`.
                    double maxCvss = impact.maxCvss() != null ? impact.maxCvss() : 0.0;
                    int direct = (int) impact.directUsages();
                    int transitive = (int) impact.transitiveUsages();
                    // Targets, not scans: a repository scanned nightly is one target.
                    int targets = (int) impact.distinctTargets();
                    int cves = (int) impact.distinctCves();

                    return new TopImpactPackage(
                            impact.packageName(),
                            extractEcosystem(impact.anyPurl()),
                            targets,
                            direct,
                            transitive,
                            cves,
                            maxCvss,
                            BlastRadiusReport.calculateScore(targets, direct, transitive, cves, maxCvss));
                })
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
    private Map<Long, RepositoryView> namedRepositories(List<ScanCatalog.FindingOnScan> rows) {
        Set<Long> ids = rows.stream()
                .map(row -> row.scan().repoId())
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toSet());
        return ids.isEmpty()
                ? Map.of()
                : targets.repositories(ids).stream()
                        .collect(Collectors.toMap(RepositoryView::id, r -> r));
    }

    private Map<Long, ContainerView> namedContainers(List<ScanCatalog.FindingOnScan> rows) {
        Set<Long> ids = rows.stream()
                .map(row -> row.scan().containerId())
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toSet());
        return ids.isEmpty()
                ? Map.of()
                : targets.containers(ids).stream()
                        .collect(Collectors.toMap(ContainerView::id, c -> c));
    }

}
