package com.asmolabs.vectispire.core.services.posture;

import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPath;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathEdge;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathGraph;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathNode;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathNodeType;
import com.asmolabs.vectispire.core.repositories.IssueRows;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.inventory.ApiInventoryService;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service that correlates ingress entrypoints, unauthenticated APIs, reachable critical vulnerabilities,
 * and high-value secret/data sinks into actionable Attack Path graphs.
 */
@Service
public class AttackPathService {

    private final GitRepositories repositories;
    private final ApiInventoryService apiInventory;
    private final Issues issues;

    public AttackPathService(
            GitRepositories repositories,
            ApiInventoryService apiInventory,
            Issues issues) {
        this.repositories = repositories;
        this.apiInventory = apiInventory;
        this.issues = issues;
    }

    /**
     * How many vulnerability nodes and how many secret nodes one target contributes.
     *
     * <p>A graph is a picture. Past a couple of dozen nodes it stops being one, and the overview
     * draws every visible repository on the same canvas — so the ceiling is per target, not per
     * page. The counts a reader acts on are unaffected: {@code totalPaths} and
     * {@code criticalExploitablePaths} are computed before the cut.
     */
    private static final int NODES_PER_TARGET = 10;

    /**
     * Actively exploited first, then severity, then reachable ahead of unknown.
     *
     * <p>The same order the ranking elsewhere uses, and the reason the cut is defensible: what
     * survives it is what an operator would have looked at first anyway.
     */
    private static final Comparator<IssueRows.GraphNode> WORST_FIRST = Comparator
            .comparing((IssueRows.GraphNode i) -> Boolean.TRUE.equals(i.isKev()) ? 0 : 1)
            .thenComparing(i -> switch (i.severity() == null ? "" : i.severity().toUpperCase(Locale.ROOT)) {
                case "CRITICAL" -> 0;
                case "HIGH" -> 1;
                case "MEDIUM" -> 2;
                case "LOW" -> 3;
                default -> 4;
            })
            .thenComparing(i -> "REACHABLE".equalsIgnoreCase(i.reachability()) ? 0 : 1)
            // Ties broken on the id so two runs of the same estate draw the same picture.
            .thenComparing(i -> i.id() == null ? Long.MAX_VALUE : i.id());

    @Transactional(readOnly = true)
    public Optional<AttackPathGraph> getAttackPathGraph(Long repositoryId) {
        Optional<RepositoryEntity> repoOpt = repositories.findById(repositoryId);
        if (repoOpt.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(buildGraph(
                repoOpt.get(),
                apiInventory.forRepository(repositoryId).endpoints(),
                issues.findUnsettledByRepositoryAndState(
                        repositoryId, "open", TriageStatus.settledWireNames(), IssueRows.GraphNode.class)));
    }

    /**
     * The graph itself, from data already in hand.
     *
     * <p><b>Separated from the reads so the overview can batch them.</b> It used to call the
     * per-target method in a loop, and each call was four queries — the repository, its endpoints,
     * its contracts, its open issues — so a page over eleven targets cost thirty-four round trips
     * where one target costs four. Nothing about the graph changed; only who fetched its inputs.
     */
    private AttackPathGraph buildGraph(
            RepositoryEntity repo,
            List<ApiInventoryService.EndpointView> endpoints,
            List<IssueRows.GraphNode> openIssues) {

        Long repositoryId = repo.getId();
        String repoName = repo.getName() != null ? repo.getName() : RepositoryUrl.redact(repo.getUrl());

        List<AttackPathNode> nodes = new ArrayList<>();
        List<AttackPathEdge> edges = new ArrayList<>();
        List<AttackPath> paths = new ArrayList<>();

        // 1. Ingress External Node (Internet 0.0.0.0/0)
        String ingressId = "ingress-ext";
        nodes.add(new AttackPathNode(
                ingressId,
                "Internet Ingress (0.0.0.0/0)",
                AttackPathNodeType.INTERNET_INGRESS,
                "INFO",
                true,
                AttackPathNode.NodeNote.PUBLIC_INGRESS,
                Map.of("exposure", "PUBLIC", "protocol", "HTTPS / HTTP")));

        // 2. Map Unauthenticated / Public API Endpoints
        List<ApiInventoryService.EndpointView> exposedEndpoints = new ArrayList<>();
        List<ApiInventoryService.EndpointView> unauthEndpoints = new ArrayList<>();

        int epCounter = 0;
        for (ApiInventoryService.EndpointView ep : endpoints) {
            boolean isUnauth = !ep.authRequired();
            boolean isPub = "PUBLIC".equalsIgnoreCase(ep.visibility()) || isUnauth;

            if (isPub || isUnauth) {
                epCounter++;
                String epNodeId = "ep-" + (ep.id() != null ? ep.id() : epCounter);
                String label = ep.method() + " " + ep.path();
                String severity = isUnauth ? (isSensitive(ep.path()) ? "CRITICAL" : "HIGH") : "MEDIUM";

                Map<String, String> meta = new LinkedHashMap<>();
                meta.put("method", ep.method());
                meta.put("path", ep.path());
                meta.put("authRequired", String.valueOf(ep.authRequired()));
                if (ep.filePath() != null) meta.put("filePath", ep.filePath());
                if (ep.framework() != null) meta.put("framework", ep.framework());

                nodes.add(new AttackPathNode(
                        epNodeId,
                        label,
                        AttackPathNodeType.API_ENDPOINT,
                        severity,
                        isUnauth,
                        isUnauth
                                ? AttackPathNode.NodeNote.UNAUTHENTICATED_ROUTE
                                : AttackPathNode.NodeNote.AUTHENTICATED_PUBLIC_ROUTE,
                        meta));

                edges.add(new AttackPathEdge(
                        "edge-ingress-" + epNodeId,
                        ingressId,
                        epNodeId,
                        isUnauth ? "EXPOSE_UNAUTHENTICATED" : "EXPOSES_PUBLIC",
                        isUnauth));

                exposedEndpoints.add(ep);
                if (isUnauth) {
                    unauthEndpoints.add(ep);
                }
            }
        }

        // 3. Map Vulnerable Components (Critical / High / Reachable / KEV)
        List<IssueRows.GraphNode> criticalVulns = new ArrayList<>();
        List<IssueRows.GraphNode> secrets = new ArrayList<>();

        for (IssueRows.GraphNode issue : openIssues) {
            String type = issue.type() != null ? issue.type().toLowerCase(Locale.ROOT) : "";
            String sev = issue.severity() != null ? issue.severity().toUpperCase(Locale.ROOT) : "LOW";

            if (type.contains("secret") || type.contains("gitleaks") || "secret".equals(type)) {
                secrets.add(issue);
            } else if ("CRITICAL".equals(sev) || "HIGH".equals(sev) || Boolean.TRUE.equals(issue.isKev()) || "REACHABLE".equalsIgnoreCase(issue.reachability())) {
                criticalVulns.add(issue);
            }
        }

        // **The graph is cut here, and the cut is the point.** Every critical vulnerability and
        // every secret became a node, so a repository with four hundred open issues drew four
        // hundred nodes: a picture nobody can read, built by a read that grows with the estate.
        // Ranked first, then cut — cutting before the ranking would draw an arbitrary ten and
        // label them the worst. `totalPaths` below still counts everything.
        criticalVulns.sort(WORST_FIRST);
        secrets.sort(WORST_FIRST);
        int criticalVulnsFound = criticalVulns.size();
        int secretsFound = secrets.size();
        criticalVulns = criticalVulns.stream().limit(NODES_PER_TARGET).collect(Collectors.toList());
        secrets = secrets.stream().limit(NODES_PER_TARGET).collect(Collectors.toList());

        int vulnCounter = 0;
        for (IssueRows.GraphNode vuln : criticalVulns) {
            vulnCounter++;
            String vulnNodeId = "vuln-" + (vuln.id() != null ? vuln.id() : vulnCounter);
            String label = (vuln.identifier() != null ? vuln.identifier() : "Vuln")
                    + (vuln.packageName() != null ? " (" + vuln.packageName() + ")" : "");

            boolean isRceOrCritical = "CRITICAL".equalsIgnoreCase(vuln.severity()) || Boolean.TRUE.equals(vuln.isKev()) || (vuln.description() != null && vuln.description().toLowerCase(Locale.ROOT).contains("remote code execution"));
            boolean isExploitable = !unauthEndpoints.isEmpty() || "REACHABLE".equalsIgnoreCase(vuln.reachability());

            Map<String, String> meta = new LinkedHashMap<>();
            if (vuln.identifier() != null) meta.put("cve", vuln.identifier());
            if (vuln.packageName() != null) meta.put("package", vuln.packageName());
            if (vuln.packageVersion() != null) meta.put("version", vuln.packageVersion());
            if (vuln.cvssScore() != null) meta.put("cvss", String.valueOf(vuln.cvssScore()));
            if (vuln.epssScore() != null) meta.put("epss", String.format(Locale.ROOT, "%.2f%%", vuln.epssScore() * 100));
            meta.put("isKev", String.valueOf(Boolean.TRUE.equals(vuln.isKev())));
            meta.put("reachability", vuln.reachability() != null ? vuln.reachability() : "UNKNOWN");
            if (vuln.filePath() != null) meta.put("filePath", vuln.filePath());

            nodes.add(new AttackPathNode(
                    vulnNodeId,
                    label,
                    AttackPathNodeType.VULNERABLE_COMPONENT,
                    vuln.severity() != null ? vuln.severity().toUpperCase(Locale.ROOT) : "HIGH",
                    isExploitable,
                    noteFor(isRceOrCritical, Boolean.TRUE.equals(vuln.isKev())),
                    meta));

            // Link from exposed endpoints to this vulnerable component
            if (!exposedEndpoints.isEmpty()) {
                for (ApiInventoryService.EndpointView ep : exposedEndpoints) {
                    String epNodeId = "ep-" + ep.id();
                    edges.add(new AttackPathEdge(
                            "edge-" + epNodeId + "-" + vulnNodeId,
                            epNodeId,
                            vulnNodeId,
                            "INVOKES_DEPENDENCY",
                            !ep.authRequired() && isRceOrCritical));
                }
            } else {
                // Fallback link if no API was explicitly scanned
                edges.add(new AttackPathEdge(
                        "edge-direct-" + vulnNodeId,
                        ingressId,
                        vulnNodeId,
                        "REACHES_COMPONENT",
                        isRceOrCritical));
            }
        }

        // 4. Map Secrets / Database Compromise Sinks
        String dbSinkId = "sink-db";
        nodes.add(new AttackPathNode(
                dbSinkId,
                "Database / Production Data Sink",
                AttackPathNodeType.DATABASE,
                "CRITICAL",
                !criticalVulns.isEmpty(),
                AttackPathNode.NodeNote.SENSITIVE_DATA_STORE,
                Map.of("asset", "PostgreSQL / MySQL Storage", "impact", "Data Exfiltration & Integrity Loss")));

        if (!criticalVulns.isEmpty()) {
            for (IssueRows.GraphNode vuln : criticalVulns) {
                String vulnNodeId = "vuln-" + vuln.id();
                edges.add(new AttackPathEdge(
                        "edge-" + vulnNodeId + "-" + dbSinkId,
                        vulnNodeId,
                        dbSinkId,
                        "EXFILTRATES_DATA",
                        "CRITICAL".equalsIgnoreCase(vuln.severity()) || Boolean.TRUE.equals(vuln.isKev())));
            }
        }

        int secretCounter = 0;
        for (IssueRows.GraphNode secret : secrets) {
            secretCounter++;
            String secretNodeId = "secret-" + (secret.id() != null ? secret.id() : secretCounter);
            String label = secret.identifier() != null ? secret.identifier() : "Hardcoded Secret";

            Map<String, String> meta = new LinkedHashMap<>();
            if (secret.filePath() != null) meta.put("filePath", secret.filePath());
            if (secret.description() != null) meta.put("description", secret.description());

            nodes.add(new AttackPathNode(
                    secretNodeId,
                    label,
                    AttackPathNodeType.SECRET,
                    "CRITICAL",
                    true,
                    AttackPathNode.NodeNote.HARDCODED_CREDENTIAL,
                    meta));

            if (!criticalVulns.isEmpty()) {
                edges.add(new AttackPathEdge(
                        "edge-vuln-" + secretNodeId,
                        "vuln-" + criticalVulns.get(0).id(),
                        secretNodeId,
                        "COMPROMISES_CREDENTIALS",
                        true));
            } else {
                edges.add(new AttackPathEdge(
                        "edge-ingress-" + secretNodeId,
                        ingressId,
                        secretNodeId,
                        "DIRECT_EXPOSURE",
                        true));
            }
        }

        // 5. Synthesize Concrete Attack Paths
        int criticalExploitableCount = 0;
        if (!unauthEndpoints.isEmpty() && !criticalVulns.isEmpty()) {
            criticalExploitableCount++;
            ApiInventoryService.EndpointView unauthEp = unauthEndpoints.get(0);
            IssueRows.GraphNode topVuln = criticalVulns.get(0);

            paths.add(new AttackPath(
                    "path-rce-exfil",
                    AttackPath.Scenario.UNAUTH_RCE_CHAIN,
                    Map.of(
                            "method", unauthEp.method() != null ? unauthEp.method() : "",
                            "path", unauthEp.path() != null ? unauthEp.path() : "",
                            "identifier", topVuln.identifier() != null ? topVuln.identifier() : "",
                            "package", topVuln.packageName() != null ? topVuln.packageName() : ""),
                    "CRITICAL",
                    true,
                    List.of(ingressId, "ep-" + unauthEp.id(), "vuln-" + topVuln.id(), dbSinkId)));
        }

        if (!secrets.isEmpty()) {
            criticalExploitableCount++;
            IssueRows.GraphNode firstSecret = secrets.get(0);
            paths.add(new AttackPath(
                    "path-secret-leak",
                    AttackPath.Scenario.PLAINTEXT_SECRET,
                    Map.of("file", firstSecret.filePath() != null ? firstSecret.filePath() : ""),
                    "CRITICAL",
                    true,
                    List.of(ingressId, "secret-" + firstSecret.id(), dbSinkId)));
        }

        if (paths.isEmpty()) {
            paths.add(new AttackPath(
                    "path-baseline",
                    AttackPath.Scenario.NO_CRITICAL_PATH,
                    Map.of(),
                    "LOW",
                    false,
                    List.of(ingressId, dbSinkId)));
        }

        // **Scored on what the target has, not on what the picture shows.** The node lists were
        // cut to keep the graph readable; a risk score computed from the cut would fall when a
        // repository crossed the ceiling, which is the one direction it must never move.
        int score = calculateRiskScore(
                criticalExploitableCount, unauthEndpoints.size(), criticalVulnsFound, secretsFound);

        return new AttackPathGraph(
                repositoryId,
                repoName,
                paths.size(),
                criticalExploitableCount,
                score,
                nodes,
                edges,
                paths);
    }

    /**
     * Every attack path the caller may see.
     *
     * <p>The overview is the per-repository graph in list form, so it repeats the same
     * disclosure: without an allowance it named every repository in the deployment and how to
     * walk from its ingress to its secrets.
     */
    @Transactional(readOnly = true)
    public List<AttackPathGraph> getOverview(Visibility allowed) {
        List<RepositoryEntity> visible = allowed.asFilter()
                .map(targets -> repositories.findAllById(targets.stream()
                        .filter(ScanTarget.Repository.class::isInstance)
                        .map(target -> ((ScanTarget.Repository) target).id())
                        .toList()))
                .orElseGet(repositories::findAll);

        if (visible.isEmpty()) {
            return List.of();
        }

        // **Three reads for the page, not four per repository.** Endpoints, contracts and open
        // issues are fetched for every visible target at once and handed to `buildGraph`, which
        // is the same computation it always was on the same inputs.
        List<Long> repoIds = visible.stream().map(RepositoryEntity::getId).toList();
        Map<Long, List<ApiInventoryService.EndpointView>> endpointsByRepo =
                apiInventory.endpointViewsByRepository(repoIds);
        Map<Long, List<IssueRows.GraphNode>> issuesByRepo = issues
                .findByStateAndRepoIdInAndTriageStatusNotIn(
                        "open", repoIds, TriageStatus.settledWireNames(), IssueRows.GraphNode.class).stream()
                .collect(Collectors.groupingBy(IssueRows.GraphNode::repoId));

        List<AttackPathGraph> graphs = new ArrayList<>();
        for (RepositoryEntity repo : visible) {
            graphs.add(buildGraph(
                    repo,
                    endpointsByRepo.getOrDefault(repo.getId(), List.of()),
                    issuesByRepo.getOrDefault(repo.getId(), List.of())));
        }
        return graphs;
    }

    private static boolean isSensitive(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.contains("admin") || lower.contains("auth") || lower.contains("login")
                || lower.contains("user") || lower.contains("payment") || lower.contains("checkout")
                || lower.contains("secret") || lower.contains("token") || lower.contains("upload");
    }

    /**
     * The two booleans a vulnerability node carries, flattened into one note.
     *
     * <p>They used to be concatenated into a sentence on the spot — {@code "RCE Potentielle · "}
     * plus one of two endings — and a concatenation is precisely what a translation cannot
     * reorder. Four constants say the same four things and leave the wording to the bundles.
     */
    private static AttackPathNode.NodeNote noteFor(boolean remoteCodeExecution, boolean activelyExploited) {
        if (remoteCodeExecution) {
            return activelyExploited
                    ? AttackPathNode.NodeNote.RCE_ACTIVELY_EXPLOITED
                    : AttackPathNode.NodeNote.RCE_EXECUTABLE;
        }
        return activelyExploited
                ? AttackPathNode.NodeNote.ACTIVELY_EXPLOITED
                : AttackPathNode.NodeNote.EXECUTABLE;
    }

    private static int calculateRiskScore(int criticalPaths, int unauthCount, int vulnCount, int secretCount) {
        if (criticalPaths == 0 && vulnCount == 0 && secretCount == 0) {
            return 10;
        }
        int base = (criticalPaths * 35) + (secretCount * 25) + (Math.min(3, vulnCount) * 10) + (Math.min(3, unauthCount) * 5);
        return Math.min(100, Math.max(15, base));
    }
}
