package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.attackpath.AttackPath;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathEdge;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathGraph;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathNode;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathNodeType;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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

    @Transactional(readOnly = true)
    public Optional<AttackPathGraph> getAttackPathGraph(Long repositoryId) {
        Optional<RepositoryEntity> repoOpt = repositories.findById(repositoryId);
        if (repoOpt.isEmpty()) {
            return Optional.empty();
        }

        RepositoryEntity repo = repoOpt.get();
        String repoName = repo.getName() != null ? repo.getName() : repo.getUrl();

        List<ApiInventoryService.EndpointView> endpoints = apiInventory.forRepository(repositoryId).endpoints();
        List<IssueEntity> openIssues = issues.findByRepositoryAndState(repositoryId, "open");

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
                "Point d'entrée public externe",
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
                        isUnauth ? "Route Non-Authentifiée" : "Route Publique Authentifiée",
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
        List<IssueEntity> criticalVulns = new ArrayList<>();
        List<IssueEntity> secrets = new ArrayList<>();

        for (IssueEntity issue : openIssues) {
            String type = issue.getType() != null ? issue.getType().toLowerCase(Locale.ROOT) : "";
            String sev = issue.getSeverity() != null ? issue.getSeverity().toUpperCase(Locale.ROOT) : "LOW";

            if (type.contains("secret") || type.contains("gitleaks") || "secret".equals(type)) {
                secrets.add(issue);
            } else if ("CRITICAL".equals(sev) || "HIGH".equals(sev) || issue.isKev() || "REACHABLE".equalsIgnoreCase(issue.getReachability())) {
                criticalVulns.add(issue);
            }
        }

        int vulnCounter = 0;
        for (IssueEntity vuln : criticalVulns) {
            vulnCounter++;
            String vulnNodeId = "vuln-" + (vuln.getId() != null ? vuln.getId() : vulnCounter);
            String label = (vuln.getIdentifier() != null ? vuln.getIdentifier() : "Vuln")
                    + (vuln.getPackageName() != null ? " (" + vuln.getPackageName() + ")" : "");

            boolean isRceOrCritical = "CRITICAL".equalsIgnoreCase(vuln.getSeverity()) || vuln.isKev() || (vuln.getDescription() != null && vuln.getDescription().toLowerCase(Locale.ROOT).contains("remote code execution"));
            boolean isExploitable = !unauthEndpoints.isEmpty() || "REACHABLE".equalsIgnoreCase(vuln.getReachability());

            Map<String, String> meta = new LinkedHashMap<>();
            if (vuln.getIdentifier() != null) meta.put("cve", vuln.getIdentifier());
            if (vuln.getPackageName() != null) meta.put("package", vuln.getPackageName());
            if (vuln.getPackageVersion() != null) meta.put("version", vuln.getPackageVersion());
            if (vuln.getCvssScore() != null) meta.put("cvss", String.valueOf(vuln.getCvssScore()));
            if (vuln.getEpssScore() != null) meta.put("epss", String.format(Locale.ROOT, "%.2f%%", vuln.getEpssScore() * 100));
            meta.put("isKev", String.valueOf(vuln.isKev()));
            meta.put("reachability", vuln.getReachability() != null ? vuln.getReachability() : "UNKNOWN");
            if (vuln.getFilePath() != null) meta.put("filePath", vuln.getFilePath());

            nodes.add(new AttackPathNode(
                    vulnNodeId,
                    label,
                    AttackPathNodeType.VULNERABLE_COMPONENT,
                    vuln.getSeverity() != null ? vuln.getSeverity().toUpperCase(Locale.ROOT) : "HIGH",
                    isExploitable,
                    (isRceOrCritical ? "RCE Potentielle · " : "") + (vuln.isKev() ? "Actively Exploited (CISA KEV)" : "Exécutable"),
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
                "Base de données & Données sensibles",
                Map.of("asset", "PostgreSQL / MySQL Storage", "impact", "Data Exfiltration & Integrity Loss")));

        if (!criticalVulns.isEmpty()) {
            for (IssueEntity vuln : criticalVulns) {
                String vulnNodeId = "vuln-" + vuln.getId();
                edges.add(new AttackPathEdge(
                        "edge-" + vulnNodeId + "-" + dbSinkId,
                        vulnNodeId,
                        dbSinkId,
                        "EXFILTRATES_DATA",
                        "CRITICAL".equalsIgnoreCase(vuln.getSeverity()) || vuln.isKev()));
            }
        }

        int secretCounter = 0;
        for (IssueEntity secret : secrets) {
            secretCounter++;
            String secretNodeId = "secret-" + (secret.getId() != null ? secret.getId() : secretCounter);
            String label = secret.getIdentifier() != null ? secret.getIdentifier() : "Hardcoded Secret";

            Map<String, String> meta = new LinkedHashMap<>();
            if (secret.getFilePath() != null) meta.put("filePath", secret.getFilePath());
            if (secret.getDescription() != null) meta.put("description", secret.getDescription());

            nodes.add(new AttackPathNode(
                    secretNodeId,
                    label,
                    AttackPathNodeType.SECRET,
                    "CRITICAL",
                    true,
                    "Clé API / Mot de passe dans le code",
                    meta));

            if (!criticalVulns.isEmpty()) {
                edges.add(new AttackPathEdge(
                        "edge-vuln-" + secretNodeId,
                        "vuln-" + criticalVulns.get(0).getId(),
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
            IssueEntity topVuln = criticalVulns.get(0);

            paths.add(new AttackPath(
                    "path-rce-exfil",
                    "Chaîne RCE & Exfiltration Non-Authentifiée",
                    "Un attaquant externe peut appeler l'endpoint non-authentifié '" + unauthEp.method() + " " + unauthEp.path() + "', déclencher l'exécution de code sur " + topVuln.getIdentifier() + " et compromettre la base de données ou les secrets.",
                    "CRITICAL",
                    true,
                    List.of(ingressId, "ep-" + unauthEp.id(), "vuln-" + topVuln.getId(), dbSinkId),
                    "1. Restreindre l'accès à " + unauthEp.path() + " par authentification Bearer ou API Key.\n2. Mettre à jour la dépendance " + topVuln.getPackageName() + " vers la version corrigée.\n3. Isoler le conteneur et restreindre les privilèges réseau vers la base de données."));
        }

        if (!secrets.isEmpty()) {
            criticalExploitableCount++;
            IssueEntity firstSecret = secrets.get(0);
            paths.add(new AttackPath(
                    "path-secret-leak",
                    "Exposition Directe de Secret de Production",
                    "Secret en clair détecté dans '" + firstSecret.getFilePath() + "'. Permet un accès direct aux ressources sans franchissement de périmètre.",
                    "CRITICAL",
                    true,
                    List.of(ingressId, "secret-" + firstSecret.getId(), dbSinkId),
                    "1. Révoquer immédiatement la clé/mot de passe compromis.\n2. Migrer le secret vers un gestionnaire sécurisé (HashiCorp Vault, AWS Secrets Manager).\n3. Nettoyer l'historique Git."));
        }

        if (paths.isEmpty()) {
            paths.add(new AttackPath(
                    "path-baseline",
                    "Flux Ingress Sécurisé (Aucun chemin d'attaque critique actif)",
                    "Aucun chemin d'exploitation directe reliant un point d'entrée non-authentifié à un composant vulnérable n'a été détecté.",
                    "LOW",
                    false,
                    List.of(ingressId, dbSinkId),
                    "Maintenir la surveillance continue et les scans périodiques."));
        }

        // Calculate Risk Score (0 - 100)
        int score = calculateRiskScore(criticalExploitableCount, unauthEndpoints.size(), criticalVulns.size(), secrets.size());

        return Optional.of(new AttackPathGraph(
                repositoryId,
                repoName,
                paths.size(),
                criticalExploitableCount,
                score,
                nodes,
                edges,
                paths));
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

        List<AttackPathGraph> graphs = new ArrayList<>();
        for (RepositoryEntity repo : visible) {
            getAttackPathGraph(repo.getId()).ifPresent(graphs::add);
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

    private static int calculateRiskScore(int criticalPaths, int unauthCount, int vulnCount, int secretCount) {
        if (criticalPaths == 0 && vulnCount == 0 && secretCount == 0) {
            return 10;
        }
        int base = (criticalPaths * 35) + (secretCount * 25) + (Math.min(3, vulnCount) * 10) + (Math.min(3, unauthCount) * 5);
        return Math.min(100, Math.max(15, base));
    }
}
