package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.asmolabs.vectispire.common.domain.apis.AttackSurfaceSummary;
import com.asmolabs.vectispire.common.domain.apis.ShadowApiDiff;
import com.asmolabs.vectispire.common.domain.apis.ShadowApiStatus;
import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.ApiContracts;
import com.asmolabs.vectispire.core.repositories.ApiEndpoints;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages API endpoint inventory, declared contracts, shadow API detection,
 * and synthesized OpenAPI 3.0 generation.
 */
@Service
public class ApiInventoryService {

    public record EndpointView(
            Long id,
            Long scanId,
            Long repositoryId,
            String method,
            String path,
            boolean authRequired,
            String authType,
            String visibility,
            String filePath,
            Integer lineNumber,
            String framework,
            String operationId,
            String summary,
            String tags,
            String shadowStatus,
            Instant createdAt) {}

    public record RepositoryApisOverview(
            Long repositoryId,
            List<EndpointView> endpoints,
            List<ApiContractEntity> contracts,
            AttackSurfaceSummary summary) {}

    public record GlobalAttackSurface(
            int totalEndpoints,
            int publicEndpoints,
            int internalEndpoints,
            int unauthenticatedEndpoints,
            int shadowEndpoints,
            int sensitiveUnprotectedEndpoints,
            List<String> frameworks,
            List<EndpointView> highRiskEndpoints,
            List<EndpointView> allEndpoints) {}

    private final ApiEndpoints apiEndpoints;
    private final ApiContracts apiContracts;
    private final Scans scans;
    private final Clock clock;

    public ApiInventoryService(ApiEndpoints apiEndpoints, ApiContracts apiContracts, Scans scans, Clock clock) {
        this.apiEndpoints = apiEndpoints;
        this.apiContracts = apiContracts;
        this.scans = scans;
        this.clock = clock;
    }

    /**
     * Records what a scan discovered about a target's API surface.
     *
     * <p><b>Each half is replaced only when its analyzer actually ran, and that is the whole
     * signature.</b> ADR-0007's rule — absent means "did not run", empty means "ran, found
     * nothing" — used to be lost one caller earlier: {@code ScanIngestor} collapsed both
     * {@code Optional}s with {@code orElse(List.of())}, and this method then deleted both tables
     * unconditionally. A contract cataloguer that fell over therefore erased every contract the
     * repository had.
     *
     * <p>The consequence was not a blank panel. {@link ShadowApiDiff} reads an empty contract list
     * as <em>nothing declared</em> and reports every endpoint as a shadow API — correctly, on
     * input that lied to it. The attack-surface screen turned entirely red because an analyzer
     * failed, which is the exact shape ADR-0007 exists to forbid.
     *
     * <p>An <em>empty but present</em> list still clears its half. That is not the same case: the
     * cataloguer ran and found nothing, so the target genuinely declares no contracts, and leaving
     * yesterday's behind would be the opposite mistake.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void record(
            ScanEntity scan, Optional<List<ApiEndpoint>> endpointsFound, Optional<List<ApiContract>> contractsFound) {
        if (scan == null) return;
        long scanId = scan.getId();
        Long repoId = scan.getRepoId();

        List<ApiEndpoint> endpoints = endpointsFound.orElse(null);
        List<ApiContract> contracts = contractsFound.orElse(null);

        // Cleared per half, and only for the half whose analyzer reported. Deleting the other
        // would be replacing knowledge with an absence of evidence.
        if (endpointsFound.isPresent()) {
            apiEndpoints.deleteByRepositoryIdOrScanId(repoId, scanId);
        }
        if (contractsFound.isPresent()) {
            apiContracts.deleteByRepositoryIdOrScanId(repoId, scanId);
        }

        if (endpoints != null && !endpoints.isEmpty()) {
            List<ApiEndpointEntity> entities = new ArrayList<>();
            Instant now = clock.instant();

            // Deduplicate incoming scan endpoints by method + path
            Map<String, ApiEndpoint> uniqueEndpoints = new LinkedHashMap<>();
            for (ApiEndpoint ep : endpoints) {
                uniqueEndpoints.put(ep.method().toUpperCase() + ":" + ep.path(), ep);
            }

            for (ApiEndpoint ep : uniqueEndpoints.values()) {
                ApiEndpointEntity entity = new ApiEndpointEntity();
                entity.setScanId(scanId);
                entity.setRepositoryId(repoId);
                entity.setHttpMethod(trim(ep.method(), 20));
                entity.setPath(trim(ep.path(), 1000));
                entity.setAuthRequired(ep.authRequired());
                entity.setAuthType(trim(ep.authType(), 50));
                entity.setVisibility(ep.visibility() != null ? ep.visibility().name() : ApiVisibility.UNKNOWN.name());
                entity.setFilePath(trim(ep.filePath(), 1000));
                entity.setLineNumber(ep.lineNumber());
                entity.setFramework(trim(ep.framework(), 50));
                entity.setOperationId(trim(ep.operationId(), 255));
                entity.setSummary(trim(ep.summary(), 500));
                entity.setTags(trim(ep.tags(), 255));
                entity.setCreatedAt(now);
                entities.add(entity);
            }
            apiEndpoints.saveAll(entities);
        }

        if (contracts != null && !contracts.isEmpty()) {
            List<ApiContractEntity> entities = new ArrayList<>();
            Instant now = clock.instant();

            for (ApiContract c : contracts) {
                ApiContractEntity entity = new ApiContractEntity();
                entity.setScanId(scanId);
                entity.setRepositoryId(repoId != null ? repoId : 0L);
                entity.setContractPath(trim(c.contractPath(), 1000));
                entity.setFormat(trim(c.format(), 50));
                entity.setTitle(trim(c.title(), 255));
                entity.setVersion(trim(c.version(), 50));
                entity.setEndpointsCount(c.endpointsCount());
                entity.setCreatedAt(now);
                entities.add(entity);
            }
            apiContracts.saveAll(entities);
        }
    }

    /**
     * Purges all discovered endpoints and contracts from the inventory.
     */
    @Transactional
    public void clearAll() {
        apiEndpoints.deleteAllInBatch();
        apiContracts.deleteAllInBatch();
    }

    /**
     * Purges discovered endpoints and contracts for a specific repository.
     */
    @Transactional
    public void clearForRepository(long repositoryId) {
        apiEndpoints.deleteByRepositoryIdOrScanId(repositoryId, -1L);
        apiContracts.deleteByRepositoryIdOrScanId(repositoryId, -1L);
    }

    /**
     * The endpoint views of several repositories, in two queries rather than two per repository.
     *
     * <p><b>Built for the attack path overview</b>, which called {@link #forRepository(long)} in a
     * loop. The shadow-API status is computed per repository exactly as it is there — an endpoint
     * is documented, undocumented or shadow relative to <em>its own</em> repository's contracts,
     * so the grouping has to happen before the comparison, not after.
     */
    @Transactional(readOnly = true)
    public Map<Long, List<EndpointView>> endpointViewsByRepository(Collection<Long> repositoryIds) {
        if (repositoryIds.isEmpty()) {
            return Map.of();
        }

        Map<Long, List<ApiEndpointEntity>> endpointsByRepo = apiEndpoints.findByRepositoryIdIn(repositoryIds)
                .stream()
                .filter(e -> e.getRepositoryId() != null)
                .collect(Collectors.groupingBy(ApiEndpointEntity::getRepositoryId));
        Map<Long, List<ApiContractEntity>> contractsByRepo = apiContracts.findByRepositoryIdIn(repositoryIds)
                .stream()
                .filter(c -> c.getRepositoryId() != null)
                .collect(Collectors.groupingBy(ApiContractEntity::getRepositoryId));

        Map<Long, List<EndpointView>> byRepository = new LinkedHashMap<>();
        for (Long repositoryId : repositoryIds) {
            byRepository.put(
                    repositoryId,
                    viewsOf(
                            endpointsByRepo.getOrDefault(repositoryId, List.of()),
                            contractsByRepo.getOrDefault(repositoryId, List.of())));
        }
        return byRepository;
    }

    /**
     * Returns API overview for a specific repository with Shadow API diff against contracts.
     */
    @Transactional(readOnly = true)
    public RepositoryApisOverview forRepository(long repositoryId) {
        List<ApiEndpointEntity> rawEndpointEntities = apiEndpoints.findByRepositoryIdOrderByPathAsc(repositoryId);
        List<ApiContractEntity> contractEntities = apiContracts.findByRepositoryIdOrderByCreatedAtDesc(repositoryId);

        // Deduplicate in memory by method + path (keep latest by ID)
        Map<String, ApiEndpointEntity> byMethodPath = new LinkedHashMap<>();
        for (ApiEndpointEntity e : rawEndpointEntities) {
            byMethodPath.put(e.getHttpMethod().toUpperCase() + ":" + e.getPath(), e);
        }
        List<ApiEndpointEntity> endpointEntities = new ArrayList<>(byMethodPath.values());

        // Convert entities to domain for diff computation
        List<ApiEndpoint> domainEndpoints = new ArrayList<>();
        for (ApiEndpointEntity e : endpointEntities) {
            domainEndpoints.add(new ApiEndpoint(
                    e.getHttpMethod(),
                    e.getPath(),
                    Boolean.TRUE.equals(e.getAuthRequired()),
                    e.getAuthType(),
                    ApiVisibility.valueOf(e.getVisibility() != null ? e.getVisibility() : "UNKNOWN"),
                    e.getFilePath(),
                    e.getLineNumber(),
                    e.getFramework(),
                    e.getOperationId(),
                    e.getSummary(),
                    e.getTags()));
        }

        List<ApiContract> domainContracts = new ArrayList<>();
        for (ApiContractEntity c : contractEntities) {
            domainContracts.add(new ApiContract(
                    c.getContractPath(),
                    c.getFormat(),
                    c.getTitle(),
                    c.getVersion(),
                    c.getEndpointsCount(),
                    List.of()));
        }

        ShadowApiDiff diff = ShadowApiDiff.compute(domainEndpoints, domainContracts);
        Set<String> shadowPathMethods = new HashSet<>();
        for (ApiEndpoint se : diff.shadowEndpoints()) {
            shadowPathMethods.add(se.method() + ":" + se.path());
        }

        List<EndpointView> views = new ArrayList<>();
        for (ApiEndpointEntity e : endpointEntities) {
            String key = e.getHttpMethod() + ":" + e.getPath();
            String status = contractEntities.isEmpty()
                    ? "UNDOCUMENTED"
                    : (shadowPathMethods.contains(key) ? ShadowApiStatus.SHADOW_API.name() : ShadowApiStatus.DOCUMENTED.name());

            views.add(new EndpointView(
                    e.getId(),
                    e.getScanId(),
                    e.getRepositoryId(),
                    e.getHttpMethod(),
                    e.getPath(),
                    Boolean.TRUE.equals(e.getAuthRequired()),
                    e.getAuthType(),
                    e.getVisibility(),
                    e.getFilePath(),
                    e.getLineNumber(),
                    e.getFramework(),
                    e.getOperationId(),
                    e.getSummary(),
                    e.getTags(),
                    status,
                    e.getCreatedAt()));
        }

        AttackSurfaceSummary summary = AttackSurfaceSummary.from(domainEndpoints, diff);
        return new RepositoryApisOverview(repositoryId, views, contractEntities, summary);
    }

    /**
     * Cross-repository global attack surface summary and high-risk endpoints,
     * <b>within the caller's allowance</b>.
     *
     * <p>It read every endpoint and every contract and answered with all of them, to any
     * authenticated account. Paths, methods, and where the declared contract and the discovered
     * code disagree — the shadow endpoints — are the most directly useful thing in this product
     * to somebody probing a neighbouring team.
     */
    @Transactional(readOnly = true)
    public GlobalAttackSurface globalAttackSurface(Visibility allowed) {
        List<Long> repositoryIds = allowed.asFilter()
                .map(targets -> targets.stream()
                        .filter(ScanTarget.Repository.class::isInstance)
                        .map(target -> ((ScanTarget.Repository) target).id())
                        .toList())
                .orElse(null);

        // An allowance of no repository is not an absent filter: `findByRepositoryIdIn` with an
        // empty collection answers empty, which is the right answer and the opposite of what
        // falling back to `findAll()` would give.
        List<ApiEndpointEntity> rawAll = repositoryIds == null
                ? apiEndpoints.findAll()
                : apiEndpoints.findByRepositoryIdIn(repositoryIds);
        List<ApiContractEntity> allContracts = repositoryIds == null
                ? apiContracts.findAll()
                : apiContracts.findByRepositoryIdIn(repositoryIds);
        List<String> frameworks = apiEndpoints.findDistinctFrameworks();

        // Deduplicate in memory by repositoryId + method + path (keep latest by ID)
        Map<String, ApiEndpointEntity> byRepoMethodPath = new LinkedHashMap<>();
        for (ApiEndpointEntity e : rawAll) {
            String key = (e.getRepositoryId() != null ? e.getRepositoryId() : 0L) + ":" + e.getHttpMethod().toUpperCase() + ":" + e.getPath();
            byRepoMethodPath.put(key, e);
        }
        List<ApiEndpointEntity> all = new ArrayList<>(byRepoMethodPath.values());

        List<ApiEndpoint> domainList = new ArrayList<>();
        for (ApiEndpointEntity e : all) {
            domainList.add(new ApiEndpoint(
                    e.getHttpMethod(),
                    e.getPath(),
                    Boolean.TRUE.equals(e.getAuthRequired()),
                    e.getAuthType(),
                    ApiVisibility.valueOf(e.getVisibility() != null ? e.getVisibility() : "UNKNOWN"),
                    e.getFilePath(),
                    e.getLineNumber(),
                    e.getFramework(),
                    e.getOperationId(),
                    e.getSummary(),
                    e.getTags()));
        }

        List<ApiContract> domainContracts = new ArrayList<>();
        for (ApiContractEntity c : allContracts) {
            domainContracts.add(new ApiContract(c.getContractPath(), c.getFormat(), c.getTitle(), c.getVersion(), c.getEndpointsCount(), List.of()));
        }

        ShadowApiDiff diff = ShadowApiDiff.compute(domainList, domainContracts);
        AttackSurfaceSummary summary = AttackSurfaceSummary.from(domainList, diff);

        List<EndpointView> highRisk = new ArrayList<>();
        List<EndpointView> allViews = new ArrayList<>();
        Set<String> shadowPathMethods = new HashSet<>();
        for (ApiEndpoint se : diff.shadowEndpoints()) {
            shadowPathMethods.add(se.method() + ":" + se.path());
        }

        for (ApiEndpointEntity e : all) {
            String key = e.getHttpMethod() + ":" + e.getPath();
            String status = allContracts.isEmpty()
                    ? "UNDOCUMENTED"
                    : (shadowPathMethods.contains(key) ? ShadowApiStatus.SHADOW_API.name() : ShadowApiStatus.DOCUMENTED.name());

            boolean unauth = !Boolean.TRUE.equals(e.getAuthRequired());
            boolean sensitive = isSensitive(e.getPath());
            boolean pub = "PUBLIC".equals(e.getVisibility());

            EndpointView view = new EndpointView(
                    e.getId(),
                    e.getScanId(),
                    e.getRepositoryId(),
                    e.getHttpMethod(),
                    e.getPath(),
                    Boolean.TRUE.equals(e.getAuthRequired()),
                    e.getAuthType(),
                    e.getVisibility(),
                    e.getFilePath(),
                    e.getLineNumber(),
                    e.getFramework(),
                    e.getOperationId(),
                    e.getSummary(),
                    e.getTags(),
                    status,
                    e.getCreatedAt());

            allViews.add(view);

            if (unauth && (sensitive || pub)) {
                highRisk.add(new EndpointView(
                        e.getId(), e.getScanId(), e.getRepositoryId(),
                        e.getHttpMethod(), e.getPath(), e.getAuthRequired(),
                        e.getAuthType(), e.getVisibility(), e.getFilePath(),
                        e.getLineNumber(), e.getFramework(), e.getOperationId(),
                        e.getSummary(), e.getTags(), "HIGH_RISK_EXPOSURE", e.getCreatedAt()));
            }
        }

        return new GlobalAttackSurface(
                summary.totalEndpoints(),
                summary.publicEndpoints(),
                summary.internalEndpoints(),
                summary.unauthenticatedEndpoints(),
                summary.shadowEndpoints(),
                summary.sensitiveUnprotectedEndpoints(),
                frameworks,
                highRisk,
                allViews);
    }

    /**
     * Synthesizes an OpenAPI 3.0.3 specification from all discovered endpoints in a repository.
     */
    @Transactional(readOnly = true)
    public String exportSynthesizedOpenApiJson(long repositoryId) {
        List<ApiEndpointEntity> endpoints = apiEndpoints.findByRepositoryIdOrderByPathAsc(repositoryId);
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"openapi\": \"3.0.3\",\n");
        json.append("  \"info\": {\n");
        json.append("    \"title\": \"Vectispire Synthesized API Inventory\",\n");
        json.append("    \"version\": \"1.0.0\",\n");
        json.append("    \"description\": \"Automatically generated by Vectispire Attack Surface Discovery\"\n");
        json.append("  },\n");
        json.append("  \"paths\": {\n");

        Set<String> uniquePaths = new HashSet<>();
        for (ApiEndpointEntity ep : endpoints) {
            uniquePaths.add(ep.getPath());
        }

        List<String> sortedPaths = new ArrayList<>(uniquePaths);
        Collections.sort(sortedPaths);

        for (int pIdx = 0; pIdx < sortedPaths.size(); pIdx++) {
            String path = sortedPaths.get(pIdx);
            json.append("    \"").append(escapeJson(path)).append("\": {\n");

            List<ApiEndpointEntity> methodsForPath = endpoints.stream()
                    .filter(e -> e.getPath().equals(path))
                    .toList();

            for (int mIdx = 0; mIdx < methodsForPath.size(); mIdx++) {
                ApiEndpointEntity ep = methodsForPath.get(mIdx);
                String verb = ep.getHttpMethod().toLowerCase();
                if (verb.equals("all")) verb = "get";

                json.append("      \"").append(verb).append("\": {\n");
                json.append("        \"summary\": \"").append(escapeJson(ep.getSummary() != null ? ep.getSummary() : "Discovered in " + ep.getFilePath())).append("\",\n");
                json.append("        \"operationId\": \"").append(escapeJson(ep.getOperationId() != null ? ep.getOperationId() : verb + "_" + path.replaceAll("[^a-zA-Z0-9]", "_"))).append("\",\n");
                json.append("        \"responses\": {\n");
                json.append("          \"200\": {\"description\": \"OK response\"}\n");
                json.append("        }\n");
                json.append("      }").append(mIdx < methodsForPath.size() - 1 ? "," : "").append("\n");
            }

            json.append("    }").append(pIdx < sortedPaths.size() - 1 ? "," : "").append("\n");
        }

        json.append("  }\n");
        json.append("}\n");
        return json.toString();
    }

    private static boolean isSensitive(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        return lower.contains("/admin") || lower.contains("/actuator") || lower.contains("/debug")
                || lower.contains("/metrics") || lower.contains("/env") || lower.contains("/internal");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String trim(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }

    /**
     * Entities to views, with the shadow-API status they carry.
     *
     * <p>Extracted from {@code forRepository} verbatim so the batch path and the single-target
     * path cannot drift: the deduplication keeps the latest row per method-and-path, and the
     * status is computed against this repository's own contracts.
     */
    private static List<EndpointView> viewsOf(
            List<ApiEndpointEntity> rawEndpointEntities, List<ApiContractEntity> contractEntities) {

        Map<String, ApiEndpointEntity> byMethodPath = new LinkedHashMap<>();
        for (ApiEndpointEntity e : rawEndpointEntities) {
            byMethodPath.put(e.getHttpMethod().toUpperCase() + ":" + e.getPath(), e);
        }
        List<ApiEndpointEntity> endpointEntities = new ArrayList<>(byMethodPath.values());

        List<ApiEndpoint> domainEndpoints = new ArrayList<>();
        for (ApiEndpointEntity e : endpointEntities) {
            domainEndpoints.add(new ApiEndpoint(
                    e.getHttpMethod(),
                    e.getPath(),
                    Boolean.TRUE.equals(e.getAuthRequired()),
                    e.getAuthType(),
                    ApiVisibility.valueOf(e.getVisibility() != null ? e.getVisibility() : "UNKNOWN"),
                    e.getFilePath(),
                    e.getLineNumber(),
                    e.getFramework(),
                    e.getOperationId(),
                    e.getSummary(),
                    e.getTags()));
        }

        List<ApiContract> domainContracts = new ArrayList<>();
        for (ApiContractEntity c : contractEntities) {
            domainContracts.add(new ApiContract(
                    c.getContractPath(),
                    c.getFormat(),
                    c.getTitle(),
                    c.getVersion(),
                    c.getEndpointsCount(),
                    List.of()));
        }

        ShadowApiDiff diff = ShadowApiDiff.compute(domainEndpoints, domainContracts);
        Set<String> shadowPathMethods = new HashSet<>();
        for (ApiEndpoint se : diff.shadowEndpoints()) {
            shadowPathMethods.add(se.method() + ":" + se.path());
        }

        List<EndpointView> views = new ArrayList<>();
        for (ApiEndpointEntity e : endpointEntities) {
            String key = e.getHttpMethod() + ":" + e.getPath();
            String status = contractEntities.isEmpty()
                    ? "UNDOCUMENTED"
                    : (shadowPathMethods.contains(key) ? ShadowApiStatus.SHADOW_API.name() : ShadowApiStatus.DOCUMENTED.name());

            views.add(new EndpointView(
                    e.getId(),
                    e.getScanId(),
                    e.getRepositoryId(),
                    e.getHttpMethod(),
                    e.getPath(),
                    Boolean.TRUE.equals(e.getAuthRequired()),
                    e.getAuthType(),
                    e.getVisibility(),
                    e.getFilePath(),
                    e.getLineNumber(),
                    e.getFramework(),
                    e.getOperationId(),
                    e.getSummary(),
                    e.getTags(),
                    status,
                    e.getCreatedAt()));
        }
        return views;
    }

}
