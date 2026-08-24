package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.asmolabs.vectispire.common.domain.apis.AttackSurfaceSummary;
import com.asmolabs.vectispire.common.domain.apis.ShadowApiDiff;
import com.asmolabs.vectispire.common.domain.apis.ShadowApiStatus;
import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import com.asmolabs.vectispire.core.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.ApiContracts;
import com.asmolabs.vectispire.core.repositories.ApiEndpoints;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
     * Records discovered API endpoints and contracts from a scan.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void record(ScanEntity scan, List<ApiEndpoint> endpoints, List<ApiContract> contracts) {
        if (scan == null) return;
        long scanId = scan.getId();
        Long repoId = scan.getRepoId();

        // Atomic cleanup of prior scan and repository state
        apiEndpoints.deleteByRepositoryIdOrScanId(repoId, scanId);
        apiContracts.deleteByRepositoryIdOrScanId(repoId, scanId);

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
     * Cross-repository global attack surface summary and high risk endpoints.
     */
    @Transactional(readOnly = true)
    public GlobalAttackSurface globalAttackSurface() {
        List<ApiEndpointEntity> rawAll = apiEndpoints.findAll();
        List<ApiContractEntity> allContracts = apiContracts.findAll();
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
}
