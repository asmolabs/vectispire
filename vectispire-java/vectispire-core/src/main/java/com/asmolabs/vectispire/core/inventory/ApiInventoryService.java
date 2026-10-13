package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.asmolabs.vectispire.common.domain.apis.AttackSurfaceSummary;
import com.asmolabs.vectispire.common.domain.apis.ShadowApiDiff;
import com.asmolabs.vectispire.common.domain.apis.ShadowApiStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.inventory.persistence.ApiContractEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ApiContractRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ApiEndpointRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
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
            List<ApiContractView> contracts,
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

    /** Writes the synthesized document; a mapper of its own, since nothing of the API's configuration applies. */
    private static final ObjectMapper OPENAPI = new ObjectMapper();

    /** The operations a path item holds (OpenAPI 3.0.3, Path Item Object), in the specification's order. */
    private static final List<String> OPERATIONS =
            List.of("get", "put", "post", "delete", "options", "head", "patch", "trace");

    /** The method the discovery records for a handler of any method. */
    private static final String ANY_METHOD = "all";

    private final ApiEndpointRepository apiEndpoints;
    private final ApiContractRepository apiContracts;
    private final Clock clock;

    public ApiInventoryService(ApiEndpointRepository apiEndpoints, ApiContractRepository apiContracts, Clock clock) {
        this.apiEndpoints = apiEndpoints;
        this.apiContracts = apiContracts;
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
            long scanId, Long repoId, Optional<List<ApiEndpoint>> endpointsFound, Optional<List<ApiContract>> contractsFound) {

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
                uniqueEndpoints.put(ep.method().toUpperCase(Locale.ROOT) + ":" + ep.path(), ep);
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
     *
     * <p><b>A repository somebody checked</b>, like the reads beside it. Every account the route
     * admits holds a role that sees the whole estate today, so the check at the route refuses nothing
     * yet; a bare id would still let the next caller — a task, a neighbouring service, a route whose
     * marker is widened — erase an inventory it was never shown.
     */
    @Transactional
    public void clearForRepository(VisibleTarget<ScanTarget.Repository> repository) {
        long repositoryId = repository.target().id();
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
     *
     * <p><b>Repositories somebody checked, not ids</b> — the proof {@link #forRepository} takes, one
     * per repository. The overview filters by the caller's visibility before it asks; with bare ids,
     * the next caller would not have had to.
     */
    @Transactional(readOnly = true)
    public Map<Long, List<EndpointView>> endpointViewsByRepository(
            Collection<VisibleTarget<ScanTarget.Repository>> repositories) {
        if (repositories.isEmpty()) {
            return Map.of();
        }
        List<Long> repositoryIds = repositories.stream()
                .map(repository -> repository.target().id())
                .distinct()
                .toList();

        Map<Long, List<ApiEndpointEntity>> endpointsByRepo = endpointsOf(repositoryIds)
                .stream()
                .filter(e -> e.getRepositoryId() != null)
                .collect(Collectors.groupingBy(ApiEndpointEntity::getRepositoryId));
        Map<Long, List<ApiContractEntity>> contractsByRepo = contractsOf(repositoryIds)
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
     *
     * <p><b>A repository somebody checked, not an id.</b> The inventory is a map of the repository's
     * attack surface. This module's services do not use {@code access}, so the refusal is the
     * caller's, and this took whatever id it was handed — from its route and from the attack-path
     * graph alike. The parameter is the proof of that check ({@link VisibleTarget}), so a caller
     * added later cannot reach the read without it.
     */
    @Transactional(readOnly = true)
    public RepositoryApisOverview forRepository(VisibleTarget<ScanTarget.Repository> repository) {
        long repositoryId = repository.target().id();
        List<ApiEndpointEntity> rawEndpointEntities = apiEndpoints.findByRepositoryIdOrderByPathAsc(repositoryId);
        List<ApiContractEntity> contractEntities = apiContracts.findByRepositoryIdOrderByCreatedAtDesc(repositoryId);

        // Deduplicate in memory by method + path (keep latest by ID)
        Map<String, ApiEndpointEntity> byMethodPath = new LinkedHashMap<>();
        for (ApiEndpointEntity e : rawEndpointEntities) {
            byMethodPath.put(e.getHttpMethod().toUpperCase(Locale.ROOT) + ":" + e.getPath(), e);
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
        return new RepositoryApisOverview(
                repositoryId, views, contractEntities.stream().map(ApiContractView::of).toList(), summary);
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

        // An allowance of no repository is not an absent filter: `endpointsOf` with an
        // empty collection answers empty, which is the right answer and the opposite of what
        // falling back to `findAll()` would give.
        List<ApiEndpointEntity> rawAll = repositoryIds == null
                ? apiEndpoints.findAll()
                : endpointsOf(repositoryIds);
        List<ApiContractEntity> allContracts = repositoryIds == null
                ? apiContracts.findAll()
                : contractsOf(repositoryIds);
        List<String> frameworks = apiEndpoints.findDistinctFrameworks();

        // Deduplicate in memory by repositoryId + method + path (keep latest by ID)
        Map<String, ApiEndpointEntity> byRepoMethodPath = new LinkedHashMap<>();
        for (ApiEndpointEntity e : rawAll) {
            String key = (e.getRepositoryId() != null ? e.getRepositoryId() : 0L) + ":" + e.getHttpMethod().toUpperCase(Locale.ROOT) + ":" + e.getPath();
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
     * Synthesizes an OpenAPI 3.0.3 specification from all discovered endpoints in a repository —
     * one the caller was checked for, as {@link #forRepository} is.
     *
     * <p><b>Built as a tree and written by Jackson.</b> It was concatenated, with an escape that knew
     * only {@code \} and {@code "}: a summary or a path carrying a control character — a tab in a
     * comment the scanner read, a newline — made the document invalid JSON. Every scan's rows were
     * written, so a method seen by two scans was the same key twice in one path item, and a handler
     * for any method ({@code ALL}) became a second {@code get}; and each path filtered the whole list
     * again. One pass groups the rows by path and method now, the latest row of each kept, as {@link
     * #forRepository} keeps it.
     *
     * <p><b>A handler for any method is every operation a path item can hold</b> that the path does
     * not declare on its own: OpenAPI has no "any", and the inventory is of what answers — Spring's
     * {@code @RequestMapping} with no method, Express's {@code app.all}. A method OpenAPI has no key for
     * is left out rather than written under a key no reader knows.
     */
    @Transactional(readOnly = true)
    public String exportSynthesizedOpenApiJson(VisibleTarget<ScanTarget.Repository> repository) {
        long repositoryId = repository.target().id();
        Map<String, Map<String, ApiEndpointEntity>> byPath = new TreeMap<>();
        apiEndpoints.findByRepositoryIdOrderByPathAsc(repositoryId).stream()
                .filter(endpoint -> endpoint.getPath() != null && endpoint.getHttpMethod() != null)
                // Oldest first, so that the row a method keeps is its latest.
                .sorted(Comparator.comparing(ApiEndpointEntity::getId, Comparator.nullsFirst(Comparator.naturalOrder())))
                .forEach(endpoint -> byPath.computeIfAbsent(endpoint.getPath(), path -> new HashMap<>())
                        .put(endpoint.getHttpMethod().toLowerCase(Locale.ROOT), endpoint));

        ObjectNode document = OPENAPI.createObjectNode();
        document.put("openapi", "3.0.3");
        ObjectNode info = document.putObject("info");
        info.put("title", "Vectispire Synthesized API Inventory");
        info.put("version", "1.0.0");
        info.put("description", "Automatically generated by Vectispire Attack Surface Discovery");
        ObjectNode paths = document.putObject("paths");

        Set<String> operationIds = new HashSet<>();
        byPath.forEach((path, byMethod) -> {
            ObjectNode item = OPENAPI.createObjectNode();
            ApiEndpointEntity anyMethod = byMethod.get(ANY_METHOD);
            for (String verb : OPERATIONS) {
                ApiEndpointEntity declared = byMethod.get(verb);
                ApiEndpointEntity endpoint = declared != null ? declared : anyMethod;
                if (endpoint == null) {
                    continue;
                }
                ObjectNode operation = item.putObject(verb);
                String summary = endpoint.getSummary() != null ? endpoint.getSummary() : "Discovered in " + endpoint.getFilePath();
                operation.put("summary", declared != null ? summary : summary + " (any method)");
                operation.put("operationId", uniqueOperationId(endpoint, verb, path, declared == null, operationIds));
                operation.putObject("responses").putObject("200").put("description", "OK response");
            }
            if (!item.isEmpty()) {
                paths.set(path, item);
            }
        });

        try {
            return OPENAPI.writerWithDefaultPrettyPrinter().writeValueAsString(document);
        } catch (JsonProcessingException impossible) {
            // A tree of strings and objects cannot fail to write; a defect if it did.
            throw new IllegalStateException("The synthesized OpenAPI document could not be written.", impossible);
        }
    }

    /**
     * The source's operation name, or one made of the method and the path — unique in the document, as
     * OpenAPI requires: a handler for any method names one operation per verb, and two handlers may
     * share a method name.
     */
    private static String uniqueOperationId(
            ApiEndpointEntity endpoint, String verb, String path, boolean anyMethod, Set<String> taken) {
        String base = endpoint.getOperationId() != null
                ? (anyMethod ? endpoint.getOperationId() + "_" + verb : endpoint.getOperationId())
                : verb + "_" + path.replaceAll("[^a-zA-Z0-9]", "_");
        String candidate = base;
        for (int n = 2; !taken.add(candidate); n++) {
            candidate = base + "_" + n;
        }
        return candidate;
    }

    private static boolean isSensitive(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.contains("/admin") || lower.contains("/actuator") || lower.contains("/debug")
                || lower.contains("/metrics") || lower.contains("/env") || lower.contains("/internal");
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
            byMethodPath.put(e.getHttpMethod().toUpperCase(Locale.ROOT) + ":" + e.getPath(), e);
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

    /** Repositories per lookup: far under every engine's bind-parameter ceiling. */
    private static final int LOOKUP_BATCH = 1_000;

    /**
     * The endpoints of these repositories, a thousand repositories per statement: the attack surface
     * and the attack-path overview hand every repository the reader may see, and {@code
     * findByRepositoryIdIn} binds one parameter each — refused by the PostgreSQL driver past 65,535.
     */
    private List<ApiEndpointEntity> endpointsOf(Collection<Long> repositoryIds) {
        List<Long> distinct = List.copyOf(new HashSet<>(repositoryIds));
        List<ApiEndpointEntity> found = new ArrayList<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            found.addAll(apiEndpoints.findByRepositoryIdIn(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size()))));
        }
        return found;
    }

    /** The contracts of these repositories, batched as {@link #endpointsOf}. */
    private List<ApiContractEntity> contractsOf(Collection<Long> repositoryIds) {
        List<Long> distinct = List.copyOf(new HashSet<>(repositoryIds));
        List<ApiContractEntity> found = new ArrayList<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            found.addAll(apiContracts.findByRepositoryIdIn(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size()))));
        }
        return found;
    }
}
