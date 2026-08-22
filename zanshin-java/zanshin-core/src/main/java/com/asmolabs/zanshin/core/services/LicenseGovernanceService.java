package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.licenses.LicenseEntry;
import com.asmolabs.zanshin.common.domain.licenses.LicensePolicy;
import com.asmolabs.zanshin.common.domain.licenses.LicenseRiskCategory;
import com.asmolabs.zanshin.common.domain.licenses.LicenseSummary;
import com.asmolabs.zanshin.core.persistence.ComponentEntity;
import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.LicensePolicyEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Components;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.Findings;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.LicensePolicies;
import com.asmolabs.zanshin.core.repositories.Scans;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service managing open source license inventory, copyleft risk classification, and policy compliance.
 */
@Service
public class LicenseGovernanceService {

    private final LicensePolicies policyRepo;
    private final Components componentsRepo;
    private final Findings findingsRepo;
    private final Scans scansRepo;
    private final GitRepositories gitRepo;
    private final Containers containersRepo;
    private final ObjectMapper objectMapper;

    public LicenseGovernanceService(
            LicensePolicies policyRepo,
            Components componentsRepo,
            Findings findingsRepo,
            Scans scansRepo,
            GitRepositories gitRepo,
            Containers containersRepo,
            ObjectMapper objectMapper) {
        this.policyRepo = policyRepo;
        this.componentsRepo = componentsRepo;
        this.findingsRepo = findingsRepo;
        this.scansRepo = scansRepo;
        this.gitRepo = gitRepo;
        this.containersRepo = containersRepo;
        this.objectMapper = objectMapper;
    }

    public LicensePolicy getPolicy() {
        return policyRepo.findById(LicensePolicyEntity.SINGLETON_ID)
                .map(this::toDomainPolicy)
                .orElseGet(LicensePolicy::defaultPolicy);
    }

    @Transactional
    public LicensePolicy updatePolicy(LicensePolicy policy) {
        LicensePolicyEntity entity = policyRepo.findById(LicensePolicyEntity.SINGLETON_ID)
                .orElseGet(() -> {
                    LicensePolicyEntity fresh = new LicensePolicyEntity();
                    fresh.setId(LicensePolicyEntity.SINGLETON_ID);
                    return fresh;
                });

        String disallowedCats = policy.disallowedCategories().stream()
                .map(Enum::name)
                .collect(Collectors.joining(","));
        entity.setDisallowedCategories(disallowedCats);
        entity.setAllowedLicenses(String.join(",", policy.explicitlyAllowedLicenses()));
        entity.setDisallowedLicenses(String.join(",", policy.explicitlyDisallowedLicenses()));
        entity.setUpdatedAt(Instant.now());

        policyRepo.save(entity);
        return policy;
    }

    public List<LicenseEntry> getInventory() {
        return getInventory(null, null);
    }

    public List<LicenseEntry> getInventory(Long repoIdFilter, Long containerIdFilter) {
        LicensePolicy policy = getPolicy();
        Map<String, LicenseEntry> entryMap = new HashMap<>();

        Map<Long, RepositoryEntity> repos = gitRepo.findAll().stream()
                .collect(Collectors.toMap(RepositoryEntity::getId, r -> r, (a, b) -> a));

        Map<Long, ContainerEntity> containers = containersRepo.findAll().stream()
                .collect(Collectors.toMap(ContainerEntity::getId, c -> c, (a, b) -> a));

        Map<Long, ScanEntity> scans = scansRepo.findAll().stream()
                .collect(Collectors.toMap(ScanEntity::getId, s -> s, (a, b) -> a));

        // 1. Ingest real licenses from Scan SBOMs (Syft / CycloneDX)
        for (ScanEntity scan : scans.values()) {
            if (repoIdFilter != null && !Objects.equals(scan.getRepoId(), repoIdFilter)) {
                continue;
            }
            if (containerIdFilter != null && !Objects.equals(scan.getContainerId(), containerIdFilter)) {
                continue;
            }
            if (repoIdFilter == null && containerIdFilter != null && scan.getRepoId() != null) {
                continue;
            }

            Long targetId = scan.getRepoId() != null ? scan.getRepoId() : scan.getContainerId();
            String targetKind = scan.getRepoId() != null ? "repository" : (scan.getContainerId() != null ? "container" : "general");
            String targetName = scan.getRepoId() != null && repos.containsKey(scan.getRepoId())
                    ? repos.get(scan.getRepoId()).getName()
                    : (scan.getContainerId() != null && containers.containsKey(scan.getContainerId())
                            ? containers.get(scan.getContainerId()).getImageName() + ":" + containers.get(scan.getContainerId()).getTag()
                            : "General");

            if (scan.getSbom() != null && !scan.getSbom().isBlank()) {
                try {
                    JsonNode root = objectMapper.readTree(scan.getSbom());
                    JsonNode artifacts = root.path("artifacts");
                    if (artifacts.isArray()) {
                        for (JsonNode artifact : artifacts) {
                            String name = artifact.path("name").asText(null);
                            if (name == null || name.isBlank()) continue;
                            String version = artifact.path("version").asText(null);
                            String purl = artifact.path("purl").asText(null);

                            String license = extractLicenseFromSbom(artifact);
                            if (license == null || license.isBlank() || "UNKNOWN".equalsIgnoreCase(license)) {
                                license = inferLicense(name);
                            }

                            LicenseRiskCategory risk = LicenseRiskCategory.classify(license);
                            boolean compliant = policy.isCompliant(license, risk);
                            String violationReason = compliant ? null : "License " + license + " is forbidden under active compliance policy (" + risk + ")";

                            String key = targetKind + ":" + targetId + ":" + name + ":" + (version != null ? version : "");
                            entryMap.put(key, new LicenseEntry(
                                    name,
                                    version != null ? version : "unknown",
                                    purl,
                                    license,
                                    risk,
                                    compliant,
                                    violationReason,
                                    targetId,
                                    targetKind,
                                    targetName));
                        }
                    }
                } catch (Exception ignored) {}
            }
        }

        // 2. Check components from CycloneDX/Component table for any scan not covered by full SBOM JSON
        List<ComponentEntity> components = componentsRepo.findAll();
        for (ComponentEntity comp : components) {
            ScanEntity scan = comp.getScanId() != null ? scans.get(comp.getScanId()) : null;
            if (scan == null) continue;

            if (repoIdFilter != null && !Objects.equals(scan.getRepoId(), repoIdFilter)) {
                continue;
            }
            if (containerIdFilter != null && !Objects.equals(scan.getContainerId(), containerIdFilter)) {
                continue;
            }

            Long targetId = scan.getRepoId() != null ? scan.getRepoId() : scan.getContainerId();
            String targetKind = scan.getRepoId() != null ? "repository" : (scan.getContainerId() != null ? "container" : "general");
            String targetName = scan.getRepoId() != null && repos.containsKey(scan.getRepoId())
                    ? repos.get(scan.getRepoId()).getName()
                    : (scan.getContainerId() != null && containers.containsKey(scan.getContainerId())
                            ? containers.get(scan.getContainerId()).getImageName() + ":" + containers.get(scan.getContainerId()).getTag()
                            : "General");

            String key = targetKind + ":" + targetId + ":" + comp.getName() + ":" + (comp.getVersion() != null ? comp.getVersion() : "");
            if (!entryMap.containsKey(key)) {
                String inferredLicense = inferLicense(comp.getName());
                LicenseRiskCategory risk = LicenseRiskCategory.classify(inferredLicense);
                boolean compliant = policy.isCompliant(inferredLicense, risk);
                String violationReason = compliant ? null : "License " + inferredLicense + " is forbidden under active compliance policy (" + risk + ")";

                entryMap.put(key, new LicenseEntry(
                        comp.getName(),
                        comp.getVersion() != null ? comp.getVersion() : "unknown",
                        comp.getPurl(),
                        inferredLicense,
                        risk,
                        compliant,
                        violationReason,
                        targetId,
                        targetKind,
                        targetName));
            }
        }

        // 3. Check direct license findings from scanners (Trivy license scanner)
        List<FindingEntity> licenseFindings = findingsRepo.findAll().stream()
                .filter(f -> "license".equalsIgnoreCase(f.getType()) || (f.getSource() != null && f.getSource().contains("license")))
                .toList();

        for (FindingEntity finding : licenseFindings) {
            ScanEntity scan = finding.getScanId() != null ? scans.get(finding.getScanId()) : null;
            if (scan == null) continue;

            if (repoIdFilter != null && !Objects.equals(scan.getRepoId(), repoIdFilter)) {
                continue;
            }
            if (containerIdFilter != null && !Objects.equals(scan.getContainerId(), containerIdFilter)) {
                continue;
            }

            Long targetId = scan.getRepoId() != null ? scan.getRepoId() : scan.getContainerId();
            String targetKind = scan.getRepoId() != null ? "repository" : (scan.getContainerId() != null ? "container" : "general");
            String targetName = scan.getRepoId() != null && repos.containsKey(scan.getRepoId())
                    ? repos.get(scan.getRepoId()).getName()
                    : (scan.getContainerId() != null && containers.containsKey(scan.getContainerId())
                            ? containers.get(scan.getContainerId()).getImageName() + ":" + containers.get(scan.getContainerId()).getTag()
                            : "General");

            String license = finding.getIdentifier() != null ? finding.getIdentifier() : "UNKNOWN";
            LicenseRiskCategory risk = LicenseRiskCategory.classify(license);
            boolean compliant = policy.isCompliant(license, risk);
            String violationReason = compliant ? null : "License " + license + " is forbidden under active compliance policy (" + risk + ")";

            String key = targetKind + ":" + targetId + ":" + (finding.getPackageName() != null ? finding.getPackageName() : "unknown") + ":" + (finding.getPackageVersion() != null ? finding.getPackageVersion() : "");
            entryMap.put(key, new LicenseEntry(
                    finding.getPackageName() != null ? finding.getPackageName() : "unknown",
                    finding.getPackageVersion() != null ? finding.getPackageVersion() : "unknown",
                    finding.getPurl(),
                    license,
                    risk,
                    compliant,
                    violationReason,
                    targetId,
                    targetKind,
                    targetName));
        }

        return new ArrayList<>(entryMap.values());
    }

    public LicenseSummary getSummary() {
        return getSummary(null, null);
    }

    public LicenseSummary getSummary(Long repoIdFilter, Long containerIdFilter) {
        List<LicenseEntry> inventory = getInventory(repoIdFilter, containerIdFilter);
        Map<LicenseRiskCategory, Long> breakdown = new EnumMap<>(LicenseRiskCategory.class);
        for (LicenseRiskCategory cat : LicenseRiskCategory.values()) {
            breakdown.put(cat, 0L);
        }

        Set<String> uniqueLicenses = new HashSet<>();
        long nonCompliantCount = 0;

        for (LicenseEntry entry : inventory) {
            breakdown.put(entry.riskCategory(), breakdown.getOrDefault(entry.riskCategory(), 0L) + 1);
            if (entry.license() != null && !entry.license().isBlank()) {
                uniqueLicenses.add(entry.license());
            }
            if (!entry.compliant()) {
                nonCompliantCount++;
            }
        }

        return new LicenseSummary(
                inventory.size(),
                uniqueLicenses.size(),
                nonCompliantCount,
                breakdown);
    }

    private String extractLicenseFromSbom(JsonNode artifact) {
        JsonNode licenses = artifact.path("licenses");
        if (licenses.isArray() && !licenses.isEmpty()) {
            List<String> values = new ArrayList<>();
            for (JsonNode lic : licenses) {
                if (lic.isTextual()) {
                    values.add(lic.asText());
                } else if (lic.isObject()) {
                    if (lic.hasNonNull("spdxExpression")) {
                        values.add(lic.path("spdxExpression").asText());
                    } else if (lic.hasNonNull("value")) {
                        values.add(lic.path("value").asText());
                    } else if (lic.has("license") && lic.path("license").hasNonNull("id")) {
                        values.add(lic.path("license").path("id").asText());
                    } else if (lic.has("license") && lic.path("license").hasNonNull("name")) {
                        values.add(lic.path("license").path("name").asText());
                    }
                }
            }
            if (!values.isEmpty()) {
                return String.join(" OR ", values);
            }
        }
        return null;
    }

    private String inferLicense(String packageName) {
        if (packageName == null) return "UNKNOWN";
        String lower = packageName.toLowerCase();
        if (lower.contains("gpl") || lower.contains("mysql-connector")) return "GPL-2.0";
        if (lower.contains("agpl")) return "AGPL-3.0";
        if (lower.contains("hibernate") || lower.contains("lgpl")) return "LGPL-2.1";
        if (lower.contains("apache") || lower.contains("spring") || lower.contains("commons") || lower.contains("log4j") || lower.contains("jackson")) return "Apache-2.0";
        if (lower.contains("react") || lower.contains("angular") || lower.contains("vue") || lower.contains("lodash") || lower.contains("express")) return "MIT";
        if (lower.contains("postgres") || lower.contains("sqlite")) return "BSD-3-Clause";
        return "MIT";
    }

    private LicensePolicy toDomainPolicy(LicensePolicyEntity entity) {
        Set<LicenseRiskCategory> disallowed = new HashSet<>();
        if (entity.getDisallowedCategories() != null) {
            for (String part : entity.getDisallowedCategories().split(",")) {
                try {
                    disallowed.add(LicenseRiskCategory.valueOf(part.trim()));
                } catch (Exception ignored) {}
            }
        }
        Set<String> allowed = entity.getAllowedLicenses() != null && !entity.getAllowedLicenses().isBlank()
                ? Arrays.stream(entity.getAllowedLicenses().split(",")).map(String::trim).collect(Collectors.toSet())
                : Set.of();
        Set<String> dis = entity.getDisallowedLicenses() != null && !entity.getDisallowedLicenses().isBlank()
                ? Arrays.stream(entity.getDisallowedLicenses().split(",")).map(String::trim).collect(Collectors.toSet())
                : Set.of();

        return new LicensePolicy(disallowed, allowed, dis);
    }
}
