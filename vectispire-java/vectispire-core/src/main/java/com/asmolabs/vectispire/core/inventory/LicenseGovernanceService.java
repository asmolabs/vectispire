package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.licenses.LicenseConflictMatrix;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseRiskCategory;
import com.asmolabs.vectispire.common.domain.licenses.LicenseSummary;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.Components;
import com.asmolabs.vectispire.core.inventory.persistence.LicensePolicies;
import com.asmolabs.vectispire.core.inventory.persistence.LicensePolicyEntity;
import com.asmolabs.vectispire.core.services.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.services.scanning.ScanFindingView;
import com.asmolabs.vectispire.core.services.scanning.ScanView;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Service managing open source license inventory, copyleft risk classification, and policy compliance.
 */
@Service
public class LicenseGovernanceService {

    private static final Logger log = LoggerFactory.getLogger(LicenseGovernanceService.class);

    private final LicensePolicies policyRepo;
    private final Components componentsRepo;
    private final ScanCatalog scansRepo;
    private final TargetCatalog targets;
    private final ObjectMapper objectMapper;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;

    public LicenseGovernanceService(
            LicensePolicies policyRepo,
            Components componentsRepo,
            ScanCatalog scansRepo,
            TargetCatalog targets,
            ObjectMapper objectMapper,
            AuditLogService audit,
            TransactionTemplate transactions) {
        this.policyRepo = policyRepo;
        this.componentsRepo = componentsRepo;
        this.scansRepo = scansRepo;
        this.targets = targets;
        this.objectMapper = objectMapper;
        this.audit = audit;
        this.transactions = transactions;
    }

    public LicensePolicy getPolicy() {
        return policyRepo.findById(LicensePolicyEntity.SINGLETON_ID)
                .map(this::toDomainPolicy)
                .orElseGet(LicensePolicy::defaultPolicy);
    }

    /**
     * Stores the policy, then audits it.
     *
     * <p>Through a {@link TransactionTemplate} rather than by calling the annotated method below:
     * through {@code this} the annotation is bypassed, and the audit entry has to follow the commit
     * rather than sit inside it — it opens its own transaction, which on SQLite waits on the
     * parent's lock, the lock being the file.
     */
    public LicensePolicy updatePolicy(LicensePolicy policy, RequestActor actor) {
        if (policy == null) {
            throw new IllegalArgumentException("A licence policy is required.");
        }
        // The record has already dropped nulls and upper-cased the identifiers. What it cannot
        // decide is what the storage can hold: the lists are stored comma-joined, so an entry
        // holding a comma would come back as two, and each list is a `text` column.
        requireStorable(policy.explicitlyAllowedLicenses(), "allowed");
        requireStorable(policy.explicitlyDisallowedLicenses(), "disallowed");
        LicensePolicy updated = transactions.execute(status -> updatePolicy(policy));
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                "license_policy",
                "Updated open source license compliance policy (disallowed=" + policy.disallowedCategories() + ")"));
        return updated;
    }

    private static void requireStorable(Set<String> licences, String which) {
        licences.stream().filter(licence -> licence.contains(",")).findFirst().ifPresent(licence -> {
            throw new IllegalArgumentException("\"" + licence + "\" contains a comma: list each "
                    + which + " licence as an entry of its own.");
        });
        BoundedText.within(String.join(",", licences), BoundedText.TEXT_MAX, "The " + which + " licence list");
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

    /**
     * The licence inventory, <b>read for the target asked about rather than for the estate</b>.
     *
     * <p><b>The filter arrived and was then ignored by every read.</b> It read every scan, every
     * component and every finding in the deployment and applied {@code repoIdFilter} afterwards
     * in Java. A scan row carries its whole SBOM payload — megabytes of JSON apiece — so asking
     * for one repository's licences parsed the estate's, and the security scorecard did exactly
     * that on every call: it asked for the unfiltered inventory and then kept one target's rows.
     *
     * <p>The scans are selected first and everything else is keyed to them, which is the shape
     * the method already had in Java and now has in SQL.
     */
    public List<LicenseEntry> getInventory(Long repoIdFilter, Long containerIdFilter) {
        LicensePolicy policy = getPolicy();
        Map<String, LicenseEntry> entryMap = new HashMap<>();

        Map<Long, RepositoryView> repos = targets.repositories().stream()
                .collect(Collectors.toMap(RepositoryView::id, r -> r, (a, b) -> a));

        Map<Long, ContainerView> containers = targets.containers().stream()
                .collect(Collectors.toMap(ContainerView::id, c -> c, (a, b) -> a));

        List<ScanView> selected;
        if (repoIdFilter != null) {
            selected = scansRepo.ofRepository(repoIdFilter);
        } else if (containerIdFilter != null) {
            selected = scansRepo.ofContainer(containerIdFilter);
        } else {
            selected = scansRepo.all();
        }
        Map<Long, ScanView> scans = selected.stream()
                .collect(Collectors.toMap(ScanView::id, s -> s, (a, b) -> a));

        // 1. Ingest real licenses from Scan SBOMs (Syft / CycloneDX)
        for (ScanView scan : scans.values()) {
            if (repoIdFilter != null && !Objects.equals(scan.repoId(), repoIdFilter)) {
                continue;
            }
            if (containerIdFilter != null && !Objects.equals(scan.containerId(), containerIdFilter)) {
                continue;
            }
            if (repoIdFilter == null && containerIdFilter != null && scan.repoId() != null) {
                continue;
            }

            Long targetId = scan.repoId() != null ? scan.repoId() : scan.containerId();
            String targetKind = scan.repoId() != null ? "repository" : (scan.containerId() != null ? "container" : "general");
            String targetName = scan.repoId() != null && repos.containsKey(scan.repoId())
                    ? repos.get(scan.repoId()).name()
                    : (scan.containerId() != null && containers.containsKey(scan.containerId())
                            ? containers.get(scan.containerId()).imageName() + ":" + containers.get(scan.containerId()).tag()
                            : "General");

            if (scan.sbom() != null && !scan.sbom().isBlank()) {
                try {
                    JsonNode root = objectMapper.readTree(scan.sbom());
                    JsonNode artifacts = root.path("artifacts");
                    if (artifacts.isArray()) {
                        for (JsonNode artifact : artifacts) {
                            String name = artifact.path("name").asText(null);
                            if (name == null || name.isBlank()) continue;
                            String version = artifact.path("version").asText(null);
                            String purl = artifact.path("purl").asText(null);

                            String license = extractLicenseFromSbom(artifact);
                            if (license == null || license.isBlank() || "UNKNOWN".equalsIgnoreCase(license)) {
                                license = UNDECLARED;
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
                } catch (Exception unreadable) {
                    // Logged, not swallowed: an SBOM that no longer parses took every licence of
                    // its scan out of the inventory with nothing to say why.
                    log.warn("Scan {}: SBOM unreadable, its licences are missing from the inventory: {}",
                            scan.id(), unreadable.getMessage());
                }
            }
        }

        // 2. Check components from CycloneDX/Component table for any scan not covered by full SBOM JSON
        List<ComponentEntity> components =
                scans.isEmpty() ? List.of() : componentsRepo.findByScanIdIn(scans.keySet());
        for (ComponentEntity comp : components) {
            ScanView scan = comp.getScanId() != null ? scans.get(comp.getScanId()) : null;
            if (scan == null) continue;

            if (repoIdFilter != null && !Objects.equals(scan.repoId(), repoIdFilter)) {
                continue;
            }
            if (containerIdFilter != null && !Objects.equals(scan.containerId(), containerIdFilter)) {
                continue;
            }

            Long targetId = scan.repoId() != null ? scan.repoId() : scan.containerId();
            String targetKind = scan.repoId() != null ? "repository" : (scan.containerId() != null ? "container" : "general");
            String targetName = scan.repoId() != null && repos.containsKey(scan.repoId())
                    ? repos.get(scan.repoId()).name()
                    : (scan.containerId() != null && containers.containsKey(scan.containerId())
                            ? containers.get(scan.containerId()).imageName() + ":" + containers.get(scan.containerId()).tag()
                            : "General");

            String key = targetKind + ":" + targetId + ":" + comp.getName() + ":" + (comp.getVersion() != null ? comp.getVersion() : "");
            if (!entryMap.containsKey(key)) {
                String inferredLicense = UNDECLARED;
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
        List<ScanFindingView> licenseFindings =
                scans.isEmpty() ? List.of() : scansRepo.licenseFindings(scans.keySet());

        for (ScanFindingView finding : licenseFindings) {
            ScanView scan = finding.scanId() != null ? scans.get(finding.scanId()) : null;
            if (scan == null) continue;

            if (repoIdFilter != null && !Objects.equals(scan.repoId(), repoIdFilter)) {
                continue;
            }
            if (containerIdFilter != null && !Objects.equals(scan.containerId(), containerIdFilter)) {
                continue;
            }

            Long targetId = scan.repoId() != null ? scan.repoId() : scan.containerId();
            String targetKind = scan.repoId() != null ? "repository" : (scan.containerId() != null ? "container" : "general");
            String targetName = scan.repoId() != null && repos.containsKey(scan.repoId())
                    ? repos.get(scan.repoId()).name()
                    : (scan.containerId() != null && containers.containsKey(scan.containerId())
                            ? containers.get(scan.containerId()).imageName() + ":" + containers.get(scan.containerId()).tag()
                            : "General");

            String license = finding.identifier() != null ? finding.identifier() : "UNKNOWN";
            LicenseRiskCategory risk = LicenseRiskCategory.classify(license);
            boolean compliant = policy.isCompliant(license, risk);
            String violationReason = compliant ? null : "License " + license + " is forbidden under active compliance policy (" + risk + ")";

            String key = targetKind + ":" + targetId + ":" + (finding.packageName() != null ? finding.packageName() : "unknown") + ":" + (finding.packageVersion() != null ? finding.packageVersion() : "");
            entryMap.put(key, new LicenseEntry(
                    finding.packageName() != null ? finding.packageName() : "unknown",
                    finding.packageVersion() != null ? finding.packageVersion() : "unknown",
                    finding.purl(),
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

    /**
     * What an undeclared licence is recorded as: unknown, and nothing more.
     *
     * <p><b>It used to be guessed from the package name</b> — "spring" meant Apache-2.0, "react"
     * meant MIT, a name containing "gpl" meant GPL-2.0 — and <b>anything unrecognised was declared
     * MIT</b>, which is permissive, so compliant under every policy. The inventory, the scorecard
     * grade and the conflict evaluation therefore reported as cleared exactly the components whose
     * licence nobody had read, to an auditor with no way of telling a declared licence from an
     * invented one. Unknown is what the risk classification and the conflict matrix already have a
     * category for; a policy that refuses unknown licences can now actually see them.
     */
    private static final String UNDECLARED = "UNKNOWN";

    private LicensePolicy toDomainPolicy(LicensePolicyEntity entity) {
        Set<LicenseRiskCategory> disallowed = new HashSet<>();
        if (entity.getDisallowedCategories() != null) {
            for (String part : entity.getDisallowedCategories().split(",")) {
                try {
                    disallowed.add(LicenseRiskCategory.valueOf(part.trim()));
                } catch (IllegalArgumentException misspelt) {
                    // A misspelt category was dropped in silence, and the category it meant to
                    // forbid was then allowed. Still dropped — failing every read over it would
                    // take the screen down — but said.
                    if (!part.isBlank()) {
                        log.warn("Licence policy names an unknown risk category \"{}\" — it forbids nothing.", part.trim());
                    }
                }
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

    @Transactional(readOnly = true)
    public List<LicenseConflictMatrix.LicenseConflict> evaluateConflicts(Long repoId, Long containerId, boolean isProprietaryTarget) {
        List<LicenseEntry> inventory = getInventory(repoId, containerId);
        List<LicenseConflictMatrix.LicenseConflict> conflicts = new ArrayList<>();

        for (LicenseEntry entry : inventory) {
            LicenseConflictMatrix.LicenseConflict eval = LicenseConflictMatrix.evaluate(
                    entry.packageName(),
                    entry.packageVersion(),
                    entry.license(),
                    entry.targetKind(),
                    entry.targetName(),
                    isProprietaryTarget);

            if (eval.compatibility() != LicenseConflictMatrix.Compatibility.COMPATIBLE) {
                conflicts.add(eval);
            }
        }
        return conflicts;
    }

    public List<LicenseConflictMatrix.CompatibilityCell> getCompatibilityRules() {
        return LicenseConflictMatrix.getStandardCompatibilityRules();
    }
}
