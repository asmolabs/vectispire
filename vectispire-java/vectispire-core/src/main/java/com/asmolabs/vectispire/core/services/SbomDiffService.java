package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.sbom.ComponentDelta;
import com.asmolabs.vectispire.common.domain.sbom.ComponentDelta.ChangeType;
import com.asmolabs.vectispire.common.domain.sbom.CveDelta;
import com.asmolabs.vectispire.common.domain.sbom.SbomDiffReport;
import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.data.domain.Limit;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Computes deterministic SBOM and vulnerability diffs between two scans.
 */
@Service
public class SbomDiffService {

    private final Scans scans;
    private final Components components;
    private final Findings findings;
    private final ObjectMapper objectMapper;

    public SbomDiffService(
            Scans scans,
            Components components,
            Findings findings,
            ObjectMapper objectMapper) {
        this.scans = scans;
        this.components = components;
        this.findings = findings;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public Optional<SbomDiffReport> diff(long fromScanId, long toScanId) {
        Optional<ScanEntity> fromOpt = scans.findById(fromScanId);
        Optional<ScanEntity> toOpt = scans.findById(toScanId);

        if (fromOpt.isEmpty() || toOpt.isEmpty()) {
            return Optional.empty();
        }

        ScanEntity fromScan = fromOpt.get();
        ScanEntity toScan = toOpt.get();

        Map<String, ComponentInfo> fromComponents = loadComponents(fromScan);
        Map<String, ComponentInfo> toComponents = loadComponents(toScan);

        List<ComponentDelta> componentDeltas = new ArrayList<>();
        int added = 0;
        int removed = 0;
        int versionChanged = 0;
        int licenseChanged = 0;

        Set<String> allNames = new HashSet<>();
        allNames.addAll(fromComponents.keySet());
        allNames.addAll(toComponents.keySet());

        List<String> sortedNames = new ArrayList<>(allNames);
        Collections.sort(sortedNames);

        for (String name : sortedNames) {
            ComponentInfo oldComp = fromComponents.get(name);
            ComponentInfo newComp = toComponents.get(name);

            if (oldComp == null && newComp != null) {
                added++;
                componentDeltas.add(new ComponentDelta(
                        newComp.name(),
                        newComp.purl(),
                        newComp.type(),
                        newComp.isDirect(),
                        null,
                        newComp.version(),
                        null,
                        newComp.license(),
                        ChangeType.ADDED));
            } else if (oldComp != null && newComp == null) {
                removed++;
                componentDeltas.add(new ComponentDelta(
                        oldComp.name(),
                        oldComp.purl(),
                        oldComp.type(),
                        oldComp.isDirect(),
                        oldComp.version(),
                        null,
                        oldComp.license(),
                        null,
                        ChangeType.REMOVED));
            } else if (oldComp != null && newComp != null) {
                boolean vDiff = !java.util.Objects.equals(oldComp.version(), newComp.version());
                boolean lDiff = !java.util.Objects.equals(oldComp.license(), newComp.license());

                if (vDiff) {
                    versionChanged++;
                    componentDeltas.add(new ComponentDelta(
                            newComp.name(),
                            newComp.purl(),
                            newComp.type(),
                            newComp.isDirect(),
                            oldComp.version(),
                            newComp.version(),
                            oldComp.license(),
                            newComp.license(),
                            ChangeType.VERSION_CHANGED));
                } else if (lDiff) {
                    licenseChanged++;
                    componentDeltas.add(new ComponentDelta(
                            newComp.name(),
                            newComp.purl(),
                            newComp.type(),
                            newComp.isDirect(),
                            oldComp.version(),
                            newComp.version(),
                            oldComp.license(),
                            newComp.license(),
                            ChangeType.LICENSE_CHANGED));
                }
            }
        }

        // Compute CVE deltas
        List<CveDelta> cveDeltas = computeCveDeltas(fromScanId, toScanId);
        int introducedCves = (int) cveDeltas.stream().filter(c -> c.status() == CveDelta.Status.INTRODUCED).count();
        int resolvedCves = (int) cveDeltas.stream().filter(c -> c.status() == CveDelta.Status.RESOLVED).count();

        String fromVer = fromScan.getVersion() != null ? fromScan.getVersion() : "scan-" + fromScanId;
        String toVer = toScan.getVersion() != null ? toScan.getVersion() : "scan-" + toScanId;

        return Optional.of(new SbomDiffReport(
                fromScanId,
                toScanId,
                fromVer,
                toVer,
                added,
                removed,
                versionChanged,
                licenseChanged,
                introducedCves,
                resolvedCves,
                componentDeltas,
                cveDeltas));
    }

    /**
     * Les deux derniers scans d'une cible, comparés.
     *
     * <p><b>Deux identifiants demandés, et non tout l'historique trié en mémoire.</b> Ceci lisait
     * {@code scans.findAll()} puis filtrait, triait et gardait deux lignes : chaque ligne de scan
     * du déploiement chargée — charge SBOM comprise, des mégaoctets pièce — pour n'en garder que
     * deux identifiants. Le coût suivait l'historique du parc entier alors que la question ne
     * porte que sur une cible.
     *
     * <p>Un seul scan donne une comparaison de ce scan avec lui-même : c'est délibéré, et cela
     * répond « rien n'a changé » plutôt que « aucune donnée », qui se lit comme une panne.
     */
    @Transactional(readOnly = true)
    public Optional<SbomDiffReport> diffLatest(Long repoId, Long containerId) {
        List<Long> recent = repoId != null
                ? scans.findRecentIdsByRepoId(repoId, Limit.of(2))
                : containerId != null
                        ? scans.findRecentIdsByContainerId(containerId, Limit.of(2))
                        : List.of();

        if (recent.size() >= 2) {
            // Du plus récent au plus ancien : le premier est l'état d'arrivée.
            return diff(recent.get(1), recent.get(0));
        }
        if (recent.size() == 1) {
            return diff(recent.get(0), recent.get(0));
        }
        return Optional.empty();
    }

    private List<CveDelta> computeCveDeltas(long fromScanId, long toScanId) {
        Map<String, FindingEntity> fromFindings = findings.findByScanId(fromScanId).stream()
                .filter(f -> "vulnerability".equalsIgnoreCase(f.getType()) || (f.getIdentifier() != null && (f.getIdentifier().toUpperCase().startsWith("CVE-") || f.getIdentifier().toUpperCase().startsWith("GHSA-"))))
                .collect(Collectors.toMap(f -> normalizeCveKey(f), Function.identity(), (a, b) -> a));

        Map<String, FindingEntity> toFindings = findings.findByScanId(toScanId).stream()
                .filter(f -> "vulnerability".equalsIgnoreCase(f.getType()) || (f.getIdentifier() != null && (f.getIdentifier().toUpperCase().startsWith("CVE-") || f.getIdentifier().toUpperCase().startsWith("GHSA-"))))
                .collect(Collectors.toMap(f -> normalizeCveKey(f), Function.identity(), (a, b) -> a));

        List<CveDelta> results = new ArrayList<>();

        for (Map.Entry<String, FindingEntity> entry : toFindings.entrySet()) {
            String key = entry.getKey();
            FindingEntity finding = entry.getValue();
            if (!fromFindings.containsKey(key)) {
                results.add(new CveDelta(
                        finding.getIdentifier() != null ? finding.getIdentifier() : "UNKNOWN",
                        finding.getSeverity(),
                        finding.getPackageName() != null ? finding.getPackageName() : finding.getFilePath(),
                        finding.getPackageVersion(),
                        CveDelta.Status.INTRODUCED));
            } else {
                results.add(new CveDelta(
                        finding.getIdentifier() != null ? finding.getIdentifier() : "UNKNOWN",
                        finding.getSeverity(),
                        finding.getPackageName() != null ? finding.getPackageName() : finding.getFilePath(),
                        finding.getPackageVersion(),
                        CveDelta.Status.PERSISTENT));
            }
        }

        for (Map.Entry<String, FindingEntity> entry : fromFindings.entrySet()) {
            String key = entry.getKey();
            FindingEntity finding = entry.getValue();
            if (!toFindings.containsKey(key)) {
                results.add(new CveDelta(
                        finding.getIdentifier() != null ? finding.getIdentifier() : "UNKNOWN",
                        finding.getSeverity(),
                        finding.getPackageName() != null ? finding.getPackageName() : finding.getFilePath(),
                        finding.getPackageVersion(),
                        CveDelta.Status.RESOLVED));
            }
        }

        return results;
    }

    private String normalizeCveKey(FindingEntity finding) {
        String cve = finding.getIdentifier() != null ? finding.getIdentifier() : "";
        String pkg = finding.getPackageName() != null ? finding.getPackageName() : "";
        return cve + ":" + pkg;
    }

    private Map<String, ComponentInfo> loadComponents(ScanEntity scan) {
        Map<String, ComponentInfo> map = new HashMap<>();

        // 1. Try t_component table first
        List<ComponentEntity> rows = components.findByScanId(scan.getId());
        if (!rows.isEmpty()) {
            for (ComponentEntity row : rows) {
                map.put(row.getName(), new ComponentInfo(
                        row.getName(),
                        row.getVersion(),
                        row.getPurl(),
                        row.getType(),
                        row.getIsDirect(),
                        inferLicense(row.getName())));
            }
            return map;
        }

        // 2. Fallback to raw SBOM JSON if t_component was empty
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
                        String type = artifact.path("type").asText(null);
                        String license = extractLicense(artifact);
                        map.put(name, new ComponentInfo(name, version, purl, type, null, license));
                    }
                }
            } catch (Exception ignored) {}
        }

        return map;
    }

    private String extractLicense(JsonNode artifact) {
        JsonNode licenses = artifact.path("licenses");
        if (licenses.isArray() && !licenses.isEmpty()) {
            JsonNode first = licenses.get(0);
            if (first.isTextual()) return first.asText();
            if (first.has("value")) return first.path("value").asText();
            if (first.has("spdxExpression")) return first.path("spdxExpression").asText();
        }
        return inferLicense(artifact.path("name").asText(""));
    }

    private String inferLicense(String name) {
        String lower = name.toLowerCase();
        if (lower.contains("apache") || lower.contains("commons-") || lower.contains("spring-")) return "Apache-2.0";
        if (lower.contains("mit") || lower.contains("slf4j") || lower.contains("express")) return "MIT";
        if (lower.contains("gpl")) return "GPL-3.0";
        return "UNKNOWN";
    }

    private record ComponentInfo(
            String name,
            String version,
            String purl,
            String type,
            Boolean isDirect,
            String license) {}
}
