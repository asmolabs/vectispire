package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.sbom.ComponentDelta.ChangeType;
import com.asmolabs.vectispire.common.domain.sbom.ComponentDelta;
import com.asmolabs.vectispire.common.domain.sbom.CveDelta;
import com.asmolabs.vectispire.common.domain.sbom.SbomDiffReport;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanFindingView;
import com.asmolabs.vectispire.core.scanning.ScanView;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
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

    private final ScanCatalog scans;
    private final ComponentRepository components;
    private final ObjectMapper objectMapper;

    public SbomDiffService(
            ScanCatalog scans,
            ComponentRepository components,
            ObjectMapper objectMapper) {
        this.scans = scans;
        this.components = components;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public Optional<SbomDiffReport> diff(long fromScanId, long toScanId) {
        Optional<ScanView> fromOpt = scans.scan(fromScanId);
        Optional<ScanView> toOpt = scans.scan(toScanId);

        if (fromOpt.isEmpty() || toOpt.isEmpty()) {
            return Optional.empty();
        }

        ScanView fromScan = fromOpt.get();
        ScanView toScan = toOpt.get();

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

        String fromVer = fromScan.version() != null ? fromScan.version() : "scan-" + fromScanId;
        String toVer = toScan.version() != null ? toScan.version() : "scan-" + toScanId;

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
     * A target's two most recent scans, compared.
     *
     * <p><b>Two identifiers asked for, not the whole history sorted in memory.</b> This read
     * {@code scans.findAll()} and then filtered, sorted and kept two rows: every scan row in the
     * deployment loaded — SBOM payload included, megabytes apiece — to retain two identifiers. The
     * cost followed the entire estate's history although the question is about one target.
     *
     * <p>A single scan yields a comparison of that scan with itself: this is deliberate, and it
     * answers "nothing changed" rather than "no data", which reads as a failure.
     */
    @Transactional(readOnly = true)
    public Optional<SbomDiffReport> diffLatest(Long repoId, Long containerId) {
        List<Long> recent = repoId != null
                ? scans.recentIds(new ScanTarget.Repository(repoId), 2)
                : containerId != null
                        ? scans.recentIds(new ScanTarget.Container(containerId), 2)
                        : List.of();

        if (recent.size() >= 2) {
            // Newest first: the first is the end state.
            return diff(recent.get(1), recent.get(0));
        }
        if (recent.size() == 1) {
            return diff(recent.get(0), recent.get(0));
        }
        return Optional.empty();
    }

    private List<CveDelta> computeCveDeltas(long fromScanId, long toScanId) {
        Map<String, ScanFindingView> fromFindings = scans.findings(fromScanId).stream()
                .filter(f -> "vulnerability".equalsIgnoreCase(f.type()) || (f.identifier() != null && (f.identifier().toUpperCase(Locale.ROOT).startsWith("CVE-") || f.identifier().toUpperCase(Locale.ROOT).startsWith("GHSA-"))))
                .collect(Collectors.toMap(f -> normalizeCveKey(f), Function.identity(), (a, b) -> a));

        Map<String, ScanFindingView> toFindings = scans.findings(toScanId).stream()
                .filter(f -> "vulnerability".equalsIgnoreCase(f.type()) || (f.identifier() != null && (f.identifier().toUpperCase(Locale.ROOT).startsWith("CVE-") || f.identifier().toUpperCase(Locale.ROOT).startsWith("GHSA-"))))
                .collect(Collectors.toMap(f -> normalizeCveKey(f), Function.identity(), (a, b) -> a));

        List<CveDelta> results = new ArrayList<>();

        for (Map.Entry<String, ScanFindingView> entry : toFindings.entrySet()) {
            String key = entry.getKey();
            ScanFindingView finding = entry.getValue();
            if (!fromFindings.containsKey(key)) {
                results.add(new CveDelta(
                        finding.identifier() != null ? finding.identifier() : "UNKNOWN",
                        finding.severity(),
                        finding.packageName() != null ? finding.packageName() : finding.filePath(),
                        finding.packageVersion(),
                        CveDelta.Status.INTRODUCED));
            } else {
                results.add(new CveDelta(
                        finding.identifier() != null ? finding.identifier() : "UNKNOWN",
                        finding.severity(),
                        finding.packageName() != null ? finding.packageName() : finding.filePath(),
                        finding.packageVersion(),
                        CveDelta.Status.PERSISTENT));
            }
        }

        for (Map.Entry<String, ScanFindingView> entry : fromFindings.entrySet()) {
            String key = entry.getKey();
            ScanFindingView finding = entry.getValue();
            if (!toFindings.containsKey(key)) {
                results.add(new CveDelta(
                        finding.identifier() != null ? finding.identifier() : "UNKNOWN",
                        finding.severity(),
                        finding.packageName() != null ? finding.packageName() : finding.filePath(),
                        finding.packageVersion(),
                        CveDelta.Status.RESOLVED));
            }
        }

        return results;
    }

    private String normalizeCveKey(ScanFindingView finding) {
        String cve = finding.identifier() != null ? finding.identifier() : "";
        String pkg = finding.packageName() != null ? finding.packageName() : "";
        return cve + ":" + pkg;
    }

    private Map<String, ComponentInfo> loadComponents(ScanView scan) {
        Map<String, ComponentInfo> map = new HashMap<>();

        // 1. Try t_component table first
        List<ComponentEntity> rows = components.findByScanId(scan.id());
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
        String lower = name.toLowerCase(Locale.ROOT);
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
