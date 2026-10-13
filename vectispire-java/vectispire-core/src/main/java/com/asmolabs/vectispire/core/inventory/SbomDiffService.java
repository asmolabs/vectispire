package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.sbom.ComponentDelta.ChangeType;
import com.asmolabs.vectispire.common.domain.sbom.ComponentDelta;
import com.asmolabs.vectispire.common.domain.sbom.CveDelta;
import com.asmolabs.vectispire.common.domain.sbom.SbomDiffReport;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanDocumentService;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Computes deterministic SBOM and vulnerability diffs between two scans.
 */
@Service
public class SbomDiffService {

    private static final Logger log = LoggerFactory.getLogger(SbomDiffService.class);

    private final ScanCatalog scans;
    private final ScanDocumentService documents;
    private final ComponentRepository components;
    private final ObjectMapper objectMapper;

    public SbomDiffService(
            ScanCatalog scans,
            ScanDocumentService documents,
            ComponentRepository components,
            ObjectMapper objectMapper) {
        this.scans = scans;
        this.documents = documents;
        this.components = components;
        this.objectMapper = objectMapper;
    }

    /**
     * Two scans the caller may see, compared.
     *
     * <p><b>Both ends refused here, not at the route.</b> A diff names the components that appeared
     * and disappeared between two scans; checking only the first would let a caller pair a scan they
     * may see with one they may not, and read the second through the difference. The route used to
     * ask, and this method answered whoever called it without. The refusal is {@code scanning}'s
     * ({@link ScanDocumentService}), so this module still uses {@code access} from its routes only,
     * and an absent scan and a hidden one read alike.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException "Scan not found." for
     *     either end absent or hidden
     */
    @Transactional(readOnly = true)
    public Optional<SbomDiffReport> diff(long fromScanId, long toScanId, Visibility allowed) {
        documents.requireVisible(fromScanId, allowed);
        documents.requireVisible(toScanId, allowed);
        return compare(fromScanId, toScanId);
    }

    private Optional<SbomDiffReport> compare(long fromScanId, long toScanId) {
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
     *
     * <p><b>A target somebody checked</b> ({@link VisibleTarget}), since this module's services do
     * not use {@code access}: the refusal is the route's, and a bare id would let the next caller
     * skip it. The two scans are the target's own, so they need no second check.
     */
    @Transactional(readOnly = true)
    public Optional<SbomDiffReport> diffLatest(VisibleTarget<?> target) {
        List<Long> recent = scans.recentIds(target.target(), 2);

        if (recent.size() >= 2) {
            // Newest first: the first is the end state.
            return compare(recent.get(1), recent.get(0));
        }
        if (recent.size() == 1) {
            return compare(recent.get(0), recent.get(0));
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

    /**
     * A scan's components by name, each with the licence it declares — never one guessed.
     *
     * <p><b>The licence is read, and unknown when nothing declares it</b>: the build's declaration on a
     * component row, else the scanner's SBOM ({@link SbomLicences}). It was inferred from the package's
     * name — "mit" in {@code commit}, {@code spring-} for Apache-2.0 — so a licence change could be one the
     * guess invented.
     *
     * @throws SbomUnreadableException when the scan's SBOM does not parse: compared as empty, it read as
     *     every component removed, or as "no changes" against another unreadable one (decision 0007)
     */
    private Map<String, ComponentInfo> loadComponents(ScanView scan) {
        Map<String, ComponentInfo> map = new HashMap<>();
        List<JsonNode> artifacts = artifacts(scan);

        // 1. Try t_component table first
        List<ComponentEntity> rows = components.findByScanId(scan.id());
        if (!rows.isEmpty()) {
            Map<String, String> licences = new HashMap<>();
            for (JsonNode artifact : artifacts) {
                String name = artifact.path("name").asText(null);
                if (name != null && !name.isBlank()) {
                    licences.putIfAbsent(name + "@" + artifact.path("version").asText(""),
                            SbomLicences.declaredOrUnknown(artifact));
                }
            }
            for (ComponentEntity row : rows) {
                // The version the scanner listed it under, where a build SBOM changed it (decision 0039).
                String listedAs = row.getScannedVersion() != null ? row.getScannedVersion() : row.getVersion();
                String license = row.getDeclaredLicense() != null && !row.getDeclaredLicense().isBlank()
                        ? row.getDeclaredLicense()
                        : licences.getOrDefault(row.getName() + "@" + (listedAs == null ? "" : listedAs),
                                SbomLicences.UNDECLARED);
                map.put(row.getName(), new ComponentInfo(
                        row.getName(),
                        row.getVersion(),
                        row.getPurl(),
                        row.getType(),
                        row.getIsDirect(),
                        license));
            }
            return map;
        }

        // 2. Fallback to raw SBOM JSON if t_component was empty
        for (JsonNode artifact : artifacts) {
            String name = artifact.path("name").asText(null);
            if (name == null || name.isBlank()) continue;
            String version = artifact.path("version").asText(null);
            String purl = artifact.path("purl").asText(null);
            String type = artifact.path("type").asText(null);
            map.put(name, new ComponentInfo(name, version, purl, type, null, SbomLicences.declaredOrUnknown(artifact)));
        }

        return map;
    }

    /** The scan's SBOM artifacts; none when it has no SBOM. */
    private List<JsonNode> artifacts(ScanView scan) {
        if (scan.sbom() == null || scan.sbom().isBlank()) {
            return List.of();
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(scan.sbom());
        } catch (Exception unreadable) {
            log.warn("Scan {}: SBOM unreadable, the diff naming it is refused: {}", scan.id(), unreadable.getMessage());
            throw new SbomUnreadableException(scan.id());
        }
        List<JsonNode> artifacts = new ArrayList<>();
        root.path("artifacts").forEach(artifacts::add);
        return artifacts;
    }

    private record ComponentInfo(
            String name,
            String version,
            String purl,
            String type,
            Boolean isDirect,
            String license) {}
}
