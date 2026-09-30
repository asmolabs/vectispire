package com.asmolabs.vectispire.core.exports;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService.ConsolidatedInventory;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService.MergedComponent;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService.TargetInventory;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanDocumentService;
import com.asmolabs.vectispire.core.scanning.ScanFindingView;
import com.asmolabs.vectispire.core.scanning.ScanView;
import com.asmolabs.vectispire.core.settings.ProductVersion;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument.*;

/**
 * Generates CycloneDX 1.5 Software Bill of Materials (SBOM) with BOM-linked
 * Vulnerability Exploitability eXchange (VEX) analysis statements.
 */
@Service
public class CycloneDxGeneratorService {

    private final ScanCatalog scansRepo;
    private final ScanDocumentService documents;
    private final IssueCatalog issuesRepo;
    private final ConsolidatedInventoryService inventory;
    private final String toolVersion;

    public CycloneDxGeneratorService(
            ScanCatalog scansRepo,
            ScanDocumentService documents,
            IssueCatalog issuesRepo,
            ConsolidatedInventoryService inventory,
            ProductVersion version) {
        this.scansRepo = scansRepo;
        this.documents = documents;
        this.issuesRepo = issuesRepo;
        this.inventory = inventory;
        // The same version every other export states, or none: the tool entry's version is
        // optional in CycloneDX, and it was the literal "0.9.0".
        this.toolVersion = version.get();
    }

    /**
     * The document of a scan the caller may see — refused here, in {@code scanning}'s words, rather
     * than trusted to a route that asked first: the same scan under another format is the same
     * question, and which caller reached this method used to decide whether it was asked.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException "Scan not found." for a
     *     scan absent or hidden
     */
    public Optional<CycloneDxDocument> generateForScan(long scanId, Visibility allowed) {
        documents.requireVisible(scanId, allowed);
        return scansRepo.scan(scanId).map(this::buildForScan);
    }

    /**
     * A project's consolidated SBOM as a CycloneDX 1.5 document, with the project's CVE issues as its
     * BOM-linked VEX — the fleet document's shape ({@link #generateAggregate}), narrowed to the project's
     * visible targets, its components the real inventory rather than only the packages a CVE named.
     *
     * <p><b>It states what was read, and no more.</b> Each component names the targets that carry it
     * ({@code vectispire:target}); the metadata names every visible target whose inventory is unknown
     * ({@code vectispire:inventory-unknown}) and whether the caller sees only part of the project ({@code
     * vectispire:partial}); and {@code compositions} says {@code complete} only when every target of the
     * project was seen and read, {@code incomplete} otherwise. A component list without that reads as
     * the whole product to whoever receives the file.
     *
     * <p>Not signed, like every other export of this module: the per-scan and the fleet documents are
     * not, and a project's is theirs in another scope. The checklists' signed document is a statement
     * people made; this one is a rendering anybody may ask for again.
     */
    public CycloneDxDocument generateForProject(VisibleScope project) {
        ConsolidatedInventory consolidated = inventory.of(project);
        Map<String, Component> componentMap = new LinkedHashMap<>();
        Map<String, String> refByPurl = new HashMap<>();
        Set<String> usedRefs = new HashSet<>();

        for (MergedComponent merged : consolidated.components()) {
            String version = merged.version();
            String bomRef = uniqueRef(merged.purl() != null
                    ? merged.purl()
                    : "urn:vectispire:component:" + merged.name() + "@" + (version == null ? "" : version), usedRefs);
            List<Property> carriers = merged.targets().stream()
                    .map(target -> new Property("vectispire:target", target.kind() + ":" + target.id()))
                    .toList();
            componentMap.put(bomRef, new Component(
                    bomRef,
                    "library",
                    extractGroup(merged.name()),
                    extractName(merged.name()),
                    version,
                    merged.purl(),
                    "required",
                    carriers));
            if (merged.purl() != null) {
                refByPurl.putIfAbsent(merged.purl(), bomRef);
            }
        }

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        for (IssueView issue : issuesRepo.issues(withCve(project.visibility()))) {
            String cve = issue.identifier();
            if (cve == null || !cve.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                continue;
            }
            String pkg = issue.packageName() != null ? issue.packageName() : "unknown";
            String version = issue.packageVersion() != null ? issue.packageVersion() : "latest";
            String purl = issue.purl() != null && !issue.purl().isBlank()
                    ? issue.purl()
                    : "pkg:generic/" + pkg + "@" + version;
            // A package the inventory did not list — an image scanned before its SBOM was kept, a finding
            // of a tool that reads no manifest — is added as the fleet document adds every one, so the
            // statement's `affects` points at a component of the document.
            String ref = refByPurl.computeIfAbsent(purl, absent -> {
                String added = uniqueRef(absent, usedRefs);
                componentMap.put(added, new Component(
                        added, "library", extractGroup(pkg), extractName(pkg), version, absent, "required"));
                return added;
            });
            vulnerabilities.add(buildVulnerability(issue, ref));
        }

        List<Property> facts = new ArrayList<>();
        facts.add(new Property("vectispire:project", String.valueOf(project.id())));
        if (project.partial()) {
            facts.add(new Property("vectispire:partial", "true"));
        }
        for (TargetInventory target : consolidated.targets()) {
            if (!target.inventory().known()) {
                facts.add(new Property("vectispire:inventory-unknown", target.kind() + ":" + target.id()));
            }
        }
        // No version: a project is not a release, and a version here would claim one.
        Component root = new Component(
                "urn:vectispire:project:" + project.id(), "application", null, project.name(), null, null, null);
        Metadata metadata = new Metadata(
                Instant.now(), List.of(new Tool("AsmoLabs", "Vectispire", toolVersion)), root, List.copyOf(facts));
        boolean whole = consolidated.complete() && !project.partial();

        return new CycloneDxDocument(
                CycloneDxDocument.BOM_FORMAT,
                CycloneDxDocument.SPEC_VERSION,
                "urn:uuid:" + UUID.randomUUID(),
                1,
                metadata,
                new ArrayList<>(componentMap.values()),
                vulnerabilities,
                List.of(new Composition(whole ? "complete" : "incomplete", List.of(root.bomRef()))));
    }

    /** A {@code bom-ref} unique in the document, as CycloneDX requires: the second of a kind gets a suffix. */
    private static String uniqueRef(String wanted, Set<String> used) {
        String ref = wanted;
        for (int n = 2; !used.add(ref); n++) {
            ref = wanted + "#" + n;
        }
        return ref;
    }

    public CycloneDxDocument generateAggregate(Visibility allowed) {
        List<IssueView> allIssues = issuesRepo.issues(withCve(allowed));
        Map<String, Component> componentMap = new HashMap<>();
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (IssueView issue : allIssues) {
            String cve = issue.identifier();
            if (cve == null || !cve.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                continue;
            }

            String pkg = issue.packageName() != null ? issue.packageName() : "unknown";
            String version = issue.packageVersion() != null ? issue.packageVersion() : "latest";
            String purl = issue.purl() != null && !issue.purl().isBlank()
                    ? issue.purl()
                    : "pkg:generic/" + pkg + "@" + version;

            componentMap.putIfAbsent(purl, new Component(
                    purl,
                    "library",
                    extractGroup(pkg),
                    extractName(pkg),
                    version,
                    purl,
                    "required"));

            vulnerabilities.add(buildVulnerability(issue, purl));
        }

        // No version: the monitored fleet is not a released thing, and "1.0.0" claimed one. The
        // field is optional in CycloneDX 1.5, and absent says what is true.
        Component rootApp = new Component(
                "urn:vectispire:inventory:aggregate",
                "application",
                "com.asmolabs.vectispire",
                "vectispire-monitored-fleet",
                null,
                null,
                null);

        Metadata metadata = new Metadata(
                Instant.now(),
                List.of(new Tool("AsmoLabs", "Vectispire", toolVersion)),
                rootApp);

        return new CycloneDxDocument(
                CycloneDxDocument.BOM_FORMAT,
                CycloneDxDocument.SPEC_VERSION,
                "urn:uuid:" + UUID.randomUUID(),
                1,
                metadata,
                new ArrayList<>(componentMap.values()),
                vulnerabilities);
    }

    private CycloneDxDocument buildForScan(ScanView scan) {
        List<ScanFindingView> scanFindings = scansRepo.findings(scan.id());
        Map<String, Component> componentMap = new HashMap<>();
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (ScanFindingView finding : scanFindings) {
            String cve = finding.identifier();
            if (cve == null || !cve.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                continue;
            }

            String pkg = finding.packageName() != null ? finding.packageName() : "unknown";
            String version = finding.packageVersion() != null ? finding.packageVersion() : "latest";
            String purl = finding.purl() != null && !finding.purl().isBlank()
                    ? finding.purl()
                    : "pkg:generic/" + pkg + "@" + version;

            componentMap.putIfAbsent(purl, new Component(
                    purl,
                    "library",
                    extractGroup(pkg),
                    extractName(pkg),
                    version,
                    purl,
                    "required"));

            // Look up corresponding issue to extract triage state
            Optional<IssueView> matchingIssue = issuesRepo.withIdentifier(cve).stream()
                    .filter(i -> (scan.repoId() != null && scan.repoId().equals(i.repoId()))
                            || (scan.containerId() != null && scan.containerId().equals(i.containerId())))
                    .findFirst();

            vulnerabilities.add(buildVulnerabilityFromFinding(finding, matchingIssue.orElse(null), purl));
        }

        String targetName = scan.repoId() != null ? "repo-" + scan.repoId() : "container-" + scan.containerId();
        Component scanTarget = new Component(
                "urn:vectispire:target:" + targetName,
                "application",
                "vectispire",
                targetName,
                scan.version() != null ? scan.version() : "latest",
                null,
                null);

        Metadata metadata = new Metadata(
                scan.createdAt() != null ? scan.createdAt() : Instant.now(),
                List.of(new Tool("AsmoLabs", "Vectispire", toolVersion)),
                scanTarget);

        return new CycloneDxDocument(
                CycloneDxDocument.BOM_FORMAT,
                CycloneDxDocument.SPEC_VERSION,
                "urn:uuid:" + UUID.randomUUID(),
                1,
                metadata,
                new ArrayList<>(componentMap.values()),
                vulnerabilities);
    }

    private Vulnerability buildVulnerability(IssueView issue, String purl) {
        String cve = issue.identifier();
        Double score = issue.cvssScore();
        String severity = issue.severity() != null ? issue.severity().toLowerCase(Locale.ROOT) : "medium";

        List<Rating> ratings = List.of(new Rating(
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                score,
                severity,
                "CVSSv31",
                null));

        Analysis analysis = mapAnalysis(issue.triageStatus(), issue.triageJustification(), issue.triageComment(), issue.state());

        return new Vulnerability(
                "vuln-" + cve + "-" + Math.abs(purl.hashCode()),
                cve,
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                ratings,
                cve + " in " + issue.packageName(),
                issue.description(),
                issue.fixVersions() != null ? "Upgrade component to version " + issue.fixVersions() : null,
                analysis,
                List.of(new Affects(purl)));
    }

    private Vulnerability buildVulnerabilityFromFinding(ScanFindingView finding, IssueView issue, String purl) {
        String cve = finding.identifier();
        Double score = finding.cvssScore();
        String severity = finding.severity() != null ? finding.severity().toLowerCase(Locale.ROOT) : "medium";

        List<Rating> ratings = List.of(new Rating(
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                score,
                severity,
                "CVSSv31",
                null));

        Analysis analysis = issue != null
                ? mapAnalysis(issue.triageStatus(), issue.triageJustification(), issue.triageComment(), issue.state())
                : new Analysis("in_triage", null, "Discovered during automated scan", List.of());

        return new Vulnerability(
                "vuln-" + cve + "-" + Math.abs(purl.hashCode()),
                cve,
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                ratings,
                cve + " in " + finding.packageName(),
                finding.description(),
                finding.fixVersions() != null ? "Upgrade component to version " + finding.fixVersions() : null,
                analysis,
                List.of(new Affects(purl)));
    }

    private Analysis mapAnalysis(String triageStatus, String triageJustification, String comment, String state) {
        // Triage clears a component; reachability does not — same reason as the CSAF and OpenVEX
        // generators. The column was handed over here and read nowhere below; nothing computes it
        // now, and a real analysis returning would still only raise concern, never remove it.
        boolean notAffected = "not_affected".equalsIgnoreCase(triageStatus);
        boolean fixed = "resolved".equalsIgnoreCase(state) || "fixed".equalsIgnoreCase(triageStatus);
        boolean underReview = "under_review".equalsIgnoreCase(triageStatus)
                || "pending_approval".equalsIgnoreCase(triageStatus);

        String cdxState;
        String justification = null;
        List<String> responses = new ArrayList<>();

        if (notAffected) {
            cdxState = "not_affected";
            justification = triageJustification != null && !triageJustification.isBlank()
                    ? triageJustification.toLowerCase(Locale.ROOT).replace(" ", "_")
                    : "vulnerable_code_not_in_execute_path";
            responses.add("will_not_fix");
        } else if (fixed) {
            cdxState = "resolved";
            responses.add("update");
        } else if (underReview) {
            cdxState = "in_triage";
        } else {
            cdxState = "exploitable";
        }

        return new Analysis(
                cdxState,
                justification,
                comment != null && !comment.isBlank() ? comment : "Evaluated by Vectispire VEX Engine",
                responses.isEmpty() ? null : responses);
    }

    private static String extractGroup(String pkg) {
        if (pkg.contains("/")) {
            return pkg.substring(0, pkg.lastIndexOf('/'));
        }
        if (pkg.contains(":")) {
            return pkg.substring(0, pkg.indexOf(':'));
        }
        return null;
    }

    private static String extractName(String pkg) {
        if (pkg.contains("/")) {
            return pkg.substring(pkg.lastIndexOf('/') + 1);
        }
        if (pkg.contains(":")) {
            return pkg.substring(pkg.indexOf(':') + 1);
        }
        return pkg;
    }

    /**
     * The issues this document is built from: those carrying a CVE, within the caller's allowance.
     *
     * <p><b>Two defects in one line.</b> The read was {@code findAll()} — every issue in the
     * deployment, with the CVE test applied afterwards in Java — and it carried no
     * {@link Visibility} at all, so an aggregate export handed a restricted reader the
     * identifiers, packages and versions of every target they had not been given.
     *
     * <p>The allowance is expressed through {@link IssueFilters}, which is where the
     * authorization predicate already lives. Restating it here would be a second copy of a rule
     * that must not have two.
     */
    private static IssueFilters withCve(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, allowed).onlyCves();
    }

}
