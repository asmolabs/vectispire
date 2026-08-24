package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument;
import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument.*;
import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * Generates CycloneDX 1.5/1.6 Software Bill of Materials (SBOM) with BOM-linked
 * Vulnerability Exploitability eXchange (VEX) analysis statements.
 */
@Service
public class CycloneDxGeneratorService {

    private final Scans scansRepo;
    private final Findings findingsRepo;
    private final Issues issuesRepo;

    public CycloneDxGeneratorService(Scans scansRepo, Findings findingsRepo, Issues issuesRepo) {
        this.scansRepo = scansRepo;
        this.findingsRepo = findingsRepo;
        this.issuesRepo = issuesRepo;
    }

    public Optional<CycloneDxDocument> generateForScan(Long scanId) {
        return scansRepo.findById(scanId).map(this::buildForScan);
    }

    public CycloneDxDocument generateAggregate() {
        List<IssueEntity> allIssues = issuesRepo.findAll();
        Map<String, Component> componentMap = new HashMap<>();
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (IssueEntity issue : allIssues) {
            String cve = issue.getIdentifier();
            if (cve == null || !cve.toUpperCase().startsWith("CVE-")) {
                continue;
            }

            String pkg = issue.getPackageName() != null ? issue.getPackageName() : "unknown";
            String version = issue.getPackageVersion() != null ? issue.getPackageVersion() : "latest";
            String purl = issue.getPurl() != null && !issue.getPurl().isBlank()
                    ? issue.getPurl()
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

        Component rootApp = new Component(
                "urn:vectispire:inventory:aggregate",
                "application",
                "com.asmolabs.vectispire",
                "vectispire-monitored-fleet",
                "1.0.0",
                null,
                null);

        Metadata metadata = new Metadata(
                Instant.now(),
                List.of(new Tool("AsmoLabs", "Vectispire", "0.9.0")),
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

    private CycloneDxDocument buildForScan(ScanEntity scan) {
        List<FindingEntity> scanFindings = findingsRepo.findByScanId(scan.getId());
        Map<String, Component> componentMap = new HashMap<>();
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (FindingEntity finding : scanFindings) {
            String cve = finding.getIdentifier();
            if (cve == null || !cve.toUpperCase().startsWith("CVE-")) {
                continue;
            }

            String pkg = finding.getPackageName() != null ? finding.getPackageName() : "unknown";
            String version = finding.getPackageVersion() != null ? finding.getPackageVersion() : "latest";
            String purl = finding.getPurl() != null && !finding.getPurl().isBlank()
                    ? finding.getPurl()
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
            Optional<IssueEntity> matchingIssue = issuesRepo.findByIdentifier(cve).stream()
                    .filter(i -> (scan.getRepoId() != null && scan.getRepoId().equals(i.getRepoId()))
                            || (scan.getContainerId() != null && scan.getContainerId().equals(i.getContainerId())))
                    .findFirst();

            vulnerabilities.add(buildVulnerabilityFromFinding(finding, matchingIssue.orElse(null), purl));
        }

        String targetName = scan.getRepoId() != null ? "repo-" + scan.getRepoId() : "container-" + scan.getContainerId();
        Component scanTarget = new Component(
                "urn:vectispire:target:" + targetName,
                "application",
                "vectispire",
                targetName,
                scan.getVersion() != null ? scan.getVersion() : "latest",
                null,
                null);

        Metadata metadata = new Metadata(
                scan.getCreatedAt() != null ? scan.getCreatedAt() : Instant.now(),
                List.of(new Tool("AsmoLabs", "Vectispire", "0.9.0")),
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

    private Vulnerability buildVulnerability(IssueEntity issue, String purl) {
        String cve = issue.getIdentifier();
        Double score = issue.getCvssScore();
        String severity = issue.getSeverity() != null ? issue.getSeverity().toLowerCase() : "medium";

        List<Rating> ratings = List.of(new Rating(
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                score,
                severity,
                "CVSSv31",
                null));

        Analysis analysis = mapAnalysis(issue.getTriageStatus(), issue.getTriageJustification(), issue.getTriageComment(), issue.getReachability(), issue.getState());

        return new Vulnerability(
                "vuln-" + cve + "-" + Math.abs(purl.hashCode()),
                cve,
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                ratings,
                cve + " in " + issue.getPackageName(),
                issue.getDescription(),
                issue.getFixVersions() != null ? "Upgrade component to version " + issue.getFixVersions() : null,
                analysis,
                List.of(new Affects(purl)));
    }

    private Vulnerability buildVulnerabilityFromFinding(FindingEntity finding, IssueEntity issue, String purl) {
        String cve = finding.getIdentifier();
        Double score = finding.getCvssScore();
        String severity = finding.getSeverity() != null ? finding.getSeverity().toLowerCase() : "medium";

        List<Rating> ratings = List.of(new Rating(
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                score,
                severity,
                "CVSSv31",
                null));

        Analysis analysis = issue != null
                ? mapAnalysis(issue.getTriageStatus(), issue.getTriageJustification(), issue.getTriageComment(), issue.getReachability(), issue.getState())
                : new Analysis("in_triage", null, "Discovered during automated scan", List.of());

        return new Vulnerability(
                "vuln-" + cve + "-" + Math.abs(purl.hashCode()),
                cve,
                new Source("NVD", "https://nvd.nist.gov/vuln/detail/" + cve),
                ratings,
                cve + " in " + finding.getPackageName(),
                finding.getDescription(),
                finding.getFixVersions() != null ? "Upgrade component to version " + finding.getFixVersions() : null,
                analysis,
                List.of(new Affects(purl)));
    }

    private Analysis mapAnalysis(String triageStatus, String triageJustification, String comment, String reachability, String state) {
        boolean notAffected = "not_affected".equalsIgnoreCase(triageStatus)
                || ReachabilityStatus.UNREACHABLE.name().equalsIgnoreCase(reachability);
        boolean fixed = "resolved".equalsIgnoreCase(state) || "fixed".equalsIgnoreCase(triageStatus);
        boolean underReview = "under_review".equalsIgnoreCase(triageStatus)
                || "pending_approval".equalsIgnoreCase(triageStatus);

        String cdxState;
        String justification = null;
        List<String> responses = new ArrayList<>();

        if (notAffected) {
            cdxState = "not_affected";
            justification = triageJustification != null && !triageJustification.isBlank()
                    ? triageJustification.toLowerCase().replace(" ", "_")
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
}
