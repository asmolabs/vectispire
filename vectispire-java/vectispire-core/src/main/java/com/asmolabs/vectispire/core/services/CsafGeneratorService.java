package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.csaf.CsafDocument;
import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import org.springframework.data.jpa.domain.Specification;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Generates OASIS CSAF 2.0 VEX security advisories for scans and aggregate target posture.
 */
@Service
public class CsafGeneratorService {

    private final Scans scansRepo;
    private final Findings findingsRepo;
    private final Issues issuesRepo;

    public CsafGeneratorService(Scans scansRepo, Findings findingsRepo, Issues issuesRepo) {
        this.scansRepo = scansRepo;
        this.findingsRepo = findingsRepo;
        this.issuesRepo = issuesRepo;
    }

    public Optional<CsafDocument> generateForScan(Long scanId) {
        return scansRepo.findById(scanId).map(this::buildCsafForScan);
    }

    public CsafDocument generateAggregate(Visibility allowed) {
        List<IssueEntity> issues = issuesRepo.findAll(withCve(allowed));
        Map<String, CsafDocument.FullProductName> productMap = new HashMap<>();
        List<CsafDocument.CsafVulnerability> vulnerabilities = new ArrayList<>();

        for (IssueEntity issue : issues) {
            String cve = issue.getIdentifier();
            if (cve == null || !cve.toUpperCase().startsWith("CVE-")) {
                continue;
            }

            String pkg = issue.getPackageName() != null ? issue.getPackageName() : "unknown";
            String version = issue.getPackageVersion() != null ? issue.getPackageVersion() : "latest";
            String productId = "CSAFPID-" + Math.abs((pkg + "@" + version).hashCode());

            productMap.putIfAbsent(productId, new CsafDocument.FullProductName(
                    productId,
                    pkg + " " + version,
                    Map.of("purl", issue.getPurl() != null ? issue.getPurl() : "pkg:generic/" + pkg + "@" + version)));

            // A person's triage clears a product. The reachability column does not: it was set
            // by a substring search that did not match, and this line published that as
            // `known_not_affected` in a document nobody approved.
            boolean notAffected = "not_affected".equalsIgnoreCase(issue.getTriageStatus());
            boolean fixed = "resolved".equalsIgnoreCase(issue.getState()) || "fixed".equalsIgnoreCase(issue.getTriageStatus());
            boolean underInvestigation = "under_review".equalsIgnoreCase(issue.getTriageStatus())
                    || "pending_approval".equalsIgnoreCase(issue.getTriageStatus());

            List<String> notAffectedList = notAffected ? List.of(productId) : List.of();
            List<String> affectedList = (!notAffected && !fixed && !underInvestigation) ? List.of(productId) : List.of();
            List<String> fixedList = fixed ? List.of(productId) : List.of();
            List<String> underInvestigationList = underInvestigation ? List.of(productId) : List.of();

            CsafDocument.ProductStatus productStatus = new CsafDocument.ProductStatus(
                    notAffectedList.isEmpty() ? null : notAffectedList,
                    affectedList.isEmpty() ? null : affectedList,
                    fixedList.isEmpty() ? null : fixedList,
                    underInvestigationList.isEmpty() ? null : underInvestigationList);

            List<CsafDocument.Threat> threats = affectedList.isEmpty() ? List.of() : List.of(new CsafDocument.Threat(
                    "impact",
                    issue.getDescription() != null ? issue.getDescription() : "Identified vulnerable component.",
                    affectedList));

            List<CsafDocument.Note> notes = notAffected && issue.getTriageJustification() != null
                    ? List.of(new CsafDocument.Note("description", "VEX Justification", issue.getTriageJustification()))
                    : List.of();

            vulnerabilities.add(new CsafDocument.CsafVulnerability(
                    cve,
                    cve + " in " + pkg,
                    productStatus,
                    threats.isEmpty() ? null : threats,
                    notes.isEmpty() ? null : notes));
        }

        Instant now = Instant.now();
        CsafDocument.DocumentMetadata meta = new CsafDocument.DocumentMetadata(
                "csaf_vex",
                "2.0",
                "Vectispire Aggregate Security Advisory",
                new CsafDocument.Publisher("vendor", "Vectispire Control Plane", "https://vectispire.internal"),
                new CsafDocument.Tracking("VECTISPIRE-AGGREGATE-CSAF", now, now, "final", "1.0.0"));

        return new CsafDocument(
                meta,
                new CsafDocument.ProductTree(new ArrayList<>(productMap.values())),
                vulnerabilities);
    }

    private CsafDocument buildCsafForScan(ScanEntity scan) {
        List<FindingEntity> scanFindings = findingsRepo.findByScanId(scan.getId());
        Map<String, CsafDocument.FullProductName> productMap = new HashMap<>();
        List<CsafDocument.CsafVulnerability> vulnerabilities = new ArrayList<>();

        for (FindingEntity finding : scanFindings) {
            String cve = finding.getIdentifier();
            if (cve == null || !cve.toUpperCase().startsWith("CVE-")) {
                continue;
            }

            String pkg = finding.getPackageName() != null ? finding.getPackageName() : "unknown";
            String version = finding.getPackageVersion() != null ? finding.getPackageVersion() : "latest";
            String productId = "CSAFPID-" + Math.abs((pkg + "@" + version).hashCode());

            productMap.putIfAbsent(productId, new CsafDocument.FullProductName(
                    productId,
                    pkg + " " + version,
                    Map.of("purl", finding.getPurl() != null ? finding.getPurl() : "pkg:generic/" + pkg + "@" + version)));

            // **Never from reachability.** That column was set by a substring search that did not
            // match, and this line put the product in the CSAF `known_not_affected` list on the
            // strength of it — a machine-readable exoneration nobody approved. A component is
            // cleared here only when a person triaged it as such.
            boolean notAffected = false;
            CsafDocument.ProductStatus productStatus = new CsafDocument.ProductStatus(
                    notAffected ? List.of(productId) : null,
                    notAffected ? null : List.of(productId),
                    null,
                    null);

            vulnerabilities.add(new CsafDocument.CsafVulnerability(
                    cve,
                    cve + " in " + pkg,
                    productStatus,
                    null,
                    null));
        }

        Instant timestamp = scan.getCreatedAt() != null ? scan.getCreatedAt() : Instant.now();
        CsafDocument.DocumentMetadata meta = new CsafDocument.DocumentMetadata(
                "csaf_vex",
                "2.0",
                "Vectispire Scan #" + scan.getId() + " Security Advisory",
                new CsafDocument.Publisher("vendor", "Vectispire Control Plane", "https://vectispire.internal"),
                new CsafDocument.Tracking("VECTISPIRE-SCAN-" + scan.getId(), timestamp, timestamp, "final", "1.0.0"));

        return new CsafDocument(
                meta,
                new CsafDocument.ProductTree(new ArrayList<>(productMap.values())),
                vulnerabilities);
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
    private static Specification<IssueEntity> withCve(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, allowed)
                .toSpecification()
                .and((root, query, builder) ->
                        builder.like(builder.upper(root.get("identifier")), "CVE-%"));
    }

}
