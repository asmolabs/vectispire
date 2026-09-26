package com.asmolabs.vectispire.core.services.exports;

import com.asmolabs.vectispire.common.domain.exports.CsafDocument;
import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.services.settings.ProductVersion;
import java.util.Locale;
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
 *
 * <p><b>It built its own CSAF model until now, and the codebase held two.</b> This one, signed
 * into the evidence bundle, and {@code CsafExport}'s, served on the per-target download — two
 * renderings of one standard over the same estate, free to disagree and with nothing to notice if
 * they did. Both omitted {@code /document/tracking/revision_history}, which the CSAF 2.0 schema
 * makes mandatory, so both were invalid in the same way for the same reason: nothing ever
 * validated either against the schema, only against itself.
 *
 * <p>One model now, {@code domain.exports.CsafDocument}, because it was the richer of the two —
 * notes, flags, remediations, scores, a generator engine and a typed product identification
 * helper where this one had a loose map.
 */
@Service
public class CsafGeneratorService {

    private final Scans scansRepo;
    private final Findings findingsRepo;
    private final Issues issuesRepo;
    private final ProductVersion version;

    public CsafGeneratorService(Scans scansRepo, Findings findingsRepo, Issues issuesRepo, ProductVersion version) {
        this.scansRepo = scansRepo;
        this.findingsRepo = findingsRepo;
        this.issuesRepo = issuesRepo;
        this.version = version;
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
            if (cve == null || !cve.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                continue;
            }

            String pkg = issue.getPackageName() != null ? issue.getPackageName() : "unknown";
            String version = issue.getPackageVersion() != null ? issue.getPackageVersion() : "latest";
            String productId = "CSAFPID-" + Math.abs((pkg + "@" + version).hashCode());

            // **Name then id, which is the opposite of the record this replaced.** Ported by
            // position, the two would have swapped and every product would carry a human label
            // where a machine expects an identifier.
            productMap.putIfAbsent(productId, new CsafDocument.FullProductName(
                    pkg + " " + version,
                    productId,
                    new CsafDocument.ProductIdentificationHelper(
                            issue.getPurl() != null ? issue.getPurl() : "pkg:generic/" + pkg + "@" + version, null)));

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

            // **Affected first.** The record this replaced took not-affected first; moving these
            // four lists across by position would have published every vulnerable product as
            // cleared, in a signed document, over the one field a consumer trusts without reading.
            CsafDocument.ProductStatus productStatus = new CsafDocument.ProductStatus(
                    affectedList.isEmpty() ? null : affectedList,
                    notAffectedList.isEmpty() ? null : notAffectedList,
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
                    notes.isEmpty() ? null : notes,
                    productStatus,
                    threats.isEmpty() ? null : threats,
                    null,
                    null,
                    null));
        }

        Instant now = Instant.now();
        return new CsafDocument(
                metadata("Vectispire Aggregate Security Advisory", "VECTISPIRE-AGGREGATE-CSAF", now),
                new CsafDocument.ProductTree(new ArrayList<>(productMap.values())),
                vulnerabilities);
    }

    private CsafDocument buildCsafForScan(ScanEntity scan) {
        List<FindingEntity> scanFindings = findingsRepo.findByScanId(scan.getId());
        Map<String, CsafDocument.FullProductName> productMap = new HashMap<>();
        List<CsafDocument.CsafVulnerability> vulnerabilities = new ArrayList<>();

        for (FindingEntity finding : scanFindings) {
            String cve = finding.getIdentifier();
            if (cve == null || !cve.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                continue;
            }

            String pkg = finding.getPackageName() != null ? finding.getPackageName() : "unknown";
            String version = finding.getPackageVersion() != null ? finding.getPackageVersion() : "latest";
            String productId = "CSAFPID-" + Math.abs((pkg + "@" + version).hashCode());

            productMap.putIfAbsent(productId, new CsafDocument.FullProductName(
                    pkg + " " + version,
                    productId,
                    new CsafDocument.ProductIdentificationHelper(
                            finding.getPurl() != null ? finding.getPurl() : "pkg:generic/" + pkg + "@" + version, null)));

            // **Never from reachability.** That column was set by a substring search that did not
            // match, and this line put the product in the CSAF `known_not_affected` list on the
            // strength of it — a machine-readable exoneration nobody approved. A component is
            // cleared here only when a person triaged it as such.
            boolean notAffected = false;
            CsafDocument.ProductStatus productStatus = new CsafDocument.ProductStatus(
                    notAffected ? null : List.of(productId),
                    notAffected ? List.of(productId) : null,
                    null,
                    null);

            vulnerabilities.add(new CsafDocument.CsafVulnerability(
                    cve,
                    cve + " in " + pkg,
                    null,
                    productStatus,
                    null,
                    null,
                    null,
                    null));
        }

        Instant timestamp = scan.getCreatedAt() != null ? scan.getCreatedAt() : Instant.now();
        return new CsafDocument(
                metadata(
                        "Vectispire Scan #" + scan.getId() + " Security Advisory",
                        "VECTISPIRE-SCAN-" + scan.getId(),
                        timestamp),
                new CsafDocument.ProductTree(new ArrayList<>(productMap.values())),
                vulnerabilities);
    }

    /**
     * The document header both advisories share.
     *
     * <p>Written once because it carries the six mandatory tracking properties, and a mandatory
     * field spelled out at two construction sites is a mandatory field that will be missing from
     * one of them. It already was: {@code revision_history} was absent from both.
     *
     * <p>The history has a single entry, and honestly so. These advisories are regenerated from
     * current data rather than amended, so there is one revision — the rendering the reader holds.
     */
    private CsafDocument.Document metadata(String title, String id, Instant at) {
        String stamp = at.toString();
        return new CsafDocument.Document(
                "csaf_vex",
                "2.0",
                title,
                new CsafDocument.Publisher("vendor", "Vectispire Control Plane", "https://vectispire.internal"),
                new CsafDocument.Tracking(
                        stamp,
                        stamp,
                        id,
                        "final",
                        "1.0.0",
                        List.of(new CsafDocument.Revision(
                                "1.0.0", stamp, "Generated from the current triage state.")),
                        new CsafDocument.Generator(
                                // The build's version, as every other export states it; it was
                                // "1.0.0", a release that does not exist. Left out when unknown.
                                new CsafDocument.Engine("Vectispire", version.get()), stamp)),
                null);
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
