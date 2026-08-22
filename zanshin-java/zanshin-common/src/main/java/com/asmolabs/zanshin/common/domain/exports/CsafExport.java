package com.asmolabs.zanshin.common.domain.exports;

import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Builds an OASIS CSAF 2.0 VEX Profile document from Zanshin issues.
 *
 * <p>Pure domain calculation: independent of database, network and framework.
 */
public final class CsafExport {

    private CsafExport() {}

    public record Options(
            String targetName,
            String author,
            String toolVersion,
            String namespace,
            Instant generatedAt) {}

    public static CsafDocument build(List<ExportableIssue> issues, Options options) {
        String target = options.targetName() == null || options.targetName().isBlank() ? "target" : options.targetName();
        String author = options.author() == null || options.author().isBlank() ? "Zanshin" : options.author();
        String version = options.toolVersion() == null || options.toolVersion().isBlank() ? "1.0.0" : options.toolVersion();
        String namespace = options.namespace() == null || options.namespace().isBlank() ? "https://zanshin.internal" : options.namespace();
        Instant now = options.generatedAt() == null ? Instant.now() : options.generatedAt();

        // 1. Build Document Metadata
        String docId = "CSAF-" + now.getEpochSecond() + "-" + Math.abs(target.hashCode());
        CsafDocument.Document document = new CsafDocument.Document(
                "csaf_vex",
                "2.0",
                "VEX Security Advisory for " + target,
                new CsafDocument.Publisher("vendor", author, namespace),
                new CsafDocument.Tracking(
                        now.toString(),
                        now.toString(),
                        docId,
                        "final",
                        "1.0.0",
                        new CsafDocument.Generator(new CsafDocument.Engine("Zanshin", version), now.toString())),
                List.of(new CsafDocument.Note("summary", "Summary", "Security and triage assessment for " + target)));

        // 2. Build Product Tree
        Map<String, String> productMap = new HashMap<>(); // key -> productId
        List<CsafDocument.FullProductName> fullProducts = new ArrayList<>();

        // Target itself is product 0
        String targetProductId = "CSAFPID-0000";
        fullProducts.add(new CsafDocument.FullProductName(target, targetProductId, null));

        int counter = 1;
        for (ExportableIssue issue : issues) {
            String pkgKey = (issue.purl() != null && !issue.purl().isBlank())
                    ? issue.purl()
                    : ((issue.packageName() != null ? issue.packageName() : "pkg") + "@" + (issue.packageVersion() != null ? issue.packageVersion() : "unknown"));

            if (!productMap.containsKey(pkgKey)) {
                String pid = String.format("CSAFPID-%04d", counter++);
                productMap.put(pkgKey, pid);
                String name = (issue.packageName() != null ? issue.packageName() : "package")
                        + (issue.packageVersion() != null ? " " + issue.packageVersion() : "");
                CsafDocument.ProductIdentificationHelper helper = issue.purl() != null && !issue.purl().isBlank()
                        ? new CsafDocument.ProductIdentificationHelper(issue.purl(), null)
                        : null;
                fullProducts.add(new CsafDocument.FullProductName(name, pid, helper));
            }
        }

        CsafDocument.ProductTree productTree = new CsafDocument.ProductTree(fullProducts);

        // 3. Build Vulnerabilities
        List<CsafDocument.Vulnerability> vulnerabilities = new ArrayList<>();
        for (ExportableIssue issue : issues) {
            String pkgKey = (issue.purl() != null && !issue.purl().isBlank())
                    ? issue.purl()
                    : ((issue.packageName() != null ? issue.packageName() : "pkg") + "@" + (issue.packageVersion() != null ? issue.packageVersion() : "unknown"));
            String pid = productMap.getOrDefault(pkgKey, targetProductId);

            List<String> knownAffected = new ArrayList<>();
            List<String> knownNotAffected = new ArrayList<>();
            List<String> fixed = new ArrayList<>();
            List<String> underInvestigation = new ArrayList<>();
            List<CsafDocument.Flag> flags = new ArrayList<>();

            TriageStatus status = issue.triageStatus() != null ? issue.triageStatus() : (issue.resolved() ? TriageStatus.FIXED : TriageStatus.UNDER_REVIEW);

            switch (status) {
                case AFFECTED -> knownAffected.add(pid);
                case NOT_AFFECTED -> {
                    knownNotAffected.add(pid);
                    String flagLabel = mapJustificationToFlag(issue.triageJustification());
                    flags.add(new CsafDocument.Flag(flagLabel, List.of(pid), now.toString()));
                }
                case FIXED -> fixed.add(pid);
                case UNDER_REVIEW -> underInvestigation.add(pid);
            }

            CsafDocument.ProductStatus productStatus = new CsafDocument.ProductStatus(
                    knownAffected.isEmpty() ? null : knownAffected,
                    knownNotAffected.isEmpty() ? null : knownNotAffected,
                    fixed.isEmpty() ? null : fixed,
                    underInvestigation.isEmpty() ? null : underInvestigation);

            List<CsafDocument.Note> notes = new ArrayList<>();
            if (issue.description() != null && !issue.description().isBlank()) {
                notes.add(new CsafDocument.Note("description", "Vulnerability Details", issue.description()));
            }
            if (issue.triageComment() != null && !issue.triageComment().isBlank()) {
                notes.add(new CsafDocument.Note("details", "Triage Justification Comment", issue.triageComment()));
            }

            List<CsafDocument.Remediation> remediations = new ArrayList<>();
            if (issue.fixVersions() != null && !issue.fixVersions().isBlank()) {
                remediations.add(new CsafDocument.Remediation("vendor_fix", "Upgrade to: " + issue.fixVersions(), List.of(pid)));
            }

            List<CsafDocument.Score> scores = new ArrayList<>();
            if (issue.cvssScore() != null) {
                scores.add(new CsafDocument.Score(Map.of("version", "3.1", "baseScore", issue.cvssScore())));
            }

            vulnerabilities.add(new CsafDocument.Vulnerability(
                    issue.identifier(),
                    issue.identifier() + " in " + (issue.packageName() != null ? issue.packageName() : target),
                    notes.isEmpty() ? null : notes,
                    productStatus,
                    flags.isEmpty() ? null : flags,
                    remediations.isEmpty() ? null : remediations,
                    scores.isEmpty() ? null : scores));
        }

        return new CsafDocument(document, productTree, vulnerabilities);
    }

    private static String mapJustificationToFlag(String justification) {
        if (justification == null) {
            return "vulnerable_code_cannot_be_controlled_by_adversary";
        }
        String clean = justification.toLowerCase();
        if (clean.contains("not_present") || clean.contains("not present") || clean.contains("absent")) {
            return "component_not_present";
        }
        if (clean.contains("mitigation") || clean.contains("inline")) {
            return "inline_mitigations_already_exist";
        }
        if (clean.contains("not_reachable") || clean.contains("unreachable") || clean.contains("cannot_be_controlled")) {
            return "vulnerable_code_cannot_be_controlled_by_adversary";
        }
        return "vulnerable_code_not_in_execute_path";
    }
}
