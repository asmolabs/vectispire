package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.common.domain.vex.OpenVexStatement;
import com.asmolabs.vectispire.common.domain.vex.VexStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ingests upstream vendor VEX documents (OpenVEX, OASIS CSAF 2.0, and CycloneDX VEX)
 * and cascades automated suppressions across matching codebase issues.
 *
 * <p><b>A document this cannot read says so.</b> It used to try each format in turn behind
 * {@code catch (Exception ignored)} and, having exhausted them, return "nothing ingested" —
 * HTTP 200, no error, no log. So when the OpenVEX model turned out to reject every conformant
 * v0.2.0 document, the endpoint reported perfect health while doing nothing at all, for anyone
 * who tried it.
 *
 * <p>Trying formats in turn is right: a caller uploads a file and should not have to declare its
 * shape. Swallowing the reason is not. What is kept now is <em>why</em> each attempt failed, and
 * a payload that matched no format at all returns that instead of silence.
 */
@Service
public class VexIngestorService {

    private final Issues issuesRepo;
    private final IssueTriageService triageService;
    private final ObjectMapper json;

    public VexIngestorService(Issues issuesRepo, IssueTriageService triageService) {
        this.issuesRepo = issuesRepo;
        this.triageService = triageService;
        this.json = new ObjectMapper()
                .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    public record IngestionResult(
            int statementsProcessed,
            int matchedIssues,
            int triagedIssues,
            List<String> appliedCves) {}

    @Transactional
    public IngestionResult ingestPayload(String payload) {
        if (payload == null || payload.isBlank()) {
            return new IngestionResult(0, 0, 0, List.of());
        }
        try {
            JsonNode root = json.readTree(payload);
            return ingestAuto(root);
        } catch (Exception notJson) {
            throw new IllegalArgumentException(
                    "This is not a JSON document: " + firstLineOf(notJson), notJson);
        }
    }

    @Transactional
    public IngestionResult ingestAuto(JsonNode root) {
        if (root == null) {
            return new IngestionResult(0, 0, 0, List.of());
        }

        List<String> refusals = new ArrayList<>();

        // 1. CycloneDX VEX detection
        if (root.has("bomFormat") && "CycloneDX".equalsIgnoreCase(root.get("bomFormat").asText())) {
            try {
                CycloneDxDocument cdx = json.treeToValue(root, CycloneDxDocument.class);
                return ingestCycloneDx(cdx);
            } catch (Exception refused) {
                refusals.add("CycloneDX: " + firstLineOf(refused));
            }
        }

        // 2. OpenVEX detection
        if (root.has("statements") || (root.has("@context") && root.get("@context").asText().contains("openvex"))) {
            try {
                OpenVexDocument openVex = json.treeToValue(root, OpenVexDocument.class);
                return ingestOpenVex(openVex);
            } catch (Exception refused) {
                refusals.add("OpenVEX: " + firstLineOf(refused));
            }
        }

        // Fallback: try parsing as OpenVEX
        try {
            OpenVexDocument doc = json.treeToValue(root, OpenVexDocument.class);
            if (doc.statements() != null && !doc.statements().isEmpty()) {
                return ingestOpenVex(doc);
            }
        } catch (Exception refused) {
            refusals.add("OpenVEX: " + firstLineOf(refused));
        }

        // A document nobody could read is the case this method exists to report, not to hide.
        // An empty result and an unreadable file used to be the same answer.
        throw new IllegalArgumentException(refusals.isEmpty()
                ? "No VEX statement was found: the document declares neither CycloneDX nor OpenVEX."
                : "No VEX format could read this document — " + String.join("; ", refusals));
    }

    @Transactional
    public IngestionResult ingestCycloneDx(CycloneDxDocument doc) {
        if (doc == null || doc.vulnerabilities() == null || doc.vulnerabilities().isEmpty()) {
            return new IngestionResult(0, 0, 0, List.of());
        }

        String author = doc.metadata() != null && doc.metadata().tools() != null && !doc.metadata().tools().isEmpty()
                ? doc.metadata().tools().get(0).name()
                : "Upstream CycloneDX Provider";

        int matched = 0;
        int triaged = 0;
        List<String> appliedCves = new ArrayList<>();

        for (CycloneDxDocument.Vulnerability vuln : doc.vulnerabilities()) {
            String cveId = vuln.id();
            if (cveId == null || cveId.isBlank()) {
                continue;
            }

            if (vuln.analysis() != null && "not_affected".equalsIgnoreCase(vuln.analysis().state())) {
                List<IssueEntity> matchingIssues = issuesRepo.findByIdentifier(cveId);
                matched += matchingIssues.size();

                com.asmolabs.vectispire.common.domain.issues.VexJustification justification = mapCycloneDxJustification(vuln.analysis().justification());
                String comment = "Upstream CycloneDX VEX by " + author + ": "
                        + (vuln.analysis().detail() != null ? vuln.analysis().detail() : "Declared not affected in CycloneDX BOM.");

                for (IssueEntity issue : matchingIssues) {
                    if ("not_affected".equalsIgnoreCase(issue.getTriageStatus())
                            || "resolved".equalsIgnoreCase(issue.getState())) {
                        continue;
                    }

                    triageService.triage(
                            issue.getId(),
                            new Triage.Request(
                                    TriageStatus.NOT_AFFECTED,
                                    "upstream_vex (CycloneDX: " + author + ")",
                                    justification,
                                    comment,
                                    null),
                            true);
                    triaged++;
                }
                appliedCves.add(cveId);
            }
        }

        return new IngestionResult(doc.vulnerabilities().size(), matched, triaged, appliedCves);
    }

    @Transactional
    public IngestionResult ingestOpenVex(OpenVexDocument doc) {
        if (doc == null || doc.statements() == null || doc.statements().isEmpty()) {
            return new IngestionResult(0, 0, 0, List.of());
        }

        String author = doc.author() != null ? doc.author() : "Upstream Vendor";
        int matched = 0;
        int triaged = 0;
        List<String> appliedCves = new ArrayList<>();

        for (OpenVexStatement statement : doc.statements()) {
            if (statement.vulnerability() == null) {
                continue;
            }

            String cveId = statement.vulnerability().get("name");
            if (cveId == null || cveId.isBlank()) {
                cveId = statement.vulnerability().get("id");
            }
            if (cveId == null || cveId.isBlank()) {
                continue;
            }

            if (statement.status() == VexStatus.NOT_AFFECTED) {
                List<IssueEntity> matchingIssues = issuesRepo.findByIdentifier(cveId);
                matched += matchingIssues.size();

                com.asmolabs.vectispire.common.domain.issues.VexJustification justification = mapJustification(statement.justification());

                String comment = "Upstream VEX statement by " + author + ": "
                        + (statement.impactStatement() != null ? statement.impactStatement() : "Declared not affected by upstream maintainer.");

                for (IssueEntity issue : matchingIssues) {
                    if ("not_affected".equalsIgnoreCase(issue.getTriageStatus())
                            || "resolved".equalsIgnoreCase(issue.getState())) {
                        continue;
                    }

                    triageService.triage(
                            issue.getId(),
                            new Triage.Request(
                                    TriageStatus.NOT_AFFECTED,
                                    "upstream_vex (" + author + ")",
                                    justification,
                                    comment,
                                    null),
                            true);
                    triaged++;
                }
                appliedCves.add(cveId);
            }
        }

        return new IngestionResult(doc.statements().size(), matched, triaged, appliedCves);
    }

    /** Jackson's messages carry the whole path on later lines; the first says what went wrong. */
    private static String firstLineOf(Exception failure) {
        return String.valueOf(failure.getMessage()).lines().findFirst().orElse(failure.toString());
    }

    /**
     * A missing justification falls back rather than refusing the statement.
     *
     * <p>The specification requires one on {@code not_affected}; a document that omits it is
     * malformed, and dropping the statement would discard an upstream vendor's assertion over a
     * field the triage record does not act on. The fallback is the weakest of the five, so a
     * missing justification never reads as a stronger claim than was made.
     *
     * <p>The translation table that used to live here is gone with the enumeration it translated:
     * one controlled vocabulary now has one Java enum, and mapping a value to itself was the shape
     * that let the two drift.
     */
    private static com.asmolabs.vectispire.common.domain.issues.VexJustification mapJustification(
            com.asmolabs.vectispire.common.domain.issues.VexJustification justification) {
        return justification == null
                ? com.asmolabs.vectispire.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST
                : justification;
    }

    private com.asmolabs.vectispire.common.domain.issues.VexJustification mapCycloneDxJustification(String justification) {
        if (justification == null) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
        }
        String normalized = justification.toLowerCase().replace("-", "_").replace(" ", "_");
        if (normalized.contains("component_not_present")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.COMPONENT_NOT_PRESENT;
        }
        if (normalized.contains("not_in_execute_path") || normalized.contains("not_in_execution_path")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH;
        }
        if (normalized.contains("not_present")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_PRESENT;
        }
        if (normalized.contains("cannot_be_controlled")) {
            return com.asmolabs.vectispire.common.domain.issues.VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY;
        }
        return com.asmolabs.vectispire.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
    }
}
