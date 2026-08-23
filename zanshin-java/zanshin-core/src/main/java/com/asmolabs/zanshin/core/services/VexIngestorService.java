package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.cyclonedx.CycloneDxDocument;
import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.vex.OpenVexDocument;
import com.asmolabs.zanshin.common.domain.vex.OpenVexStatement;
import com.asmolabs.zanshin.common.domain.vex.VexStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ingests upstream vendor VEX documents (OpenVEX, OASIS CSAF 2.0, and CycloneDX 1.5/1.6 VEX)
 * and cascades automated suppressions across matching codebase issues.
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
        } catch (Exception e) {
            return new IngestionResult(0, 0, 0, List.of());
        }
    }

    @Transactional
    public IngestionResult ingestAuto(JsonNode root) {
        if (root == null) {
            return new IngestionResult(0, 0, 0, List.of());
        }

        // 1. CycloneDX VEX detection
        if (root.has("bomFormat") && "CycloneDX".equalsIgnoreCase(root.get("bomFormat").asText())) {
            try {
                CycloneDxDocument cdx = json.treeToValue(root, CycloneDxDocument.class);
                return ingestCycloneDx(cdx);
            } catch (Exception ignored) {}
        }

        // 2. OpenVEX detection
        if (root.has("statements") || (root.has("@context") && root.get("@context").asText().contains("openvex"))) {
            try {
                OpenVexDocument openVex = json.treeToValue(root, OpenVexDocument.class);
                return ingestOpenVex(openVex);
            } catch (Exception ignored) {}
        }

        // Fallback: try parsing as OpenVEX
        try {
            OpenVexDocument doc = json.treeToValue(root, OpenVexDocument.class);
            if (doc.statements() != null && !doc.statements().isEmpty()) {
                return ingestOpenVex(doc);
            }
        } catch (Exception ignored) {}

        return new IngestionResult(0, 0, 0, List.of());
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

                com.asmolabs.zanshin.common.domain.issues.VexJustification justification = mapCycloneDxJustification(vuln.analysis().justification());
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

                com.asmolabs.zanshin.common.domain.issues.VexJustification justification = mapJustification(statement.justification());

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

    private com.asmolabs.zanshin.common.domain.issues.VexJustification mapJustification(
            com.asmolabs.zanshin.common.domain.vex.VexJustification justification) {
        if (justification == null) {
            return com.asmolabs.zanshin.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
        }
        return switch (justification) {
            case COMPONENT_NOT_PRESENT -> com.asmolabs.zanshin.common.domain.issues.VexJustification.COMPONENT_NOT_PRESENT;
            case VULNERABLE_CODE_NOT_PRESENT -> com.asmolabs.zanshin.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_PRESENT;
            case VULNERABLE_CODE_NOT_IN_EXECUTE_PATH -> com.asmolabs.zanshin.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH;
            case VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY -> com.asmolabs.zanshin.common.domain.issues.VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY;
            case INLINE_MITIGATIONS_EXIST -> com.asmolabs.zanshin.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
        };
    }

    private com.asmolabs.zanshin.common.domain.issues.VexJustification mapCycloneDxJustification(String justification) {
        if (justification == null) {
            return com.asmolabs.zanshin.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
        }
        String normalized = justification.toLowerCase().replace("-", "_").replace(" ", "_");
        if (normalized.contains("component_not_present")) {
            return com.asmolabs.zanshin.common.domain.issues.VexJustification.COMPONENT_NOT_PRESENT;
        }
        if (normalized.contains("not_in_execute_path") || normalized.contains("not_in_execution_path")) {
            return com.asmolabs.zanshin.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH;
        }
        if (normalized.contains("not_present")) {
            return com.asmolabs.zanshin.common.domain.issues.VexJustification.VULNERABLE_CODE_NOT_PRESENT;
        }
        if (normalized.contains("cannot_be_controlled")) {
            return com.asmolabs.zanshin.common.domain.issues.VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY;
        }
        return com.asmolabs.zanshin.common.domain.issues.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST;
    }
}
