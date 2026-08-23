package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.vex.OpenVexDocument;
import com.asmolabs.zanshin.common.domain.vex.OpenVexStatement;
import com.asmolabs.zanshin.common.domain.vex.VexStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ingests upstream vendor VEX documents (OpenVEX / CSAF) and cascades automated suppressions.
 */
@Service
public class VexIngestorService {

    private final Issues issuesRepo;
    private final IssueTriageService triageService;

    public VexIngestorService(Issues issuesRepo, IssueTriageService triageService) {
        this.issuesRepo = issuesRepo;
        this.triageService = triageService;
    }

    public record IngestionResult(
            int statementsProcessed,
            int matchedIssues,
            int triagedIssues,
            List<String> appliedCves) {}

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
}
