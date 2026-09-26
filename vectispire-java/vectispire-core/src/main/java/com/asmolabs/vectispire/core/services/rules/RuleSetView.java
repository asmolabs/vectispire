package com.asmolabs.vectispire.core.services.rules;

import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import java.time.Instant;

/**
 * A stored rule set as the layers above the services hold it: the row's properties under their own
 * names, not the row.
 *
 * <p>{@code files} is left out: it is the rules themselves, stored as one JSON document, and the
 * routes that answer with this record describe a set rather than serve it. The one route that
 * serves the rules reads them through {@link RuleSetService#contentByHash}.
 */
public record RuleSetView(
        Long id,
        String name,
        String contentHash,
        int ruleCount,
        int fileCount,
        Long sizeBytes,
        Boolean isActive,
        String uploadedBy,
        Instant uploadedAt,
        String activationNote) {

    public static RuleSetView of(SemgrepRuleSetEntity row) {
        return new RuleSetView(
                row.getId(),
                row.getName(),
                row.getContentHash(),
                row.getRuleCount(),
                row.getFileCount(),
                row.getSizeBytes(),
                row.getIsActive(),
                row.getUploadedBy(),
                row.getUploadedAt(),
                row.getActivationNote());
    }
}
