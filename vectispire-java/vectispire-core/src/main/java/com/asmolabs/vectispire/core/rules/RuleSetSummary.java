package com.asmolabs.vectispire.core.rules;

import com.asmolabs.vectispire.core.rules.persistence.RuleSetRow;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

/**
 * A rule set as the listing shows it: everything except the rules themselves.
 *
 * <p><b>The wire's record, not the query's.</b> The listing used to send the projection the query
 * selects into, so the table's shape was the contract without any rule seeing it (decision 0028
 * listed it for step 5). The components and their JSON names are the projection's, one for one —
 * {@code openapi.json} did not move — and the two can now change apart.
 *
 * @param active {@code true} for the one active set, {@code null} for the others. See {@code
 *     RuleSets} for why it is not {@code false}
 */
public record RuleSetSummary(
        Long id,
        String name,
        String contentHash,
        int ruleCount,
        int fileCount,
        String sizeBytes,
        @JsonProperty("isActive") Boolean active,
        String uploadedBy,
        Instant uploadedAt,
        String activationNote) {

    static RuleSetSummary of(RuleSetRow row) {
        return new RuleSetSummary(
                row.id(),
                row.name(),
                row.contentHash(),
                row.ruleCount(),
                row.fileCount(),
                row.sizeBytes(),
                row.active(),
                row.uploadedBy(),
                row.uploadedAt(),
                row.activationNote());
    }
}
