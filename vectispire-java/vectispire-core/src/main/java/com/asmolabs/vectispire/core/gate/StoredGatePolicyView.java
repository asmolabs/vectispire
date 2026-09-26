package com.asmolabs.vectispire.core.gate;

import com.asmolabs.vectispire.common.domain.gate.GatePolicy;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyEntity;
import java.time.Instant;

/**
 * A stored version of a gate policy as the layers above the services hold it: the row's properties
 * under their own names, and {@link #policy} — the rule those columns amount to, read by {@link
 * ActiveGatePolicies#storedPolicy} exactly as the verdict reads it.
 *
 * <p>Not {@code GatePolicyView}: that is the policies route's response record, and the published
 * schema is named after it.
 */
public record StoredGatePolicyView(
        Long id,
        String targetKind,
        Long targetId,
        int version,
        Boolean isActive,
        String failOnSeverity,
        boolean failOnKev,
        boolean fixableOnly,
        boolean includeTriaged,
        boolean includeAiReview,
        boolean failOnUncoveredLanguages,
        String note,
        String createdBy,
        Instant createdAt,
        GatePolicy policy) {

    public static StoredGatePolicyView of(GatePolicyEntity row) {
        return new StoredGatePolicyView(
                row.getId(),
                row.getTargetKind(),
                row.getTargetId(),
                row.getVersion(),
                row.getIsActive(),
                row.getFailOnSeverity(),
                row.getFailOnKev(),
                row.getFixableOnly(),
                row.getIncludeTriaged(),
                row.getIncludeAiReview(),
                row.getFailOnUncoveredLanguages(),
                row.getNote(),
                row.getCreatedBy(),
                row.getCreatedAt(),
                ActiveGatePolicies.storedPolicy(row).policy());
    }
}
