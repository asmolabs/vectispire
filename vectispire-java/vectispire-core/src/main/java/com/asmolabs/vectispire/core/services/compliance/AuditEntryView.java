package com.asmolabs.vectispire.core.services.compliance;

import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * An audit entry as the trail's screen reads it, hashes included: they are what lets a reader
 * check the chain themselves. The row's fields, not the row — no JPA entity crosses the API.
 */
public record AuditEntryView(
        UUID id,
        String description,
        String operationType,
        String resourceId,
        Instant timestamp,
        String userId,
        String ipAddress,
        String userAgent,
        String previousHash,
        String entryHash) {

    public static AuditEntryView of(AuditLogEntity row) {
        return new AuditEntryView(
                row.getId(),
                row.getDescription(),
                row.getOperationType(),
                row.getResourceId(),
                row.getTimestamp(),
                row.getUserId(),
                row.getIpAddress(),
                row.getUserAgent(),
                row.getPreviousHash(),
                row.getEntryHash());
    }
}
