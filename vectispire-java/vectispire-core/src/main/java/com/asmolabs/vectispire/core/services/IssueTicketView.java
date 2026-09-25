package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.core.persistence.IssueTicketEntity;
import java.time.Instant;

/**
 * A ticket link as a route returns it: the row's fields, not the row — no JPA entity crosses the
 * API. Names are the entity's properties, so the wire is unchanged.
 */
public record IssueTicketView(
        Long id,
        Long issueId,
        String provider,
        String ticketKey,
        String ticketUrl,
        String status,
        Instant createdAt,
        Instant updatedAt) {

    public static IssueTicketView of(IssueTicketEntity row) {
        return new IssueTicketView(
                row.getId(),
                row.getIssueId(),
                row.getProvider(),
                row.getTicketKey(),
                row.getTicketUrl(),
                row.getStatus(),
                row.getCreatedAt(),
                row.getUpdatedAt());
    }
}
